"""Safely import a selected CI regression witness into the Git-tracked corpus.

A CI artifact is UNTRUSTED data: no zip member is extracted as a path, and
review/promotion happens only after evidence, oracle and Base checks pass.
"""

from __future__ import annotations

import json
import re
import subprocess
from hashlib import sha256
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

import yaml

from .analyze import compare, signature
from .build import build_variant
from .config import ROOT, ConfigError, UniqueKeyLoader, load_cases, load_config, oracle_argv, validate_case_args, workspace_path
from .report import generate_case
from .run import ENV, run_case
from .source import inventory, tree_digest

MAX_ENTRIES = 30_000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 400 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _relative(name: str) -> str:
    """Normalize a zip member name; never accept escape or absolute members."""
    path = PurePosixPath(name)
    if (not name or "\\" in name or "\x00" in name or path.is_absolute()
        or any(part in ("", ".", "..") for part in name.split("/"))):
        raise ConfigError(f"unsafe archive member: {name!r}")
    return path.as_posix()


def _bytes(zf: ZipFile, entries: dict[str, object], name: str) -> bytes:
    name = _relative(name)
    info = entries.get(name)
    if info is None or info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
        raise ConfigError(f"missing or oversized evidence member: {name}")
    data = zf.read(info)
    if len(data) != info.file_size:
        raise ConfigError(f"truncated evidence member: {name}")
    return data


def _dict(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} is not an object")
    return value


def inspect_archive(archive: Path, config: dict, case_id: str) -> tuple[dict, dict]:
    """Read only the selected fixture and its evidence, never extract the zip."""
    with ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
            raise ConfigError("CI evidence archive exceeds safety limits")
        entries = {}
        for info in infos:
            name = _relative(info.filename.rstrip("/"))
            if name in entries:
                raise ConfigError(f"duplicate archive member: {name}")
            # Reject Unix symlinks, even though we never extract members.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ConfigError(f"symlink archive member: {name}")
            entries[name] = info
        report_candidates = [name for name in entries
                             if name.startswith("artifacts/") and name.endswith("/report.json")]
        if len(report_candidates) != 1:
            raise ConfigError("CI evidence must contain exactly one run report.json")
        report = _dict(json.loads(_bytes(zf, entries, report_candidates[0])), "report")
        run_dir = _dict(report.get("run"), "run").get("directory")
        if report_candidates[0] != f"{run_dir}/report.json" or report.get("schema") != "patchguard-safelab/1":
            raise ConfigError("run path or report schema mismatch")
        resolved = _dict(_dict(report.get("config"), "config").get("resolved"), "resolved config")
        if (_dict(resolved.get("target"), "target").get("name") != config["target"]["name"]
            or _dict(resolved.get("regression"), "regression").get("dir") != config["regression"]["dir"]):
            raise ConfigError("evidence is for a different target or regression directory")
        if resolved.get("corpus") != config["corpus"]:
            raise ConfigError("CI corpus differs from the trusted configuration")
        generated_dir = config["regression"]["dir"].rstrip("/")
        manifest_name = f"{generated_dir}/manifest.yaml"
        rows = yaml.load(_bytes(zf, entries, manifest_name), Loader=UniqueKeyLoader)
        if not isinstance(rows, list):
            raise ConfigError("generated regression manifest must be a list")
        matches = [row for row in rows if isinstance(row, dict) and row.get("id") == case_id]
        if len(matches) != 1:
            raise ConfigError(f"case {case_id!r} not uniquely present in generated manifest")
        row = matches[0]
        required = {"id", "kind", "input", "expected_exit", "expected_stdout",
                    "input_sha256", "preserved_signature", "witness_role", "witness_mode"}
        if not required <= set(row) or set(row) - required - {"args"}:
            raise ConfigError("generated witness has unknown or missing fields")
        if row["witness_role"] not in ("base", "candidate"):
            raise ConfigError("witness_role must be base or candidate")
        args = validate_case_args(row.get("args", config["run"].get("args", [])),
                                  config["run"]["method"], "generated.args")
        if row["kind"] not in ("valid", "invalid", "boundary", "regression"):
            raise ConfigError("invalid generated case kind")
        if row["witness_mode"] not in ("release", "checked"):
            raise ConfigError("invalid witness mode")
        if not HEX64.fullmatch(str(row["input_sha256"])) or not HEX64.fullmatch(str(row["preserved_signature"])):
            raise ConfigError("invalid witness hashes")
        if not re.fullmatch(r"generated-[0-9a-f]{12}-[0-9a-f]{12}-(?:base|candidate)-(?:release|checked)(?:-a[0-9a-f]{10})?", case_id):
            raise ConfigError("malformed generated case ID")
        prefix = f"generated-{row['input_sha256'][:12]}-{row['preserved_signature'][:12]}-"
        if not case_id.startswith(prefix):
            raise ConfigError("generated case ID disagrees with the archived input/fault hash")
        if '-a' in case_id:
            argv_hash = sha256(json.dumps(args, ensure_ascii=True).encode()).hexdigest()[:10]
            if not case_id.endswith(f'-a{argv_hash}') or 'args' not in row:
                raise ConfigError("generated case ID disagrees with the archived argv")
        if row["input"] != f"{row['input_sha256'][:12]}.bin" or row["expected_stdout"] != f"{case_id}.out":
            raise ConfigError("noncanonical generated fixture filenames")
        data = _bytes(zf, entries, f"{generated_dir}/{row['input']}")
        expected = _bytes(zf, entries, f"{generated_dir}/{row['expected_stdout']}")
        if (sha256(data).hexdigest() != row["input_sha256"]
            or len(data) > config["run"]["max_input_bytes"]
            or len(expected) > config["run"]["output_limit_bytes"]
            or type(row["expected_exit"]) is not int or not 0 <= row["expected_exit"] <= 255):
            raise ConfigError("generated fixture hash, bounds or expected exit mismatch")
        matches = [b for b in report.get("replay", []) if isinstance(b, dict)
                   and b.get("generated", {}).get("id") == case_id
                   and b.get("role") == row["witness_role"] and b.get("mode") == row["witness_mode"]
                   and b.get("generated", {}).get("manifest") == manifest_name]
        if not matches or not any(b.get("stable") for b in matches):
            raise ConfigError("no stable witness replay evidence for selected case")
        for bundle in matches:
            if not bundle.get("stable"):
                continue
            history = bundle.get("history")
            if (bundle.get("signature") != row["preserved_signature"]
                or bundle.get("minimized_sha256") != row["input_sha256"]
                or bundle.get("minimized_expected_exit") != row["expected_exit"]
                or bundle.get("minimized_expected_stdout") != expected.hex()
                or bundle.get("args", config["run"].get("args", [])) != args
                or not isinstance(history, list) or len(history) != 3
                or any(not isinstance(a, dict) or a.get("signature") != bundle["signature"] for a in history)):
                continue
            minimized = _bytes(zf, entries, bundle["minimized"])
            if minimized != data:
                continue
            # Each of the three recorded JSONs must agree with the reported signature.
            verified = True
            for attempt in history:
                record = _dict(json.loads(_bytes(zf, entries, attempt["path"])), "attempt")
                if signature(record) != bundle["signature"]:
                    verified = False
                    break
            if verified:
                return (dict(id=case_id, kind=row["kind"], input=data,
                             expected_exit=row["expected_exit"], expected_stdout=expected,
                             witness_role=row["witness_role"], witness_mode=row["witness_mode"],
                             preserved_signature=row["preserved_signature"],
                             **({"args": args} if "args" in row else {})),
                        dict(run_id=report["run"]["id"], base_revision=report.get("sources", {}).get("base", {}).get("revision"),
                             source_digest=report.get("sources", {}).get(row["witness_role"], {}).get("digest"),
                             history_count=3, minimized_sha256=sha256(data).hexdigest(),
                             args_explicit="args" in row))
        raise ConfigError("three replay records or minimized fixture do not match the evidence")


def check_independent_oracle(config: dict, case: dict) -> None:
    """Run the trusted independent oracle, not the patched binary."""
    oracle = config.get("oracle")
    if not oracle:
        # A byte-exact, independently reviewed fixture is also an independent
        # oracle; a newly shortened, unknown input is NOT.
        corpus = workspace_path(config["corpus"]["path"], "corpus.path")
        run = config["run"]
        reference_cases = load_cases(corpus, run["max_input_bytes"],
                                     run["output_limit_bytes"], run=run)
        expected_args = case.get("args", run.get("args", []))
        if any(row["input"] == case["input"] and row["expected_exit"] == case["expected_exit"]
               and row["expected_stdout"] == case["expected_stdout"]
               and row.get("args", run.get("args", [])) == expected_args for row in reference_cases):
            return
        raise ConfigError("promotion requires an independent oracle for a new minimized input")
    try:
        result = subprocess.run(oracle_argv(oracle, case.get("args", config["run"].get("args", []))),
                                input=case["input"], cwd=ROOT,
                                env=ENV, capture_output=True,
                                timeout=oracle.get("timeout_seconds", 2), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigError(f"independent oracle could not complete: {exc}") from exc
    if (result.returncode != case["expected_exit"] or result.stdout != case["expected_stdout"]
        or len(result.stdout) > config["run"]["output_limit_bytes"]):
        raise ConfigError("independent oracle disagrees with archived expected output")


def check_base_replay(config: dict, case: dict, metadata: dict, *, expected_digest: str | None = None) -> None:
    """Build the archived witness variant and repeat its exact fault three times."""
    role = case["witness_role"]
    base = workspace_path(config["sources"]["base" if role == "base" else "patched"], "witness source")
    if not expected_digest or not HEX64.fullmatch(str(expected_digest)):
        raise ConfigError("CI evidence has no valid witness source digest")
    digest = tree_digest(inventory(base))
    if expected_digest and digest != expected_digest:
        raise ConfigError("current witness source differs from archived run")
    work = workspace_path(Path("artifacts/promotion-check") / case["id"], "promotion check")
    work.mkdir(parents=True, exist_ok=True)
    build = build_variant(config["build"], base, role, case["witness_mode"], work, digest)
    if build.get("error"):
        raise ConfigError(f"Witness cannot be built: {build['error']}")
    for count in range(1, 4):
        result = run_case(build, case, config["run"], work / f"attempt-{count}")
        record = result | compare(case, result)
        if signature(record) != case["preserved_signature"]:
            raise ConfigError(f"{role} replay {count}/3 did not preserve the archived fault signature")


def promote_archive(config_path: str, archive_path: str, case_id: str, *, verify_base: bool = True,
                    dry_run: bool = False) -> dict:
    """Import a reviewed selected case; never modify the tracked corpus on failed checks."""
    config = load_config(config_path)
    if "reviewed" not in config["regression"]:
        raise ConfigError("configure regression.reviewed before promoting")
    archive = workspace_path(archive_path, "--evidence-zip")
    case, metadata = inspect_archive(archive, config, case_id)
    check_independent_oracle(config, case)
    if verify_base:
        check_base_replay(config, case, metadata, expected_digest=metadata["source_digest"])
    if dry_run:
        return dict(id=case_id, dry_run=True, **metadata)
    destination = workspace_path(config["regression"]["reviewed"], "regression.reviewed")
    result = generate_case(destination, case, case["input"], case["preserved_signature"],
                           expected_exit=case["expected_exit"], expected_stdout=case["expected_stdout"],
                           witness_role=case["witness_role"], witness_mode=case["witness_mode"],
                           args=case.get("args"), case_id=case_id)
    if result["id"] != case_id:
        raise ConfigError("generated case ID differs from imported case")
    return result | metadata
