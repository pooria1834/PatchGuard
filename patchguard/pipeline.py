"""Coordinate the generic evaluation and preserve completed stages."""

from hashlib import sha256
import os
from pathlib import Path

from .analyze import compare, signature
from .binary_info import collect, hardening_warnings, metadata_sufficient
from .build import build_variant
from .classify import assess, priority, registry
from .correlate import associate, parse_diff
from .diagnostics import assess_runtime, memory_key
from .config import ROOT, ConfigError, load_cases, load_config, load_yaml, workspace_path
from .report import evidence_complete, write_json
from .replay import reproduce
from .run import execute, run_case
from .source import inventory, source_diff, tree_digest


def evaluate(config_path: str, patched: str | None, directory: Path, report: dict) -> tuple[int, str]:
    """Build and run configured cases, updating report evidence in order."""
    stage = "configuration"
    try:
        config = load_config(config_path, patched)
        report["config"]["resolved"] = config
        if not directory.is_relative_to(ROOT / "artifacts"):
            raise ConfigError("evaluation report directory must be under artifacts/")
        if any(path.is_symlink() for path in directory.rglob("*")):
            raise ConfigError("evaluation report tree must not contain symlinks")
        settings = config["run"]
        limits = (settings["max_input_bytes"], settings["output_limit_bytes"])
        manifest = workspace_path(config["corpus"]["path"], "corpus.path")
        regression = workspace_path(config["regression"]["dir"], "regression.dir")
        cases = load_cases(manifest, *limits, run=settings)
        local_cases = load_cases(regression / "manifest.yaml", *limits, optional=True, run=settings)
        if reviewed_path := config["regression"].get("reviewed"):
            reviewed = workspace_path(reviewed_path, "regression.reviewed")
            reviewed_cases = load_cases(reviewed / "manifest.yaml", *limits, optional=True, run=settings)
            by_id = {case["id"]: case for case in reviewed_cases}
            for case in local_cases:
                if case["id"] not in by_id:
                    continue
                fields = ("input", "expected_exit", "expected_stdout", "preserved_signature",
                          "kind", "witness_role", "witness_mode", "args")
                if any(case.get(field) != by_id[case["id"]].get(field) for field in fields):
                    raise ConfigError(f"local and reviewed regression cases disagree: {case['id']}")
            cases.extend(reviewed_cases)
            local_cases = [case for case in local_cases if case["id"] not in by_id]
        cases.extend(local_cases)
        if len({case["id"] for case in cases}) != len(cases):
            raise ConfigError("case IDs must be unique across the corpus and generated suite")
        cases.sort(key=lambda case: case["id"])
        if settings["method"] == "argv" and any(b"\0" in case["input"] for case in cases):
            raise ConfigError("argv input cannot contain a NUL byte; use stdin or file")
        known_oracles = {}
        for case in cases:
            expected = (case["expected_exit"], case["expected_stdout"])
            key = (case["input"], tuple(case.get("args", settings.get("args", []))))
            if known_oracles.setdefault(key, expected) != expected:
                raise ConfigError(f"conflicting independent oracles for {case['id']}")
        report["cases"] = [
            case | {key: case[key].hex() for key in ("input", "expected_stdout")} |
            {"input_sha256": sha256(case["input"]).hexdigest()} for case in cases
        ]
        report["stages"].append(dict(name=stage, status="passed"))
        stage = "source"
        sources = {"base": ROOT / config["sources"]["base"], "candidate": ROOT / config["sources"]["patched"]}
        git = execute(["git", "-c", "safe.directory=*", "rev-parse", "HEAD"],
                      directory / "provenance" / "git")
        revision = (ROOT / git["stdout"]["path"]).read_text().strip() if git["returncode"] == 0 else None
        report["toolchain"]["git"] = git
        files = {role: inventory(path) for role, path in sources.items()}
        report["sources"] = {
            role: dict(path=path.relative_to(ROOT).as_posix(), files=files[role], digest=tree_digest(files[role]),
                       revision=(os.environ.get("PATCHGUARD_BASE_REVISION") or revision) if role == "base" else revision,
                       origin=None)
            for role, path in sources.items()
        }
        for role, path in sources.items():
            provenance = path / "PROVENANCE.json"
            if provenance.is_file() and not provenance.is_symlink():
                record = load_yaml(provenance)
                if isinstance(record, dict) and record.get("source_tree_digest") == report["sources"][role]["digest"]:
                    report["sources"][role]["origin"] = record.get("origin")
        diff_path = directory / "diff" / "source.patch"
        diff_path.parent.mkdir(parents=True, exist_ok=True)
        diff = source_diff(sources["base"], sources["candidate"], set(files["base"]) | set(files["candidate"]))
        diff_path.write_text(diff)
        git_diff = execute(["git", "-c", "safe.directory=*", "diff", "--no-index", "--no-ext-diff",
                            "--no-color", "--", str(sources["base"]), str(sources["candidate"])],
                           directory / "diff" / "git", limit=1024 * 1024)
        report["toolchain"]["git_diff"] = git_diff
        if git_diff["returncode"] not in (0, 1) or git_diff["state"] != "normal":
            raise ConfigError("Git source comparison failed; see the diff logs")
        report["diff"] = dict(path=diff_path.relative_to(ROOT).as_posix(), algorithm="difflib.unified_diff",
                              git_stdout=git_diff["stdout"]["path"],
                              git_truncated=git_diff["stdout"]["truncated"])
        report["stages"].append(dict(name=stage, status="passed"))
        stage = "build"
        build_system = config["build"].get("system", "direct")
        tool = config["build"]["command"][0] if build_system == "direct" else build_system
        tool_probe = execute([tool, "--version"], directory / "provenance" / "build-tool")
        report["toolchain"]["build_tool"] = tool_probe
        if tool_probe["state"] != "normal" or tool_probe["returncode"] != 0:
            raise ConfigError("build tool version probe failed; see build-tool logs")
        version = (ROOT / tool_probe["stdout"]["path"]).read_text(errors="replace").strip()
        if build_system == "direct":
            report["toolchain"]["compiler"] = tool_probe
        else:
            report["toolchain"]["compiler"] = execute(["cc", "--version"],
                                                        directory / "provenance" / "compiler")
        compiler_probe = report["toolchain"]["compiler"]
        compiler_version = ((ROOT / compiler_probe["stdout"]["path"]).read_text(errors="replace").strip()
                            if compiler_probe["state"] == "normal" and compiler_probe["returncode"] == 0
                            else "unavailable (compiler selected by build system)")
        for role, source in sources.items():
            for mode in ("release", "checked"):
                build = build_variant(config["build"], source, role, mode, directory, report["sources"][role]["digest"])
                build.update(compiler=compiler_version, build_tool_version=version,
                             revision=report["sources"][role]["revision"])
                report["builds"].append(build)
                if build["error"]:
                    raise ConfigError(build["error"])
        report["stages"].append(dict(name=stage, status="passed"))
        stage = "execution"
        for build in report["builds"]:
            for case in cases:
                report["tests_started"] = True
                path = directory / "runs" / build["role"] / build["mode"] / case["id"]
                result = run_case(build, case, settings, path)
                record = result | compare(case, result) | dict(role=build["role"], mode=build["mode"])
                write_json(path / "result.json", record)
                report["executions"].append(record | dict(record=(path / "result.json").relative_to(ROOT).as_posix()))
        report["stages"].append(dict(name=stage, status="passed"))
        stage = "classification"
        observations = assess(cases, report["executions"])
        hunks = parse_diff(diff)
        report["diff"]["hunks"] = hunks
        report["observations"] = observations
        report["runtime_findings"] = assess_runtime(report["executions"], sources, report["builds"])
        report["correlation"] = associate(hunks, sources, observations["differences"],
                                          report["runtime_findings"], report["builds"])
        report["stages"].append(dict(name=stage, status="passed"))
        stage = "repeatability"
        bundles = reproduce(config, report, cases, directory)
        report["replay"] = bundles
        stable = bool(bundles) and all(bundle["stable"] for bundle in bundles)
        observed_base = any(bundle["stable"] and bundle["role"] == "base" for bundle in bundles)
        memory_base = any(bundle["stable"] and bundle["role"] == "base" and
                          memory_key(bundle.get("diagnostic")) for bundle in bundles)
        base_found = memory_base if settings.get("require_memory_finding") else observed_base
        stable_sites = {(bundle["case_id"], bundle["mode"], bundle["role"]) for bundle in bundles
                        if bundle["stable"] and memory_key(bundle.get("diagnostic"))}
        for finding in report["runtime_findings"]:
            finding["stable"] = all(
                (finding["case_id"], finding["mode"], role) in stable_sites
                for side, role in (("before", "base"), ("after", "candidate"))
                if memory_key(finding[side])
            )
            if not finding["stable"]:
                finding["provisional_status"] = finding["status"]
                finding["status"] = "Inconclusive"
        # A stable Candidate finding has priority even if Base evidence is unstable.
        runtime_remaining = any(
            (finding["case_id"], finding["mode"], "candidate") in stable_sites
            for finding in report["runtime_findings"]
        )
        signatures = {}
        for row in report["executions"]:
            signatures.setdefault(row["case_id"], {}).setdefault((row["role"], row["mode"]), set()).add(signature(row))
        report["generated_observations"] = []
        for case in cases:
            if "preserved_signature" not in case:
                continue
            role, mode = case.get("witness_role"), case.get("witness_mode")
            observed = (signatures[case["id"]].get((role, mode), set()) if role and mode
                        else set().union(*signatures[case["id"]].values()))
            report["generated_observations"].append(dict(
                case_id=case["id"], witness_role=role, witness_mode=mode,
                status="reproduced" if case["preserved_signature"] in observed else "changed"
            ))
        retained_base_witnesses = all(
            row["status"] == "reproduced" for row in report["generated_observations"]
            if row["witness_role"] == "base"
        )
        report["stages"].append(dict(name=stage, status="passed" if stable else "incomplete"))
        stage = "binary_metadata"
        for build in report["builds"]:
            key = f"{build['role']}-{build['mode']}"
            report["binary_metadata"][key] = collect(build, directory / "binary-info" / key)
        metadata_complete = metadata_sufficient(report["binary_metadata"])
        report["stages"].append(dict(name=stage, status="passed" if metadata_complete else "incomplete"))
        report["hardening_warnings"] = hardening_warnings(
            report["binary_metadata"]["base-release"]["hardening"],
            report["binary_metadata"]["candidate-release"]["hardening"],
        )
        complete = evidence_complete(report)
        report["checks"] = registry(dict(
            base_contract_mismatch=base_found, oracle_coverage=observations["oracle_coverage"],
            repeatability=stable, minimization=stable, regression_case=stable and retained_base_witnesses,
            binary_metadata=metadata_complete, report_complete=complete,
        ), unstable=bool(bundles) and not stable)
        report["security_state"] = "findings" if runtime_remaining else ("fixed_within_corpus" if memory_base and stable and observations["oracle_coverage"] else "inconclusive")
        report["contract_state"] = "remaining" if observations["remaining"] else (
            "corrected_within_corpus" if base_found and observations["candidate_matches_all"] else "inconclusive")
        stable_releases = {bundle["case_id"] for bundle in bundles
                           if bundle["stable"] and bundle["role"] == "candidate" and bundle["mode"] == "release"}
        regressions = stable_releases.intersection(observations["regressions"])
        report["functional_state"] = "regression" if regressions else (
            "preserved" if observations["valid_preserved"]
            else "inconclusive")
        checked_memory = {
            (row["case_id"], row["role"]) for row in report["executions"]
            if row["mode"] == "checked" and
            (row["case_id"], "checked", row["role"]) in stable_sites
        }
        review_needed = any(
            row.get("diagnostic") and not memory_key(row["diagnostic"]) and not (
                row["mode"] == "release" and row["state"] == "signal" and
                (row["case_id"], row["role"]) in checked_memory
            )
            for row in report["executions"]
        )
        checks_pass = all(check["status"] == "passed" for check in report["checks"].values()) and not review_needed
        if review_needed:
            report["analysis_notes"] = ["Unclassified runtime diagnostic requires review."]
        report["completeness"] = "complete" if checks_pass else "incomplete"
        if any(row["state"] == "runner_error" for row in report["executions"]):
            return 30, "At least one target process could not be started."

        outcomes = []
        if runtime_remaining or (base_found and stable and observations["remaining"]):
            outcomes.append(10)
        if regressions:
            outcomes.append(20)
        # Known security/functional failures are conclusive outcomes, not
        # missing evidence. A separate incomplete mandatory check overrides both.
        if not checks_pass or observations["unexplained"]:
            outcomes.append(40)
        reason = ("Classification uses repeated runtime and contract observations." if stable and base_found
                  else "Required Base finding or stable mismatch evidence was missing.")
        return priority(*outcomes), reason
    except (ConfigError, OSError, ValueError) as exc:
        report["stages"].append(dict(name=stage, status="failed", reason=str(exc)))
        return 30, str(exc)
