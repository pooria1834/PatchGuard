"""Load and validate PatchGuard configuration without executing commands."""

from __future__ import annotations

import math
import os
from hashlib import sha256
import re
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError

ROOT = Path(os.environ.get("PATCHGUARD_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
# In a reusable GitHub Action, engine modules live outside the target checkout.
# This opt-in root points every config/source/report path to the checked-out target.
LOCKED_ENV = {"PATH", "LANG", "LC_ALL", "PYTHONHASHSEED", "HOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME"}
TOKEN = re.compile(r"[a-zA-Z0-9_./+=,:@%{}-]+")
FIELD = re.compile(r"\{([a-z_]+)\}")
PARENT_SEGMENT = re.compile(r"(?:^|[/=,:])\.\.(?:$|[/,])")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")


class ConfigError(ValueError):
    """A configuration input is missing or violates the schema."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Use the safe YAML constructor with unique mapping keys."""

    def construct_mapping(self, node, deep=False):
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ConstructorError(None, None, "YAML merge keys are unsupported", key_node.start_mark)
        pairs = self.construct_pairs(node, deep=deep)
        mapping = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in mapping:
                raise ConstructorError(None, None, f"invalid or duplicate key {key!r}", node.start_mark)
            mapping[key] = value
        return mapping


def workspace_path(value: str | Path, field: str, *, within: Path = ROOT) -> Path:
    """Resolve a path and require it to stay inside its workspace boundary."""
    try:
        path = Path(value)
        if ".." in path.parts or "\x00" in str(path):
            raise ConfigError(f"{field}: path traversal or invalid path: {value!s}")
        resolved = (ROOT / path).resolve()
    except (OSError, RuntimeError, TypeError) as exc:
        raise ConfigError(f"{field}: cannot resolve {value!s}: {exc}") from exc
    if not resolved.is_relative_to(within):
        raise ConfigError(f"{field}: path must stay inside {within}: {value!s}")
    return resolved


def load_yaml(path: Path) -> object:
    """Read a single safe YAML document with a readable file diagnostic."""
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def _mapping(value: object, field: str, required: str, optional: str = "") -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{field}: expected a mapping")
    missing = set(required.split()) - value.keys()
    unknown = value.keys() - set(required.split()) - set(optional.split())
    if unknown or missing:
        details = [f"unknown keys {', '.join(sorted(unknown))}"] if unknown else []
        if missing:
            details.append(f"missing keys {', '.join(sorted(missing))}")
        raise ConfigError(f"{field}: " + ", ".join(details))
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ConfigError(f"{field}: expected a nonempty string")
    return value


def _identifier(value: object, field: str) -> str:
    value = _string(value, field)
    if not IDENTIFIER.fullmatch(value):
        raise ConfigError(f"{field}: expected an identifier, got {value!r}")
    return value


def _tokens(
    value: object, field: str, allowed: tuple[str, ...] = (), *, empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not value and not empty):
        raise ConfigError(f"{field}: expected an argv list" + ("" if empty else " with at least one element"))
    for item in value:
        token = _string(item, field)
        literal = FIELD.sub("", token)
        if not TOKEN.fullmatch(token) or "{" in literal or "}" in literal:
            raise ConfigError(f"{field}: malformed placeholder or unsafe argv element {token!r}")
        if PARENT_SEGMENT.search(token):
            raise ConfigError(f"{field}: path traversal in {token!r}")
        for name in FIELD.findall(token):
            if name not in allowed:
                raise ConfigError(f"{field}: unsupported placeholder {{{name}}}")
            if name in {"sources", "flags", "case_args"} and token != "{" + name + "}":
                raise ConfigError(f"{field}: {{{name}}} must be a complete argv element")
    return value


def _within(value: object, field: str, parent: Path = ROOT) -> Path:
    return workspace_path(_string(value, field), field, within=parent)


def _relative_build_path(value: object, field: str) -> str:
    """Accept a build-tree-relative name, never an absolute or parent path."""
    name = _string(value, field)
    path = Path(name)
    if (path.is_absolute() or ".." in path.parts or name in (".", "..")
            or not re.fullmatch(r"[a-zA-Z0-9_./+-]+", name)
            or any(part.startswith(".") for part in path.parts if part != ".")):
        raise ConfigError(f"{field}: expected a safe relative path")
    return name


def _validate_build(build: dict, source_dirs: tuple[Path, Path]) -> None:
    system = build.get("system", "direct")
    if system not in ("direct", "make", "cmake"):
        raise ConfigError("build.system: expected direct, make or cmake")
    flags = _mapping(build["flags"], "build.flags", "release checked")
    for mode, values in flags.items():
        _tokens(values, f"build.flags.{mode}")
    _identifier(build["output"], "build.output")
    if system == "direct":
        command = _tokens(build["command"], "build.command", ("flags", "sources", "output"))
        if "{" in command[0] or command[0].startswith("-") or "/" in command[0]:
            raise ConfigError("build.command: first element must be a tool name")
        for name in ("flags", "sources", "output"):
            placeholder = "{" + name + "}"
            if sum(token.count(placeholder) for token in command) != 1:
                raise ConfigError(f"build.command: expected {placeholder} exactly once")
        templates = _tokens(build["sources"], "build.sources", ("source_dir",))
        for template in templates:
            if not template.startswith("{source_dir}/") or template.count("{source_dir}") != 1:
                raise ConfigError("build.sources: each source path must start with {source_dir}/")
            for source_dir in source_dirs:
                path = template.replace("{source_dir}", str(source_dir))
                source = _within(path, "build.sources", source_dir)
                if not source.is_file():
                    raise ConfigError(f"build.sources: file does not exist: {source}")
    else:
        _relative_build_path(build["binary"], "build.binary")
        root = _relative_build_path(build.get("root", "."), "build.root") if build.get("root", ".") != "." else "."
        for directory in source_dirs:
            project = workspace_path(directory / root, "build.root", within=directory)
            if not project.is_dir():
                raise ConfigError(f"build.root: directory does not exist: {project}")
            if system == "cmake" and not (project / "CMakeLists.txt").is_file():
                raise ConfigError(f"build.root: missing CMakeLists.txt: {project}")
            if system == "make":
                makefile = build.get("makefile")
                if makefile is not None:
                    _relative_build_path(makefile, "build.makefile")
                    if not workspace_path(project / makefile, "build.makefile", within=project).is_file():
                        raise ConfigError(f"build.makefile: missing file in {project}")
                elif not any((project / name).is_file() for name in ("GNUmakefile", "makefile", "Makefile")):
                    raise ConfigError(f"build.root: missing Makefile in {project}")
        if "target" in build:
            if system == "make":
                _relative_build_path(build["target"], "build.target")
            else:
                _identifier(build["target"], "build.target")
        if "timeout_seconds" in build:
            timeout = build["timeout_seconds"]
            if type(timeout) not in (int, float) or timeout <= 0 or not math.isfinite(timeout):
                raise ConfigError("build.timeout_seconds: expected a finite positive number")
        for field in ("args", "configure_args"):
            if field in build:
                _tokens(build[field], f"build.{field}", empty=True)


def _validate_run(run: dict) -> None:
    method = run["method"]
    if method not in ("stdin", "file", "argv"):
        raise ConfigError("run.method: expected stdin, file or argv")
    args = run.get("args", [])
    validate_case_args(args, method, "run.args", require_delivery=bool(args))
    timeout = run["timeout_seconds"]
    if type(timeout) not in (int, float) or timeout <= 0 or (type(timeout) is float and not math.isfinite(timeout)):
        raise ConfigError("run.timeout_seconds: expected a finite positive number")
    for key in ("max_input_bytes", "output_limit_bytes"):
        if type(run[key]) is not int or run[key] <= 0:
            raise ConfigError(f"run.{key}: expected a positive integer")
    env = run["env"]
    if not isinstance(env, dict):
        raise ConfigError("run.env: expected a mapping of string values")
    for key, value in env.items():
        if key in LOCKED_ENV or key.startswith("LD_"):
            raise ConfigError(f"run.env: {key} is locked")
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", key) or not isinstance(value, str) or "\x00" in value:
            raise ConfigError(f"run.env: invalid variable name or value for {key!r}")


def validate_case_args(args: object, method: str, field: str, *,
                       require_delivery: bool = True) -> list[str]:
    """Validate argv *elements*, not a shell command or a restrictive DSL.

    CLI flags may legitimately contain spaces, quotes, JSON, pipes, and braces
    (for example jq filter expressions). subprocess.Popen uses an argv list
    without shell evaluation, so those are literal bytes, not executable code.
    Only delivery placeholders have special meaning.
    """
    if not isinstance(args, list) or len(args) > 128:
        raise ConfigError(f"{field}: expected an argv list with at most 128 elements")
    for item in args:
        if not isinstance(item, str) or "\x00" in item or len(item) > 8192:
            raise ConfigError(f"{field}: argv elements must be strings without NUL (max 8192 characters)")
        if method != "file" and "{input_file}" in item:
            raise ConfigError(f"{field}: unsupported placeholder {{input_file}} for {method}")
        if method != "argv" and "{input_arg}" in item:
            raise ConfigError(f"{field}: unsupported placeholder {{input_arg}} for {method}")
    if require_delivery and method in ("file", "argv"):
        marker = "{input_file}" if method == "file" else "{input_arg}"
        if not any(marker in item for item in args):
            raise ConfigError(f"{field}: {method} delivery requires {marker}")
    return args


def oracle_argv(oracle: dict, args: list[str]) -> list[str]:
    """Pass case-specific CLI flags to a trusted independent reference model.

    The {case_args} placeholder expands as complete subprocess argv elements,
    never via a shell. An oracle without the placeholder stays input-only.
    """
    return [value for token in oracle["command"]
            for value in (args if token == "{case_args}" else [token])]


def load_config(path: str | Path, patched: str | Path | None = None) -> dict:
    """Validate the canonical configuration and apply a Candidate path override."""
    config_path = workspace_path(path, "config")
    data = _mapping(load_yaml(config_path), "config", "target sources build run corpus regression", "oracle")
    target = _mapping(data["target"], "target", "name")
    _identifier(target["name"], "target.name")
    sources = _mapping(data["sources"], "sources", "base patched")
    base = _within(sources["base"], "sources.base")
    configured_candidate = _within(sources["patched"], "sources.patched")
    candidate = workspace_path(patched, "--patched") if patched is not None else configured_candidate
    for field, directory in (("sources.base", base), ("sources.patched", candidate)):
        if not directory.is_dir():
            raise ConfigError(f"{field}: directory does not exist: {directory}")
    sources.update(base=base.relative_to(ROOT).as_posix(), patched=candidate.relative_to(ROOT).as_posix())
    raw_build = data["build"]
    if not isinstance(raw_build, dict):
        raise ConfigError("build: expected a mapping")
    system = raw_build.get("system", "direct")
    if system not in ("direct", "make", "cmake"):
        raise ConfigError("build.system: expected direct, make or cmake")
    if system == "direct":
        build = _mapping(raw_build, "build", "command sources flags output", "system")
    else:
        build = _mapping(raw_build, "build", "flags output binary", "system root target makefile args configure_args timeout_seconds")
        if system == "make" and "configure_args" in build:
            raise ConfigError("build.configure_args: only supported for cmake")
        if system == "cmake" and "makefile" in build:
            raise ConfigError("build.makefile: only supported for make")
    _validate_build(build, (base, candidate))
    run = _mapping(data["run"], "run", "method timeout_seconds max_input_bytes output_limit_bytes env", "args require_memory_finding")
    _validate_run(run)
    if type(run.get("require_memory_finding", False)) is not bool:
        raise ConfigError("run.require_memory_finding: expected a boolean")
    corpus = _mapping(data["corpus"], "corpus", "path")
    _within(corpus["path"], "corpus.path")
    if "oracle" in data:
        oracle = _mapping(data["oracle"], "oracle", "command", "timeout_seconds")
        command = _tokens(oracle["command"], "oracle.command", ("case_args",))
        if "{" in command[0] or command[0].startswith("-") or "/" in command[0]:
            raise ConfigError("oracle.command: first element must be a tool name")
        timeout = oracle.get("timeout_seconds", 2)
        if type(timeout) not in (int, float) or timeout <= 0 or not math.isfinite(timeout):
            raise ConfigError("oracle.timeout_seconds: expected a finite positive number")
    regression = _mapping(data["regression"], "regression", "dir", "reviewed")
    output_dir = _within(regression["dir"], "regression.dir")
    if not any(output_dir.is_relative_to(ROOT / folder) for folder in ("tests/regression/generated", "artifacts")):
        raise ConfigError("regression.dir: expected a directory under tests/regression/generated or artifacts")
    if "reviewed" not in regression:
        # Automatic PRs must work for existing configurations that only set
        # regression.dir; use a stable, target-specific reviewed suite.
        regression["reviewed"] = f"tests/regression/reviewed/{target['name']}"
    reviewed = _within(regression["reviewed"], "regression.reviewed")
    if not reviewed.is_relative_to(ROOT / "tests/regression/reviewed"):
        raise ConfigError("regression.reviewed must be under tests/regression/reviewed")
    return data


def load_cases(manifest: Path, limit: int, output_limit: int, *, optional: bool = False,
               run: dict | None = None) -> list[dict]:
    """Load byte-exact independent oracles relative to their fixture root."""
    if optional and not manifest.exists():
        return []
    manifest = workspace_path(manifest, "manifest", within=manifest.parent)
    data = load_yaml(manifest)
    if not isinstance(data, list) or not data:
        raise ConfigError(f"{manifest}: expected a nonempty case list")
    cases = []
    ids = set()
    for value in data:
        row = _mapping(value, str(manifest), "id kind input expected_exit expected_stdout",
                       "description preserved_signature input_sha256 witness_role witness_mode args")
        case_id = _identifier(row["id"], "case.id")
        if case_id in ids:
            raise ConfigError(f"{manifest}: duplicate case ID {case_id}")
        ids.add(case_id)
        if row["kind"] not in ("valid", "invalid", "boundary", "regression"):
            raise ConfigError(f"{case_id}: invalid case kind")
        code = row["expected_exit"]
        if type(code) is not int or not 0 <= code <= 255:
            raise ConfigError(f"{case_id}: expected a normal exit code from 0 to 255")
        if "args" in row:
            # An explicit [] overrides global args for stdin cases.
            if run is None:
                raise ConfigError(f"{case_id}.args: run settings are required for validation")
            validate_case_args(row["args"], run["method"], f"{case_id}.args")
        elif run is not None:
            validate_case_args(run.get("args", []), run["method"], f"{case_id}.effective_args")
        case = dict(row, manifest_path=manifest.relative_to(ROOT).as_posix())
        if run is not None:
            case["effective_args"] = list(row.get("args", run.get("args", [])))
        for field, maximum in (("input", limit), ("expected_stdout", output_limit)):
            relative = Path(_string(row[field], f"{case_id}.{field}"))
            if relative.is_absolute():
                raise ConfigError(f"{case_id}.{field}: expected a relative path")
            path = workspace_path(manifest.parent / relative, field, within=manifest.parent)
            try:
                if not path.is_file():
                    raise ConfigError(f"{case_id}.{field}: file does not exist: {path}")
                with path.open("rb") as stream:
                    content = stream.read(maximum + 1)
            except OSError as exc:
                raise ConfigError(f"{case_id}.{field}: {exc}") from exc
            if len(content) > maximum:
                raise ConfigError(f"{case_id}.{field}: exceeds configured byte limit {maximum}")
            case[field] = content
            case[f"{field}_path"] = path.relative_to(ROOT).as_posix()
        if "input_sha256" in row:
            if row["input_sha256"] != sha256(case["input"]).hexdigest():
                raise ConfigError(f"{case_id}: input SHA-256 mismatch")
        if "description" in row:
            _string(row["description"], "case.description")
        if "preserved_signature" in row and not (
            isinstance(row["preserved_signature"], str) and re.fullmatch(r"[a-f0-9]{64}", row["preserved_signature"])
        ):
            raise ConfigError(f"{case_id}: invalid preserved signature")
        if "witness_role" in row and row["witness_role"] not in ("base", "candidate"):
            raise ConfigError(f"{case_id}: witness_role must be base or candidate")
        if "witness_mode" in row and row["witness_mode"] not in ("release", "checked"):
            raise ConfigError(f"{case_id}: witness_mode must be release or checked")
        if ("witness_role" in row) != ("witness_mode" in row):
            raise ConfigError(f"{case_id}: witness_role and witness_mode must appear together")
        cases.append(case)
    return sorted(cases, key=lambda row: row["id"])
