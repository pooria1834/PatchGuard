"""Build a C/C++ executable with direct compilation, Make or CMake."""

import os
import shutil
from hashlib import sha256
from pathlib import Path

from .config import ROOT
from .run import execute


def elf_header(path: Path) -> dict:
    """Read the required Linux x86-64 ELF header fields."""
    with path.open("rb") as stream:
        data = stream.read(64)
    if len(data) != 64 or data[:7] != b"\x7fELF\x02\x01\x01" or data[18:20] != b"\x3e\0":
        raise ValueError(f"invalid x86-64 ELF header: {path}")
    file_type = int.from_bytes(data[16:18], "little")
    if file_type not in (2, 3) or not os.access(path, os.X_OK):
        raise ValueError(f"ELF is not executable: {path}")
    return dict(magic=data[:4].hex(), elf_class=64, byte_order="little", machine=62, elf_type=file_type)


def _build_with_system(settings: dict, source: Path, name: str, mode: str,
                       report: Path) -> tuple[dict, dict | None, Path]:
    """Perform a clean, isolated Make/CMake build, leaving source trees intact."""
    system = settings["system"]
    workspace = report / "builds" / f"_work_{name}"
    if workspace.exists():
        shutil.rmtree(workspace)
    copied = workspace / "source"
    # Source inventories already forbid symlinks. The copy prevents generated
    # source/object files from contaminating another role or instrumentation mode.
    shutil.copytree(source, copied, symlinks=False,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    project = copied / settings.get("root", ".")
    flags = " ".join(settings["flags"][mode])
    target = settings.get("target")
    if system == "make":
        # Make's command-line variable assignments override Makefile defaults.
        # Both compile and link flags are required for sanitizer instrumentation.
        command = ["make", "--no-print-directory", "-C", str(project)]
        if settings.get("makefile"):
            command.extend(["-f", settings["makefile"]])
        command.extend(settings.get("args", []))
        command += [f"CFLAGS={flags}", f"CXXFLAGS={flags}", f"LDFLAGS={flags}"]
        if target:
            command.append(target)
        process = execute(command, report / "builds" / f"{name}-logs", cwd=project,
                          timeout=settings.get("timeout_seconds", 120), limit=65536)
        return process, None, project / settings["binary"]

    object_dir = workspace / "objects"
    command = ["cmake", "-S", str(project), "-B", str(object_dir)]
    command.extend(settings.get("configure_args", []))
    # Keep checked/release instrumentation under PatchGuard's control, even
    # when unrelated project-specific CMake definitions are supplied.
    command.extend(["-DCMAKE_BUILD_TYPE=" + ("Release" if mode == "release" else "Debug"),
                    "-DCMAKE_C_FLAGS=" + flags,
                    "-DCMAKE_CXX_FLAGS=" + flags,
                    "-DCMAKE_EXE_LINKER_FLAGS=" + flags,
                    "-DCMAKE_SHARED_LINKER_FLAGS=" + flags])
    configure = execute(command, report / "builds" / f"{name}-configure-logs", cwd=workspace,
                        timeout=settings.get("timeout_seconds", 120), limit=65536)
    if configure["state"] != "normal" or configure["returncode"] != 0:
        return configure, configure, object_dir / settings["binary"]
    command = ["cmake", "--build", str(object_dir)]
    if target:
        command.extend(["--target", target])
    if settings.get("args"):
        command.extend(["--", *settings["args"]])
    process = execute(command, report / "builds" / f"{name}-logs", cwd=workspace,
                      timeout=settings.get("timeout_seconds", 120), limit=65536)
    return process, configure, object_dir / settings["binary"]


def build_variant(settings: dict, source: Path, role: str, mode: str, report: Path,
                  source_digest: str) -> dict:
    """Build one role/mode and retain build provenance and executable evidence."""
    name = f"{settings['output']}_{role}_{mode}"
    binary = report / "builds" / name
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.unlink(missing_ok=True)
    system = settings.get("system", "direct")
    flags = settings["flags"][mode]
    configure = None
    staged = report / "builds" / f"_work_{name}"
    # These paths are provenance for correlating sanitizer frames emitted by
    # isolated Make/CMake builds with the original source-side Git diff.
    location_info = dict(
        staged_source_root=(staged / "source").relative_to(ROOT).as_posix() if system != "direct" else None,
        project_subdir=settings.get("root", ".") if system != "direct" else ".",
        staged_build_root=(staged / "objects").relative_to(ROOT).as_posix() if system == "cmake" else None,
    )
    if system == "direct":
        sources = [template.replace("{source_dir}", str(source)) for template in settings["sources"]]
        argv = []
        for token in settings["command"]:
            argv.extend({"{sources}": sources, "{flags}": flags}.get(token, [token.replace("{output}", str(binary))]))
        execution = execute(argv, report / "builds" / f"{name}-logs", cwd=source)
        produced = binary
    else:
        try:
            execution, configure, produced = _build_with_system(settings, source, name, mode, report)
        except (OSError, shutil.Error) as exc:
            return dict(role=role, mode=mode, flags=flags, source_digest=source_digest,
                        build_system=system, process=None, configure_process=None, path=None,
                        sha256=None, elf=None, **location_info,
                        error=f"build staging failed for {role}/{mode}: {exc}")
    build = dict(role=role, mode=mode, flags=flags, source_digest=source_digest,
                 build_system=system, process=execution, configure_process=configure,
                 path=None, sha256=None, elf=None, error=None, **location_info)
    if execution["state"] != "normal" or execution["returncode"] != 0:
        step = "CMake configuration" if configure is execution else "compilation"
        return build | {"error": f"{step} failed for {role}/{mode}"}
    try:
        if system != "direct":
            expected_root = report / "builds" / f"_work_{name}"
            if not produced.resolve().is_relative_to(expected_root.resolve()):
                raise ValueError(f"configured binary escapes isolated build tree: {produced}")
            if produced.is_symlink() or not produced.is_file():
                raise ValueError(f"configured binary missing or symlink: {produced}")
            shutil.copy2(produced, binary)
        elf = elf_header(binary)
        return build | dict(path=binary.relative_to(ROOT).as_posix(),
                            sha256=sha256(binary.read_bytes()).hexdigest(), elf=elf)
    except (OSError, ValueError) as exc:
        return build | {"error": str(exc)}
