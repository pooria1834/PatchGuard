"""Translate sanitizer file paths from isolated build copies to original sources."""

from pathlib import Path

from .config import ROOT


def source_location(reported: str, source: Path, build: dict | None = None) -> Path | None:
    """Return an original source file only when the reported location is unambiguous.

    Compiler diagnostics may contain absolute paths to Make/CMake staging copies,
    paths relative to their working directory, or paths relative to the project.
    The return value is always within the original source tree, so callers can
    safely compare it with the source diff; unresolved paths provide no evidence.
    """
    build = build or {}
    staged = ROOT / build["staged_source_root"] if build.get("staged_source_root") else None
    project = build.get("project_subdir", ".")
    objects = ROOT / build["staged_build_root"] if build.get("staged_build_root") else None
    source = source.resolve()
    reported_path = Path(reported)

    # First interpret the path exactly. Absolute paths under the workspace are
    # already stored as ROOT-relative paths by parse_diagnostics().
    absolute = reported_path if reported_path.is_absolute() else ROOT / reported_path
    absolute = absolute.resolve()
    for root in (source, staged):
        if root is not None and absolute.is_relative_to(root.resolve()):
            candidate = source / absolute.relative_to(root.resolve())
            # A generated CMake/Make file is not part of the original diff.
            # Existing direct-build behavior still recognizes explicit paths.
            return candidate if root == source or candidate.is_file() else None

    if reported_path.is_absolute():
        return None

    # Relative sanitizer paths come from compiler commands, not necessarily
    # PatchGuard's execution cwd. Refuse to guess when they match multiple files.
    matches = set()
    for origin in (source / project, source, staged / project if staged else None,
                   staged, objects):
        if origin is None:
            continue
        resolved = (origin / reported_path).resolve()
        for root in (source, staged):
            if root is not None and resolved.is_relative_to(root.resolve()):
                candidate = source / resolved.relative_to(root.resolve())
                if candidate.is_file():
                    matches.add(candidate)
    return next(iter(matches)) if len(matches) == 1 else None
