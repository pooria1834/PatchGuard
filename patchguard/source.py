"""Compute a deterministic inventory and diff for a source tree."""

from difflib import unified_diff
from hashlib import sha256
from pathlib import Path

IGNORED = {".git", "__pycache__", ".pytest_cache", "artifacts", "build", "dist", "PROVENANCE.json"}


def inventory(root: Path) -> dict[str, str]:
    """Hash each regular source-tree file in relative path order."""
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if IGNORED.intersection(relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"symlink in source tree: {path}")
        if path.is_file():
            result[relative.as_posix()] = sha256(path.read_bytes()).hexdigest()
    return result


def tree_digest(files: dict[str, str]) -> str:
    """Hash the canonical path, separator and file digest sequence."""
    return sha256("".join(f"{name}\0{files[name]}\n" for name in sorted(files)).encode()).hexdigest()


def source_diff(before: Path, after: Path, names: set[str]) -> str:
    """Produce a stable unified diff and identify binary file changes."""
    sections = []
    for name in sorted(names):
        old_path, new_path = before / name, after / name
        old = old_path.read_bytes() if old_path.is_file() else b""
        new = new_path.read_bytes() if new_path.is_file() else b""
        if old == new and old_path.is_file() == new_path.is_file():
            continue
        try:
            old_lines, new_lines = old.decode().splitlines(True), new.decode().splitlines(True)
        except UnicodeDecodeError:
            sections.append(f"Binary files a/{name} and b/{name} differ\n")
            continue
        if not old_lines and not new_lines:
            operation = "added" if new_path.is_file() else "removed"
            sections.append(f"Empty file {name} {operation}\n")
            continue
        lines = unified_diff(old_lines, new_lines,
                             f"a/{name}" if old_path.is_file() else "/dev/null",
                             f"b/{name}" if new_path.is_file() else "/dev/null")
        sections.extend(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines)
    return "".join(sections)
