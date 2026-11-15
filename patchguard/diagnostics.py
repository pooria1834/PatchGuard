"""Read sanitizer diagnostics and retain runtime source locations."""

from difflib import SequenceMatcher
import re
from pathlib import Path

from .config import ROOT
from .source_locations import source_location

MEMORY_KINDS = {"out of bounds", "null pointer", "misaligned address", "insufficient space"}

UBSAN = re.compile(r"^(.*?):(\d+):(\d+): runtime error: (.+)$", re.MULTILINE)
FRAME = re.compile(r"^\s*#\d+\s+(?:0x[0-9a-f]+\s+)?in (.+?) ([^\s:]+):(\d+)(?::\d+)?\s*$", re.MULTILINE)
ASAN = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)")


def _relative(path: str) -> str:
    reported = Path(path)
    if reported.is_absolute() and reported.is_relative_to(ROOT):
        return reported.relative_to(ROOT).as_posix()
    # Preserve relative subdirectories (and absolute external locations):
    # discarding them could falsely match a different source with the same name.
    return reported.as_posix()


def parse_diagnostics(stderr: str, returncode: int | None) -> dict | None:
    """Identify an observed detection mechanism and any reported source frames."""
    match = UBSAN.search(stderr)
    address = ASAN.search(stderr)
    frames = [
        dict(function=function, path=_relative(path), line=int(line))
        for function, path, line in FRAME.findall(stderr)
    ]
    if match:
        path, line, column, message = match.groups()
        categories = ("out of bounds", "division by zero", "null pointer", "misaligned address",
                      "signed integer overflow", "insufficient space")
        kind = next((item for item in categories if item in message), "undefined_behavior")
        return dict(mechanism="UBSan", kind=kind,
                    location=dict(path=_relative(path), line=int(line), column=int(column)),
                    frames=frames, detail=message)
    if address:
        return dict(mechanism="ASan", kind=address[1], location=frames[0] if frames else None,
                    frames=frames, detail=address[0])
    if returncode is not None and returncode < 0:
        mechanism = "stack_protector" if "stack smashing detected" in stderr else "signal"
        return dict(mechanism=mechanism, kind="stack_smashing" if mechanism == "stack_protector" else "unknown",
                    location=None, frames=[], detail=None)
    return None


def memory_key(diagnostic: dict | None) -> tuple | None:
    """Use the runtime category and top source frame as finding identity."""
    if not diagnostic or diagnostic["mechanism"] not in ("ASan", "UBSan") or not diagnostic["location"]:
        return None
    if diagnostic["mechanism"] == "UBSan" and diagnostic["kind"] not in MEMORY_KINDS:
        return None
    location = diagnostic["location"]
    # Variant directories differ, while the source file and its top frame identify the site.
    frame = next((item["function"] for item in diagnostic["frames"]
                  if item["path"] == location["path"] and item["line"] == location["line"]), None)
    return diagnostic["mechanism"], diagnostic["kind"], Path(location["path"]).name, frame, location["line"]


def assess_runtime(records: list[dict], sources: dict | None = None,
                   builds: list[dict] | None = None) -> list[dict]:
    """Compare the diagnosed sites for each input under corresponding modes."""
    by_case = {}
    for row in records:
        key = row["case_id"], row["mode"]
        by_case.setdefault(key, {})[row["role"]] = row
    line_maps = {}
    build_index = {(row["role"], row["mode"]): row for row in (builds or [])}

    def same_site(before: dict, after: dict, b: tuple, a: tuple) -> bool:
        if not sources:
            return a == b
        if b[:2] != a[:2]:
            return False
        paths = []
        for diagnostic, role in ((before, "base"), (after, "candidate")):
            path = source_location(diagnostic["location"]["path"], sources[role],
                                   build_index.get((role, mode)))
            if path is None or not path.is_file():
                return a == b
            paths.append(path)
        old_path, new_path = paths
        if old_path.relative_to(sources["base"]) != new_path.relative_to(sources["candidate"]):
            return False
        key = old_path, new_path
        if key not in line_maps:
            old = old_path.read_bytes().splitlines()
            new = new_path.read_bytes().splitlines()
            line_maps[key] = {
                i + offset + 1: j + offset + 1
                for i, j, length in SequenceMatcher(None, old, new, autojunk=False).get_matching_blocks()
                for offset in range(length)
            }
        return line_maps[key].get(b[-1]) == a[-1]

    findings = []
    for (case_id, mode), sides in by_case.items():
        if set(sides) != {"base", "candidate"}:
            continue
        before, after = (sides[role] for role in ("base", "candidate"))
        b, a = (memory_key(row.get("diagnostic")) for row in (before, after))
        if b is None and a is None:
            continue
        if any(row["state"] not in ("normal", "signal") or row["stdout"]["truncated"] or row["stderr"]["truncated"]
               for row in (before, after)):
            continue
        if b and a and same_site(before["diagnostic"], after["diagnostic"], b, a):
            status = "Incomplete Fix"
        elif a:
            status = "New Issue"
        elif after["state"] == "normal" and not after.get("diagnostic"):
            status = "Fixed"
        else:
            status = "Inconclusive"
        findings.append(dict(case_id=case_id, mode=mode, status=status,
                             before=before.get("diagnostic"), after=after.get("diagnostic"),
                             base_record=before["record"], candidate_record=after["record"]))
    return findings
