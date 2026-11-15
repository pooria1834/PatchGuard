"""Parse unified diff hunks and attach concrete behavior evidence."""

import re

from .source_locations import source_location

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
FUNCTION = re.compile(r"^\s*(?:static\s+)?[\w* ]+\s+(\w+)\([^;]*\)\s*\{")


def parse_diff(text: str) -> list[dict]:
    """Extract paths, ranges and added or removed lines from a unified diff."""
    path, old_path, current = "", "", None
    hunks = []
    for line in text.splitlines():
        if line.startswith("--- ") and current is None:
            old_path = line[4:].removeprefix("a/")
        elif line.startswith("+++ ") and current is None:
            path = old_path if line[4:] == "/dev/null" else line[4:].removeprefix("b/")
        elif match := HUNK.match(line):
            old, old_count, new, new_count = match.groups()
            current = dict(path=path, old=[int(old), int(old_count or 1)],
                           new=[int(new), int(new_count or 1)], added=[], removed=[],
                           removed_lines=[], added_lines=[])
            old_line, new_line = int(old), int(new)
            hunks.append(current)
            old_left, new_left = current["old"][1], current["new"][1]
        elif current and line[:1] in (" ", "+", "-"):
            if line.startswith("+"):
                current["added"].append(line[1:])
                current["added_lines"].append(new_line)
            elif line.startswith("-"):
                current["removed"].append(line[1:])
                current["removed_lines"].append(old_line)
            old_line += not line.startswith("+")
            new_line += not line.startswith("-")
            old_left -= not line.startswith("+")
            new_left -= not line.startswith("-")
            if not old_left and not new_left:
                current = None
    return hunks


def associate(hunks: list[dict], sources: dict, differences: list[dict],
              findings: list[dict], builds: list[dict] | None = None) -> list[dict]:
    """Link behavior changes to runtime evidence from the same case."""
    for hunk in hunks:
        if not hunk["path"].endswith((".c", ".cc", ".cpp", ".cxx")):
            continue
        for role, side, lines_key in (("base", "old", "removed_lines"),
                                      ("candidate", "new", "added_lines")):
            path = sources[role] / hunk["path"]
            lines = path.read_text().splitlines() if path.is_file() else []
            functions = set()
            for line_number in hunk[lines_key]:
                definitions = [match[1] for line in lines[:line_number] if (match := FUNCTION.match(line))]
                if definitions:
                    functions.add(definitions[-1])
            hunk[f"{side}_functions"] = sorted(functions)

    correlate_runtime(findings, hunks, sources, builds)
    by_case = {}
    for finding in findings:
        by_case.setdefault(finding["case_id"], []).extend(finding["correlation"]["evidence"])
    result = []
    for difference in differences:
        evidence = by_case.get(difference["case_id"], [])
        label = "direct" if any(row["label"] == "direct" for row in evidence) else (
            "indirect" if evidence else "unknown")
        result.append(difference | dict(label=label, evidence=evidence))
    return result


def correlate_runtime(findings: list[dict], hunks: list[dict], sources: dict,
                      builds: list[dict] | None = None) -> None:
    """Map each observed diagnostic location or caller into matching diff hunks."""
    build_index = {(row["role"], row["mode"]): row for row in (builds or [])}
    for finding in findings:
        evidence = []
        for side, role, range_key in (("before", "base", "old"), ("after", "candidate", "new")):
            diagnostic = finding.get(side)
            if not diagnostic:
                continue
            locations = [diagnostic["location"], *diagnostic["frames"]]
            for frame in filter(None, locations):
                full = source_location(frame["path"], sources[role],
                                       build_index.get((role, finding.get("mode"))))
                if full is None:
                    continue
                path = full.relative_to(sources[role]).as_posix()
                for hunk in hunks:
                    if hunk["path"] != path:
                        continue
                    start, count = hunk[range_key]
                    key = "removed_lines" if range_key == "old" else "added_lines"
                    within = frame["line"] in hunk[key] if key in hunk else start <= frame["line"] < start + count
                    function = frame.get("function")
                    if not within and (not function or function not in hunk.get(f"{range_key}_functions", [hunk.get("function")])):
                        continue
                    item = dict(side=side, label="direct" if within else "indirect",
                                frame=frame, path=path, changed_range=hunk[range_key])
                    if item not in evidence:
                        evidence.append(item)
        label = "direct" if any(item["label"] == "direct" for item in evidence) else (
            "indirect" if evidence else "unknown")
        finding["correlation"] = dict(label=label, evidence=evidence)
