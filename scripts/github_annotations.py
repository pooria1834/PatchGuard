"""Emit a handful of GitHub Actions error annotations, never raw log spam."""
import argparse
import json
import os
from pathlib import Path


def escape_property(text: object) -> str:
    return (str(text).replace("%", "%25").replace("\r", "%0D")
            .replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C"))


def escape_message(text: object) -> str:
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(report: dict) -> list[str]:
    code = report.get("exit_code", 30)
    if code == 0:
        return []
    messages = []
    emitted = set()
    for row in report.get("runtime_findings", []):
        if row.get("status") not in ("Incomplete Fix", "New Issue") or not row.get("stable"):
            continue
        after = row.get("after") or {}
        location = after.get("location") or {}
        key = (location.get("path"), location.get("line"), after.get("kind"), row["status"])
        if key in emitted:
            continue
        emitted.add(key)
        label = f"{row['status']}: {after.get('kind', 'security finding')} (case {row['case_id']})"
        path, line = location.get("path"), location.get("line")
        if isinstance(path, str) and isinstance(line, int) and line > 0 and not Path(path).is_absolute():
            messages.append(f"::error file={escape_property(path)},line={line}::{escape_message(label)}")
        else:
            messages.append(f"::error::{escape_message(label)}")
        if len(messages) == 3:
            break
    if not messages:
        verdict = report.get("result", "PATCH_REJECTED")
        observations = report.get("observations") or {}
        cases = (observations.get("regressions") or [])[:3]
        detail = (f"; affected valid cases: {', '.join(cases)}" if cases else "")
        messages.append(f"::error::{escape_message(f'PatchGuard gate BLOCKED ({code}: {verdict}){detail}')}" )
    return messages


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args(argv)
    root = Path(os.environ.get("PATCHGUARD_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
    path = (root / args.report_dir).resolve() / "report.json"
    if not path.is_relative_to(root / "artifacts"):
        parser.error("report must be under artifacts/")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(f"missing or invalid report: {exc}")
    for line in annotations(data):
        print(line)


if __name__ == "__main__":
    main()
