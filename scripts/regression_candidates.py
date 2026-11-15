"""Create a small, reviewable index of Base regression candidates from a run."""

import argparse
import json
import os
from pathlib import Path

import yaml


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args(argv)
    root = Path(os.environ.get("PATCHGUARD_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
    folder = (root / args.report_dir).resolve()
    if not folder.is_relative_to(root / "artifacts"):
        parser.error("report directory must be under artifacts/")
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    generated_root = ((report.get("config", {}).get("resolved") or {}).get("regression") or {}).get("dir")
    generated_manifest = generated_root.rstrip("/") + "/manifest.yaml" if generated_root else None
    reviewed_ids = set()
    reviewed_rel = ((report.get("config", {}).get("resolved") or {}).get("regression") or {}).get("reviewed")
    if reviewed_rel:
        reviewed = (root / reviewed_rel).resolve()
        if reviewed.is_relative_to(root / "tests/regression/reviewed") and (reviewed / "manifest.yaml").is_file():
            reviewed_rows = yaml.safe_load((reviewed / "manifest.yaml").read_text(encoding="utf-8"))
            if isinstance(reviewed_rows, list):
                reviewed_ids = {str(r["id"]) for r in reviewed_rows if isinstance(r, dict) and "id" in r}
    rows = {}
    for entry in report.get("replay", []):
        generated = entry.get("generated") or {}
        case_id = generated.get("id")
        if (entry.get("role") == "base" and entry.get("stable") is True
            and generated.get("manifest") == generated_manifest
            and isinstance(case_id, str) and case_id.startswith("generated-")
            and case_id not in reviewed_ids):
            rows.setdefault(case_id, entry)
    lines = ["# Suggested security regression cases", "",
             f"**{len(rows)} stable Base case(s)** are available for manual review.", "",
             "These are **candidates**, not automatically approved tests. Review the replay, "
             "independent oracle, and input before promoting one into the tracked corpus.", "",
             "| Generated case ID | Origin case | Mode | Bytes |", "| --- | --- | --- | ---: |"]
    for case_id, entry in sorted(rows.items())[:15]:
        name = entry.get("minimized")
        path = (root / name).resolve() if isinstance(name, str) else None
        size = path.stat().st_size if path and path.is_relative_to(root / "artifacts") and path.is_file() else "see bundle"
        # Case IDs are sanitized by config validation; keep Markdown safe anyway.
        case_id = case_id.replace("|", "")
        lines.append(f"| `{case_id}` | `{str(entry.get('case_id', 'unknown')).replace('|', '')}` | "
                     f"{entry.get('mode', '?')} | {size} |")
    if len(rows) > 15:
        lines.append(f"\n…and {len(rows)-15} more in `report.json` → `replay`.")
    if not rows:
        lines.append("| *(no newly generated stable Base witnesses)* | – | – | – |")
    lines.extend(["", "To retain one, run the manual **Review PatchGuard regression for tracking** "
                  "workflow with this run's ID and the generated case ID. The workflow proposes "
                  "a PR; it does not automatically merge.", ""])
    (folder / "regression-candidates.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Regression candidate index: {folder.relative_to(root) / 'regression-candidates.md'} ({len(rows)} candidates)")


if __name__ == "__main__":
    main()
