"""Package the noisy per-run evidence as one optional technical attachment.

The short human summary, compact verdict, and the full machine JSON stay outside
this archive, so GitHub Actions can upload four small discoverable files.
"""

import argparse
import json
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args(argv)
    workspace = Path(os.environ.get("PATCHGUARD_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
    report_dir = (workspace / args.report_dir).resolve()
    artifacts = workspace / "artifacts"
    if not report_dir.is_relative_to(artifacts) or not report_dir.is_dir():
        parser.error("report directory must exist inside artifacts/")
    if not (report_dir / "report.json").is_file():
        parser.error("report.json was not generated")
    report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    destination = report_dir / "technical-evidence.zip"
    temporary = report_dir / ".technical-evidence.tmp"
    selected = []
    for path in sorted(report_dir.rglob("*")):
        if path.is_file() and not path.is_symlink() and path not in (destination, temporary):
            # Short summaries and indexes are already uploaded separately.
            if path in (report_dir / "summary.md", report_dir / "verdict.json", report_dir / "evidence-index.md"):
                continue
            selected.append(path)
    # Preserve generated fixtures referenced by the repeatability/replay bundles.
    regression_rel = (report.get("config", {}).get("resolved") or {}).get("regression", {}).get("dir")
    regression = (workspace / regression_rel).resolve() if regression_rel else None
    if regression and regression.is_relative_to(workspace) and regression.is_dir():
        for path in sorted(regression.rglob("*")):
            if path.is_file() and not path.is_symlink():
                selected.append(path)
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
        for path in selected:
            archive.write(path, path.relative_to(workspace))
    temporary.replace(destination)
    print(f"Technical evidence: {destination.relative_to(workspace)} ({len(selected)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
