"""Show where to read the newest run verdicts; never enumerate raw files."""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Find PatchGuard run reports")
    parser.add_argument("--limit", type=int, default=10, help="show newest N reports (0 means all)")
    args = parser.parse_args(argv)
    artifacts = ROOT / "artifacts"
    if not artifacts.exists():
        print("No PatchGuard runs in artifacts/ yet.")
        return
    reports = sorted((p for p in artifacts.rglob("report.json")
                      if "pytest-tmp" not in p.relative_to(artifacts).parts),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        print("No PatchGuard reports found.")
        return
    print(f"PatchGuard runs ({len(reports)} reports, newest first):")
    for report in reports[:args.limit or None]:
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            print(f"  [{data.get('exit_code', '?')}] {data.get('result', '?')} → "
                  f"{(report.parent / 'summary.md').relative_to(ROOT)}")
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"  [unreadable] {report.relative_to(ROOT)}: {exc}")
            continue
        print(f"      log map: {(report.parent / 'evidence-index.md').relative_to(ROOT)}")
        print(f"      machine: {report.relative_to(ROOT)}")
        archive = report.parent / "technical-evidence.zip"
        if archive.is_file():
            print(f"      archive: {archive.relative_to(ROOT)}")
    if args.limit and len(reports) > args.limit:
        print(f"  … {len(reports) - args.limit} older runs not shown (use --limit 0)")


if __name__ == "__main__":
    main()
