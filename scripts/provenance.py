"""Generate or verify provenance records for configured source variants."""
import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchguard.source import inventory, source_diff, tree_digest


def main() -> int:
    """Generate source records or check committed bytes."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    ok = True
    for directory in sorted((ROOT / "targets").glob("*/*")):
        base = directory.parent / "base"
        extensions = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"}
        filenames = {p.relative_to(root).as_posix() for root in (base, directory)
                     for p in root.rglob("*") if p.is_file() and p.suffix in extensions}
        diff = source_diff(base, directory, filenames).encode()
        patch = directory / "diff_from_base.patch"
        if not args.check:
            patch.write_bytes(diff)
        files = inventory(directory)
        manifest = directory / "PROVENANCE.json"
        previous = json.loads(manifest.read_text()) if manifest.is_file() else {}
        note = directory / "PATCH.md"
        description = (note.read_text().split("\n\n", 1)[-1].strip()
                       if note.is_file() else previous.get("description", ""))
        record = dict(origin=previous.get("origin", "self-authored"),
                      parent=previous.get("parent", None if directory == base else "base"),
                      description=description, files=files,
                      source_tree_digest=tree_digest(files), diff_sha256=sha256(diff).hexdigest())
        data = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
        if not args.check:
            manifest.write_bytes(data)
        matches = patch.read_bytes() == diff and manifest.read_bytes() == data
        print(directory.relative_to(ROOT), "verified" if matches else "mismatch")
        ok &= matches
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
