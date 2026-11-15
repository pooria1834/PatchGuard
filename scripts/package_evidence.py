"""Archive the completed acceptance evidence without compiled executables."""

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Write a ZIP after validating the recorded acceptance index."""
    artifacts = ROOT / "artifacts"
    verify = artifacts / "verify"
    acceptance = json.loads((verify / "acceptance.json").read_text())
    if acceptance["exit_code"] != 0 or not acceptance["scenarios"] or not all(
        row["passed"] for row in acceptance["scenarios"]
    ):
        raise SystemExit("Run make verify successfully before packaging.")
    destination = ROOT / "submission"
    destination.mkdir(exist_ok=True)
    archive = destination / "patchguard-evidence.zip"
    temporary = destination / "patchguard-evidence.tmp"
    with ZipFile(temporary, "w", ZIP_DEFLATED) as output:
        for directory in (verify, artifacts / "ci", artifacts / "negative-ci", artifacts / "regression"):
            for path in sorted(directory.rglob("*")):
                if not path.is_file() or path.is_symlink() or path.name.startswith("."):
                    continue
                with path.open("rb") as stream:
                    if stream.read(4) == b"\x7fELF":
                        continue
                output.write(path, path.relative_to(ROOT))
    temporary.replace(archive)
    print(archive.relative_to(ROOT))


if __name__ == "__main__":
    main()
