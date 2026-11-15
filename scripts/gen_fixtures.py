"""Generate byte-exact fixtures using the two written contracts."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def record_oracle(data: bytes) -> tuple[int, bytes]:
    """Evaluate the independent Record Parser contract."""
    match = re.fullmatch(rb"name:([A-Za-z0-9]{1,15})\n", data)
    return (0, b"OK:" + match[1] + b"\n") if match else (2, b"ERR\n")


def score_oracle(data: bytes) -> tuple[int, bytes]:
    """Evaluate the independent Score Record contract."""
    match = re.fullmatch(rb"score:(0|[1-9][0-9]{0,2})\n", data)
    return (0, b"OK:" + match[1] + b"\n") if match and int(match[1]) <= 100 else (2, b"ERR\n")


def main() -> None:
    """Write both corpora in stable case order."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    def store(path: Path, content: bytes) -> None:
        if args.check:
            if path.read_bytes() != content:
                raise ValueError(f"fixture differs: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    matrix = json.loads((ROOT / "tests/target_matrix.json").read_text())["targets"]
    additions = {
        "record_parser": {
            "empty": b"name:\n", "embedded_nul": b"name:A\0B\n", "crlf": b"name:A\r\n",
            "space": b"name:A \n", "long": b"name:" + b"A" * 80 + b"\n",
            "shrink_from": b"name:" + b"A" * 26 + b"\n",
            "shrink_to": b"name:" + b"A" * 18 + b"\n",
            "reader_limit": b"name:" + b"A" * 4090 + b"\n",
            "above_reader_limit": b"name:" + b"A" * 4091 + b"\n",
        },
        "score_record": {
            "one": b"score:1\n", "missing_newline": b"score:1",
            "extra_line": b"score:1\nscore:2\n", "wrong_prefix": b"scale:1\n",
            "empty": b"score:\n", "oversized": b"score:" + b"9" * 122 + b"\n",
            "sign": b"score:+1\n", "space": b"score: 1\n",
        },
    }
    for target, oracle in (("record_parser", record_oracle), ("score_record", score_oracle)):
        inputs = {case["id"]: case["input_utf8"].encode() for case in matrix[target]}
        inputs.update(additions[target])
        directory = ROOT / "tests/fixtures" / target
        cases, inventory = [], []
        for case_id, data in sorted(inputs.items()):
            code, output = oracle(data)
            kind = "valid" if code == 0 else "invalid"
            if target == "record_parser" and re.fullmatch(rb"name:[A-Za-z0-9]{16,4090}\n", data):
                kind = "boundary"
            if target == "score_record" and re.fullmatch(rb"score:(10[12]|150|200)\n", data):
                kind = "boundary"
            paths = (f"inputs/{case_id}.bin", f"expected/{case_id}.out")
            cases.append(dict(id=case_id, kind=kind, input=paths[0], expected_exit=code, expected_stdout=paths[1]))
            for relative, content in zip(paths, (data, output), strict=True):
                path = directory / relative
                store(path, content)
                inventory.append(dict(id=case_id, path=relative, sha256=hashlib.sha256(content).hexdigest(),
                                      bytes=len(content), hex_preview=content[:24].hex()))
        store(directory / "cases.yaml", yaml.safe_dump(cases, sort_keys=False).encode())
        store(directory / "FIXTURES.json", (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode())
        print(f"{target}: {len(cases)} cases, {len(inventory)} hashed files")


if __name__ == "__main__":
    main()
