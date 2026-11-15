#!/usr/bin/env python3
"""Compile and check the safe toy targets against independent expected behavior."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("base", "correct", "incomplete", "regression")
TARGETS = {
    "record_parser": "record_parser.c",
    "score_record": "score_record.c",
}


def main() -> int:
    compiler = os.environ.get("CC") or shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        print("No C compiler found. Install clang or gcc.", file=sys.stderr)
        return 30
    matrix = json.loads((ROOT / "tests/target_matrix.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    total = 0
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="target-matrix-", dir=artifacts) as tmp:
        build_root = Path(tmp)
        binaries: dict[tuple[str, str], Path] = {}
        for target, source_name in TARGETS.items():
            for variant in VARIANTS:
                source = ROOT / "targets" / target / variant / source_name
                output = build_root / f"{target}-{variant}"
                command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(output)]
                built = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                if built.returncode != 0:
                    failures.append(f"BUILD {target}/{variant}: {built.stderr.decode(errors='replace')}")
                    continue
                binaries[(target, variant)] = output
        for target, cases in matrix["targets"].items():
            for variant in VARIANTS:
                binary = binaries.get((target, variant))
                if binary is None:
                    continue
                for case in cases:
                    total += 1
                    data = case["input_utf8"].encode("utf-8")
                    result = subprocess.run([str(binary)], input=data, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, timeout=2, check=False)
                    expected_out = case["expected_stdout"][variant].encode("utf-8")
                    expected_exit = case["expected_exit"][variant]
                    if result.returncode != expected_exit or result.stdout != expected_out:
                        failures.append(
                            f"{target}/{variant}/{case['id']}: got exit={result.returncode}, "
                            f"stdout={result.stdout!r}; expected exit={expected_exit}, stdout={expected_out!r}"
                        )
    print(f"Cases checked: {total}")
    if failures:
        print("FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS: all target variants match the independent behavior matrix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
