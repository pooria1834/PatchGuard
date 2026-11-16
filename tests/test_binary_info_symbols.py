"""Regression coverage for bounded, two-stage readelf symbol collection."""

from pathlib import Path

import pytest

from patchguard import binary_info


HEADERS = """ELF Header:
  Type: DYN (Position-Independent Executable file)
Program Headers:
  GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10
  GNU_RELRO 0x0 0x0 0x0 0x0 0x0 R 0x1
Dynamic section:
  0x000000000000001e (FLAGS) BIND_NOW
  0x000000006ffffffb (FLAGS_1) Flags: NOW PIE
"""
CANARY = "  123: 00000000 0 FUNC GLOBAL DEFAULT UND __stack_chk_fail@GLIBC_2.4\n"


def _collect(monkeypatch, tmp_path, *, dynamic=CANARY, full=CANARY,
             dynamic_returncode=0, full_returncode=0, full_truncated=False):
    """Simulate readelf with an auditable evidence file and captured argv."""
    monkeypatch.setattr(binary_info, "ROOT", tmp_path)
    calls = []

    def fake_execute(argv, directory, *, limit):
        calls.append((argv, limit))
        directory.mkdir(parents=True, exist_ok=True)
        if "--dyn-syms" in argv:
            stdout, code = dynamic.encode(), dynamic_returncode
        elif "-s" in argv:
            stdout, code = full.encode(), full_returncode
        elif argv[0] == "readelf":
            stdout, code = HEADERS.encode(), 0
        else:
            stdout, code = b"ELF 64-bit executable\n", 0
        total = len(stdout)
        if full_truncated and "-s" in argv:
            stdout = stdout[:limit]
            total = max(total, limit + 1)
        else:
            stdout = stdout[:limit]
        path = directory / "stdout.bin"
        path.write_bytes(stdout)
        (directory / "stderr.bin").write_bytes(b"")
        return {
            "returncode": code,
            "stdout": {"path": path.relative_to(tmp_path).as_posix(),
                       "bytes": total, "truncated": total > len(stdout)},
            "stderr": {"path": (directory / "stderr.bin").relative_to(tmp_path).as_posix(),
                       "bytes": 0, "truncated": False},
        }

    monkeypatch.setattr(binary_info, "execute", fake_execute)
    build = dict(path="bin/program", elf="ELF", sha256="a" * 64,
                 flags=["-fstack-protector-strong"], compiler="gcc")
    record = binary_info.collect(build, tmp_path / "artifacts" / "binary-info" / "base-release")
    return record, calls


def test_dynamic_symbols_with_canary_are_enough(monkeypatch, tmp_path):
    record, calls = _collect(monkeypatch, tmp_path, dynamic=CANARY, full="")
    assert record["tools"]["symbols"]["source"] == "dynamic"
    assert record["tools"]["symbols"]["status"] == "available"
    assert record["hardening"]["stack_canary"]["status"] == "present"
    assert record["hardening"]["stack_canary"]["evidence"] == [CANARY.strip()]
    assert not any("-s" in argv for argv, _ in calls)
    assert any("--dyn-syms" in argv and limit == 1024 * 1024 for argv, limit in calls)
    assert record["tools"]["symbols"]["process"]["stdout"]["path"].endswith("/symbols/stdout.bin")


def test_fallback_reads_large_full_table_to_find_canary(monkeypatch, tmp_path):
    # Reproduce jq's old failure mode: a >64 KiB symbol table.
    full = "placeholder_symbol\n" * 5000 + CANARY
    assert 65536 < len(full) < 1024 * 1024
    record, calls = _collect(monkeypatch, tmp_path, dynamic="", full=full)
    assert record["tools"]["symbols"]["source"] == "full"
    assert record["tools"]["symbols"]["status"] == "available"
    assert record["hardening"]["stack_canary"]["status"] == "present"
    assert any("-s" in argv and limit == 1024 * 1024 for argv, limit in calls)
    path = tmp_path / record["tools"]["symbols"]["process"]["stdout"]["path"]
    assert path.read_bytes() == full.encode()


@pytest.mark.parametrize("full,full_returncode,full_truncated,expected", [
    ("no canary symbol\n", 0, False, "not_observed"),
    ("not enough evidence\n", 0, True, "unknown"),
    ("readelf failed\n", 1, False, "unknown"),
])
def test_absence_requires_complete_successful_full_table(monkeypatch, tmp_path, full,
                                                           full_returncode, full_truncated, expected):
    record, _ = _collect(monkeypatch, tmp_path, dynamic="", full=full,
                         full_returncode=full_returncode, full_truncated=full_truncated)
    assert record["hardening"]["stack_canary"]["status"] == expected
    assert record["tools"]["symbols"]["status"] == (
        "available" if expected == "not_observed" else "unavailable")


def test_dynamic_tool_failure_uses_full_table(monkeypatch, tmp_path):
    record, _ = _collect(monkeypatch, tmp_path, dynamic="", full=CANARY,
                         dynamic_returncode=1)
    assert record["hardening"]["stack_canary"]["status"] == "present"
    assert record["tools"]["symbols"]["source"] == "full"
