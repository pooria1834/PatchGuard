"""Compare normal process results with independent expected bytes."""

from .config import ROOT
from .diagnostics import memory_key, parse_diagnostics


def compare(case: dict, result: dict) -> dict:
    """Describe matched fields, mismatches and execution anomalies."""
    actual = (ROOT / result["stdout"]["path"]).read_bytes()
    code = result["returncode"]
    expected = case["expected_stdout"]
    if result["state"] != "normal" or result["stdout"]["truncated"] or result["stderr"]["truncated"]:
        mismatch = "anomaly"
    elif code != case["expected_exit"]:
        mismatch = "exit_mismatch" if actual == expected else "both_mismatch"
    else:
        mismatch = None if actual == expected else "stdout_mismatch"
    error = None
    if "path" in result["stderr"]:
        stderr = (ROOT / result["stderr"]["path"]).read_text(errors="replace")
        error = parse_diagnostics(stderr, code) if result["state"] in ("normal", "signal") else None
    return dict(diagnostic=error, mismatch_kind=mismatch, match=mismatch is None, actual_exit=code,
                expected_exit=case["expected_exit"], actual_stdout_hex=actual.hex(),
                expected_stdout_hex=expected.hex())


def signature(observation: dict) -> str | None:
    """Hash only the stable fields defining an exact normal mismatch."""
    from hashlib import sha256

    diagnostic = observation.get("diagnostic")
    if (key := memory_key(diagnostic)) and observation.get("state") in ("normal", "signal") and not any(
        observation.get(stream, {}).get("truncated") for stream in ("stdout", "stderr")
    ):
        return sha256("|".join(map(str, key)).encode()).hexdigest()

    kind = observation["mismatch_kind"]
    if kind in (None, "anomaly"):
        return None
    expected = sha256(bytes.fromhex(observation["expected_stdout_hex"])).hexdigest()
    actual = sha256(bytes.fromhex(observation["actual_stdout_hex"])).hexdigest()
    fields = (kind, observation["expected_exit"], observation["actual_exit"], expected, actual)
    return sha256("|".join(map(str, fields)).encode()).hexdigest()
