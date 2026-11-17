"""Historical minimized cases must keep checking for *reintroduced* faults."""

import pytest

from patchguard.analyze import signature
from patchguard.pipeline import assess_registered_regressions


def _run(case_id, role, mode, *, error=None, exit_code=0, state="normal",
         truncated=False, match=True):
    row = dict(case_id=case_id, role=role, mode=mode, state=state, match=match,
               mismatch_kind=None if match else "both_mismatch",
               expected_exit=0, actual_exit=exit_code,
               expected_stdout_hex=b"OK\n".hex(), actual_stdout_hex=b"OK\n".hex() if match else "",
               stdout=dict(truncated=truncated), stderr=dict(truncated=False),
               diagnostic=error)
    return row


def _run_matrix(case_id):
    return [_run(case_id, role, mode) for role in ("base", "candidate")
            for mode in ("release", "checked")]


def _case(case_id, sig, role="base", mode="checked"):
    return dict(id=case_id, preserved_signature=sig, witness_role=role, witness_mode=mode)


def _asan():
    return dict(mechanism="ASan", kind="stack-buffer-overflow",
                location=dict(path="src/example.c", line=42),
                frames=[dict(path="src/example.c", line=42, function="f")])


def test_previously_fixed_case_is_resolved_if_all_four_executions_are_clean():
    rows = _run_matrix("old-stack")
    cases = [_case("old-stack", "a" * 64)]
    observations, valid = assess_registered_regressions(cases, rows)
    assert observations == [dict(case_id="old-stack", witness_role="base",
                                 witness_mode="checked", status="resolved")]
    assert valid


def test_original_fault_still_reproduces_in_current_base():
    rows = _run_matrix("heap")
    fault = rows[1]  # Base checked
    fault.update(diagnostic=_asan(), match=False, actual_exit=1)
    cases = [_case("heap", signature(fault))]
    observations, valid = assess_registered_regressions(cases, rows)
    assert observations[0]["status"] == "reproduced"
    assert valid


@pytest.mark.parametrize("corruption", [
    dict(state="timeout", match=False),
    dict(match=False),
    dict(truncated=True),
    dict(error=_asan(), match=False, exit_code=1),
])
def test_old_signature_missing_does_not_accept_other_failures(corruption):
    rows = _run_matrix("old-stack")
    row = rows[-1]  # Candidate checked
    if "truncated" in corruption:
        row["stdout"]["truncated"] = corruption["truncated"]
    if "error" in corruption:
        row["diagnostic"] = corruption["error"]
    for key in ("state", "match", "exit_code"):
        if key in corruption:
            row["actual_exit" if key == "exit_code" else key] = corruption[key]
    cases = [_case("old-stack", "a" * 64)]
    observations, valid = assess_registered_regressions(cases, rows)
    assert observations[0]["status"] == "changed"
    assert not valid


def test_incomplete_execution_set_cannot_be_called_resolved():
    rows = _run_matrix("old-stack")[:3]
    observations, valid = assess_registered_regressions([_case("old-stack", "a" * 64)], rows)
    assert observations[0]["status"] == "changed"
    assert not valid


def test_multiple_historical_cases_can_be_resolved_and_reproduced_together():
    rows = _run_matrix("stack") + _run_matrix("heap")
    heap = next(row for row in rows if row["case_id"] == "heap" and
                row["role"] == "base" and row["mode"] == "checked")
    heap.update(diagnostic=_asan(), match=False, actual_exit=1)
    cases = [_case("stack", "a" * 64), _case("heap", signature(heap))]
    observations, valid = assess_registered_regressions(cases, rows)
    assert [(row["case_id"], row["status"]) for row in observations] == [
        ("stack", "resolved"), ("heap", "reproduced")]
    assert valid
