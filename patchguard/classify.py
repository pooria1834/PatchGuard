"""Derive independent behavior states and select the documented exit priority."""

from hashlib import sha256

from .analyze import signature

CHECKS = {
    "base_contract_mismatch": "base_mismatch_not_observed",
    "oracle_coverage": "oracle_coverage_missing",
    "repeatability": "repeat_missing",
    "minimization": "minimization_missing",
    "regression_case": "regression_case_missing",
    "binary_metadata": "binary_metadata_missing",
    "report_complete": "report_incomplete",
}
NAMES = {0: "CORRECTED", 10: "INCOMPLETE_CORRECTION", 20: "FUNCTIONAL_REGRESSION",
         30: "BUILD_OR_CONFIG_ERROR", 40: "INCONCLUSIVE"}


def priority(*codes: int) -> int:
    """Select the strongest observed outcome."""
    return next(code for code in (40, 20, 10, 30, 0) if code == 0 or code in codes)


def assess(cases: list[dict], records: list[dict]) -> dict:
    """Identify observations corroborated by both build modes."""
    # Compare the same build modes across versions. Sanitizers may legitimately
    # make the Checked execution terminate when Release does not.
    from .diagnostics import memory_key

    index = {(row["case_id"], row["role"], row["mode"]): row for row in records}
    observations = {}
    expected_exits = {0, *(case["expected_exit"] for case in cases)}
    complete = bool(cases) and len(index) == len(records) == 4 * len(cases)
    fields = ("mismatch_kind", "actual_exit", "actual_stdout_hex")
    for case in cases:
        name = case["id"]
        for role in ("base", "candidate"):
            release = index.get((name, role, "release"))
            checked = index.get((name, role, "checked"))
            if not release or not checked:
                complete = False
                continue
            if any(row.get("state", "normal") not in ("normal", "signal") or any(
                row.get(stream, {}).get("truncated", False) for stream in ("stdout", "stderr")
            ) for row in (release, checked)):
                complete = False
                continue
            diagnosed_memory = bool(memory_key(checked.get("diagnostic")))
            if release.get("state", "normal") == "signal":
                # A real Release crash is an important observation, not an
                # absent test. Accept it only if the corresponding Checked
                # execution independently identifies a memory fault.
                if not diagnosed_memory:
                    complete = False
                    continue
            elif release.get("state", "normal") != "normal" or release["actual_exit"] not in expected_exits:
                complete = False
                continue
            if not diagnosed_memory and (
                checked.get("state", "normal") != "normal" or any(release[field] != checked[field] for field in fields)
            ):
                # A distinct Checked outcome without a classified sanitizer
                # finding is not grounds for silently declaring success.
                complete = False
            observations[name, role] = release

    def rule(row: dict) -> tuple:
        # The exact rejection oracle identifies the contract outcome.
        return tuple(row[key] for key in ("expected_exit", "expected_stdout_hex", "mismatch_kind", "actual_exit"))

    base_mismatches = []
    remaining, regressions, differences, fixed, new_issues = [], [], [], [], []
    # Equal bytes with different CLI arguments are different logical tests.
    import json
    def invocation_key(case: dict) -> str:
        invocation = json.dumps(case.get('effective_args', case.get('args', [])), separators=(',', ':'), ensure_ascii=True)
        return sha256(case['input'] + b'\0' + invocation.encode('ascii')).hexdigest()

    rules = {}
    unexplained = False
    for case in cases:
        name = case["id"]
        base = observations.get((name, "base"))
        if base and not base["match"] and case["kind"] in ("invalid", "boundary"):
            base_mismatches.append(name)
            rules.setdefault(rule(base), set()).add(invocation_key(case))

    for case in cases:
        name = case["id"]
        base = observations.get((name, "base"))
        candidate = observations.get((name, "candidate"))
        if not base or not candidate:
            continue
        if any(base[field] != candidate[field] for field in fields[1:]):
            differences.append(dict(case_id=name, before={field: base[field] for field in fields},
                                    after={field: candidate[field] for field in fields}))
        if candidate["match"]:
            if name in base_mismatches:
                fixed.append(name)
            continue
        other = rules.get(rule(candidate), set()) - {invocation_key(case)}
        if base and not base["match"] and case["kind"] in ("invalid", "boundary") and other and signature(candidate) == signature(base):
            remaining.append(name)
        elif case["kind"] == "valid" and base["match"]:
            regressions.append(name)
        else:
            if base["match"]:
                new_issues.append(name)
            unexplained = True
    valid_cases = [case for case in cases if case["kind"] == "valid"]
    valid_preserved = bool(valid_cases) and all(
        observations.get((case["id"], role), {}).get("match")
        for case in valid_cases for role in ("base", "candidate")
    )
    return dict(valid_preserved=valid_preserved, base_mismatches=base_mismatches, remaining=remaining, regressions=regressions,
                fixed=fixed, new_issues=new_issues, differences=differences, oracle_coverage=complete, unexplained=unexplained,
                candidate_matches_all=bool(cases) and all(
                    observations.get((case["id"], "candidate"), {}).get("match") for case in cases))


def registry(states: dict[str, bool], unstable: bool = False) -> dict:
    """Build the mandatory check registry with fixed reason strings."""
    return {
        key: dict(status="not_yet_enabled" if key not in states else "passed" if states[key] else "failed",
                  reason=None if key not in states or states[key] else
                  "repeat_unstable" if key == "repeatability" and unstable else reason)
        for key, reason in CHECKS.items()
    }
