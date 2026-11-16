"""Repeat and minimize observations using their original execution settings."""

from hashlib import sha256
from pathlib import Path
from shutil import rmtree

from .analyze import compare, signature
from .config import ROOT, oracle_argv
from .diagnostics import memory_key
from .minimize import ddmin
from .report import generate_case, write_json
from .run import execute, run_case


def reproduce(config: dict, report: dict, cases: list[dict], directory: Path) -> list[dict]:
    """Record repeat and minimization bundles for classification witnesses."""
    findings = report["observations"]
    selected = {"base": set(findings["base_mismatches"]),
                "candidate": set(findings["remaining"] + findings["regressions"])}
    for finding in report.get("runtime_findings", []):
        for role, side in (("base", "before"), ("candidate", "after")):
            if memory_key(finding[side]):
                selected[role].add(finding["case_id"])
    builds = {(item["role"], item["mode"]): item for item in report["builds"]}
    inputs = {case["id"]: case for case in cases}
    oracles = {}
    for case in cases:
        oracles.setdefault((case["input"], tuple(case.get("args", config["run"].get("args", [])))), set()).add((case["expected_exit"], case["expected_stdout"]))
    computed_oracles = {}

    def independent_oracle(data: bytes, prefix: Path, args: list[str]):
        # Stored fixture outcomes are valid without consulting the patched code.
        key = (data, tuple(args))
        if key in oracles and len(oracles[key]) == 1:
            return next(iter(oracles[key]))
        if key in computed_oracles:
            return computed_oracles[key]
        reference = config.get("oracle")
        if not reference:
            return None
        probe = execute(oracle_argv(reference, args), prefix, data=data,
                        timeout=reference.get("timeout_seconds", 2),
                        limit=config["run"]["output_limit_bytes"])
        try:
            if (probe["state"] != "normal" or probe["returncode"] is None
                or not 0 <= probe["returncode"] <= 255
                or probe["stdout"]["truncated"] or probe["stderr"]["truncated"]):
                computed_oracles[key] = None
            else:
                computed_oracles[key] = (probe["returncode"],
                                          (ROOT / probe["stdout"]["path"]).read_bytes())
        finally:
            # Transient oracle-probe streams create thousands of redundant files;
            # committed expected bytes and the minimized reproducer remain.
            rmtree(prefix, ignore_errors=True)
        return computed_oracles[key]

    bundles = []
    for observation in report["executions"]:
        role, mode, name = (observation[key] for key in ("role", "mode", "case_id"))
        if name not in selected[role]:
            continue
        case = inputs[name]
        expected = signature(observation)
        if expected is None:
            continue
        build = builds[role, mode]
        bundle = directory / "cases" / f"{expected}-{role}-{mode}-{name}"
        bundle.mkdir(parents=True, exist_ok=True)
        original = case["input"]
        case_args = case.get("args", config["run"].get("args", []))
        (bundle / "original.bin").write_bytes(original)
        attempts = []
        for index in range(1, 4):
            attempt_dir = bundle / "attempts" / f"attempt-{index}"
            result = run_case(build, case, config["run"], attempt_dir)
            record = result | compare(case, result)
            path = bundle / "attempts" / f"attempt-{index}.json"
            write_json(path, record)
            attempts.append(dict(path=path.relative_to(ROOT).as_posix(), signature=signature(record)))
        stable = all(attempt["signature"] == expected for attempt in attempts)
        manifest = dict(role=role, mode=mode, case_id=name, signature=expected, stable=stable,
                        history=attempts, configuration=report["config"], build=build,
                        source=report["sources"][role], argv=observation.get("argv"),
                        environment=observation.get("env"), diagnostic=observation.get("diagnostic"),
                        args=case_args, original_sha256=sha256(original).hexdigest(),
                        original=(bundle / "original.bin").relative_to(ROOT).as_posix(),
                        expected_exit=case["expected_exit"], expected_stdout=case["expected_stdout"].hex())
        if stable and "preserved_signature" in case:
            # A generated test has already passed the minimizer. Reprocessing
            # it recursively would multiply cases and runtime on each CI run.
            minimized = original
            (bundle / "minimized.bin").write_bytes(minimized)
            manifest.update(
                minimization=dict(status="already_registered", attempts=0, budget=250,
                                  cache_hits=0, executions=0),
                minimized=(bundle / "minimized.bin").relative_to(ROOT).as_posix(),
                minimized_sha256=sha256(minimized).hexdigest(),
                minimized_expected_exit=case["expected_exit"],
                minimized_expected_stdout=case["expected_stdout"].hex(),
                generated=dict(manifest=case["manifest_path"],
                               id=case["id"], deduplicated=True, already_registered=True),
            )
        elif stable:
            trial = executions = 0
            trace = []

            def preserves(data: bytes) -> bool:
                nonlocal trial, executions
                # The independent oracle, not the candidate binary, defines
                # the expected output of every new minimization input.
                trial += 1
                row = dict(trial=trial, sha256=sha256(data).hexdigest(), input_bytes=len(data),
                           same_fault=False, oracle_available=False)
                oracle = independent_oracle(data, bundle / "oracle" / str(trial), case_args)
                if oracle is None or oracle[0] != case["expected_exit"]:
                    trace.append(row)
                    return False
                row["oracle_available"] = True
                changed = case | {"input": data, "expected_exit": oracle[0],
                                  "expected_stdout": oracle[1]}
                trial_dir = bundle / "trials" / str(trial)
                executions += 1
                try:
                    result = run_case(build, changed, config["run"], trial_dir)
                    record = result | compare(changed, result)
                    row["same_fault"] = signature(record) == expected
                    row["termination"] = dict(state=record["state"], returncode=record["returncode"],
                                               diagnostic=record.get("diagnostic", {}).get("kind") if record.get("diagnostic") else None)
                    trace.append(row)
                    return row["same_fault"]
                finally:
                    # Only confirmed original/minimized witnesses and the
                    # required three repeat records need raw stdout/stderr.
                    # The tiny trace preserves how minimization was decided.
                    rmtree(trial_dir, ignore_errors=True)

            # Sanitizer witnesses justify a larger search budget. Contract-only
            # mismatches retain an exact output signature and typically cannot
            # shrink much, so bound their oracle subprocess cost separately.
            budget = 150 if memory_key(observation.get("diagnostic")) else 30
            minimized, stats = ddmin(original, preserves, budget=budget)
            (bundle / "minimized.bin").write_bytes(minimized)
            stats["executions"] = executions
            write_json(bundle / "minimization-trace.json", dict(attempts=trace, statistics=stats,
                                                                kept_original_bytes=len(original),
                                                                kept_minimized_bytes=len(minimized)))
            expected_minimized = independent_oracle(minimized, bundle / "oracle" / "final", case_args)
            if expected_minimized is None:
                raise ValueError("minimized input lacks an independent expected result")
            generated = generate_case(ROOT / config["regression"]["dir"], case, minimized, expected,
                                      expected_exit=expected_minimized[0],
                                      expected_stdout=expected_minimized[1],
                                      witness_role=role, witness_mode=mode, args=case_args,
                                      identity_args=case_args if "args" in case else None)
            manifest.update(minimization=stats, minimized=(bundle / "minimized.bin").relative_to(ROOT).as_posix(),
                            minimized_sha256=sha256(minimized).hexdigest(),
                            minimized_expected_exit=expected_minimized[0],
                            minimized_expected_stdout=expected_minimized[1].hex(),
                            generated=generated)
        (bundle / "README.md").write_text(
            "# Replay case\n\nRun from the workspace root using the matching PatchGuard tool version:\n\n"
            f"`python3 /path/to/PatchGuard/scripts/replay_case.py --bundle {bundle.relative_to(ROOT)}`\n\n"
            "The command can be executed in the provided Docker image with the tool checkout mounted at /tool "
            "and PATCHGUARD_WORKSPACE pointing to the candidate source checkout.\n"
        )
        write_json(bundle / "manifest.json", manifest)
        bundles.append(manifest | dict(path=(bundle / "manifest.json").relative_to(ROOT).as_posix()))
    return bundles
