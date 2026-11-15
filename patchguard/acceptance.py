"""Run the acceptance plan through the public CLI."""

import json
import subprocess
import sys
from pathlib import Path

from .classify import CHECKS
from .config import ROOT, load_yaml, workspace_path
from .report import evidence_complete, write_json


def verify(directory: Path) -> int:
    """Execute each configured scenario and check its evidence."""
    directory = workspace_path(directory, "--report-dir", within=ROOT / "artifacts")
    plan = load_yaml(ROOT / "configs/acceptance.yaml")["scenarios"]
    if not isinstance(plan, list) or not plan or len({row["id"] for row in plan}) != len(plan):
        raise ValueError("expected a nonempty list of uniquely named acceptance scenarios")
    results = []
    for row in plan:
        scenario = workspace_path(directory / row["id"], "scenario", within=directory)
        scenario.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [sys.executable, "-m", "patchguard", "validate", "--config", row["config"],
             "--patched", row["patched"], "--report-dir", str(scenario)],
            cwd=ROOT, capture_output=True, check=False,
        )
        (scenario / "cli.stdout").write_bytes(result.stdout)
        (scenario / "cli.stderr").write_bytes(result.stderr)
        path = scenario / "report.json"
        report = json.loads(path.read_text()) if path.is_file() else {}
        expected = row["expected_exit"]
        checks = report.get("checks", {})
        complete = bool(report) and evidence_complete(report) and (scenario / "summary.md").is_file()
        passed = (result.returncode == expected == report.get("exit_code") and complete
                  and all(checks.get(key, {}).get("status") == "passed" for key in CHECKS))
        results.append(dict(id=row["id"], expected_exit=expected, observed_exit=result.returncode,
                            evidence_complete=complete, passed=passed,
                            tests_started=report.get("tests_started", False),
                            report=path.relative_to(ROOT).as_posix() if path.is_file() else None))
    code = 0 if all(row["passed"] for row in results) else 1
    if all(row["observed_exit"] == 30 and not row["tests_started"] for row in results):
        statuses = [json.loads((ROOT / row["report"]).read_text()) for row in results if row["report"]]
        if len(statuses) == len(results) and all(
            item["exit_reason"] == "compiler version probe failed; see compiler logs" for item in statuses
        ):
            code = 30
    write_json(directory / "acceptance.json", dict(exit_code=code, scenarios=results))
    print(f"{sum(row['passed'] for row in results)}/{len(results)} scenarios accepted")
    return code
