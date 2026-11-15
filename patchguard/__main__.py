"""Command-line entry point for PatchGuard."""

import argparse
import sys
from datetime import datetime, timezone
from time import monotonic

from .acceptance import verify as verify_all
from .classify import registry
from .config import ConfigError, workspace_path
from .pipeline import evaluate
from .report import write_partial_report


def main(argv: list[str] | None = None) -> int:
    """Dispatch the two documented commands."""
    parser = argparse.ArgumentParser(prog="python -m patchguard")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Evaluate a Base/Candidate pair")
    validate.add_argument("--config", required=True)
    validate.add_argument("--patched", help="Override the Candidate source directory")
    validate.add_argument("--report-dir", required=True)
    verify = commands.add_parser("verify-all", help="Check the configured acceptance scenarios")
    verify.add_argument("--report-dir", required=True)
    args = parser.parse_args(argv)

    started_at = datetime.now(timezone.utc).isoformat()
    started = monotonic()
    try:
        directory = workspace_path(args.report_dir, "--report-dir")
        directory.mkdir(parents=True, exist_ok=True)
    except (ConfigError, OSError) as exc:
        print(f"report directory {args.report_dir!r}: {exc}", file=sys.stderr)
        return 30

    config = getattr(args, "config", None)
    evidence = None
    if args.command == "validate":
        evidence = dict(config=dict(path=config, resolved=None), stages=[], tests_started=False,
                        builds=[], executions=[], cases=[], sources={}, diff=None, toolchain={},
                        correlation=[], observations=None, replay=[], generated_observations=[],
                        binary_metadata={}, checks=registry({}), contract_state="inconclusive",
                        functional_state="inconclusive", completeness="incomplete")
        code, reason = evaluate(args.config, args.patched, directory, evidence)
        stage = "evaluation"
    else:
        stage = "acceptance"
        try:
            return verify_all(directory)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            code, reason = 30, str(exc)
    try:
        write_partial_report(
            directory, command=args.command, config=config, resolved=None,
            started_at=started_at, started=started, stage=stage, code=code, reason=reason, evidence=evidence,
        )
    except (OSError, ConfigError) as exc:
        print(f"cannot write report in {directory}: {exc}", file=sys.stderr)
        print(reason, file=sys.stderr)
        return 30
    print(reason, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
