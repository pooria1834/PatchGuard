"""Promote one reviewed Base regression into the tracked test corpus.

For CI evidence, use --evidence-zip to validate archived replay records, an
independent oracle, and (by default) rebuild and replay Base three times.
A maintainer must still inspect and approve the resulting Git diff/PR.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchguard.config import ConfigError, load_cases, load_config, workspace_path
from patchguard.promotion import promote_archive, check_independent_oracle
from patchguard.report import generate_case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--evidence-zip", help="Technical evidence ZIP downloaded from a PR CI run")
    parser.add_argument("--no-base-replay", action="store_true",
                        help="Skip independent Base replays (manual/offline inspection ONLY)")
    parser.add_argument("--dry-run", action="store_true", help="Check evidence but do not write reviewed files")
    args = parser.parse_args()
    try:
        if args.evidence_zip:
            result = promote_archive(args.config, args.evidence_zip, args.case,
                                     verify_base=not args.no_base_replay, dry_run=args.dry_run)
        else:
            config = load_config(args.config)
            settings = config["regression"]
            if "reviewed" not in settings:
                raise ConfigError("configure regression.reviewed before promoting a case")
            generated = workspace_path(settings["dir"], "regression.dir")
            reviewed = workspace_path(settings["reviewed"], "regression.reviewed")
            run = config["run"]
            cases = load_cases(generated / "manifest.yaml", run["max_input_bytes"], run["output_limit_bytes"])
            case = next((row for row in cases if row["id"] == args.case), None)
            if not case or case.get("witness_role") != "base" or not case.get("preserved_signature"):
                raise ConfigError("choose a generated Base witness from the local manifest")
            check_independent_oracle(config, case)
            if args.dry_run:
                result = dict(id=case["id"], dry_run=True)
            else:
                result = generate_case(reviewed, case, case["input"], case["preserved_signature"],
                                       witness_role="base", witness_mode=case["witness_mode"])
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ConfigError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, IndexError) as exc:
        print(f"Promotion blocked: {exc}", file=sys.stderr)
        return 30


if __name__ == "__main__":
    raise SystemExit(main())
