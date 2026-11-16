"""Replay a saved mismatch on the recorded and hash-verified executable."""

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchguard.analyze import compare, signature
from patchguard.build import build_variant
from patchguard.config import ROOT, ConfigError, workspace_path
from patchguard.source import inventory, tree_digest
from patchguard.run import run_case


def main() -> int:
    """Check a saved input and record its new observed signature."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--original", action="store_true")
    args = parser.parse_args()
    try:
        directory = workspace_path(args.bundle, "bundle")
        manifest = json.loads((directory / "manifest.json").read_text())
        build = manifest["build"]
        binary = workspace_path(build["path"], "binary")
        if not binary.is_file():
            source = workspace_path(manifest["source"]["path"], "replay source")
            digest = tree_digest(inventory(source))
            if digest != build["source_digest"]:
                raise ValueError("source digest differs from replay record")
            rebuilt = build_variant(manifest["configuration"]["resolved"]["build"], source,
                                    build["role"], build["mode"], directory / "manual-replay", digest)
            if rebuilt["error"]:
                raise ValueError(rebuilt["error"])
            binary = ROOT / rebuilt["path"]
            build = build | {"path": rebuilt["path"]}
        if sha256(binary.read_bytes()).hexdigest() != build["sha256"]:
            raise ValueError("binary hash differs from replay record")
        input_key = "original" if args.original else "minimized"
        data = workspace_path(manifest[input_key], "input", within=directory).read_bytes()
        if sha256(data).hexdigest() != manifest[f"{input_key}_sha256"]:
            raise ValueError("input hash differs from replay record")
        if not args.original and "minimized_expected_exit" in manifest:
            expected_exit = manifest["minimized_expected_exit"]
            expected_stdout = bytes.fromhex(manifest["minimized_expected_stdout"])
        else:
            expected_exit = manifest["expected_exit"]
            expected_stdout = bytes.fromhex(manifest["expected_stdout"])
        case = dict(id=manifest["case_id"], input=data, expected_exit=expected_exit,
                    expected_stdout=expected_stdout, args=manifest.get("args", manifest["configuration"]["resolved"]["run"].get("args", [])))
        run = run_case(build, case, manifest["configuration"]["resolved"]["run"], directory / "manual-replay")
        observed = signature(run | compare(case, run))
        print(json.dumps(dict(observed_signature=observed, expected_signature=manifest["signature"])))
        return 0 if observed == manifest["signature"] else 40
    except (ConfigError, OSError, ValueError, KeyError) as exc:
        print(exc, file=sys.stderr)
        return 30


if __name__ == "__main__":
    raise SystemExit(main())
