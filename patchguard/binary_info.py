"""Collect descriptive compiler and ELF evidence."""

from pathlib import Path
import re

# Bound stored ELF evidence without applying the small per-test output cap.
SYMBOL_OUTPUT_LIMIT = 1024 * 1024

from .config import ROOT
from .run import execute


def collect(build: dict, directory: Path) -> dict:
    """Preserve tool output and describe optional metadata availability."""
    binary = ROOT / build["path"]
    result = {}
    commands = {
        "readelf": ["readelf", "-W", "-h", "-l", "-d", str(binary)],
        "file": ["file", str(binary)],
    }
    for name, argv in commands.items():
        probe = execute(argv, directory / name, limit=65536)
        result[name] = dict(status="available" if probe["returncode"] == 0 and not probe["stdout"]["truncated"] else "unavailable",
                            process=probe)

    # Dynamic symbols normally contain __stack_chk_fail for dynamically linked
    # programs. If absent, consult the full table (including static symbols).
    # Keep the selected evidence under symbols/ for existing report paths.
    dynamic_probe = execute(["readelf", "-W", "--dyn-syms", str(binary)],
                            directory / "symbols", limit=SYMBOL_OUTPUT_LIMIT)
    dynamic_ok = dynamic_probe["returncode"] == 0 and not dynamic_probe["stdout"]["truncated"]
    dynamic_text = ((ROOT / dynamic_probe["stdout"]["path"]).read_text(errors="replace")
                    if dynamic_ok else "")
    if dynamic_ok and re.search(r"\b__stack_chk_fail\b", dynamic_text):
        selected, selected_text, source = dynamic_probe, dynamic_text, "dynamic"
    else:
        selected = execute(["readelf", "-W", "-s", str(binary)],
                           directory / "symbols", limit=SYMBOL_OUTPUT_LIMIT)
        selected_ok = selected["returncode"] == 0 and not selected["stdout"]["truncated"]
        selected_text = ((ROOT / selected["stdout"]["path"]).read_text(errors="replace")
                         if selected_ok else None)
        source = "full"
    result["symbols"] = dict(status="available" if selected_text is not None else "unavailable",
                             source=source, process=selected)
    readelf = result["readelf"]["process"]
    rows = (ROOT / readelf["stdout"]["path"]).read_text(errors="replace").splitlines()
    interpreter = next((row.strip().removesuffix("]").split(": ", 1)[-1]
                        for row in rows if "[Requesting program interpreter:" in row), None)
    checks = hardening("\n".join(rows) if readelf["returncode"] == 0 and not readelf["stdout"]["truncated"] else "",
                       selected_text)
    return dict(hardening=checks, elf=build["elf"], sha256=build["sha256"], flags=build["flags"],
                compiler=build["compiler"], interpreter=interpreter, tools=result)


def hardening(headers: str, symbols: str | None) -> dict:
    """Interpret ELF markers with the exact source lines used by each check."""
    rows = headers.splitlines()
    stack = next((row for row in rows if row.lstrip().startswith("GNU_STACK ")), None)
    relro = next((row for row in rows if row.lstrip().startswith("GNU_RELRO ")), None)
    dynamic = [row for row in rows if re.search(r"\((?:FLAGS(?:_1)?|BIND_NOW)\)", row)]
    binding = [row for row in dynamic if re.search(r"\b(?:BIND_NOW|NOW)\b", row)]
    type_row = next((row for row in rows if row.lstrip().startswith("Type:")), None)
    pie = [row for row in dynamic if re.search(r"\bPIE\b", row)]
    canary = [row for row in (symbols or "").splitlines() if re.search(r"\b__stack_chk_fail\b", row)]
    return {
        "nx": dict(status=("disabled" if re.search(r"\bR?W?E\b", stack) else "enabled") if stack else "unknown",
                   evidence=[stack.strip()] if stack else []),
        "pie": dict(status="enabled" if pie else
                    "disabled" if type_row and re.search(r"\bEXEC\b", type_row) else "unknown",
                    evidence=[row.strip() for row in ([type_row] if type_row else []) + pie]),
        "relro": dict(status=("full" if binding else "partial") if relro else
                      "none" if any("Program Headers:" in row for row in rows) else "unknown",
                      evidence=[row.strip() for row in ([relro] if relro else []) + binding]),
        "stack_canary": dict(status="present" if canary else "not_observed" if symbols is not None else "unknown",
                             evidence=[row.strip() for row in canary]),
    }


def hardening_warnings(base: dict, candidate: dict) -> list[dict]:
    """Flag observed decreases in Release ELF protections."""
    levels = {"nx": ("disabled", "enabled"), "pie": ("disabled", "enabled"),
              "relro": ("none", "partial", "full"), "stack_canary": ("not_observed", "present")}
    warnings = []
    for name, order in levels.items():
        before, after = base[name]["status"], candidate[name]["status"]
        if before in order and after in order and order.index(before) > order.index(after):
            warnings.append(dict(protection=name, before=base[name], after=candidate[name]))
    return warnings


def metadata_sufficient(records: dict) -> bool:
    """Require interpretable Release hardening data, not just four rows."""
    if len(records) != 4:
        return False
    known = {
        "nx": {"enabled", "disabled"},
        "pie": {"enabled", "disabled"},
        "relro": {"none", "partial", "full"},
        "stack_canary": {"present", "not_observed"},
    }
    for role in ("base", "candidate"):
        record = records.get(f"{role}-release", {})
        if any(record.get("tools", {}).get(name, {}).get("status") != "available"
               for name in ("readelf", "symbols")):
            return False
        hardening_data = record.get("hardening", {})
        if any(hardening_data.get(name, {}).get("status") not in states
               for name, states in known.items()):
            return False
    return True
