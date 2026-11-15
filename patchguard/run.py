"""Execute a local process and retain bounded raw evidence."""

import os
import resource
import selectors
import signal
import subprocess
from hashlib import sha256
from pathlib import Path
from time import monotonic

from .config import ROOT, workspace_path

ENV = {"LANG": "C", "LC_ALL": "C", "PYTHONHASHSEED": "0", "PATH": "/usr/local/bin:/usr/bin:/bin",
       "HOME": "/tmp"}
LIMITS = {"core_bytes": 0, "cpu_seconds": 30, "file_bytes": 64 * 1024 * 1024}


def _limits() -> None:
    for key, kind in (("core_bytes", resource.RLIMIT_CORE), ("cpu_seconds", resource.RLIMIT_CPU),
                      ("file_bytes", resource.RLIMIT_FSIZE)):
        value = LIMITS[key]
        resource.setrlimit(kind, (value, value))


def _stop_group(pid: int, signum: int) -> None:
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def execute(argv: list[str], directory: Path, *, data: bytes = b"", timeout: float = 30,
            limit: int = 8192, env: dict | None = None, cwd: Path = ROOT) -> dict:
    """Run argv and concurrently drain both streams under a wall-clock deadline."""
    directory = workspace_path(directory, "process evidence", within=ROOT / "artifacts")
    directory.mkdir(parents=True, exist_ok=True)
    effective_env = ENV | (env or {})
    started = monotonic()
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    counts = dict.fromkeys(captures, 0)
    state, error, code = "normal", None, None
    try:
        with subprocess.Popen(argv, cwd=cwd, env=effective_env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True, preexec_fn=_limits) as child:
            deadline = started + timeout
            try:
                with selectors.DefaultSelector() as ready:
                    for name in captures:
                        stream = getattr(child, name)
                        os.set_blocking(stream.fileno(), False)
                        ready.register(stream, selectors.EVENT_READ, name)
                    pending = memoryview(data)
                    if pending:
                        os.set_blocking(child.stdin.fileno(), False)
                        ready.register(child.stdin, selectors.EVENT_WRITE, "stdin")
                    else:
                        child.stdin.close()
                    while ready.get_map():
                        remaining = deadline - monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(argv, timeout)
                        for key, _ in ready.select(remaining):
                            stream, name = key.fileobj, key.data
                            if name == "stdin":
                                try:
                                    pending = pending[os.write(stream.fileno(), pending):]
                                except BrokenPipeError:
                                    pending = pending[len(pending):]
                                if not pending:
                                    ready.unregister(stream)
                                    stream.close()
                                continue
                            chunk = os.read(stream.fileno(), 65536)
                            if not chunk:
                                ready.unregister(stream)
                                continue
                            counts[name] += len(chunk)
                            captures[name].extend(chunk[:limit - len(captures[name])])
                code = child.wait(timeout=max(0, deadline - monotonic()))
                if code < 0:
                    state = "resource_limit" if -code in (signal.SIGXCPU, signal.SIGXFSZ) else "signal"
            except subprocess.TimeoutExpired:
                state = "timeout"
            finally:
                if state == "timeout" or child.poll() is None:
                    _stop_group(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                    _stop_group(child.pid, signal.SIGKILL)
                    code = child.wait()
                if state == "timeout":
                    for name in captures:
                        stream = getattr(child, name)
                        while True:
                            try:
                                chunk = os.read(stream.fileno(), 65536)
                            except BlockingIOError:
                                break
                            if not chunk:
                                break
                            counts[name] += len(chunk)
                            captures[name].extend(chunk[:limit - len(captures[name])])
    except (OSError, subprocess.SubprocessError) as exc:
        state, error = "runner_error", str(exc)
    output = {}
    for name, captured in captures.items():
        path = workspace_path(directory / f"{name}.bin", name, within=directory)
        path.write_bytes(captured)
        output[name] = dict(path=path.relative_to(ROOT).as_posix(), bytes=counts[name],
                            truncated=counts[name] > len(captured), sha256=sha256(captured).hexdigest())
    terminating_signal = signal.Signals(-code).name if code is not None and code < 0 else None
    return dict(signal=terminating_signal, argv=argv, cwd=str(cwd), env=effective_env, limits=LIMITS, timeout_seconds=timeout,
                duration_seconds=monotonic() - started, returncode=code, state=state,
                timed_out=state == "timeout", error=error, **output)


def run_case(build: dict, case: dict, settings: dict, directory: Path) -> dict:
    """Deliver case bytes and record hashes and build context."""
    binary = ROOT / build["path"]
    data = case["input"]
    argv = [str(binary)]
    digest = sha256(data).hexdigest()
    method = settings["method"]
    staged = None
    if method == "file":
        staged = workspace_path(directory / "staged" / "input.bin", "staged input", within=directory)
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(data)
    for arg in settings.get("args", []):
        if method == "file":
            argv.append(arg.replace("{input_file}", str(staged)))
        elif method == "argv":
            # Preserve non-NUL bytes via the filesystem encoding/surrogateescape.
            argv.append(arg.replace("{input_arg}", os.fsdecode(data)))
        else:
            argv.append(arg)
    result = execute(argv, directory, data=data if method == "stdin" else b"",
                     timeout=settings["timeout_seconds"], limit=settings["output_limit_bytes"],
                     env=settings["env"])
    return result | dict(case_id=case["id"], input_sha256=digest, binary_sha256=build["sha256"],
                         flags=build["flags"], delivery=method,
                         staged=staged.relative_to(ROOT).as_posix() if staged else None)
