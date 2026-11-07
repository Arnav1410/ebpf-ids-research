"""Bounded, shell-free commands and evidence for the isolated network lab."""
import datetime
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time


MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_CHILD_SECONDS = 300


def _timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _seconds(value):
    value = float(value)
    if not math.isfinite(value) or not 0 < value <= MAX_CHILD_SECONDS:
        raise ValueError(f"Deadline must be greater than zero and at most {MAX_CHILD_SECONDS}s")
    return value


class Recorder:
    """Own subprocesses, retain bounded logs, and refuse output-directory reuse."""

    def __init__(self, out):
        self.out = Path(out).absolute()
        self._owner = None
        if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            self._owner = (int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        self._created_parents = []
        parent = self.out.parent
        while not parent.exists():
            self._created_parents.append(parent)
            parent = parent.parent
        self.out.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.records = []
        self._children = {}
        self._lock = threading.RLock()
        self._closed = False
        self._save()

    def write_json(self, filename, value):
        path = self.out / filename
        if path.parent != self.out or path.name in ("", ".", ".."):
            raise ValueError("Evidence filenames must be direct children of the output directory")
        temporary = path.with_name(path.name + ".tmp")
        with self._lock:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
            temporary.replace(path)
            if self._owner is not None:
                os.chown(path, *self._owner, follow_symlinks=False)

    def _save(self):
        self.write_json("commands.json", self.records)

    def _start(self, label, argv, timeout):
        if self._closed:
            raise RuntimeError("Recorder is closed")
        timeout = _seconds(timeout)
        if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise ValueError("Commands require a nonempty list of string arguments")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
            raise ValueError("Child labels must contain only letters, digits, underscores or hyphens")
        with self._lock:
            index = len(self.records) + 1
            stem = f"{index:04d}-{label}"
            stdout_path = self.out / (stem + ".stdout.log")
            stderr_path = self.out / (stem + ".stderr.log")
            record = {"index": index, "label": label, "argv": list(argv),
                      "started_at": _timestamp(), "deadline_seconds": timeout,
                      "stdout": stdout_path.name, "stderr": stderr_path.name,
                      "exit_code": None}
            self.records.append(record)
            self._save()
        output = stdout_path.open("xb")
        try:
            errors = stderr_path.open("xb")
        except BaseException:
            output.close()
            raise
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True)
        except BaseException as exc:
            output.close()
            errors.close()
            record.update(ended_at=_timestamp(), start_error=str(exc))
            self._save()
            raise
        record["pid"] = proc.pid
        proc.stdout_path = stdout_path
        proc.stderr_path = stderr_path
        done = threading.Event()
        child = {"proc": proc, "record": record, "threads": [], "done": done,
                 "started": time.monotonic()}
        self._children[proc.pid] = child

        def pump(source, destination, channel):
            written = 0
            try:
                while True:
                    chunk = source.read1(65536)
                    if not chunk:
                        break
                    remaining = MAX_LOG_BYTES - written
                    if remaining > 0:
                        kept = chunk[:remaining]
                        destination.write(kept)
                        destination.flush()
                        written += len(kept)
                    if len(chunk) > remaining:
                        with self._lock:
                            record["limit_error"] = f"{channel} exceeded {MAX_LOG_BYTES} bytes"
                        if proc.poll() is None:
                            proc.kill()
            except (OSError, ValueError) as exc:
                with self._lock:
                    record["capture_error"] = str(exc)
                if proc.poll() is None:
                    proc.kill()
            finally:
                source.close()
                destination.close()

        for source, destination, channel in ((proc.stdout, output, "stdout"),
                                              (proc.stderr, errors, "stderr")):
            thread = threading.Thread(target=pump, args=(source, destination, channel), daemon=True)
            child["threads"].append(thread)
            thread.start()

        def deadline():
            if not done.wait(timeout) and proc.poll() is None:
                with self._lock:
                    record["timed_out"] = True
                proc.kill()

        threading.Thread(target=deadline, daemon=True).start()
        self._save()
        return proc

    def spawn(self, label, argv):
        return self._start(label, argv, MAX_CHILD_SECONDS)

    def _finish(self, proc):
        child = self._children.get(proc.pid)
        if child is None or child["proc"] is not proc:
            raise ValueError("Process is not owned by this recorder")
        record = child["record"]
        if "ended_at" in record:
            return record
        if proc.poll() is None:
            raise RuntimeError("Cannot finalize a running child")
        child["done"].set()
        for thread in child["threads"]:
            thread.join(timeout=5)
            if thread.is_alive():
                record["capture_error"] = "Output pipe remained open after owned process exit"
        record.update(exit_code=proc.returncode, ended_at=_timestamp(),
                      duration_seconds=time.monotonic() - child["started"])
        self._save()
        return record

    def run(self, argv, timeout=30, check=True):
        timeout = _seconds(timeout)
        proc = self._start("command", argv, timeout)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            child = self._children[proc.pid]
            child["record"]["timed_out"] = True
            self.stop(proc, signal.SIGKILL)
        record = self._finish(proc)
        stdout = proc.stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = proc.stderr_path.read_text(encoding="utf-8", errors="replace")
        result = subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
        if record.get("timed_out"):
            raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr)
        if record.get("limit_error") or record.get("capture_error"):
            raise RuntimeError(record.get("limit_error") or record["capture_error"])
        if check:
            result.check_returncode()
        return result

    def json(self, argv, timeout=30):
        return json.loads(self.run(argv, timeout=timeout).stdout)

    def stop(self, proc, sig=signal.SIGTERM, timeout=5):
        timeout = _seconds(timeout)
        child = self._children.get(proc.pid)
        if child is None or child["proc"] is not proc:
            raise ValueError("Refusing to signal a process not spawned by this recorder")
        if proc.poll() is None:
            proc.send_signal(sig)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                child["record"]["required_sigkill"] = True
                proc.kill()
                proc.wait(timeout=5)
        self._finish(proc)
        return proc.returncode

    def stop_children(self):
        errors = []
        for child in reversed(list(self._children.values())):
            try:
                self.stop(child["proc"])
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError("Child cleanup failed: " + "; ".join(errors))

    def _return_output_ownership(self):
        if self._owner is not None:
            for path in self.out.iterdir():
                os.chown(path, *self._owner, follow_symlinks=False)
            os.chown(self.out, *self._owner, follow_symlinks=False)
            for parent in self._created_parents:
                os.chown(parent, *self._owner, follow_symlinks=False)

    def close(self):
        if self._closed:
            return
        try:
            self.stop_children()
        finally:
            self._save()
            self._return_output_ownership()
            self._closed = True
