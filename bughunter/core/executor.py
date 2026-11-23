"""Bounded subprocess execution with process-group cleanup."""
import os
import signal
import subprocess


def run_command(argv, timeout=60):
    if not argv or isinstance(argv, (str, bytes)):
        raise ValueError('argv must be a nonempty argument list')
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    result.check_returncode()
    return result
