#!/usr/bin/env python3
"""
FD Leak Simulator — opens temp files in a tight loop without closing them,
and also opens/closes files rapidly to trigger the fd_monitor eBPF program.

Detectable by the Neural eBPF daemon as a fd_anomaly event.

Usage: python fd_leak.py [--duration 30] [--rate 200]
"""
import argparse
import os
import signal
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30, help="Seconds to run")
    parser.add_argument("--rate", type=int, default=200, help="File opens per second")
    args = parser.parse_args()

    print(f"[fd_leak] PID={os.getpid()} | rate={args.rate}/sec | duration={args.duration}s", flush=True)

    leaked_fds = []
    running = True

    def handle_stop(sig, frame):
        nonlocal running
        print(f"\n[fd_leak] PID={os.getpid()} received signal {sig}, cleaning up.")
        for fd in leaked_fds:
            try:
                os.close(fd)
            except Exception:
                pass
        running = False
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    tmpdir = tempfile.mkdtemp(prefix="fd_leak_")
    interval = 1.0 / args.rate
    deadline = time.time() + args.duration
    count = 0

    while time.time() < deadline and running:
        try:
            # Accumulate leaked FDs (never closed until we hit OS limit)
            path = os.path.join(tmpdir, f"leak_{count % 1000}.tmp")
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
            leaked_fds.append(fd)
            count += 1

            if count % 100 == 0:
                remaining = int(deadline - time.time())
                print(f"\r[fd_leak] {count} FDs open, {remaining}s remaining", end="", flush=True)

            time.sleep(interval)
        except OSError as e:
            print(f"\n[fd_leak] OSError (FD limit hit?): {e}")
            time.sleep(1)

    # Cleanup
    for fd in leaked_fds:
        try:
            os.close(fd)
        except Exception:
            pass
    try:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass

    print(f"\n[fd_leak] PID={os.getpid()} finished. Opened {count} FDs total.")


if __name__ == "__main__":
    main()
