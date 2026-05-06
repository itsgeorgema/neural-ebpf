#!/usr/bin/env python3
"""
CPU Leak Simulator — spins multiple threads at 100% CPU.
Detectable by the Neural eBPF daemon as a cpu_anomaly event.

Usage: python cpu_leak.py [--duration 30] [--threads 4]
"""
import argparse
import os
import signal
import sys
import threading
import time


def spin(stop_event: threading.Event):
    while not stop_event.is_set():
        _ = sum(i * i for i in range(10_000))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30, help="Seconds to run")
    parser.add_argument("--threads", type=int, default=2, help="Number of CPU-spinning threads")
    args = parser.parse_args()

    print(f"[cpu_leak] PID={os.getpid()} | threads={args.threads} | duration={args.duration}s", flush=True)

    stop = threading.Event()
    workers = [threading.Thread(target=spin, args=(stop,), daemon=True) for _ in range(args.threads)]
    for w in workers:
        w.start()

    def handle_stop(sig, frame):
        print(f"\n[cpu_leak] PID={os.getpid()} received signal {sig}, stopping.")
        stop.set()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    deadline = time.time() + args.duration
    while time.time() < deadline:
        remaining = int(deadline - time.time())
        print(f"\r[cpu_leak] running... {remaining}s remaining", end="", flush=True)
        time.sleep(1)

    stop.set()
    print(f"\n[cpu_leak] PID={os.getpid()} finished naturally after {args.duration}s.")


if __name__ == "__main__":
    main()
