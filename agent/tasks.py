"""
agent/tasks.py — Background task infrastructure for the noc-agent.

Usage:
    from .tasks import start_background_task

    def my_work():
        ...

    start_background_task(my_work, interval_secs=300, name='my-task')

Each task:
  - Runs immediately on start (unless run_immediately=False).
  - Sleeps interval_secs, then repeats forever.
  - Is a daemon thread — exits automatically when the main process exits.
  - Catches and prints all exceptions so one failure never kills the loop.

To add a new periodic task, define a zero-arg callable and call
start_background_task() from loop.run() after config is loaded.
"""

import threading
import time
import traceback


def start_background_task(
    fn,
    interval_secs: int,
    name: str = '',
    run_immediately: bool = True,
) -> threading.Thread:
    """
    Start fn() in a daemon background thread.

    fn() is called once immediately (if run_immediately=True), then every
    interval_secs seconds until the process exits.

    Returns the Thread object (usually not needed — tasks are fire-and-forget).
    """
    task_name = name or getattr(fn, '__name__', 'background-task')

    def _loop():
        if run_immediately:
            _safe_call(fn, task_name)
        while True:
            time.sleep(interval_secs)
            _safe_call(fn, task_name)

    thread = threading.Thread(target=_loop, name=task_name, daemon=True)
    thread.start()
    print(f'[tasks] started "{task_name}" — interval {interval_secs}s')
    return thread


def _safe_call(fn, name: str) -> None:
    """Call fn(), printing (but not re-raising) any exception."""
    try:
        fn()
    except Exception:
        print(f'[tasks] exception in "{name}":')
        traceback.print_exc()
