"""
The timeout of a Unicorn start.

Unicorn 2.1.4 on arm64 hosts can lose a stop that another thread sends while emulation
runs, so a start with Unicorn's own timeout, which sends one stop, can run forever
(https://github.com/unicorn-engine/unicorn/issues/2458). Speakeasy starts Unicorn without
a timeout and stops it from this timer instead, which repeats the stop until the start
returns. The timer measures time with time.monotonic(), as the run loop does, so a start
that it stops has reached the deadline of the run loop.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

STOP_REPEAT = 0.001
IDLE_EXIT = 5.0


class StartTimer:
    """
    Calls a stop function from a thread when the timeout of a start passes, and again every
    STOP_REPEAT seconds until the start disarms the timer. The thread exits when the timer
    is not armed for IDLE_EXIT seconds, and the next arm starts it again.
    """

    def __init__(self, stop):
        self.stop: Callable[[], object] = stop
        self._deadline: float | None = None
        self._thread: threading.Thread | None = None
        self._cond: threading.Condition = threading.Condition()

    def arm(self, timeout):
        with self._cond:
            self._deadline = time.monotonic() + timeout
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="speakeasy-start-timer", daemon=True)
                self._thread.start()
            else:
                self._cond.notify()

    def disarm(self):
        with self._cond:
            self._deadline = None

    def _run(self):
        with self._cond:
            while True:
                if self._deadline is None:
                    if not self._cond.wait(IDLE_EXIT) and self._deadline is None:
                        self._thread = None
                        return
                    continue
                remaining = self._deadline - time.monotonic()
                if remaining > 0:
                    self._cond.wait(remaining)
                    continue
                self.stop()
                self._cond.wait(STOP_REPEAT)
