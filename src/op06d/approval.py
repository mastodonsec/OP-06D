# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-8: the operator approval prompt.

``ConsoleApprover`` implements ``op06d.tools.ApprovalHook`` for an
interactive terminal session. It is used ONLY when a run is actually
interactive - the approver-selection logic in ``op06d.cli`` falls back to
``DenyAllApprover`` for every unattended, piped, or ``--non-interactive``
run, so an intrusive action can never auto-approve itself just because no
one happened to be watching.

**Cross-platform timeout.** ``select()`` on stdin does not work on Windows,
so this reads the operator's line on a daemon thread and waits for it with
``Thread.join(timeout)`` instead of trying to poll the file descriptor.
Timing out leaves that reader thread to die on its own (it is a daemon, so
it never blocks interpreter exit); the action is declined either way.

**Default-deny.** Only an explicit "y"/"yes" (case-insensitive) approves.
Anything else - "n", an empty line, EOF, a timeout, or any exception raised
while prompting - denies.
"""

from __future__ import annotations

import queue
import threading
from typing import Callable

from op06d.tools import ApprovalHook, ApprovalRequest

_YES = {"y", "yes"}


class ConsoleApprover(ApprovalHook):
    def __init__(
        self,
        *,
        timeout: float = 120.0,
        input_fn: Callable[[], str] = input,
        print_fn: Callable[[str], None] = print,
    ) -> None:
        self._timeout = float(timeout)
        self._input = input_fn
        self._print = print_fn

    def approve(self, request: ApprovalRequest) -> bool:
        try:
            self._print(self._render(request))
            answer = self._read_with_timeout()
        except Exception:
            return False
        return isinstance(answer, str) and answer.strip().lower() in _YES

    def _render(self, request: ApprovalRequest) -> str:
        # request.parameters is already redacted by GatedToolbox before this
        # is ever called - never a raw secret reaches this prompt.
        return (
            "\n--- OP-06D: operator approval required ---\n"
            f"iteration : {request.iteration}\n"
            f"tool      : {request.tool}\n"
            f"target    : {request.target}\n"
            f"parameters: {request.parameters}\n"
            f"risk      : {request.risk.name}\n"
            f"reason    : {request.reason}\n"
            f"Approve? [y/N] (times out after {self._timeout:.0f}s and denies): "
        )

    def _read_with_timeout(self) -> str | None:
        result: "queue.Queue[str | None]" = queue.Queue(maxsize=1)

        def reader() -> None:
            try:
                line = self._input()
            except Exception:
                line = None
            try:
                result.put_nowait(line)
            except queue.Full:
                pass

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        thread.join(self._timeout)
        if thread.is_alive():
            return None  # timed out: deny; the daemon reader thread is abandoned
        try:
            return result.get_nowait()
        except queue.Empty:
            return None
