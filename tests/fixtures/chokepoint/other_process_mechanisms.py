# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: pty, multiprocessing, asyncio and executor process creation. Parsed, never imported.
"""

import asyncio
import asyncio.subprocess
import multiprocessing
import pty
from asyncio import create_subprocess_shell
from concurrent import futures
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Process


async def scan(target, loop):
    await asyncio.create_subprocess_exec("nmap", target)
    await create_subprocess_shell("nmap " + target)
    await loop.subprocess_exec(None, "nmap", target)
    pty.spawn(["nmap", target])
    multiprocessing.Process(target=print).start()
    Process(target=print).start()
    futures.ProcessPoolExecutor()
    return ProcessPoolExecutor()
