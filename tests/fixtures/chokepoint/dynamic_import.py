# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: dynamic imports and evaluation. Parsed, never imported.
"""

import importlib
import sys
from importlib import import_module


def scan(target):
    sp = importlib.import_module("subprocess")
    other = import_module("os")
    third = __import__("pty")
    fourth = sys.modules["subprocess"]
    exec("import subprocess")
    return eval("subprocess.run")(["nmap", target]), sp, other, third, fourth
