# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: aliased subprocess imports. Parsed, never imported.
"""

import subprocess as sp
from subprocess import Popen as P


def scan(target):
    sp.run(["nmap", target], check=False)
    return P(["nuclei", "-u", target])
