# SPDX-License-Identifier: AGPL-3.0-or-later
"""Gate chokepoint test fixture: GatedToolbox.execute() must be the only path to the tools.

Negative fixture for tests/test_gate_chokepoint.py: from os import system. Parsed, never imported.
"""

from os import system


def scan(target):
    return system("nmap " + target)
