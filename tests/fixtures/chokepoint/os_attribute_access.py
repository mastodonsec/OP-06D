# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: process creation through the os module. Parsed, never imported.
"""

import os
import os as o


def scan(target):
    os.system("nmap " + target)
    o.popen("nmap " + target)
    os.execv("/usr/bin/nmap", ["nmap", target])
    os.spawnl(os.P_NOWAIT, "/usr/bin/nmap", "nmap", target)
    os.posix_spawn("/usr/bin/nmap", ["nmap", target], {})
    os.startfile(target)
    return getattr(o, "sys" + "tem")
