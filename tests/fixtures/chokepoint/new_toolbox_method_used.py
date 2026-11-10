# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: toolbox attributes outside the allowlist used from another module. Parsed, never imported.
"""

from op06d.tools import GatedToolbox


class Loop:
    def __init__(self, toolbox: GatedToolbox):
        self._toolbox = toolbox

    def step(self, action):
        self._toolbox.execute(action, iteration=1)
        return self._toolbox.run_tool(action)


def wire(engagement, gate, log, toolset, action):
    box = GatedToolbox(engagement, gate, log, toolset)
    alias = box
    alias.tools["nmap"].run(action.target, {})
    getattr(box, "_GatedToolbox__tools")
    return box._GatedToolbox__tools
