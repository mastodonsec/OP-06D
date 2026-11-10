# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: tools run directly, bypassing GatedToolbox.execute. Parsed, never imported.
"""

from op06d.nmap_tool import NmapTool
from op06d.tools import default_tools, run_subprocess


def helper(tool):
    return tool


def quick_scan(engagement, target):
    tools = default_tools(engagement)
    first = tools[0]
    first.run(target, {})
    for tool in tools:
        tool.run(target, {})
    helper(first)
    run_subprocess(["nmap", target], 30.0)
    return NmapTool(10).run(target, {})
