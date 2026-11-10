# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: a second toolbox method that invokes a tool. Parsed, never imported.
"""


class GatedToolbox:
    def __init__(self, gate, tools):
        self.__tools = {t.name: t for t in tools}
        self.__gate = gate

    def describe(self):
        return [{"name": t.name} for t in self.__tools.values()]

    def redact(self, action):
        return dict(action.parameters)

    def execute(self, action, *, iteration):
        return self.__execute(action, iteration)

    def __execute(self, action, iteration):
        if not self.__gate.check(action.target).allowed:
            return None
        return self.__tools[action.tool].run(action.target, dict(action.parameters))

    def run_unchecked(self, name, target):
        return self.__tools[name].run(target, {})
