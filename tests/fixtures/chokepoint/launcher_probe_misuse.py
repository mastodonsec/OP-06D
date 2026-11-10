# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: an availability-probe import that is then used. Parsed, never imported.
"""


def render_pdf(report, out_path):
    try:
        import playwright
    except ImportError:
        return None
    return playwright.sync_api.sync_playwright()
