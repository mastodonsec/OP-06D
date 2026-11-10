# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Negative fixture for tests/test_gate_chokepoint.py: third-party process launchers. Parsed, never imported.
"""

import docker
import pexpect
import sh
from plumbum import local
from selenium import webdriver


def render(html):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        return p.chromium.launch(), docker, pexpect, sh, local, webdriver
