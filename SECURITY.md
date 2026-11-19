# Security policy

This is how to report a vulnerability in OP-06D itself, privately.

## What to report

Weaknesses in OP-06D, for example:

- a way past the guardrail gate or the scope check;
- an action outside the engagement's scope, rate or window;
- secrets leaking into the audit log, the evidence store or reports;
- tool output (prompt injection) changing what OP-06D does;
- escaping the isolated lab;
- supply-chain problems in how OP-06D is built.

## What not to report here

- Findings about systems you scanned with OP-06D. Those belong to the systems'
  owners.
- Usage questions.

## How to report

Use GitHub's private vulnerability reporting: **Report a vulnerability** on the
repository's **Security** tab. If that isn't available, email
thomas@mastodonsec.com.

Don't open a public issue or pull request for a vulnerability.

## What to include

- The affected version or commit.
- Steps to reproduce.
- The impact.
- Any engagement file or output needed to reproduce it, with secrets removed.

## Response

Reports are handled on a best-effort basis by the maintainer. There are no fixed
response times and no bug bounty. Please allow time for a fix before disclosing
publicly.

## Supported versions

The latest code on `main` and the latest release.
