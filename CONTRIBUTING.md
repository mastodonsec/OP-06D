# Contributing to OP-06D

Thanks for your interest in OP-06D. A few things keep the project legally clean
and open.

## License

OP-06D is licensed under the **GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later)**. By contributing, you agree that your contributions are
licensed under the same terms.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a separate contributor agreement. It is a lightweight statement that
you wrote the contribution, or otherwise have the right to submit it under the
project's license.

**Every commit must be signed off.** Add a `Signed-off-by` line to your commit
message with your real name and email:

```
Signed-off-by: Your Name <you@example.com>
```

Git does this for you with the `-s` flag:

```
git commit -s -m "Add a short imperative subject"
```

The full DCO text is reproduced in `DCO.txt`. A sign-off certifies that you agree
to it for that contribution.

## Source file headers

Add this header to the top of every new source file (adjust the comment syntax to
the language):

```python
# OP-06D — AI-driven security validation
# Copyright (c) 2026 Thomas Pavan / Mastodon Security
# SPDX-License-Identifier: AGPL-3.0-or-later
```

The `SPDX-License-Identifier` line is machine-readable and is the preferred way to
mark each file; the full license lives once in `LICENSE`.

## Before you run anything

OP-06D is an offensive-security tool. Read `NOTICE` — only run it against
systems you own or are explicitly authorized to test.
