---
name: Bug report
about: Report a problem with waxseal
title: "[Bug]: "
labels: bug
assignees: ""
---

**What happened**

A clear description of the incorrect behavior. Include the command you ran and
the output you saw. If verification accepted or rejected a seal incorrectly,
say so explicitly and include the seal and archive if you can share them.

**Expected behavior**

What you expected waxseal to do instead.

**Reproduction**

Minimal steps. Include the exact commands and a fixture archive or `seal.json`
where possible.

```bash
waxseal verify capture.wacz -s capture.seal.json
```

**File / format and version**

- Archive type: WACZ (state the WACZ version if known)
- waxseal version or revision:
- Seal / proof involved (yes or no):
- Key type, if relevant (Ed25519):

**Environment**

- OS:
- Bun version (`bun --version`):
- Install method (from source, package manager):
