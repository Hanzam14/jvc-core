# Quickstart Guide

This guide walks you through setting up JVC, registering a project, running routing, executing declared checks, and performing governed writes.

---

## 1. Installation

Install JVC in your active Python virtual environment (Python 3.10+):

```bash
pip install .
```

Verify installation:

```bash
jvc --version
```

---

## 2. Define a Project Registry

Create a `PROJECT_ROUTES.md` file (or use an existing Markdown table):

```markdown
# Project Routes Registry

| Project ID | Aliases and keywords | Absolute project path | Required startup | Handoff/current state | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `demo-app` | `demo-app`, `app` | `/srv/demo-app` (example absolute path) | `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` | Active | `active` |
```

Validate the registry structure:

```bash
jvc validate-routes --registry PROJECT_ROUTES.md
```

---

## 3. Query the Route Engine

Resolve natural-language project requests against the registry:

```bash
jvc route "please update authentication on the app" --registry PROJECT_ROUTES.md
```

Output:
```
ROUTED: please update authentication on the app
project_id: demo-app
root: /srv/demo-app
privacy_status: active
startup:
  1. /srv/demo-app/AGENTS.md
  2. /srv/demo-app/CONTEXT.md
  3. /srv/demo-app/HANDOFF.md
runtime: python
preflight: {'argv': ['{runtime}', 'test.py'], 'timeout_seconds': 30, 'expected_exit': 0, 'expected_contains': 'PASS'}
write_policy: governed writes only
Read the returned root trio in order, then follow HANDOFF.md to the current stage. Load no unrelated context.
```

---

## 4. Run the Synthetic Demo

Test all 15 core operations (routing, checks, CAS writes, rollback, Git staging, and continuity) end-to-end:

```bash
jvc demo
```
