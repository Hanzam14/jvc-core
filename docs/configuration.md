# Configuration Reference

JVC uses configuration-driven routing, governance policies, and execution contracts.

---

## 1. Project Registry (`PROJECT_ROUTES.md`)

The project registry is maintained as a Markdown table with 6 required columns:

| Column | Description | Format |
| --- | --- | --- |
| **Project ID** | Unique lowercase alphanumeric identifier | `` `project-id` `` |
| **Aliases and keywords** | Comma-separated list of recognized aliases | `app, web, frontend` |
| **Absolute project path** | Root directory of the repository | `` `{project_root}` `` or relative |
| **Required startup** | Onboarding files read in strict sequence | `` `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` `` |
| **Handoff/current state** | Brief status summary or link | Text |
| **Status** | Lifecycle / capability classification | `active`, `held`, `complete`, `superseded` |

---

## 2. Execution Contract (`AGENTS.md`)

Each registered project defines its execution parameters inside `AGENTS.md`:

```markdown
<!-- ICM_EXECUTION_START -->
```json
{
  "schema_version": 1,
  "project_id": "my-service",
  "cwd": "{project_root}",
  "persistence": "git",
  "privacy": "standard",
  "permission_class": "read-test",
  "runtime": {
    "kind": "python",
    "candidates": [["python"]],
    "probe_argv": ["--version"]
  },
  "preflight": {
    "argv": ["{runtime}", "-m", "pytest", "tests/unit"],
    "timeout_seconds": 60,
    "expected_exit": 0,
    "expected_contains": "passed"
  },
  "verify": {
    "argv": ["{runtime}", "-m", "pytest", "tests/"],
    "timeout_seconds": 120,
    "expected_exit": 0,
    "expected_contains": "passed"
  },
  "write_policy": "governed writes only"
}
```
<!-- ICM_EXECUTION_END -->
```

---

## 3. Governance Policy (`governance-policy.json`)

Controls mutation invariants and secret classification:

```json
{
  "schema_version": 1,
  "policy_id": "jvc-governed-execution-v1",
  "fail_closed": true,
  "model_facing": {
    "raw_shell": false,
    "generic_command": false,
    "operator_authorization": false
  },
  "mutation": {
    "registered_routes_only": true,
    "canonical_containment_required": true,
    "mandatory_secret_deny": true,
    "cas_required_for_overwrite": true,
    "git_stage_exact_files_only": true
  },
  "secret_classes": [
    ".env", ".env.*", "credential.*", "credentials.*",
    "secret.*", "secrets.*", "token.*", "tokens.*",
    "auth.*", "*.pem", "*.key", "*.ppk", "*.p12", "*.pfx"
  ],
  "protected_surfaces": [
    ".git", ".continuity", "_config", "contracts", "_promotions", ".gitattributes"
  ]
}
```
