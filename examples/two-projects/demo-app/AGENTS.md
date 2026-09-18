# Demo App Operating Guide

<!-- ICM_EXECUTION_START -->
```json
{
  "schema_version": 1,
  "project_id": "demo-app",
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
    "argv": ["{runtime}", "-c", "print('PASS: demo preflight ready')"],
    "timeout_seconds": 30,
    "expected_exit": 0,
    "expected_contains": "PASS: demo preflight ready"
  },
  "verify": null,
  "write_policy": "governed writes only"
}
```
<!-- ICM_EXECUTION_END -->

## Project Boundaries
Follow standard project conventions.
