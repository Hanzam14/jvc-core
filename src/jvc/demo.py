"""Synthetic disposable demo for JVC core features.

Exercises all 15 core lifecycle invariants against temporary fictional fixtures:
1. create/load project registry
2. route demo-app
3. route demo-library
4. reject unknown route
5. reject intentionally ambiguous route
6. run declared preflight
7. attempt a protected write and reject it
8. perform an authorized governed write
9. retry with stale preimage and reject it
10. rollback
11. stage the exact owned file
12. commit the exact owned file
13. initialize continuity
14. mutate revision
15. reject stale continuity revision
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from jvc.configuration import ProjectRegistry, Route
from jvc.continuity.state import ConflictError, ContinuityManager
from jvc.contracts import run_check
from jvc.execution.executor import GovernedExecutor
from jvc.policy.authority import sha256_bytes, sha256_file
from jvc.recovery.store import RecoveryStore
from jvc.routing import resolve_query


def setup_demo_fixtures(base_dir: Path) -> tuple[Path, Path, ProjectRegistry]:
    """Create disposable demo-app and demo-library projects."""
    app_dir = base_dir / "demo-app"
    lib_dir = base_dir / "demo-library"
    app_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.mkdir(parents=True, exist_ok=True)

    # Initialize Git repos
    for d in (app_dir, lib_dir):
        subprocess.run(["git", "init"], cwd=str(d), check=True, capture_output=True)
        # Pin line-ending conversion: JVC's sanitized environment ignores
        # ambient system autocrlf, so demo repos must not depend on it.
        subprocess.run(
            ["git", "config", "core.autocrlf", "false"],
            cwd=str(d),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Demo User"],
            cwd=str(d),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "demo@example.invalid"],
            cwd=str(d),
            check=True,
            capture_output=True,
        )

    # demo-app files
    app_contract = {
        "schema_version": 1,
        "project_id": "demo-app",
        "cwd": str(app_dir.resolve()),
        "persistence": "git",
        "privacy": "standard",
        "permission_class": "read-test",
        "runtime": {
            "kind": "python",
            "candidates": [[sys.executable]],
            "probe_argv": ["-c", "print('ready')"],
        },
        "preflight": {
            "argv": ["{runtime}", "-c", "print('PASS: demo preflight ready')"],
            "timeout_seconds": 10,
            "expected_exit": 0,
            "expected_contains": "PASS: demo preflight ready",
        },
        "verify": None,
        "write_policy": "governed writes only",
    }
    app_agents_content = (
        "# Demo App Agents\n\n"
        "<!-- ICM_EXECUTION_START -->\n```json\n"
        + json.dumps(app_contract, indent=2)
        + "\n```\n<!-- ICM_EXECUTION_END -->\n"
    )
    (app_dir / "AGENTS.md").write_text(app_agents_content, encoding="utf-8")
    (app_dir / "CONTEXT.md").write_text("# Demo App Context\n", encoding="utf-8")
    (app_dir / "HANDOFF.md").write_text("# Demo App Handoff\n\nInitial state.\n", encoding="utf-8")
    (app_dir / "app.py").write_text("print('hello demo')\n", encoding="utf-8")

    # demo-library files
    lib_contract = {
        "schema_version": 1,
        "project_id": "demo-library",
        "cwd": str(lib_dir.resolve()),
        "persistence": "git",
        "privacy": "standard",
        "permission_class": "docs-only",
        "runtime": {"kind": "none", "candidates": [], "probe_argv": []},
        "preflight": None,
        "verify": None,
        "write_policy": "governed writes only",
    }
    lib_agents_content = (
        "# Demo Library Agents\n\n"
        "<!-- ICM_EXECUTION_START -->\n```json\n"
        + json.dumps(lib_contract, indent=2)
        + "\n```\n<!-- ICM_EXECUTION_END -->\n"
    )
    (lib_dir / "AGENTS.md").write_text(lib_agents_content, encoding="utf-8")
    (lib_dir / "CONTEXT.md").write_text("# Demo Library Context\n", encoding="utf-8")
    (lib_dir / "HANDOFF.md").write_text("# Demo Library Handoff\n\nLibrary state.\n", encoding="utf-8")
    (lib_dir / "lib.py").write_text("def helper(): return 42\n", encoding="utf-8")

    routes = [
        Route(
            project_id="demo-app",
            aliases=("demo-app", "app", "application"),
            root=app_dir.resolve(),
            startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
            handoff="HANDOFF.md",
            status="active",
        ),
        Route(
            project_id="demo-library",
            aliases=("demo-library", "lib", "library", "helper"),
            root=lib_dir.resolve(),
            startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
            handoff="HANDOFF.md",
            status="active",
        ),
    ]
    registry = ProjectRegistry(routes)
    return app_dir, lib_dir, registry


def run_demo(base_dir: Path | None = None) -> dict[int, dict[str, Any]]:
    """Run all 15 demo steps sequentially and return step-by-step results."""
    temp_obj = None
    if base_dir is None:
        temp_obj = tempfile.TemporaryDirectory()
        work_dir = Path(temp_obj.name)
    else:
        work_dir = base_dir.resolve()

    results: dict[int, dict[str, Any]] = {}

    try:
        app_dir, lib_dir, registry = setup_demo_fixtures(work_dir)
        recovery_dir = work_dir / "recovery"
        executor = GovernedExecutor(registry=registry, recovery_store=recovery_dir)

        # 1. create/load project registry
        val = registry.validate()
        step1_pass = val["status"] == "PASS" and val["route_count"] == 2
        results[1] = {
            "name": "create/load project registry",
            "status": "PASS" if step1_pass else "FAIL",
            "detail": f"routes={val['route_count']}, aliases={val['alias_count']}",
        }

        # 2. route demo-app
        r2 = resolve_query("work on demo app features", registry.list_routes())
        step2_pass = r2["status"] == "ROUTED" and r2["routes"][0]["project_id"] == "demo-app"
        results[2] = {
            "name": "route demo-app",
            "status": "PASS" if step2_pass else "FAIL",
            "detail": f"status={r2['status']}, routed_to={r2['routes'][0]['project_id'] if r2['routes'] else None}",
        }

        # 3. route demo-library
        r3 = resolve_query("inspect the library helper module", registry.list_routes())
        step3_pass = r3["status"] == "ROUTED" and r3["routes"][0]["project_id"] == "demo-library"
        results[3] = {
            "name": "route demo-library",
            "status": "PASS" if step3_pass else "FAIL",
            "detail": f"status={r3['status']}, routed_to={r3['routes'][0]['project_id'] if r3['routes'] else None}",
        }

        # 4. reject unknown route
        r4 = resolve_query("update payments system", registry.list_routes())
        step4_pass = r4["status"] == "UNKNOWN" and len(r4["routes"]) == 0
        results[4] = {
            "name": "reject unknown route",
            "status": "PASS" if step4_pass else "FAIL",
            "detail": f"status={r4['status']}, routes_count={len(r4['routes'])}",
        }

        # 5. reject intentionally ambiguous route
        # "app and library" has multi marker, but "check app library" has no marker and matches both!
        r5 = resolve_query("check app library", registry.list_routes())
        step5_pass = r5["status"] == "AMBIGUOUS" and len(r5["routes"]) == 2
        results[5] = {
            "name": "reject intentionally ambiguous route",
            "status": "PASS" if step5_pass else "FAIL",
            "detail": f"status={r5['status']}, matches={len(r5['routes'])}",
        }

        # 6. run declared preflight
        from jvc.contracts import load_contract as lc
        contract = lc(app_dir / "AGENTS.md").to_dict()
        runtime = {
            "status": "PASS",
            "kind": "python",
            "argv": [sys.executable],
            "detail": sys.executable,
        }
        chk_res = run_check(contract, "preflight", runtime, app_dir)
        step6_pass = chk_res["status"] == "PASS" and chk_res["returncode"] == 0
        results[6] = {
            "name": "run declared preflight",
            "status": "PASS" if step6_pass else "FAIL",
            "detail": f"status={chk_res['status']}, exit_code={chk_res.get('returncode')}",
        }

        # 7. attempt a protected write and reject it
        step7_pass = False
        try:
            executor.fs_write("demo-app", ".git/hooks/pre-commit", "# malicious hook")
        except PermissionError:
            step7_pass = True
        except Exception:
            step7_pass = False
        results[7] = {
            "name": "attempt a protected write and reject it",
            "status": "PASS" if step7_pass else "FAIL",
            "detail": "control-plane path .git/hooks/pre-commit correctly rejected with PermissionError",
        }

        # 8. perform an authorized governed write
        initial_hash = sha256_file(app_dir / "app.py")
        new_content = "print('hello updated demo')\n"
        w_res = executor.fs_write(
            "demo-app",
            "app.py",
            new_content,
            expected_preimage_sha256=initial_hash,
        )
        step8_pass = (
            w_res["status"] == "PASS"
            and (app_dir / "app.py").read_text(encoding="utf-8") == new_content
        )
        results[8] = {
            "name": "perform an authorized governed write",
            "status": "PASS" if step8_pass else "FAIL",
            "detail": f"write receipt_id={w_res.get('receipt_id')}, postimage={w_res.get('postimage_sha256')}",
        }

        # 9. retry with stale preimage and reject it
        step9_pass = False
        try:
            # Retrying with the old initial_hash should fail CAS
            executor.fs_write(
                "demo-app",
                "app.py",
                "print('stale edit')\n",
                expected_preimage_sha256=initial_hash,
            )
        except ValueError as exc:
            step9_pass = "preimage CAS conflict" in str(exc)
        results[9] = {
            "name": "retry with stale preimage and reject it",
            "status": "PASS" if step9_pass else "FAIL",
            "detail": "stale preimage CAS conflict rejected with ValueError",
        }

        # 10. rollback
        current_postimage = sha256_file(app_dir / "app.py")
        rb_res = executor.fs_rollback("demo-app", "app.py", current_postimage)
        restored_hash = sha256_file(app_dir / "app.py")
        step10_pass = rb_res["status"] == "ROLLED_BACK" and restored_hash == initial_hash
        results[10] = {
            "name": "rollback",
            "status": "PASS" if step10_pass else "FAIL",
            "detail": f"restored_sha256={restored_hash[:16]}... matches initial={initial_hash[:16]}...",
        }

        # 11. stage the exact owned file
        # Make a fresh edit to stage
        edit_content = "print('feature branch demo')\n"
        w2 = executor.fs_write(
            "demo-app",
            "app.py",
            edit_content,
            expected_preimage_sha256=initial_hash,
        )
        stage_res = executor.git_stage("demo-app", ["app.py"])
        staged_files = executor._staged_files(app_dir)
        step11_pass = stage_res["status"] == "PASS" and "app.py" in staged_files
        results[11] = {
            "name": "stage the exact owned file",
            "status": "PASS" if step11_pass else "FAIL",
            "detail": f"staged_paths={stage_res.get('staged_paths')}",
        }

        # 12. commit the exact owned file
        commit_res = executor.git_commit("demo-app", "feat: update app for demo")
        step12_pass = (
            commit_res["status"] == "PASS"
            and "app.py" in commit_res.get("committed_paths", [])
        )
        results[12] = {
            "name": "commit the exact owned file",
            "status": "PASS" if step12_pass else "FAIL",
            "detail": f"committed_paths={commit_res.get('committed_paths')}",
        }

        # 13. initialize continuity
        cm = ContinuityManager(app_dir)
        init_res = cm.init("demo-app")
        step13_pass = init_res["status"] == "PASS" and cm.is_initialized()
        results[13] = {
            "name": "initialize continuity",
            "status": "PASS" if step13_pass else "FAIL",
            "detail": f"initialized revision={init_res.get('revision')}",
        }

        # 14. mutate revision
        h_path = app_dir / "HANDOFF.md"
        cur_h_sha = sha256_file(h_path)
        cp_res = cm.checkpoint(
            expected_handoff_sha256=cur_h_sha,
            payload={"summary": "Demo step 14 checkpoint"},
            expected_metadata_revision=1,
        )
        step14_pass = cp_res["status"] == "PASS" and cp_res["metadata_revision"] == 2
        results[14] = {
            "name": "mutate revision",
            "status": "PASS" if step14_pass else "FAIL",
            "detail": f"advanced metadata_revision to {cp_res.get('metadata_revision')}",
        }

        # 15. reject stale continuity revision
        step15_pass = False
        try:
            # Expecting revision 1 when current is 2 should raise ConflictError
            cm.checkpoint(
                expected_handoff_sha256=cur_h_sha,
                payload={"summary": "Stale checkpoint"},
                expected_metadata_revision=1,
            )
        except ConflictError as exc:
            step15_pass = "revision conflict" in str(exc)
        results[15] = {
            "name": "reject stale continuity revision",
            "status": "PASS" if step15_pass else "FAIL",
            "detail": "stale metadata revision 1 rejected with ConflictError",
        }

    finally:
        if temp_obj is not None:
            temp_obj.cleanup()

    return results


def main() -> int:
    """CLI entry point for running the synthetic demo."""
    print("==================================================")
    print("       JVC Core Synthetic Demo Verification       ")
    print("==================================================")
    results = run_demo()
    all_passed = True
    for step, res in sorted(results.items()):
        mark = "PASS" if res["status"] == "PASS" else "FAIL"
        if mark != "PASS":
            all_passed = False
        print(f"Step {step:02d}: [{mark}] {res['name']}")
        print(f"         Detail: {res['detail']}")
    print("==================================================")
    overall = "ALL 15 STEPS PASSED" if all_passed else "SOME STEPS FAILED"
    print(f"Result: {overall}")
    print("==================================================")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
