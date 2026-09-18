"""Adversarial interprocess concurrency tests (Astra Finding 1).

Genuinely overlapping processes (not sequential simulations):
1. Two processes writing with the SAME expected preimage -> exactly one wins.
2. Two processes updating continuity from the SAME revision -> one wins.
3. A held lock serializes/blocks a competing mutator (timeout).
4. Lock released after normal completion.
5. Lock released after a handled failure (stale CAS inside the lock).
6. Invalid/corrupt/unavailable lock state fails closed.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[2] / "src"


def _child_fs_write(payload: dict) -> str:
    sys.path.insert(0, str(payload["src_dir"]))
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    route = Route(
        project_id="race-proj",
        aliases=("race",),
        root=Path(payload["root"]),
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=Path(payload["recovery"]),
        confirmation_store=Path(payload["confirmations"]),
        lock_dir=Path(payload["locks"]),
    )
    try:
        res = executor.fs_write(
            "race-proj",
            "shared.txt",
            payload["content"],
            expected_preimage_sha256=payload["preimage"],
            lock_timeout=payload.get("lock_timeout", 20.0),
        )
        return f"OK:{res['postimage_sha256']}"
    except ValueError as exc:
        return f"STALE:{exc}"
    except Exception as exc:  # noqa: BLE001 - reported back to parent
        import traceback

        return f"ERROR:{type(exc).__name__}:{exc}\n{traceback.format_exc()}"


def _child_checkpoint(payload: dict) -> str:
    sys.path.insert(0, str(payload["src_dir"]))
    from jvc.continuity.state import ConflictError, ContinuityManager

    try:
        cm = ContinuityManager(Path(payload["root"]), lock_dir=Path(payload["locks"]))
        res = cm.checkpoint(
            expected_handoff_sha256=payload["handoff_sha"],
            payload={"summary": payload["content"]},
            expected_metadata_revision=payload["revision"],
            lock_timeout=payload.get("lock_timeout", 20.0),
        )
        return f"OK:{res['metadata_revision']}"
    except ConflictError as exc:
        return f"CONFLICT:{exc}"
    except Exception as exc:  # noqa: BLE001
        return f"ERROR:{type(exc).__name__}:{exc}"


def _child_hold_lock(payload: dict) -> str:
    sys.path.insert(0, str(payload["src_dir"]))
    import time

    from jvc.policy.locks import ResourceLock, lock_name_for_resource

    try:
        with ResourceLock(
            Path(payload["locks"]),
            lock_name_for_resource("fs", Path(payload["root"]) / "shared.txt"),
            timeout=10.0,
        ):
            time.sleep(float(payload.get("hold_seconds", 4.0)))
        return "OK:released"
    except Exception as exc:  # noqa: BLE001
        return f"ERROR:{type(exc).__name__}:{exc}"


def _child_create(payload: dict) -> str:
    sys.path.insert(0, str(payload["src_dir"]))
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    route = Route(
        project_id="race-proj",
        aliases=("race",),
        root=Path(payload["root"]),
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=Path(payload["recovery"]),
        confirmation_store=Path(payload["confirmations"]),
        lock_dir=Path(payload["locks"]),
    )
    try:
        executor.fs_write(
            "race-proj", payload["rel"], payload["content"], lock_timeout=20.0
        )
        return "OK"
    except ValueError as exc:
        return f"EXPECTED:{exc}"
    except Exception as exc:  # noqa: BLE001
        import traceback

        return f"ERROR:{type(exc).__name__}:{exc}\n{traceback.format_exc()}"


def _child_init(payload: dict) -> str:
    sys.path.insert(0, str(payload["src_dir"]))
    from jvc.continuity.state import ContinuityManager

    try:
        ContinuityManager(
            Path(payload["root"]), lock_dir=Path(payload["locks"])
        ).init("p")
        return "OK"
    except Exception as exc:  # noqa: BLE001
        return f"EXPECTED:{type(exc).__name__}"


@pytest.fixture
def race_env(tmp_path):
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    root = tmp_path / "project"
    root.mkdir()
    recovery = tmp_path / "recovery"
    confirmations = tmp_path / "confirmations"
    locks = tmp_path / "locks"
    route = Route(
        project_id="race-proj",
        aliases=("race",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=recovery,
        confirmation_store=confirmations,
        lock_dir=locks,
    )
    return root, executor, recovery, confirmations, locks


def _payload(race_env, **extra):
    root, _, recovery, confirmations, locks = race_env
    base = {
        "src_dir": str(SRC_DIR),
        "root": str(root),
        "recovery": str(recovery),
        "confirmations": str(confirmations),
        "locks": str(locks),
    }
    base.update(extra)
    return base


def test_two_processes_same_preimage_exactly_one_wins(race_env):
    root, executor, *_ = race_env
    first = executor.fs_write("race-proj", "shared.txt", "initial")
    preimage = first["postimage_sha256"]

    payload_a = _payload(race_env, content="writer A", preimage=preimage)
    payload_b = _payload(race_env, content="writer B", preimage=preimage)
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_child_fs_write, [payload_a, payload_b]))

    ok = [r for r in results if r.startswith("OK:")]
    stale = [r for r in results if r.startswith("STALE:")]
    assert len(ok) == 1, results
    assert len(stale) == 1, results
    # The winner's bytes are intact; no torn interleaving.
    final = (root / "shared.txt").read_text(encoding="utf-8")
    assert final in {"writer A", "writer B"}


def test_two_processes_same_revision_exactly_one_wins(race_env, tmp_path):
    from jvc.continuity.state import ContinuityManager
    from jvc.policy.authority import sha256_file

    root, *_ = race_env
    locks = tmp_path / "locks"
    (root / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    cm = ContinuityManager(root, lock_dir=locks)
    cm.init("race-proj")
    handoff_sha = sha256_file(root / "HANDOFF.md")

    payload_a = _payload(
        race_env, content="checkpoint A", handoff_sha=handoff_sha, revision=1
    )
    payload_b = _payload(
        race_env, content="checkpoint B", handoff_sha=handoff_sha, revision=1
    )
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_child_checkpoint, [payload_a, payload_b]))

    ok = [r for r in results if r.startswith("OK:")]
    conflict = [r for r in results if r.startswith("CONFLICT:")]
    assert len(ok) == 1, results
    assert len(conflict) == 1, results
    assert ContinuityManager(root, lock_dir=locks).load_state()["metadata_revision"] == 2


def _make_link(target: Path, link: Path) -> bool:
    """Create a directory link; return False if the platform forbids it."""
    try:
        import subprocess as _sp

        if os.name == "nt":
            proc = _sp.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
            )
            return proc.returncode == 0 and link.is_dir()
        os.symlink(target, link, target_is_directory=True)
        return link.is_dir()
    except (OSError, NotImplementedError):
        return False


def test_symlink_junction_aliases_share_lock_identity(tmp_path):
    """Two spellings of one resource via links share one lock (Astra §19.4)."""
    from jvc.continuity.state import ContinuityManager
    from jvc.policy.locks import canonical_resource_id, lock_name_for_resource

    real = tmp_path / "real"
    (real / ".continuity").mkdir(parents=True)
    (real / ".continuity" / "state.json").write_text("{}", encoding="utf-8")
    (real / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    alias = tmp_path / "alias"
    if not _make_link(real, alias):
        pytest.skip("platform forbids link creation here")

    assert canonical_resource_id(
        alias / ".continuity" / "state.json"
    ) == canonical_resource_id(real / ".continuity" / "state.json")
    locks = tmp_path / "locks"
    direct = ContinuityManager(real, lock_dir=locks)
    via_link = ContinuityManager(alias, lock_dir=locks)
    assert direct._revision_lock().name == via_link._revision_lock().name
    # And file targets resolve identically too.
    assert lock_name_for_resource(
        "fs", alias / ".continuity" / "state.json"
    ) == lock_name_for_resource("fs", real / ".continuity" / "state.json")


def test_held_lock_blocks_competing_mutator(race_env):
    import time

    from jvc.policy.locks import LockTimeoutError

    root, executor, *_ = race_env
    first = executor.fs_write("race-proj", "shared.txt", "initial")
    preimage = first["postimage_sha256"]

    holder_payload = _payload(race_env, hold_seconds=4.0)
    contender_payload = _payload(
        race_env, content="contender", preimage="0" * 64, lock_timeout=2.0
    )
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as pool:
        holder = pool.submit(_child_hold_lock, holder_payload)
        time.sleep(1.0)  # let the holder take the lock first
        contender = pool.submit(_child_fs_write, contender_payload)
        holder_res = holder.result(timeout=30)
        contender_res = contender.result(timeout=30)

    assert holder_res == "OK:released", holder_res
    # The contender could not even enter the critical section in time.
    assert "LockTimeoutError" in contender_res, contender_res
    # Original content untouched.
    assert (root / "shared.txt").read_text(encoding="utf-8") == "initial"


def test_lock_released_after_normal_completion(race_env):
    from jvc.policy.locks import ResourceLock, lock_name_for

    _, executor, _, _, locks = race_env
    res = executor.fs_write("race-proj", "shared.txt", "v1")
    # A second, sequential writer proceeds immediately (no leftover lock).
    executor.fs_write(
        "race-proj",
        "shared.txt",
        "v2",
        expected_preimage_sha256=res["postimage_sha256"],
    )
    # The lock can be acquired freely now.
    with ResourceLock(locks, lock_name_for("fs", "race-proj", "shared.txt"), timeout=5.0):
        pass


def test_lock_released_after_handled_failure(race_env):
    from jvc.policy.locks import ResourceLock, lock_name_for

    _, executor, _, _, locks = race_env
    res = executor.fs_write("race-proj", "shared.txt", "v1")
    with pytest.raises(ValueError, match="preimage CAS conflict"):
        executor.fs_write(
            "race-proj", "shared.txt", "stale", expected_preimage_sha256="0" * 64
        )
    # Lock was released despite the in-critical-section failure; a valid
    # write proceeds.
    res2 = executor.fs_write(
        "race-proj",
        "shared.txt",
        "v2",
        expected_preimage_sha256=res["postimage_sha256"],
    )
    assert res2["status"] == "PASS"
    with ResourceLock(locks, lock_name_for("fs", "race-proj", "shared.txt"), timeout=5.0):
        pass


def test_corrupt_lock_state_fails_closed(race_env):
    from jvc.policy.locks import LockError, ResourceLock

    root, executor, _, _, locks = race_env
    # Lock directory path occupied by a file -> fail closed, no write.
    locks.mkdir(parents=True, exist_ok=True)
    (locks / "jvc-deadlock-sentinel.lock").write_text("x", encoding="utf-8")
    blocker = locks / "nested"
    blocker.write_text("i am a file, not a directory", encoding="utf-8")

    bad_executor_kwargs = {"lock_dir": blocker}
    from jvc.configuration import ProjectRegistry, Route

    route = Route(
        project_id="race-proj",
        aliases=("race",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    import jvc.execution.executor as exec_mod

    bad = exec_mod.GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=race_env[2],
        confirmation_store=race_env[3],
        **bad_executor_kwargs,
    )
    with pytest.raises(LockError):
        bad.fs_write("race-proj", "shared.txt", "must not land")
    assert not (root / "shared.txt").exists()

    # Lock directory inside a governed root -> fail closed at acquisition.
    evil_dir = root / "agent-controlled-locks"
    with pytest.raises(LockError, match="outside governed roots"):
        with ResourceLock(
            evil_dir, "somename", timeout=2.0, governed_roots=[root]
        ):
            pass


def test_lock_name_invalid_fails_closed(tmp_path):
    from jvc.policy.locks import LockError, ResourceLock

    with pytest.raises(LockError):
        with ResourceLock(tmp_path, "../escape", timeout=1.0):
            pass


def test_absent_file_case_aliases_share_lock_identity(tmp_path):
    """Windows absent-target aliases must map to one lock (Astra §19.3)."""
    import os as _os

    from jvc.policy.locks import canonical_resource_id, lock_name_for_resource

    root = tmp_path / "project"
    root.mkdir()
    lower = lock_name_for_resource("fs", root / "audit-absent.txt")
    upper = lock_name_for_resource("fs", root / "AUDIT-ABSENT.TXT")
    mixed_sep = lock_name_for_resource("fs", root / "SUB" / ".." / "audit-absent.txt")
    if _os.name == "nt":
        assert lower == upper
        assert lower == mixed_sep
    else:
        # POSIX filesystems are case-sensitive: genuinely different resources.
        assert lower != upper
    # Canonical identity is absolute: different spellings of the same
    # absolute resource agree on every platform.
    assert canonical_resource_id(root / "x.txt") == canonical_resource_id(
        root / "SUB" / ".." / "x.txt"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows case-alias semantics only")
def test_two_processes_case_aliased_creates_exactly_one_wins(race_env):
    """Differently-cased creates of the same missing Windows file serialize."""
    import concurrent.futures as _futures

    root, _, recovery, confirmations, locks = race_env
    base = {
        "src_dir": str(SRC_DIR),
        "root": str(root),
        "recovery": str(recovery),
        "confirmations": str(confirmations),
        "locks": str(locks),
    }
    payload_a = dict(base, rel="shared-case.txt", content="writer A")
    payload_b = dict(base, rel="SHARED-CASE.TXT", content="writer B")
    with _futures.ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_child_create, [payload_a, payload_b]))
    ok = [r for r in results if r == "OK"]
    expected = [r for r in results if r.startswith("EXPECTED:")]
    assert len(ok) == 1, results
    assert len(expected) == 1, results
    final = (root / "shared-case.txt").read_text(encoding="utf-8")
    assert final in {"writer A", "writer B"}


def test_concurrent_init_exactly_one_wins(tmp_path):
    import concurrent.futures as _futures

    from jvc.continuity.state import ContinuityManager

    root = tmp_path / "cproj"
    root.mkdir()
    (root / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    locks = tmp_path / "locks"

    payload = {"src_dir": str(SRC_DIR), "root": str(root), "locks": str(locks)}
    with _futures.ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_child_init, [payload, payload]))
    assert results.count("OK") == 1, results
    assert len([r for r in results if r.startswith("EXPECTED:")]) == 1, results
    assert ContinuityManager(root, lock_dir=locks).load_state()["metadata_revision"] == 1


def test_record_decision_advances_revision(tmp_path):
    from jvc.continuity.state import ConflictError, ContinuityManager

    root = tmp_path / "cproj"
    root.mkdir()
    (root / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    cm = ContinuityManager(root, lock_dir=tmp_path / "locks")
    cm.init("p")
    res = cm.record_decision("dec-001", 1, {"note": "first"})
    assert res["metadata_revision"] == 2
    assert cm.load_state()["metadata_revision"] == 2
    # A concurrent decision from the same expected revision now conflicts.
    with pytest.raises(ConflictError, match="revision conflict"):
        cm.record_decision("dec-002", 1, {"note": "stale"})


@pytest.mark.parametrize(
    "bad_id", ["../escape", "sub/dir", "a\\b", "", ".", "x" * 200, "dec id"]
)
def test_record_decision_rejects_unsafe_ids(tmp_path, bad_id):
    from jvc.continuity.state import ContinuityManager

    root = tmp_path / "cproj"
    root.mkdir()
    (root / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    cm = ContinuityManager(root, lock_dir=tmp_path / "locks")
    cm.init("p")
    with pytest.raises(ValueError, match="invalid decision_id"):
        cm.record_decision(bad_id, 1, {})


def test_reconcile_enforces_expected_handoff(tmp_path):
    from jvc.continuity.state import ConflictError, ContinuityManager
    from jvc.policy.authority import sha256_file

    root = tmp_path / "cproj"
    root.mkdir()
    (root / "HANDOFF.md").write_text("# v1\n", encoding="utf-8")
    cm = ContinuityManager(root, lock_dir=tmp_path / "locks")
    cm.init("p")
    h1 = sha256_file(root / "HANDOFF.md")
    (root / "HANDOFF.md").write_text("# v2\n", encoding="utf-8")
    h2 = sha256_file(root / "HANDOFF.md")
    # Wrong expected (recorded) handoff is rejected even though the observed
    # on-disk value is correct.
    with pytest.raises(ConflictError, match="expected SHA-256 conflict"):
        cm.reconcile_handoff(
            expected_handoff_sha256="0" * 64,
            observed_handoff_sha256=h2,
            payload={},
            expected_metadata_revision=1,
        )
    rec = cm.reconcile_handoff(
        expected_handoff_sha256=h1,
        observed_handoff_sha256=h2,
        payload={},
        expected_metadata_revision=1,
    )
    assert rec["metadata_revision"] == 2
