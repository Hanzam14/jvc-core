"""Transactional recovery journal tests (Astra Finding 5).

Failure injection at journal boundaries (no machine killing):
A. failure after backup creation but before target write
B. failure after target replacement but before receipt finalization
C. failure while finalizing metadata
D. restart with PREPARED transaction
E. restart with target matching expected postimage
F. restart with unexpected intervening target contents
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor
from jvc.policy.authority import sha256_bytes
from jvc.recovery.store import (
    InjectedFailure,
    RecoveryError,
    RecoveryRequiredError,
    RecoveryStore,
)


@pytest.fixture
def journal_env(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    recovery_dir = tmp_path / "recovery"
    route = Route(
        project_id="journal-proj",
        aliases=("proj",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    store = RecoveryStore(recovery_dir)
    executor = GovernedExecutor(
        registry=reg, recovery_store=store, confirmation_store=tmp_path / "trust"
    )
    return root, executor, store, recovery_dir


def _receipts(recovery_dir: Path):
    return sorted(recovery_dir.glob("recovery-*.json"))


def test_a_failure_after_backup_before_target_write(journal_env):
    root, executor, store, recovery_dir = journal_env
    store.failure_points.add("after_backup")
    with pytest.raises(InjectedFailure):
        executor.fs_write("journal-proj", "data.txt", "new content")
    # Target never created; journal holds exactly one PREPARED transaction.
    assert not (root / "data.txt").exists()
    receipts = _receipts(recovery_dir)
    assert len(receipts) == 1
    data = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert data["tx_state"] == "PREPARED"
    # Restart reconciles deterministically: mutation never applied.
    summary = store.recover()
    assert summary["recovery_required"] == []
    assert len(summary["recovered"]) == 1
    data = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert data["tx_state"] == "RECOVERED_UNAPPLIED"
    assert not (root / "data.txt").exists()


def test_b_failure_after_target_write_before_finalize(journal_env):
    root, executor, store, recovery_dir = journal_env
    store.failure_points.add("after_target_write")
    with pytest.raises(InjectedFailure):
        executor.fs_write("journal-proj", "data.txt", "new content")
    # Target WAS replaced but no postimage recorded: PREPARED + diverged.
    assert (root / "data.txt").read_text(encoding="utf-8") == "new content"
    receipts = _receipts(recovery_dir)
    assert len(receipts) == 1
    # Restart must fail closed: cannot prove what happened.
    summary = store.recover()
    assert len(summary["recovery_required"]) == 1
    data = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert data["tx_state"] == "RECOVERY_REQUIRED"


def test_c_failure_during_finalize_recovers_on_restart(journal_env):
    root, executor, store, recovery_dir = journal_env
    store.failure_points.add("during_finalize")
    with pytest.raises(InjectedFailure):
        executor.fs_write("journal-proj", "data.txt", "new content")
    receipts = _receipts(recovery_dir)
    data = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert data["tx_state"] == "APPLIED"
    assert data["postimage_sha256"] == sha256_bytes(b"new content")
    # Restart: target matches recorded postimage -> finalize to VERIFIED.
    summary = store.recover()
    assert summary["recovery_required"] == []
    assert summary["verified"] == 1
    data = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert data["tx_state"] == "VERIFIED"
    # Rollback still works after recovery.
    store.failure_points.clear()
    rb = executor.fs_rollback(
        "journal-proj", "data.txt", sha256_bytes(b"new content")
    )
    assert rb["status"] == "ROLLED_BACK"
    assert not (root / "data.txt").exists()


def test_d_restart_with_prepared_transaction_unapplied(journal_env):
    root, executor, store, recovery_dir = journal_env
    first = executor.fs_write("journal-proj", "doc.txt", "v1")
    # Craft a PREPARED transaction manually: backup of v1, target untouched.
    target = root / "doc.txt"
    receipt = store.save_preimage(
        "journal-proj", target, (root / "doc.txt").read_bytes()
    )
    assert receipt["tx_state"] == "PREPARED"
    summary = store.recover()
    assert summary["recovery_required"] == []
    data = json.loads((recovery_dir / f"{receipt['receipt_id']}.json").read_text(encoding="utf-8"))
    assert data["tx_state"] == "RECOVERED_UNAPPLIED"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v1"


def test_e_restart_with_target_matching_postimage_finalizes(journal_env):
    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    assert res["tx_state"] == "VERIFIED"
    summary = store.recover()
    assert summary["recovered"] == []
    assert summary["recovery_required"] == []
    assert summary["verified"] == 1
    assert summary["orphans"] == []


def test_f_restart_with_unexpected_contents_requires_recovery(journal_env):
    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    # Simulate an interrupted second mutation: PREPARED receipt exists but
    # the target holds unexpected bytes (neither preimage nor postimage).
    target = root / "doc.txt"
    receipt = store.save_preimage("journal-proj", target, target.read_bytes())
    assert receipt["tx_state"] == "PREPARED"
    target.write_text("unexpected-intervening-bytes", encoding="utf-8")
    summary = store.recover()
    assert len(summary["recovery_required"]) == 1
    data = json.loads((recovery_dir / f"{receipt['receipt_id']}.json").read_text(encoding="utf-8"))
    assert data["tx_state"] == "RECOVERY_REQUIRED"
    # The unexpected content is preserved, never silently clobbered.
    assert target.read_text(encoding="utf-8") == "unexpected-intervening-bytes"


def test_receipt_updates_are_atomic(journal_env):
    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    receipt_path = recovery_dir / f"{res['receipt_id']}.json"
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert data["tx_state"] == "VERIFIED"
    assert data["postimage_sha256"] == res["postimage_sha256"]
    # No torn/partial JSON: every receipt parses and carries required keys.
    for receipt_file in _receipts(recovery_dir):
        parsed = json.loads(receipt_file.read_text(encoding="utf-8"))
        for key in ("receipt_id", "project_id", "path", "tx_state"):
            assert key in parsed


def test_corrupt_receipt_fails_closed_on_recover(journal_env):
    root, executor, store, recovery_dir = journal_env
    executor.fs_write("journal-proj", "doc.txt", "v1")
    receipts = _receipts(recovery_dir)
    assert receipts
    receipts[0].write_text("{not valid json", encoding="utf-8")
    summary = store.recover()
    assert len(summary["recovery_required"]) == 1


def test_recovery_races_active_writer_without_mismarking(journal_env):
    """Recovery defers (never mismarks) while a live writer holds the lock."""
    import threading

    root, executor, store, recovery_dir = journal_env
    first = executor.fs_write("journal-proj", "race.txt", "v1")
    preimage = first["postimage_sha256"]
    entered = threading.Event()
    release = threading.Event()
    outcome: dict[str, str] = {}

    original_save = store.save_preimage

    def slow_save(project_id, target, content):
        receipt = original_save(project_id, target, content)
        entered.set()
        release.wait(timeout=30)
        return receipt

    store.save_preimage = slow_save  # type: ignore[method-assign]
    try:

        def _writer():
            try:
                executor.fs_write(
                    "journal-proj", "race.txt", "v2",
                    expected_preimage_sha256=preimage,
                )
                outcome["write"] = "OK"
            except Exception as exc:  # noqa: BLE001
                outcome["write"] = f"FAIL:{type(exc).__name__}"

        thread = threading.Thread(target=_writer)
        thread.start()
        assert entered.wait(timeout=30)
        # Recovery runs while the writer sits between PREPARED and replace:
        # it must defer on the live-held lock, not mismark the transaction.
        summary = store.recover(lock_for=lambda p: executor._target_lock(Path(p), 2.0))
        assert summary["recovery_required"] == []
        assert len(summary["deferred"]) == 1
        release.set()
        thread.join(timeout=60)
    finally:
        store.save_preimage = original_save  # type: ignore[method-assign]

    assert outcome.get("write") == "OK", outcome
    assert (root / "race.txt").read_text(encoding="utf-8") == "v2"
    final = store.recover()
    assert final["recovery_required"] == []
    assert final["verified"] >= 1


def test_unresolved_recovery_blocks_write(journal_env):
    from jvc.recovery.store import RecoveryRequiredError

    root, executor, store, recovery_dir = journal_env
    executor.fs_write("journal-proj", "doc.txt", "v1")
    target = root / "doc.txt"
    receipt = store.save_preimage("journal-proj", target, target.read_bytes())
    target.write_text("unexpected-intervening-bytes", encoding="utf-8")
    summary = store.recover()
    assert len(summary["recovery_required"]) == 1
    # Fresh mutation is blocked until the operator resolves recovery.
    with pytest.raises(RecoveryRequiredError, match="RECOVERY_REQUIRED blocks mutation"):
        executor.fs_write(
            "journal-proj", "doc.txt", "new attempt",
            expected_preimage_sha256=sha256_bytes(b"unexpected-intervening-bytes"),
        )
    assert target.read_text(encoding="utf-8") == "unexpected-intervening-bytes"


def test_malformed_empty_receipt_fails_closed(journal_env):
    root, executor, store, recovery_dir = journal_env
    executor.fs_write("journal-proj", "doc.txt", "v1")
    (recovery_dir / "recovery-journal-proj-bogus.json").write_text("{}", encoding="utf-8")
    summary = store.recover()
    assert summary["recovery_required"] != []
    # No receipt defaults to VERIFIED: verified counts only the real one.
    assert summary["verified"] == 1


def test_missing_tx_state_never_defaults_verified(journal_env):
    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    receipt_path = recovery_dir / f"{res['receipt_id']}.json"
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    del data["tx_state"]
    receipt_path.write_text(json.dumps(data), encoding="utf-8")
    summary = store.recover()
    assert summary["verified"] == 0
    assert len(summary["recovery_required"]) == 1


def test_missing_backup_detected_on_recover(journal_env):
    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res["postimage_sha256"],
    )
    (recovery_dir / f"{res2['receipt_id']}.bak").unlink()
    summary = store.recover()
    assert len(summary["recovery_required"]) == 1
    with pytest.raises(RecoveryRequiredError, match="RECOVERY_REQUIRED blocks mutation"):
        executor.fs_write(
            "journal-proj", "doc.txt", "v3",
            expected_preimage_sha256=res2["postimage_sha256"],
        )


def test_rollback_crash_boundary_recovers(journal_env):
    from jvc.policy.authority import sha256_file

    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    v2 = res2["postimage_sha256"]
    store.failure_points.add("rollback_before_terminal")
    with pytest.raises(InjectedFailure):
        executor.fs_rollback("journal-proj", "doc.txt", v2)
    # The target WAS restored, but terminal states were not persisted.
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v1"
    store.failure_points.clear()
    summary = store.recover()
    assert summary["recovery_required"] == []
    # Rollback finalized idempotently: source receipt is ROLLED_BACK.
    source = json.loads(
        (recovery_dir / f"{res2['receipt_id']}.json").read_text(encoding="utf-8")
    )
    assert source["tx_state"] == "ROLLED_BACK"


def test_rollback_finalization_persists_terminal_state(journal_env):
    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    rb = executor.fs_rollback("journal-proj", "doc.txt", res2["postimage_sha256"])
    assert rb["status"] == "ROLLED_BACK"
    assert "rollback_receipt_id" in rb
    rb_data = json.loads(
        (recovery_dir / f"{rb['rollback_receipt_id']}.json").read_text(encoding="utf-8")
    )
    assert rb_data["tx_state"] == "VERIFIED"
    assert rb_data["original_operation"] == "ROLLBACK"
    source = json.loads(
        (recovery_dir / f"{res2['receipt_id']}.json").read_text(encoding="utf-8")
    )
    assert source["tx_state"] == "ROLLED_BACK"


def test_unresolved_transactions_survive_pruning(journal_env):
    root, executor, store, recovery_dir = journal_env
    executor.fs_write("journal-proj", "doc.txt", "v1")
    target = root / "doc.txt"
    receipt = store.save_preimage("journal-proj", target, target.read_bytes())
    target.write_text("diverged", encoding="utf-8")
    store.recover()
    pruned = store.prune(retention_days=-1)  # everything "expired"
    # The RECOVERY_REQUIRED receipt (and diverged target) survive pruning.
    assert (recovery_dir / f"{receipt['receipt_id']}.json").is_file()
    assert target.read_text(encoding="utf-8") == "diverged"
    assert pruned >= 0


def test_transaction_ordering_uses_seq(journal_env):
    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    res3 = executor.fs_write(
        "journal-proj", "doc.txt", "v3",
        expected_preimage_sha256=res2["postimage_sha256"],
    )
    target = root / "doc.txt"
    latest = store.find_latest_receipt(
        "journal-proj", target, res3["postimage_sha256"]
    )
    assert latest is not None
    assert latest["receipt_id"] == res3["receipt_id"]
    # seq ordering is monotonic across the three writes.
    seqs = [
        json.loads((recovery_dir / f"{r['receipt_id']}.json").read_text(encoding="utf-8"))["seq"]
        for r in (res1, res2, res3)
    ]
    assert seqs == sorted(seqs)


def test_completed_rollback_survives_reopen(journal_env):
    """A successful rollback must not become RECOVERY_REQUIRED on restart.

    Reproduced failure: VERIFIED rollback receipts carry no backup, and the
    old reopen audit required one whenever preimage_exists was true.
    """
    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    rb = executor.fs_rollback("journal-proj", "doc.txt", res2["postimage_sha256"])
    assert rb["status"] == "ROLLED_BACK"
    summary = store.recover()
    assert summary["recovery_required"] == []
    # Source receipt reached its terminal state; the gate is clear.
    source = json.loads(
        (recovery_dir / f"{res2['receipt_id']}.json").read_text(encoding="utf-8")
    )
    assert source["tx_state"] == "ROLLED_BACK"
    res3 = executor.fs_write(
        "journal-proj", "doc.txt", "v3",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    assert res3["status"] == "PASS"


def test_recovery_does_not_overwrite_completed_receipt(journal_env):
    """Recovery rereads under the lock: no stale-data RECOVERY_REQUIRED.

    Reproduced failure: recovery read PREPARED, waited on the lock while the
    writer completed, then overwrote the completed receipt as REQUIRED.
    """
    import threading

    root, executor, store, recovery_dir = journal_env
    first = executor.fs_write("journal-proj", "doc.txt", "v1")
    preimage = first["postimage_sha256"]
    entered = threading.Event()
    release = threading.Event()
    outcome: dict[str, str] = {}
    original_save = store.save_preimage

    def slow_save(project_id, target, content):
        receipt = original_save(project_id, target, content)
        entered.set()
        release.wait(timeout=30)
        return receipt

    store.save_preimage = slow_save  # type: ignore[method-assign]
    try:

        def _writer():
            try:
                executor.fs_write(
                    "journal-proj", "doc.txt", "v2",
                    expected_preimage_sha256=preimage,
                )
                outcome["write"] = "OK"
            except Exception as exc:  # noqa: BLE001
                outcome["write"] = f"FAIL:{type(exc).__name__}"

        thread = threading.Thread(target=_writer)
        thread.start()
        assert entered.wait(timeout=30)
        # Recovery scans while the writer holds PREPARED, then blocks on the
        # same lock. Release the writer FIRST: it completes (releases the
        # lock only after persisting VERIFIED), recovery then acquires and
        # must see the completed state, not its stale PREPARED read.
        def _recover():
            outcome["summary"] = store.recover(
                lock_for=lambda p: executor._target_lock(Path(p), 30.0)
            )

        rec_thread = threading.Thread(target=_recover)
        rec_thread.start()
        import time as _time

        _time.sleep(1.0)  # let recovery reach the lock wait
        release.set()
        thread.join(timeout=60)
        rec_thread.join(timeout=60)
    finally:
        store.save_preimage = original_save  # type: ignore[method-assign]

    assert outcome.get("write") == "OK", outcome
    summary = outcome.get("summary")
    assert isinstance(summary, dict), outcome
    assert summary["recovery_required"] == [], summary
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v2"


def test_corrupt_receipt_blocks_governed_write(journal_env):
    """Corruption fails closed at the gate, not just in the summary.

    Reproduced failure: has_blocking_state skipped unreadable receipts, so a
    corrupt journal was reported yet writes proceeded.
    """
    from jvc.recovery.store import RecoveryRequiredError

    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    (recovery_dir / "recovery-journal-proj-corrupt.json").write_text(
        "{broken", encoding="utf-8"
    )
    summary = store.recover()
    assert len(summary["recovery_required"]) == 1
    with pytest.raises(RecoveryRequiredError, match="corrupt recovery journal"):
        executor.fs_write(
            "journal-proj", "doc.txt", "v2",
            expected_preimage_sha256=res["postimage_sha256"],
        )
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v1"
    # Operator repairs the journal: gate clears.
    (recovery_dir / "recovery-journal-proj-corrupt.json").unlink()
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res["postimage_sha256"],
    )
    assert res2["status"] == "PASS"


def test_rollback_source_completed_idempotently(journal_env):
    """Crash between the two terminal rollback writes completes on restart."""
    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    rb = executor.fs_rollback("journal-proj", "doc.txt", res2["postimage_sha256"])
    rb_id = rb["rollback_receipt_id"]
    # Simulate the crash: rollback receipt terminal, source still VERIFIED.
    source_path = recovery_dir / f"{res2['receipt_id']}.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["tx_state"] = "VERIFIED"
    source_path.write_text(json.dumps(source), encoding="utf-8")
    summary = store.recover()
    assert summary["recovery_required"] == []
    source = json.loads(source_path.read_text(encoding="utf-8"))
    assert source["tx_state"] == "ROLLED_BACK"
    rb_data = json.loads((recovery_dir / f"{rb_id}.json").read_text(encoding="utf-8"))
    assert rb_data["tx_state"] == "VERIFIED"


def test_corruption_blocks_rollback(journal_env):
    """The corruption gate covers rollback, not just writes (blocker 1)."""
    from jvc.recovery.store import RecoveryRequiredError as _RRR

    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    res2 = executor.fs_write(
        "journal-proj", "doc.txt", "v2",
        expected_preimage_sha256=res1["postimage_sha256"],
    )
    (recovery_dir / "recovery-journal-proj-corrupt.json").write_text(
        "{broken", encoding="utf-8"
    )
    # Executor-level rollback is denied before any journal mutation.
    with pytest.raises(_RRR, match="corrupt recovery journal"):
        executor.fs_rollback("journal-proj", "doc.txt", res2["postimage_sha256"])
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v2"
    # Raw store rollback is denied too.
    with pytest.raises(_RRR, match="corrupt recovery journal"):
        store.rollback("journal-proj", root / "doc.txt", res2["postimage_sha256"])
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v2"


def test_incomplete_transaction_reconciled_inline_on_next_write(journal_env):
    """A failed write's PREPARED receipt reconciles on the next write (blocker 2).

    No explicit recover() runs between the failure and the retry: the writer
    reconciles-or-denies under its own target lock.
    """
    root, executor, store, recovery_dir = journal_env
    store.failure_points.add("after_backup")
    with pytest.raises(InjectedFailure):
        executor.fs_write("journal-proj", "doc.txt", "v1")
    store.failure_points.clear()
    # Target untouched + receipt PREPARED: retry reconciles to
    # RECOVERED_UNAPPLIED inline and the write proceeds.
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    assert res["status"] == "PASS"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v1"


def test_incomplete_diverged_transaction_denied_inline(journal_env):
    """A diverged PREPARED receipt denies the next write without recover()."""
    from jvc.recovery.store import RecoveryRequiredError as _RRR

    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    target = root / "doc.txt"
    store.save_preimage("journal-proj", target, target.read_bytes())
    target.write_text("diverged-by-crash", encoding="utf-8")
    # No recover() call: the writer itself must deny under its lock.
    with pytest.raises(_RRR, match="RECOVERY_REQUIRED blocks mutation"):
        executor.fs_write(
            "journal-proj", "doc.txt", "v3",
            expected_preimage_sha256=res["postimage_sha256"],
        )
    assert target.read_text(encoding="utf-8") == "diverged-by-crash"


def test_rollback_selection_ignores_wall_clock(journal_env):
    """Backward clock adjustment must not select the wrong preimage (blocker 3).

    Successive writes A -> B -> C -> B, then seq fields scrambled to simulate
    a backward clock: rollback of B must restore C (chain head), never A.
    """
    root, executor, store, recovery_dir = journal_env
    r1 = executor.fs_write("journal-proj", "doc.txt", "A")
    r2 = executor.fs_write(
        "journal-proj", "doc.txt", "B", expected_preimage_sha256=r1["postimage_sha256"]
    )
    r3 = executor.fs_write(
        "journal-proj", "doc.txt", "C", expected_preimage_sha256=r2["postimage_sha256"]
    )
    r4 = executor.fs_write(
        "journal-proj", "doc.txt", "B", expected_preimage_sha256=r3["postimage_sha256"]
    )
    # Scramble seq: newest receipt gets the oldest timestamp and vice versa.
    seqs = {}
    for r in (r1, r2, r3, r4):
        p = recovery_dir / f"{r['receipt_id']}.json"
        d = json.loads(p.read_text(encoding="utf-8"))
        seqs[r["receipt_id"]] = d.get("seq", 0)
    ordered = sorted(seqs, key=lambda k: seqs[k])
    flipped = {rid: seqs[other] for rid, other in zip(ordered, reversed(ordered))}
    for r in (r1, r2, r3, r4):
        p = recovery_dir / f"{r['receipt_id']}.json"
        d = json.loads(p.read_text(encoding="utf-8"))
        d["seq"] = flipped[r["receipt_id"]]
        p.write_text(json.dumps(d), encoding="utf-8")
    rb = executor.fs_rollback("journal-proj", "doc.txt", r4["postimage_sha256"])
    assert rb["status"] == "ROLLED_BACK"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "C"


def test_non_object_receipt_returns_summary(journal_env):
    """A receipt containing `[]` must not crash recovery's scan."""
    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    (recovery_dir / "recovery-journal-proj-array.json").write_text("[]", encoding="utf-8")
    summary = store.recover()
    assert "recovery-journal-proj-array.json" in summary["recovery_required"]
    assert summary["verified"] == 1
    # And the gate still blocks writes until repaired.
    from jvc.recovery.store import RecoveryRequiredError as _RRR

    with pytest.raises(_RRR, match="corrupt recovery journal"):
        executor.fs_write(
            "journal-proj", "doc.txt", "v2",
            expected_preimage_sha256=res["postimage_sha256"],
        )


def _write_chain(journal_env):
    """Build successive writes A -> B -> C -> B; return env + receipts."""
    root, executor, store, recovery_dir = journal_env
    r1 = executor.fs_write("journal-proj", "doc.txt", "A")
    r2 = executor.fs_write(
        "journal-proj", "doc.txt", "B", expected_preimage_sha256=r1["postimage_sha256"]
    )
    r3 = executor.fs_write(
        "journal-proj", "doc.txt", "C", expected_preimage_sha256=r2["postimage_sha256"]
    )
    r4 = executor.fs_write(
        "journal-proj", "doc.txt", "B", expected_preimage_sha256=r3["postimage_sha256"]
    )
    return (root, executor, store, recovery_dir), (r1, r2, r3, r4)


def _scramble_seq(recovery_dir, receipts):
    """Simulate a backward clock adjustment across the given receipts."""
    seqs = {}
    for r in receipts:
        p = recovery_dir / f"{r['receipt_id']}.json"
        d = json.loads(p.read_text(encoding="utf-8"))
        seqs[r["receipt_id"]] = d.get("seq", 0)
    ordered = sorted(seqs, key=lambda k: seqs[k])
    flipped = {rid: seqs[other] for rid, other in zip(ordered, reversed(ordered))}
    for r in receipts:
        p = recovery_dir / f"{r['receipt_id']}.json"
        d = json.loads(p.read_text(encoding="utf-8"))
        d["seq"] = flipped[r["receipt_id"]]
        p.write_text(json.dumps(d), encoding="utf-8")


def test_rollback_ignores_unapplied_successor(journal_env):
    """An unapplied write must not steal chain-head status (blocker).

    A -> B -> C -> B, then a crashed B -> E write (PREPARED, never applied).
    With a backward clock, rollback of B must restore C, not A.
    """
    from jvc.policy.authority import sha256_bytes

    (root, executor, store, recovery_dir), (r1, r2, r3, r4) = _write_chain(journal_env)
    # Crashed successor: backup durable, target never replaced. The
    # preimage is the actual on-disk bytes, as the executor would pass.
    crashed = store.save_preimage(
        "journal-proj", root / "doc.txt", (root / "doc.txt").read_bytes()
    )
    assert crashed["tx_state"] == "PREPARED"
    assert crashed["prev_receipt_id"] == r4["receipt_id"]
    _scramble_seq(recovery_dir, (r1, r2, r3, r4))
    rb = executor.fs_rollback("journal-proj", "doc.txt", r4["postimage_sha256"])
    assert rb["status"] == "ROLLED_BACK"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "C"
    assert rb["receipt_id"] == r4["receipt_id"]
    assert sha256_bytes(b"C") == rb["restored_sha256"]
    # The orphaned PREPARED intent must not block the future: recovery runs
    # twice with nothing to repair, then a valid governed write succeeds
    # without manual receipt repair.
    crashed_data = json.loads(
        (recovery_dir / f"{crashed['receipt_id']}.json").read_text(encoding="utf-8")
    )
    assert crashed_data["tx_state"] == "SUPERSEDED"
    for _ in range(2):
        summary = store.recover()
        assert summary["recovery_required"] == [], summary
    nxt = executor.fs_write(
        "journal-proj", "doc.txt", "E2",
        expected_preimage_sha256=sha256_bytes(b"C"),
    )
    assert nxt["status"] == "PASS"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "E2"


def test_rollback_ignores_rolled_back_successor(journal_env):
    """A rolled-back write must not steal chain-head status (blocker).

    A -> B -> C -> B, then B -> D, then rollback D -> B. With a backward
    clock, rollback of B must restore C, not A.
    """
    (root, executor, store, recovery_dir), (r1, r2, r3, r4) = _write_chain(journal_env)
    r5 = executor.fs_write(
        "journal-proj", "doc.txt", "D", expected_preimage_sha256=r4["postimage_sha256"]
    )
    rb1 = executor.fs_rollback("journal-proj", "doc.txt", r5["postimage_sha256"])
    assert rb1["status"] == "ROLLED_BACK"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "B"
    _scramble_seq(recovery_dir, (r1, r2, r3, r4, r5))
    rb2 = executor.fs_rollback("journal-proj", "doc.txt", r4["postimage_sha256"])
    assert rb2["status"] == "ROLLED_BACK"
    assert (root / "doc.txt").read_text(encoding="utf-8") == "C"
    assert rb2["receipt_id"] == r4["receipt_id"]


def test_ambiguous_lineage_fails_closed(journal_env):
    """A RECOVERY_REQUIRED pointer at the head denies rollback (fail closed)."""
    from jvc.recovery.store import RecoveryRequiredError as _RRR

    (root, executor, store, recovery_dir), (r1, r2, r3, r4) = _write_chain(journal_env)
    # Craft an ambiguous successor: PREPARED receipt flipped to REQUIRED
    # while still pointing at the head (simulates an unknown-apply crash).
    target = root / "doc.txt"
    amb = store.save_preimage("journal-proj", target, target.read_bytes())
    amb_path = recovery_dir / f"{amb['receipt_id']}.json"
    amb_data = json.loads(amb_path.read_text(encoding="utf-8"))
    assert amb_data["prev_receipt_id"] == r4["receipt_id"]
    amb_data["tx_state"] = "RECOVERY_REQUIRED"
    amb_path.write_text(json.dumps(amb_data), encoding="utf-8")
    with pytest.raises(_RRR, match="ambiguous lineage|RECOVERY_REQUIRED"):
        executor.fs_rollback("journal-proj", "doc.txt", r4["postimage_sha256"])
    # Target bytes preserved; nothing silently restored.
    assert (root / "doc.txt").read_text(encoding="utf-8") == "B"


def test_applied_diverged_pending_denies_rollback(journal_env):
    """An APPLIED receipt matching nothing on disk denies rollback.

    Simulates a recorded replacement whose bytes never landed (or were
    overwritten outside the journal): the pending state is genuinely
    ambiguous, so rollback fails closed instead of superseding it.
    """
    from jvc.recovery.store import RecoveryRequiredError as _RRR

    root, executor, store, recovery_dir = journal_env
    res = executor.fs_write("journal-proj", "doc.txt", "v1")
    target = root / "doc.txt"
    # Record a replacement that never reaches the target.
    amb = store.save_preimage("journal-proj", target, target.read_bytes())
    amb_path = recovery_dir / f"{amb['receipt_id']}.json"
    amb_data = json.loads(amb_path.read_text(encoding="utf-8"))
    amb_data["postimage_sha256"] = sha256_bytes(b"phantom-bytes")
    amb_data["tx_state"] = "APPLIED"
    amb_path.write_text(json.dumps(amb_data), encoding="utf-8")
    with pytest.raises(_RRR, match="ambiguous applied transaction"):
        executor.fs_rollback("journal-proj", "doc.txt", res["postimage_sha256"])
    assert target.read_text(encoding="utf-8") == "v1"
    # The ambiguous receipt is now fail-closed blocking, not silent.
    amb_data = json.loads(amb_path.read_text(encoding="utf-8"))
    assert amb_data["tx_state"] == "RECOVERY_REQUIRED"


def test_replaced_but_unrecorded_prepared_denies_rollback(journal_env):
    """A crash between replace and journaling must not be superseded.

    Uses the `after_target_write` failure point: the target holds NEW bytes
    while the receipt is still PREPARED with preimage OLD. Rollback must
    deny (preserving the unresolved receipt), and subsequent writes must
    remain blocked — not silently cleared as SUPERSEDED.
    """
    from jvc.policy.authority import sha256_file
    from jvc.recovery.store import RecoveryRequiredError as _RRR

    root, executor, store, recovery_dir = journal_env
    res1 = executor.fs_write("journal-proj", "doc.txt", "v1")
    store.failure_points.add("after_target_write")
    with pytest.raises(InjectedFailure):
        executor.fs_write(
            "journal-proj", "doc.txt", "v2",
            expected_preimage_sha256=res1["postimage_sha256"],
        )
    store.failure_points.clear()
    # Crash window: NEW bytes on disk, receipt still PREPARED with OLD preimage.
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v2"
    new_hash = sha256_file(root / "doc.txt")
    assert new_hash != res1["postimage_sha256"]
    # Attempted rollback is denied and preserves the unresolved receipt.
    with pytest.raises(_RRR, match="unresolved|RECOVERY_REQUIRED|ambiguous"):
        executor.fs_rollback("journal-proj", "doc.txt", new_hash)
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v2"
    prepared = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in recovery_dir.glob("recovery-*.json")
        if json.loads(p.read_text(encoding="utf-8")).get("tx_state") == "RECOVERY_REQUIRED"
    ]
    assert len(prepared) == 1, "unresolved receipt must be REQUIRED, never SUPERSEDED"
    # Subsequent writes remain blocked (no silent clearing).
    with pytest.raises(_RRR, match="RECOVERY_REQUIRED blocks mutation"):
        executor.fs_write(
            "journal-proj", "doc.txt", "v3",
            expected_preimage_sha256=new_hash,
        )
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v2"
