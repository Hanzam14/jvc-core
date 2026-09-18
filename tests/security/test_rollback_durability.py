"""Security tests for rollback durability and atomic restoration.

Review Area C: Rollback durability and failure/interruption behavior.
"""

import json
import pytest
from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor
from jvc.policy.authority import sha256_file
from jvc.recovery.store import RecoveryError, RecoveryStore


@pytest.fixture
def rollback_env(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    recovery_dir = tmp_path / "recovery"
    recovery_dir.mkdir()

    route = Route(
        project_id="rollback-proj",
        aliases=("proj",),
        root=root,
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    store = RecoveryStore(recovery_dir)
    executor = GovernedExecutor(registry=reg, recovery_store=store)
    return root, executor, store, recovery_dir


def test_tampered_backup_fails_closed_without_modifying_target(rollback_env):
    root, executor, store, recovery_dir = rollback_env

    # 1. Initial write
    res1 = executor.fs_write("rollback-proj", "data.bin", "original version")
    v1_sha = res1["postimage_sha256"]
    receipt_id = res1["receipt_id"]

    # 2. Second write
    res2 = executor.fs_write(
        "rollback-proj", "data.bin", "modified version", expected_preimage_sha256=v1_sha
    )
    v2_sha = res2["postimage_sha256"]
    receipt2_id = res2["receipt_id"]

    # 3. Corrupt the backup file for receipt2 in recovery store
    backup_file = recovery_dir / f"{receipt2_id}.bak"
    assert backup_file.is_file()
    backup_file.write_bytes(b"corrupted backup bytes")

    # 4. Attempt rollback -> must fail closed with RecoveryError
    with pytest.raises(RecoveryError, match="hash mismatch"):
        executor.fs_rollback("rollback-proj", "data.bin", v2_sha)

    # 5. Target file MUST remain untouched (still "modified version")
    assert (root / "data.bin").read_text(encoding="utf-8") == "modified version"


def test_rollback_on_newer_work_rejected(rollback_env):
    root, executor, _, _ = rollback_env

    res1 = executor.fs_write("rollback-proj", "doc.txt", "v1")
    res2 = executor.fs_write("rollback-proj", "doc.txt", "v2", expected_preimage_sha256=res1["postimage_sha256"])

    # File is updated to v3
    (root / "doc.txt").write_text("v3-newer-work", encoding="utf-8")

    # Attempting to rollback assuming postimage was v2 fails because current content is v3
    with pytest.raises(RecoveryError, match="stale postimage"):
        executor.fs_rollback("rollback-proj", "doc.txt", res2["postimage_sha256"])

    # Target is preserved
    assert (root / "doc.txt").read_text(encoding="utf-8") == "v3-newer-work"
