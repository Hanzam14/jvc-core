"""Integration tests for RecoveryStore durability and lifecycle."""

import time
import pytest
from jvc.policy.authority import sha256_bytes, sha256_file
from jvc.recovery.store import RecoveryError, RecoveryStore


def test_recovery_store_full_flow(tmp_path):
    store_dir = tmp_path / "recovery"
    store = RecoveryStore(store_dir)
    target = tmp_path / "file.txt"

    # 1. Save preimage of absent file
    rec1 = store.save_preimage("proj", target, None)
    assert not rec1["preimage_exists"]
    assert rec1["preimage_sha256"] is None

    # Write file
    target.write_text("created text", encoding="utf-8")
    post1 = sha256_file(target)
    store.record_postimage(rec1["receipt_id"], post1)

    # 2. Rollback newly created file -> deletes target
    rb1 = store.rollback("proj", target, post1)
    assert rb1["status"] == "ROLLED_BACK"
    assert rb1["action"] == "deleted"
    assert not target.exists()

    # 3. Create file again and edit
    target.write_text("v1 content", encoding="utf-8")
    v1_bytes = target.read_bytes()
    v1_sha = sha256_bytes(v1_bytes)

    rec2 = store.save_preimage("proj", target, v1_bytes)
    assert rec2["preimage_exists"]
    assert rec2["preimage_sha256"] == v1_sha

    target.write_text("v2 content", encoding="utf-8")
    v2_sha = sha256_file(target)
    store.record_postimage(rec2["receipt_id"], v2_sha)

    # 4. Rollback edited file -> restores v1
    rb2 = store.rollback("proj", target, v2_sha)
    assert rb2["status"] == "ROLLED_BACK"
    assert rb2["action"] == "restored"
    assert target.read_text(encoding="utf-8") == "v1 content"


def test_recovery_store_stale_postimage_conflict(tmp_path):
    store = RecoveryStore(tmp_path / "recovery")
    target = tmp_path / "file.txt"
    target.write_text("initial", encoding="utf-8")
    rec = store.save_preimage("proj", target, b"initial")

    target.write_text("new content", encoding="utf-8")
    new_sha = sha256_file(target)
    store.record_postimage(rec["receipt_id"], new_sha)

    # Attempt rollback with wrong expected postimage
    with pytest.raises(RecoveryError, match="stale postimage"):
        store.rollback("proj", target, "0" * 64)
