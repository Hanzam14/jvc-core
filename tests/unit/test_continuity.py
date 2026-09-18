"""Unit tests for project continuity, state revision CAS, and handoff integrity."""

import pytest
from jvc.continuity.state import ConflictError, ContinuityError, ContinuityManager
from jvc.policy.authority import sha256_file


def test_continuity_lifecycle(tmp_path):
    handoff = tmp_path / "HANDOFF.md"
    handoff.write_text("# Initial Handoff\n", encoding="utf-8")
    h_sha1 = sha256_file(handoff)

    cm = ContinuityManager(tmp_path)
    assert not cm.is_initialized()

    # 1. Init
    init_res = cm.init("test-proj")
    assert init_res["status"] == "PASS"
    assert cm.is_initialized()
    state = cm.load_state()
    assert state["metadata_revision"] == 1
    assert state["handoff_sha256"] == h_sha1

    # 2. Advance revision with checkpoint
    cp1 = cm.checkpoint(
        expected_handoff_sha256=h_sha1,
        payload={"task": "first step complete"},
        expected_metadata_revision=1,
    )
    assert cp1["metadata_revision"] == 2

    # 3. Conflict detection on stale revision
    with pytest.raises(ConflictError, match="metadata revision conflict"):
        cm.checkpoint(
            expected_handoff_sha256=h_sha1,
            payload={"task": "stale step"},
            expected_metadata_revision=1,  # Stale! Current is 2
        )

    # 4. Conflict detection on handoff drift
    handoff.write_text("# Externally Updated Handoff\n", encoding="utf-8")
    with pytest.raises(ConflictError, match="handoff SHA-256 conflict"):
        cm.checkpoint(
            expected_handoff_sha256=h_sha1,  # Stale handoff hash!
            payload={"task": "step 3"},
            expected_metadata_revision=2,
        )

    # 5. Reconcile handoff
    h_sha2 = sha256_file(handoff)
    rec = cm.reconcile_handoff(
        expected_handoff_sha256=h_sha1,
        observed_handoff_sha256=h_sha2,
        payload={"reason": "external edit adopted"},
        expected_metadata_revision=2,
    )
    assert rec["metadata_revision"] == 3

    # 6. Verify health
    v = cm.verify()
    assert v["status"] == "PASS"
    assert v["metadata_revision"] == 3
