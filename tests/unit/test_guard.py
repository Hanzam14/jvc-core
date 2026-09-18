"""Unit tests for PrewriteGuard lifecycle and intent verification."""

import pytest
from jvc.policy.authority import sha256_bytes
from jvc.policy.guard import GuardError, PrewriteGuard


def test_prewrite_guard_lifecycle(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    guard = PrewriteGuard(root)

    test_file = root / "doc.txt"
    test_file.write_text("initial text", encoding="utf-8")
    initial_sha = sha256_bytes(b"initial text")

    manifest_file = tmp_path / "guard-manifest.json"

    # 1. Capture
    manifest = guard.capture(["doc.txt"], manifest_file)
    assert manifest["lifecycle_state"] == "proposed"
    assert manifest["entries"][0]["sha256"] == initial_sha

    # 2. Verify unchanged
    v1 = guard.verify(manifest_file)
    assert v1["status"] == "PASS"

    # 3. Bind intent
    new_content = "updated text"
    new_sha = sha256_bytes(new_content.encode("utf-8"))
    guard.bind_intent(manifest_file, {"doc.txt": new_sha})

    # 4. Transition: proposed -> approved -> applied
    guard.transition(manifest_file, "approved")
    guard.transition(manifest_file, "applied")

    # 5. Simulate write
    test_file.write_text(new_content, encoding="utf-8")

    # 6. Receipt (completes applied -> verified)
    receipt_file = tmp_path / "receipt.json"
    r = guard.receipt(manifest_file, receipt_file)
    assert r["status"] == "PASS"
    assert r["receipt_state"] == "verified"
    assert "doc.txt" in r["changed_paths"]


def test_prewrite_guard_preimage_conflict(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    guard = PrewriteGuard(root)

    target = root / "data.csv"
    target.write_text("v1", encoding="utf-8")

    manifest_file = tmp_path / "manifest.json"
    guard.capture(["data.csv"], manifest_file)

    # Modify file externally
    target.write_text("v2-tampered", encoding="utf-8")

    v = guard.verify(manifest_file)
    assert v["status"] == "FAIL"
    assert any("preimage changed" in f for f in v["failures"])


def test_prewrite_guard_rejects_protected_output_paths(tmp_path):
    from jvc.policy.guard import GuardError, PrewriteGuard

    root = tmp_path / "repo"
    root.mkdir()
    guard = PrewriteGuard(root)
    (root / "ok.txt").write_text("v1", encoding="utf-8")

    with pytest.raises(GuardError, match="protected guard manifest path"):
        guard.capture(["ok.txt"], root / ".continuity" / "evil.json")
    with pytest.raises(GuardError, match="protected guard manifest path"):
        guard.capture(["ok.txt"], root / "token.json")
    # Outside the guarded root remains the host's responsibility.
    manifest = guard.capture(["ok.txt"], tmp_path / "manifest.json")
    assert manifest["lifecycle_state"] == "proposed"
