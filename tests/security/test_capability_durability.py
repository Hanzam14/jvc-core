"""Capability replay durability and trust-store boundary tests (Astra Finding 2).

Contract under test: capability single-use is guaranteed within ONE
configured trust store under the supported local-host model. The consumed
record is durably persisted (flush + fsync) BEFORE the privileged action
executes, and the trust store is host-owned outside every governed root.
"""

from __future__ import annotations

import concurrent.futures
import json
import sys
from pathlib import Path

import pytest

from jvc.policy.authority import (
    create_confirmation_request,
    sha256_bytes,
    sign_capability,
    validate_and_consume_capability,
)

SRC_DIR = Path(__file__).resolve().parents[2] / "src"


def _make_claims(conf_store: Path, cid: str, payload: dict, secret: bytes) -> str:
    proposal = conf_store / "pending" / f"{cid}.json"
    p_data = json.loads(proposal.read_text(encoding="utf-8"))
    claims = {
        "confirmation_id": cid,
        "project_id": "replay-proj",
        "operation": "FS_WRITE",
        "target": "action.txt",
        "payload_sha256": p_data["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": p_data["nonce"],
        "expires_at": p_data["expires_at"],
    }
    return sign_capability(claims, secret), payload


@pytest.fixture
def replay_env(tmp_path):
    import secrets as _secrets

    conf_store = tmp_path / "trust"
    secret = _secrets.token_bytes(32)
    return tmp_path, conf_store, secret


def _issue(conf_store: Path, secret: bytes, target: str = "action.txt"):
    payload = {"path": target, "content": "privileged"}
    req = create_confirmation_request(
        conf_store,
        "replay-proj",
        "FS_WRITE",
        target,
        payload,
        expected_preimage_sha256=None,
        confirmation_class="OPERATOR_ACTION",
        reason="replay test",
    )
    cid = req["confirmation_id"]
    token, _ = _make_claims(conf_store, cid, payload, secret)
    return cid, token, payload


def test_sequential_replay_rejected(replay_env):
    _, conf_store, secret = replay_env
    cid, token, payload = _issue(conf_store, secret)
    assert validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )
    assert not validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )


def _child_consume(payload: dict) -> bool:
    sys.path.insert(0, str(payload["src_dir"]))
    from jvc.policy.authority import validate_and_consume_capability

    return bool(
        validate_and_consume_capability(
            Path(payload["store"]),
            payload["cid"],
            payload["token"],
            "replay-proj",
            "FS_WRITE",
            "action.txt",
            payload["payload"],
            None,
            bytes.fromhex(payload["secret_hex"]),
        )
    )


def test_concurrent_replay_processes_exactly_one_winner(replay_env):
    tmp_path, conf_store, secret = replay_env
    cid, token, payload = _issue(conf_store, secret)
    child_payload = {
        "src_dir": str(SRC_DIR),
        "store": str(conf_store),
        "cid": cid,
        "token": token,
        "payload": payload,
        "secret_hex": secret.hex(),
    }
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_child_consume, [child_payload, child_payload]))
    assert results.count(True) == 1, results
    assert results.count(False) == 1, results


def test_replay_store_outside_governed_root(tmp_path):
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    root = tmp_path / "project"
    root.mkdir()
    route = Route(
        project_id="replay-proj",
        aliases=("replay",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=tmp_path / "recovery",
        confirmation_store=tmp_path / "trust",
    )
    assert executor.confirmation_store.resolve().is_relative_to(tmp_path)
    assert not str(executor.confirmation_store.resolve()).startswith(str(root.resolve()))


def test_trust_store_inside_governed_root_rejected(tmp_path):
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    root = tmp_path / "project"
    root.mkdir()
    route = Route(
        project_id="replay-proj",
        aliases=("replay",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    with pytest.raises(ValueError, match="host-owned outside governed root"):
        GovernedExecutor(
            registry=ProjectRegistry([route]),
            recovery_store=root / "recovery-inside",
            confirmation_store=tmp_path / "trust",
        )
    with pytest.raises(ValueError, match="host-owned outside governed root"):
        GovernedExecutor(
            registry=ProjectRegistry([route]),
            recovery_store=tmp_path / "recovery",
            confirmation_store=root / "trust-inside",
        )


def test_governed_write_cannot_modify_replay_store(tmp_path):
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    root = tmp_path / "project"
    root.mkdir()
    trust = tmp_path / "trust"
    trust.mkdir()
    (trust / "sentinel.txt").write_text("host-owned", encoding="utf-8")
    route = Route(
        project_id="replay-proj",
        aliases=("replay",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=tmp_path / "recovery",
        confirmation_store=trust,
    )
    # Path traversal toward the sibling trust store is contained.
    with pytest.raises((ValueError, PermissionError)):
        executor.fs_write("replay-proj", "../trust/sentinel.txt", "tampered")
    assert (trust / "sentinel.txt").read_text(encoding="utf-8") == "host-owned"


def test_restart_reopen_same_store_retains_nonce(replay_env):
    tmp_path, conf_store, secret = replay_env
    cid, token, payload = _issue(conf_store, secret)
    assert validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )
    # "Restart": re-open the same trust store path in a fresh handle set.
    reopened = Path(str(conf_store))
    assert not validate_and_consume_capability(
        reopened, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )
    consumed = list((conf_store / "consumed").glob("*.json"))
    assert len(consumed) == 1


def test_corrupt_pending_proposal_fails_closed(replay_env):
    _, conf_store, secret = replay_env
    cid, token, payload = _issue(conf_store, secret)
    (conf_store / "pending" / f"{cid}.json").write_text("{corrupt json", encoding="utf-8")
    assert not validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )
    assert list((conf_store / "consumed").glob("*.json")) == []


def test_separate_stores_do_not_share_state(replay_env):
    """Documents the contract limit: separate trust stores are independent."""
    tmp_path, conf_store, secret = replay_env
    other_store = tmp_path / "other-trust"
    cid, token, payload = _issue(conf_store, secret)
    assert validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )
    # The same token against a store that never saw the proposal fails
    # closed (unknown proposal), which is the documented boundary: the
    # guarantee holds within one configured trust store only.
    assert not validate_and_consume_capability(
        other_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )


def test_nonce_fsync_failure_denies_authorization(replay_env, monkeypatch):
    """A failed nonce fsync must deny, never authorize (Astra §19.5)."""
    import jvc.policy.authority as auth

    _, conf_store, secret = replay_env
    cid, token, payload = _issue(conf_store, secret)

    def _boom(_fileno):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(auth, "_sync_file", _boom)
    assert not validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )
    # No durable consumed record remains; the proposal is retained for retry.
    assert list((conf_store / "consumed").glob("*.json")) == []
    assert (conf_store / "pending" / f"{cid}.json").is_file()


def test_directory_sync_failure_matches_documented_contract(replay_env, monkeypatch):
    """Directory sync is best-effort: its failure must not deny authorization."""
    import jvc.policy.authority as auth

    _, conf_store, secret = replay_env
    cid, token, payload = _issue(conf_store, secret)
    monkeypatch.setattr(auth, "_sync_dir", lambda _d: "failed")
    # File-content durability (_sync_file) still succeeds, so authorization
    # is granted per the documented weaker guarantee.
    assert validate_and_consume_capability(
        conf_store, cid, token, "replay-proj", "FS_WRITE", "action.txt",
        payload, None, secret,
    )


def test_privileged_action_not_executed_on_persistence_failure(tmp_path, monkeypatch):
    """End-to-end: fsync failure => no capability => no privileged write."""
    import jvc.policy.authority as auth
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor
    from jvc.policy.authority import (
        create_confirmation_request,
        sha256_bytes,
        sign_capability,
    )

    root = tmp_path / "project"
    root.mkdir()
    trust = tmp_path / "trust"
    secret = __import__("secrets").token_bytes(32)
    route = Route(
        project_id="replay-proj",
        aliases=("replay",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=tmp_path / "recovery",
        confirmation_store=trust,
        operator_secret=secret,
    )
    target = ".continuity/state.json"
    content = '{"privileged": true}'
    payload = {
        "path": target,
        "content_sha256": sha256_bytes(content.encode()),
        "bytes": len(content.encode()),
    }
    req = create_confirmation_request(
        trust, "replay-proj", "FS_WRITE", target, payload, None,
        "OPERATOR_CONTROL_PLANE", "test",
    )
    cid = req["confirmation_id"]
    proposal = json.loads((trust / "pending" / f"{cid}.json").read_text(encoding="utf-8"))
    claims = {
        "confirmation_id": cid,
        "project_id": "replay-proj",
        "operation": "FS_WRITE",
        "target": target,
        "payload_sha256": proposal["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": proposal["nonce"],
        "expires_at": proposal["expires_at"],
    }
    token = sign_capability(claims, secret)

    def _boom(_fileno):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(auth, "_sync_file", _boom)
    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR"):
        executor.fs_write(
            "replay-proj", target, content,
            confirmation_id=cid, confirmation_token=token,
        )
    # The privileged action demonstrably did not execute.
    assert not (root / ".continuity" / "state.json").exists()
    assert list((trust / "consumed").glob("*.json")) == []


def test_held_write_full_round_trip(tmp_path):
    """Proposal -> operator signature -> fs_write authorizes a HELD write.

    Regression test for the proposal/validation payload mismatch: the
    executor must accept a capability signed over the exact proposal it
    issued (single canonical payload construction).
    """
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor
    from jvc.policy.authority import sha256_bytes, sign_capability

    root = tmp_path / "held-proj"
    root.mkdir()
    trust = tmp_path / "trust"
    secret = __import__("secrets").token_bytes(32)
    route = Route(
        project_id="held-proj",
        aliases=("held",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="held",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=tmp_path / "recovery",
        confirmation_store=trust,
        operator_secret=secret,
    )
    # 1. Ungated HELD write yields a confirmation request, not a write.
    first = executor.fs_write("held-proj", "notes.txt", "hello held")
    assert first["status"] == "REQUIRES_CONFIRMATION"
    cid = first["confirmation_id"]

    # 2. Operator signs exactly the issued proposal.
    proposal = json.loads((trust / "pending" / f"{cid}.json").read_text(encoding="utf-8"))
    claims = {
        "confirmation_id": cid,
        "project_id": "held-proj",
        "operation": "FS_WRITE",
        "target": "notes.txt",
        "payload_sha256": proposal["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": proposal["nonce"],
        "expires_at": proposal["expires_at"],
    }
    token = sign_capability(claims, secret)

    # 3. The signed capability authorizes the write.
    res = executor.fs_write(
        "held-proj", "notes.txt", "hello held",
        confirmation_id=cid, confirmation_token=token,
    )
    assert res["status"] == "PASS"
    assert (root / "notes.txt").read_text(encoding="utf-8") == "hello held"

    # 4. Replaying the SAME confirmation ID/token is denied: no second
    # write occurs; a fresh confirmation request is required instead.
    replay = executor.fs_write(
        "held-proj", "notes.txt", "hello held",
        confirmation_id=cid, confirmation_token=token,
    )
    assert replay["status"] == "REQUIRES_CONFIRMATION"
    assert replay["confirmation_id"] != cid
    assert (root / "notes.txt").read_text(encoding="utf-8") == "hello held"
