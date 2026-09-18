"""HMAC trust-root provisioning tests (Astra Finding 6).

1. trust root under a governed project is rejected
2. first provisioning succeeds
3. second provisioning without explicit rotation is rejected
4. ordinary governed write to the trust store is rejected
5. the secret is never logged/printed by normal commands
6. malformed/unsafe key state fails closed
7. permissions behavior where feasible
8. environment-provided key works without persisting it
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from jvc.configuration import ProjectRegistry, Route
from jvc.policy.authority import (
    decode_and_verify_capability,
    generate_operator_key,
    rotate_operator_key,
    sign_capability,
    validate_and_consume_capability,
    validate_operator_key,
)


@pytest.fixture
def proj(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    route = Route(
        project_id="trust-proj",
        aliases=("trust",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    return tmp_path, root, ProjectRegistry([route])


def test_trust_root_under_governed_project_rejected(proj):
    tmp_path, root, _ = proj
    with pytest.raises(ValueError, match="unsafe trust-root placement"):
        generate_operator_key(root / "operator.key", forbidden_roots=[root])


def test_first_provisioning_succeeds(tmp_path):
    key_path = tmp_path / "trust" / "operator.key"
    report: dict = {}
    secret = generate_operator_key(
        key_path, forbidden_roots=[tmp_path / "governed"], hardening_report=report
    )
    assert isinstance(secret, bytes) and len(secret) == 32
    assert key_path.read_bytes() == secret
    assert report["chmod_ok"] is True
    assert report["acl"]["attempted"] == (os.name == "nt")


def test_second_provisioning_without_rotation_rejected(tmp_path):
    key_path = tmp_path / "trust" / "operator.key"
    generate_operator_key(key_path, forbidden_roots=[])
    with pytest.raises(FileExistsError, match="explicit rotation"):
        generate_operator_key(key_path, forbidden_roots=[])


def test_omitted_placement_context_is_type_error(tmp_path):
    """Placement context is required: omitting it must fail loudly."""
    key_path = tmp_path / "trust" / "operator.key"
    with pytest.raises(TypeError):
        generate_operator_key(key_path)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        rotate_operator_key(key_path)  # type: ignore[call-arg]
    assert not key_path.exists()


def test_explicit_rotation_replaces_key(tmp_path):
    key_path = tmp_path / "trust" / "operator.key"
    first = generate_operator_key(key_path, forbidden_roots=[])
    second = rotate_operator_key(key_path, forbidden_roots=[])
    assert second != first
    assert key_path.read_bytes() == second
    with pytest.raises(FileNotFoundError, match="provision first"):
        rotate_operator_key(tmp_path / "missing.key", forbidden_roots=[])


def test_interrupted_rotation_preserves_old_key(tmp_path, monkeypatch):
    """Atomic rotation: a crash during replace keeps the previous key."""
    import jvc.recovery.store as store

    key_path = tmp_path / "trust" / "operator.key"
    first = generate_operator_key(key_path, forbidden_roots=[])

    def _boom(_src, _dst):
        raise OSError("simulated crash during rotation")

    monkeypatch.setattr(store, "durable_replace", _boom)
    with pytest.raises(OSError, match="simulated crash"):
        rotate_operator_key(key_path, forbidden_roots=[])
    assert key_path.read_bytes() == first
    monkeypatch.undo()
    second = rotate_operator_key(key_path, forbidden_roots=[])
    assert second != first


def test_governed_write_to_trust_store_rejected(proj):
    from jvc.execution.executor import GovernedExecutor

    tmp_path, root, reg = proj
    trust = tmp_path / "trust"
    key_path = trust / "operator.key"
    secret = generate_operator_key(key_path, forbidden_roots=[root])
    executor = GovernedExecutor(
        registry=reg,
        recovery_store=tmp_path / "recovery",
        confirmation_store=trust,
        operator_secret=secret,
    )
    with pytest.raises((ValueError, PermissionError)):
        executor.fs_write("trust-proj", "../trust/operator.key", "tampered")


def test_secret_never_logged_or_printed(tmp_path, capsys):
    key_path = tmp_path / "trust" / "operator.key"
    secret = generate_operator_key(key_path, forbidden_roots=[])
    claims = {"sub": "test", "nonce": "abc", "expires_at": 9999999999}
    token = sign_capability(claims, secret)
    out, err = capsys.readouterr()
    assert secret.hex() not in out
    assert secret.hex() not in err
    assert token not in out
    # The raw key file bytes never appear on stdout either.
    assert key_path.read_bytes().decode("latin1") not in out


def test_malformed_key_state_fails_closed(tmp_path):
    key_path = tmp_path / "trust" / "operator.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(b"too-short")
    raw = key_path.read_bytes()
    assert len(raw) != 32
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        decode_and_verify_capability("bad.token", raw[:0] or b"\x00")
    # Empty key file is equally unusable.
    key_path.write_bytes(b"")
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        decode_and_verify_capability("bad.token", b"")
    # All-zero 32-byte key is weak and rejected.
    with pytest.raises(ValueError, match="all-zero"):
        validate_operator_key(b"\x00" * 32)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        validate_operator_key(b"short")
    # Invalid keys fail closed (False) through the consumption path.
    assert not validate_and_consume_capability(
        tmp_path / "trust", "cid", "tok", "p", "FS_WRITE", "t", {}, None, b""
    )


def test_key_permissions_hardened_where_feasible(tmp_path):
    key_path = tmp_path / "trust" / "operator.key"
    generate_operator_key(key_path, forbidden_roots=[])
    assert key_path.is_file()
    if os.name != "nt":
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600, oct(mode)


def test_windows_acl_result_is_observable(tmp_path, monkeypatch):
    """ACL hardening outcome is reported, never silently ignored."""
    import jvc.policy.authority as auth

    key_path = tmp_path / "trust" / "operator.key"

    calls: list[list[str]] = []

    class _Result:
        returncode = 1
        stderr = b"Access denied (simulated)"

    monkeypatch.setattr(
        auth.subprocess, "run", lambda *a, **k: (calls.append(a[0]), _Result())[1]
    )
    report: dict = {}
    generate_operator_key(key_path, forbidden_roots=[], hardening_report=report)
    # Provisioning succeeds (warning policy) but the failure is observable.
    assert key_path.is_file()
    if os.name == "nt":
        assert report["acl"]["attempted"] is True
        assert report["acl"]["hardened"] is False
        assert "simulated" in report["acl"]["detail"]
        assert calls and calls[0][0] == "icacls"
    else:
        assert report["acl"]["attempted"] is False


def test_environment_secret_protocol(tmp_path, monkeypatch):
    """Documented env protocol: hex secret loads, validates, never persists."""
    import secrets as _secrets

    from jvc.policy.authority import load_operator_secret_from_env

    raw = _secrets.token_bytes(32)
    monkeypatch.setenv("JVC_OPERATOR_SECRET_HEX", raw.hex())
    loaded = load_operator_secret_from_env()
    assert loaded == raw
    # Malformed values fail closed.
    monkeypatch.setenv("JVC_OPERATOR_SECRET_HEX", "not-hex!!")
    with pytest.raises(ValueError, match="64 hex"):
        load_operator_secret_from_env()
    monkeypatch.setenv("JVC_OPERATOR_SECRET_HEX", "00" * 32)
    with pytest.raises(ValueError, match="all-zero"):
        load_operator_secret_from_env()
    monkeypatch.delenv("JVC_OPERATOR_SECRET_HEX")
    with pytest.raises(ValueError, match="64 hex"):
        load_operator_secret_from_env()
    # Nothing was persisted anywhere near the project.
    assert list(tmp_path.rglob("*.key")) == []


def test_environment_key_works_without_persisting(tmp_path):
    import secrets as _secrets

    from jvc.policy.authority import (
        create_confirmation_request,
        validate_and_consume_capability,
    )

    trust = tmp_path / "trust"
    env_secret = _secrets.token_bytes(32)  # never written to disk
    payload = {"path": "x.txt", "content": "y"}
    req = create_confirmation_request(
        trust, "p", "FS_WRITE", "x.txt", payload, None, "CLS", "reason"
    )
    cid = req["confirmation_id"]
    import json as _json

    p_data = _json.loads((trust / "pending" / f"{cid}.json").read_text(encoding="utf-8"))
    claims = {
        "confirmation_id": cid,
        "project_id": "p",
        "operation": "FS_WRITE",
        "target": "x.txt",
        "payload_sha256": p_data["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": p_data["nonce"],
        "expires_at": p_data["expires_at"],
    }
    token = sign_capability(claims, env_secret)
    assert validate_and_consume_capability(
        trust, cid, token, "p", "FS_WRITE", "x.txt", payload, None, env_secret
    )
    # Nothing about the environment key was persisted into the trust store.
    for item in trust.rglob("*"):
        if item.is_file():
            assert env_secret not in item.read_bytes()
