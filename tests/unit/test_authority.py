"""Unit tests for host operator capability signing and trusted executable resolution."""

import time
import pytest
from jvc.policy.authority import (
    create_confirmation_request,
    decode_and_verify_capability,
    generate_operator_key,
    resolve_trusted_executable,
    sha256_file,
    sign_capability,
    validate_and_consume_capability,
)


def test_operator_key_generation(tmp_path):
    key_path = tmp_path / "operator.key"
    key = generate_operator_key(key_path, forbidden_roots=[tmp_path / "governed"])
    assert len(key) == 32
    assert key_path.read_bytes() == key


def test_capability_signing_and_verification():
    secret = b"k" * 32
    claims = {"user": "operator", "action": "promote", "nonce": "abc123xyz"}
    token = sign_capability(claims, secret)

    verified = decode_and_verify_capability(token, secret)
    assert verified["user"] == "operator"
    assert verified["nonce"] == "abc123xyz"

    # Tampered signature
    body, sig = token.split(".", 1)
    tampered_token = f"{body}.{sig[:-4]}0000"
    with pytest.raises(PermissionError, match="invalid capability signature"):
        decode_and_verify_capability(tampered_token, secret)


def test_validate_and_consume_single_use(tmp_path):
    conf_store = tmp_path / "confirmations"
    secret = b"s" * 32
    payload = {"path": "file.txt", "content": "hello"}

    req = create_confirmation_request(
        conf_store,
        "demo-proj",
        "FS_WRITE",
        "file.txt",
        payload,
        expected_preimage_sha256=None,
        confirmation_class="OPERATOR_GATE",
        reason="test capability",
    )
    cid = req["confirmation_id"]
    proposal = conf_store / "pending" / f"{cid}.json"
    import json
    p_data = json.loads(proposal.read_text(encoding="utf-8"))

    claims = {
        "confirmation_id": cid,
        "project_id": "demo-proj",
        "operation": "FS_WRITE",
        "target": "file.txt",
        "payload_sha256": p_data["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": p_data["nonce"],
        "expires_at": p_data["expires_at"],
    }
    token = sign_capability(claims, secret)

    # 1. First consumption -> succeeds
    res1 = validate_and_consume_capability(
        conf_store, cid, token, "demo-proj", "FS_WRITE", "file.txt", payload, None, secret
    )
    assert res1 is True

    # 2. Replay attempt -> denied
    res2 = validate_and_consume_capability(
        conf_store, cid, token, "demo-proj", "FS_WRITE", "file.txt", payload, None, secret
    )
    assert res2 is False


def test_resolve_trusted_executable(tmp_path):
    dummy_exe = tmp_path / "my_tool.exe"
    dummy_exe.write_bytes(b"MZBINARYCONTENT")
    expected_hash = sha256_file(dummy_exe)

    spec = {
        "my_tool": {
            "class": "my_tool",
            "path": str(dummy_exe),
            "sha256": expected_hash,
        }
    }
    resolved = resolve_trusted_executable("my_tool", spec)
    assert resolved == dummy_exe

    # Integrity mismatch
    tampered_spec = {
        "my_tool": {
            "class": "my_tool",
            "path": str(dummy_exe),
            "sha256": "0" * 64,
        }
    }
    with pytest.raises(PermissionError, match="integrity mismatch"):
        resolve_trusted_executable("my_tool", tampered_spec)
