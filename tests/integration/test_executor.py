"""Integration tests for GovernedExecutor file mutations and rollbacks."""

import pytest
from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor
from jvc.policy.authority import generate_operator_key, sha256_file, sign_capability
from jvc.recovery.store import RecoveryStore


@pytest.fixture
def test_env(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    recovery = tmp_path / "recovery"
    conf_store = tmp_path / "confirmations"
    key_file = tmp_path / "operator.key"
    secret = generate_operator_key(key_file, forbidden_roots=[root])

    route = Route(
        project_id="my-proj",
        aliases=("proj",),
        root=root,
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    executor = GovernedExecutor(
        registry=reg,
        recovery_store=recovery,
        confirmation_store=conf_store,
        operator_secret=secret,
    )
    return root, executor, secret, conf_store


def test_fs_write_create_and_edit(test_env):
    root, executor, _, _ = test_env

    # 1. Create new file
    res1 = executor.fs_write("my-proj", "hello.txt", "hello world")
    assert res1["status"] == "PASS"
    assert res1["op_class"] == "FILE_CREATE"
    assert (root / "hello.txt").read_text(encoding="utf-8") == "hello world"

    # 2. Edit existing file with matching expected_preimage
    pre_sha = res1["postimage_sha256"]
    res2 = executor.fs_write(
        "my-proj", "hello.txt", "hello updated", expected_preimage_sha256=pre_sha
    )
    assert res2["status"] == "PASS"
    assert res2["op_class"] == "FILE_EDIT"
    assert (root / "hello.txt").read_text(encoding="utf-8") == "hello updated"


def test_fs_write_stale_preimage_rejection(test_env):
    root, executor, _, _ = test_env
    res = executor.fs_write("my-proj", "file.txt", "initial")
    correct_sha = res["postimage_sha256"]

    with pytest.raises(ValueError, match="preimage CAS conflict"):
        executor.fs_write(
            "my-proj",
            "file.txt",
            "tamper",
            expected_preimage_sha256="0" * 64,
        )


def test_fs_rollback_durable(test_env):
    root, executor, _, _ = test_env
    res1 = executor.fs_write("my-proj", "file.txt", "version 1")
    v1_sha = res1["postimage_sha256"]

    res2 = executor.fs_write(
        "my-proj", "file.txt", "version 2", expected_preimage_sha256=v1_sha
    )
    v2_sha = res2["postimage_sha256"]

    # Rollback version 2 -> restores version 1
    rb = executor.fs_rollback("my-proj", "file.txt", v2_sha)
    assert rb["status"] == "ROLLED_BACK"
    assert (root / "file.txt").read_text(encoding="utf-8") == "version 1"
    assert sha256_file(root / "file.txt") == v1_sha


def test_control_plane_write_authorization_flow(test_env):
    root, executor, secret, conf_store = test_env

    # 1. Unprivileged attempt to write control-plane target is denied
    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR_CONTROL_PLANE_CAPABILITY"):
        executor.fs_write("my-proj", ".continuity/state.json", "{}")

    # 2. Pre-create proposal record & sign capability
    from jvc.policy.authority import create_confirmation_request, sha256_bytes
    payload = {
        "path": ".continuity/state.json",
        "content_sha256": sha256_bytes(b"{}"),
        "bytes": len(b"{}"),
    }
    req = create_confirmation_request(
        conf_store,
        "my-proj",
        "FS_WRITE",
        ".continuity/state.json",
        payload,
        expected_preimage_sha256=None,
        confirmation_class="OPERATOR_CONTROL_PLANE",
        reason="authorized state init",
    )
    cid = req["confirmation_id"]
    import json
    p_data = json.loads((conf_store / "pending" / f"{cid}.json").read_text(encoding="utf-8"))
    claims = {
        "confirmation_id": cid,
        "project_id": "my-proj",
        "operation": "FS_WRITE",
        "target": ".continuity/state.json",
        "payload_sha256": p_data["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": p_data["nonce"],
        "expires_at": p_data["expires_at"],
    }
    token = sign_capability(claims, secret)

    # 3. Authorized write succeeds
    res = executor.fs_write(
        "my-proj",
        ".continuity/state.json",
        "{}",
        confirmation_id=cid,
        confirmation_token=token,
    )
    assert res["status"] == "PASS"
    assert (root / ".continuity/state.json").read_text(encoding="utf-8") == "{}"
