"""Security tests for concurrency, CAS conflicts, and capability replay.

Review Area B: Concurrency / CAS / Replay protections.
"""

import concurrent.futures
import json
import pytest
from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor
from jvc.policy.authority import (
    create_confirmation_request,
    generate_operator_key,
    sha256_file,
    sign_capability,
    validate_and_consume_capability,
)


@pytest.fixture
def secure_env(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    conf_store = tmp_path / "confirmations"
    key_file = tmp_path / "operator.key"
    secret = generate_operator_key(key_file, forbidden_roots=[root])

    route = Route(
        project_id="concurrency-proj",
        aliases=("proj",),
        root=root,
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    executor = GovernedExecutor(
        registry=reg,
        recovery_store=tmp_path / "recovery",
        confirmation_store=conf_store,
        operator_secret=secret,
    )
    return root, executor, secret, conf_store


def test_cas_conflict_on_intervening_write(secure_env):
    root, executor, _, _ = secure_env
    res = executor.fs_write("concurrency-proj", "state.txt", "initial content")
    initial_hash = res["postimage_sha256"]

    # Intervening write
    (root / "state.txt").write_text("intervening modification", encoding="utf-8")

    # Stale write attempt with initial_hash fails
    with pytest.raises(ValueError, match="preimage CAS conflict"):
        executor.fs_write(
            "concurrency-proj",
            "state.txt",
            "new content",
            expected_preimage_sha256=initial_hash,
        )


def test_capability_replay_attack_rejected(secure_env):
    _, executor, secret, conf_store = secure_env
    payload = {"path": "action.txt", "content": "privileged"}

    req = create_confirmation_request(
        conf_store,
        "concurrency-proj",
        "FS_WRITE",
        "action.txt",
        payload,
        expected_preimage_sha256=None,
        confirmation_class="OPERATOR_ACTION",
        reason="test replay",
    )
    cid = req["confirmation_id"]
    proposal = conf_store / "pending" / f"{cid}.json"
    p_data = json.loads(proposal.read_text(encoding="utf-8"))

    claims = {
        "confirmation_id": cid,
        "project_id": "concurrency-proj",
        "operation": "FS_WRITE",
        "target": "action.txt",
        "payload_sha256": p_data["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": p_data["nonce"],
        "expires_at": p_data["expires_at"],
    }
    token = sign_capability(claims, secret)

    # First validation succeeds
    assert validate_and_consume_capability(
        conf_store, cid, token, "concurrency-proj", "FS_WRITE", "action.txt", payload, None, secret
    )

    # Replay attempt fails immediately
    assert not validate_and_consume_capability(
        conf_store, cid, token, "concurrency-proj", "FS_WRITE", "action.txt", payload, None, secret
    )


def test_concurrent_capability_consumption_race(secure_env):
    _, _, secret, conf_store = secure_env
    payload = {"path": "race.txt", "content": "race"}

    req = create_confirmation_request(
        conf_store,
        "concurrency-proj",
        "FS_WRITE",
        "race.txt",
        payload,
        expected_preimage_sha256=None,
        confirmation_class="RACE_TEST",
        reason="test concurrent race",
    )
    cid = req["confirmation_id"]
    proposal = conf_store / "pending" / f"{cid}.json"
    p_data = json.loads(proposal.read_text(encoding="utf-8"))

    claims = {
        "confirmation_id": cid,
        "project_id": "concurrency-proj",
        "operation": "FS_WRITE",
        "target": "race.txt",
        "payload_sha256": p_data["payload_sha256"],
        "expected_preimage_sha256": "",
        "nonce": p_data["nonce"],
        "expires_at": p_data["expires_at"],
    }
    token = sign_capability(claims, secret)

    # Launch two concurrent threads trying to consume the same capability
    def attempt():
        return validate_and_consume_capability(
            conf_store, cid, token, "concurrency-proj", "FS_WRITE", "race.txt", payload, None, secret
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(attempt)
        f2 = ex.submit(attempt)
        results = [f1.result(), f2.result()]

    # Exactly one must succeed, and exactly one must fail
    assert results.count(True) == 1
    assert results.count(False) == 1
