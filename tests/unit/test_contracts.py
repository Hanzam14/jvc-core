"""Unit tests for ICM execution contracts."""

import json
import pytest
from jvc.contracts import (
    ContractError,
    check_applicability,
    command_argv,
    is_verification_satisfied,
    load_contract,
    validate_contract,
)


def test_load_contract_success(tmp_path):
    contract_data = {
        "schema_version": 1,
        "project_id": "test-pkg",
        "cwd": str(tmp_path),
        "persistence": "git",
        "privacy": "standard",
        "permission_class": "read-test",
        "runtime": {"kind": "python", "candidates": [["python"]], "probe_argv": ["--version"]},
        "preflight": {
            "argv": ["{runtime}", "-c", "print('ok')"],
            "timeout_seconds": 15,
            "expected_exit": 0,
            "expected_contains": "ok",
        },
        "verify": None,
        "write_policy": "governed writes only",
    }
    agents_file = tmp_path / "AGENTS.md"
    agents_file.write_text(
        f"# Agents\n\n<!-- ICM_EXECUTION_START -->\n```json\n{json.dumps(contract_data)}\n```\n<!-- ICM_EXECUTION_END -->\n",
        encoding="utf-8",
    )
    loaded = load_contract(agents_file)
    assert loaded.project_id == "test-pkg"
    assert loaded.persistence == "git"


def test_load_contract_malformed_markers(tmp_path):
    agents_file = tmp_path / "AGENTS.md"
    agents_file.write_text("# Agents without markers", encoding="utf-8")
    with pytest.raises(ContractError, match="must contain exactly one ICM execution block"):
        load_contract(agents_file)


def test_validate_contract_errors():
    errors = validate_contract({})
    assert "schema_version must be 1" in errors
    assert "project_id must be a non-empty string" in errors

    bad_runtime = {
        "schema_version": 1,
        "project_id": "proj",
        "cwd": "C:\\fake",
        "persistence": "git",
        "privacy": "standard",
        "permission_class": "read-test",
        "runtime": {"kind": "invalid"},
        "preflight": None,
        "verify": None,
        "write_policy": "policy",
    }
    errors = validate_contract(bad_runtime)
    assert "runtime.kind must be python or none" in errors


def test_check_applicability():
    contract = {
        "permission_class": "docs-only",
        "runtime": {"kind": "none"},
        "preflight": None,
        "verify": {
            "argv": ["python", "test.py"],
            "timeout_seconds": 10,
            "expected_exit": 0,
            "expected_contains": "",
        },
    }
    # preflight is null with docs-only -> NOT_APPLICABLE
    assert check_applicability(contract, "preflight") == "NOT_APPLICABLE"
    # verify is configured dict -> CONFIGURED
    assert check_applicability(contract, "verify") == "CONFIGURED"
    # missing key -> MISSING
    assert check_applicability(contract, "unknown") == "MISSING"


def test_is_verification_satisfied():
    pass_res = {
        "name": "preflight",
        "status": "PASS",
        "executed": True,
        "applicable": True,
        "returncode": 0,
        "failure_kind": "none",
    }
    assert is_verification_satisfied(pass_res, expected_name="preflight")

    fail_res = {
        "name": "preflight",
        "status": "FAIL",
        "executed": True,
        "applicable": True,
        "returncode": 1,
        "failure_kind": "behavioral",
    }
    assert not is_verification_satisfied(fail_res, expected_name="preflight")

    na_res = {
        "name": "verify",
        "status": "NOT_APPLICABLE",
        "executed": False,
        "applicable": False,
        "failure_kind": "none",
    }
    assert is_verification_satisfied(na_res, allow_na=True, expected_name="verify")
    assert not is_verification_satisfied(na_res, allow_na=False, expected_name="verify")
