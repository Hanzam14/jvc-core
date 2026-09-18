"""Unit tests for filesystem boundaries, containment, and path policy."""

import pytest
from jvc.policy.boundaries import (
    assert_permitted_path,
    canonical_target,
    is_control_plane_path,
    is_secret_path,
    is_within,
    normalize_path,
)


def test_is_secret_path():
    assert is_secret_path("secrets.json")
    assert is_secret_path(".env")
    assert is_secret_path(".env.local")
    assert is_secret_path("credentials.toml")
    assert is_secret_path("config/id_rsa")
    assert is_secret_path("certs/server.pem")
    assert is_secret_path("tokens.yaml")
    assert is_secret_path("token.json")
    assert is_secret_path("auth.json")
    assert is_secret_path("bundle.p12")
    assert is_secret_path("bundle.pfx")
    assert not is_secret_path("README.md")
    assert not is_secret_path("src/app.py")


def test_is_control_plane_path():
    assert is_control_plane_path(".git/HEAD")
    assert is_control_plane_path(".continuity/state.json")
    assert is_control_plane_path("_config/governance-policy.json")
    assert is_control_plane_path("_config/anything-else.yaml")
    assert is_control_plane_path("contracts/task.json")
    assert is_control_plane_path("_promotions/plan.md")
    assert is_control_plane_path(".gitattributes")
    assert is_control_plane_path("sub/.gitattributes")
    assert not is_control_plane_path("src/main.py")
    assert not is_control_plane_path("docs/quickstart.md")


def test_canonical_target_rejections(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    # Traversal escape
    with pytest.raises(ValueError, match="escapes project root"):
        canonical_target(root, "../outside.txt")

    # Control chars
    with pytest.raises(ValueError, match="invalid characters detected"):
        canonical_target(root, "file\x00name.txt")

    # URL encoded traversal
    with pytest.raises(ValueError, match="invalid characters detected"):
        canonical_target(root, "%2e%2e/escape.txt")

    # Absolute path
    with pytest.raises(ValueError, match="absolute paths and drive escapes are forbidden"):
        canonical_target(root, "C:/Windows/System32/calc.exe")

    # UNC device-path forms are explicitly unsupported
    with pytest.raises(ValueError, match="unsupported device-path form"):
        canonical_target(root, "//?/C:/Windows/win.ini")
    with pytest.raises(ValueError, match="unsupported device-path form"):
        canonical_target(root, "\\\\?\\C:\\Windows\\win.ini")


def test_assert_permitted_path(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    # Secret path denied
    with pytest.raises(PermissionError, match="secret-bearing path denied"):
        assert_permitted_path(root, "credentials.yaml", "test_op")

    # Control plane denied without operator privilege
    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR_CONTROL_PLANE_CAPABILITY"):
        assert_permitted_path(root, ".git/hooks/pre-commit", "test_op")

    # Control plane allowed WITH operator privilege
    target, rel = assert_permitted_path(
        root, ".git/config", "test_op", is_operator_privileged=True
    )
    assert rel == ".git/config"

    # Ordinary file allowed
    target, rel = assert_permitted_path(root, "src/index.js", "test_op")
    assert rel == "src/index.js"
