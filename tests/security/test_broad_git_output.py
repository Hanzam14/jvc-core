"""Bounded git-diff regression tests (Astra Finding 3).

0.1.0 contract: git diff is a bounded inspection interface over explicitly
listed files, NOT a repository-wide confidentiality scanner. Repository-wide
diff is removed; directories are rejected; output is byte-bounded.
"""

from __future__ import annotations

import subprocess

import pytest

from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor


@pytest.fixture
def git_repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init"], cwd=str(root), check=True, capture_output=True)
    # Pin line-ending conversion explicitly: JVC's sanitized subprocess
    # environment ignores ambient system autocrlf, so fixtures must not
    # depend on it (otherwise phantom `M` entries appear under one view).
    subprocess.run(
        ["git", "config", "core.autocrlf", "false"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / "README.md").write_text("public base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )

    route = Route(
        project_id="test-git",
        aliases=("repo",),
        root=root,
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    executor = GovernedExecutor(registry=reg, recovery_store=tmp_path / "recovery")
    return root, executor


def _dirty(root, rel: str, content: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_protected_exact_file_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, ".continuity/state.json", "{}")
    with pytest.raises(PermissionError, match="control-plane|REQUIRES_OPERATOR"):
        executor.git_diff("test-git", path=".continuity/state.json")


def test_directory_with_protected_descendant_cannot_leak(git_repo):
    root, executor = git_repo
    _dirty(root, "docs/public.md", "public base\n")
    _dirty(root, "docs/token.json", '{"token": "SECRET-123"}')
    subprocess.run(["git", "add", "docs/public.md"], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add public doc"], cwd=str(root), check=True, capture_output=True
    )
    _dirty(root, "docs/public.md", "public change\n")
    # Directories are rejected outright in 0.1.0 (files only).
    with pytest.raises(ValueError, match="directory diff|exact relative file"):
        executor.git_diff("test-git", path="docs")
    # And the protected descendant itself is denied directly.
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", path="docs/token.json")
    # The safe sibling still diffs without leaking the secret.
    res = executor.git_diff("test-git", path="docs/public.md")
    assert res["status"] == "PASS"
    assert "public change" in res["diff"]
    assert "SECRET-123" not in res["diff"]


def test_token_json_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, "token.json", '{"token": "SECRET"}')
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", path="token.json")


def test_auth_json_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, "auth.json", '{"auth": "SECRET"}')
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", path="auth.json")


def test_id_rsa_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, "id_rsa", "PRIVATE KEY BYTES")
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", path="id_rsa")


def test_p12_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, "bundle.p12", "PKCS12 BYTES")
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", path="bundle.p12")


def test_pfx_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, "bundle.pfx", "PKCS12 BYTES")
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", path="bundle.pfx")


def test_contracts_control_paths_do_not_leak(git_repo):
    root, executor = git_repo
    _dirty(root, "contracts/secret-deal.md", "CONFIDENTIAL TERMS")
    with pytest.raises(PermissionError, match="control-plane|REQUIRES_OPERATOR"):
        executor.git_diff("test-git", path="contracts/secret-deal.md")


def test_promotions_does_not_leak(git_repo):
    root, executor = git_repo
    _dirty(root, "_promotions/plan.md", "PROMOTION SECRET")
    with pytest.raises(PermissionError, match="control-plane|REQUIRES_OPERATOR"):
        executor.git_diff("test-git", path="_promotions/plan.md")


def test_config_surfaces_do_not_leak(git_repo):
    root, executor = git_repo
    _dirty(root, "_config/governance-policy.json", '{"admin": true}')
    with pytest.raises(PermissionError, match="control-plane|REQUIRES_OPERATOR"):
        executor.git_diff("test-git", path="_config/governance-policy.json")


def test_safe_file_diff_succeeds(git_repo):
    root, executor = git_repo
    _dirty(root, "README.md", "safe public change\n")
    res = executor.git_diff("test-git", path="README.md")
    assert res["status"] == "PASS"
    assert res["truncated"] is False
    assert "safe public change" in res["diff"]


def test_output_bound_truncates_explicitly(git_repo):
    root, executor = git_repo
    _dirty(root, "README.md", "x" * 5000 + "\n")
    res = executor.git_diff("test-git", path="README.md", max_bytes=512)
    assert res["status"] == "PASS"
    assert res["truncated"] is True
    assert res["max_bytes"] == 512
    assert len(res["diff"].encode("utf-8", errors="replace")) <= 512


def test_no_repository_wide_diff_available(git_repo):
    _, executor = git_repo
    with pytest.raises(ValueError, match="repository-wide diff is not available"):
        executor.git_diff("test-git")

def test_multi_path_diff_validates_every_path(git_repo):
    root, executor = git_repo
    _dirty(root, "a.txt", "alpha change\n")
    _dirty(root, "token.json", '{"token": "SECRET"}')
    subprocess.run(["git", "add", "a.txt"], cwd=str(root), check=True, capture_output=True)
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_diff("test-git", paths=["a.txt", "token.json"])


def test_deleted_directory_pathspec_rejected(git_repo):
    root, executor = git_repo
    _dirty(root, "deldir/one.txt", "one\n")
    _dirty(root, "deldir/two.txt", "two\n")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add dir"], cwd=str(root), check=True, capture_output=True
    )
    import shutil

    shutil.rmtree(root / "deldir")
    # The directory no longer exists on disk, but Git still represents it in
    # the index: the pathspec must be rejected, not expanded recursively.
    with pytest.raises(ValueError, match="directory pathspec|exact relative file"):
        executor.git_diff("test-git", path="deldir")


def test_deleted_exact_file_allowed(git_repo):
    root, executor = git_repo
    _dirty(root, "gone.txt", "here\n")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add file"], cwd=str(root), check=True, capture_output=True
    )
    (root / "gone.txt").unlink()
    res = executor.git_diff("test-git", path="gone.txt")
    assert res["status"] == "PASS"
    assert "gone.txt" in res["diff"]


def test_multibyte_utf8_boundary_never_exceeds(git_repo):
    root, executor = git_repo
    _dirty(root, "uni.txt", "base\n")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add uni"], cwd=str(root), check=True, capture_output=True
    )
    _dirty(root, "uni.txt", "héllo wörld ✓✓✓\n")
    full = executor.git_diff("test-git", path="uni.txt")["diff"]
    assert "✓" in full
    for bound in (0, 1, 2, 3, 5, 16, 64):
        res = executor.git_diff("test-git", path="uni.txt", max_bytes=bound)
        assert res["status"] == "PASS"
        raw = res["diff"].encode("utf-8")
        assert len(raw) <= bound, (bound, raw)
        # Output decodes as valid UTF-8 (no split sequences).
        res["diff"].encode("utf-8").decode("utf-8")
        assert res["truncated"] is True


def test_max_bytes_zero_returns_empty_truncated(git_repo):
    root, executor = git_repo
    _dirty(root, "README.md", "change\n")
    res = executor.git_diff("test-git", path="README.md", max_bytes=0)
    assert res["status"] == "PASS"
    assert res["diff"] == ""
    assert res["truncated"] is True


def test_negative_max_bytes_rejected(git_repo):
    _, executor = git_repo
    with pytest.raises(ValueError, match="max_bytes"):
        executor.git_diff("test-git", path="README.md", max_bytes=-1)
    with pytest.raises(ValueError, match="max_bytes"):
        executor.git_status("test-git", max_bytes=-100)


def test_huge_stdout_bounded_with_exact_count(git_repo):
    root, executor = git_repo
    _dirty(root, "big.txt", "base\n")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add big"], cwd=str(root), check=True, capture_output=True
    )
    _dirty(root, "big.txt", ("payload line %d\n" % 1) * 20000)
    res = executor.git_diff("test-git", path="big.txt", max_bytes=1024)
    assert res["status"] == "PASS"
    assert res["truncated"] is True
    assert len(res["diff"].encode("utf-8")) <= 1024
    assert len(res["diff"]) > 0


def test_huge_stderr_bounded(git_repo):
    from jvc.execution.executor import GovernedExecutor

    root, executor = git_repo
    _dirty(root, "README.md", "change\n")

    def fake_capped(_root, _args, _cap, timeout=30):
        return 128, b"", b"E" * 200000, False, True

    executor._run_git_capped = fake_capped  # type: ignore[method-assign]
    res = executor.git_diff("test-git", path="README.md", max_bytes=512)
    assert res["status"] == "FAIL"
    assert len(res["error"].encode("utf-8")) <= 32 * 1024
    assert res["error_truncated"] is True
