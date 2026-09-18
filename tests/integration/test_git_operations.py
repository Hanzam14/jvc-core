"""Integration tests for bounded GovernedExecutor Git operations."""

import subprocess
import pytest
from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor


@pytest.fixture
def git_project(tmp_path):
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


def test_git_stage_and_commit(git_project):
    root, executor = git_project
    (root / "README.md").write_text("initial commit", encoding="utf-8")

    # Stage
    stage_res = executor.git_stage("test-git", ["README.md"])
    assert stage_res["status"] == "PASS"
    assert "README.md" in stage_res["staged_paths"]

    # Commit
    commit_res = executor.git_commit("test-git", "initial commit")
    assert commit_res["status"] == "PASS"
    assert "README.md" in commit_res["committed_paths"]

    # Verify log
    log_res = executor.git_log("test-git", n=5)
    assert log_res["status"] == "PASS"
    assert "initial commit" in log_res["log"]


def test_git_stage_atomic_rejection_of_secret(git_project):
    root, executor = git_project
    (root / "safe.txt").write_text("safe content", encoding="utf-8")
    (root / "credentials.toml").write_text("secret content", encoding="utf-8")

    # Mixed batch containing a secret-bearing target must fail atomically before any staging
    with pytest.raises(PermissionError, match="secret-bearing"):
        executor.git_stage("test-git", ["safe.txt", "credentials.toml"])

    staged = executor._staged_files(root)
    assert staged == set()


def test_git_branch_operations(git_project):
    root, executor = git_project
    (root / "README.md").write_text("main branch", encoding="utf-8")
    executor.git_stage("test-git", ["README.md"])
    executor.git_commit("test-git", "initial")

    # Create & switch to feature branch
    b_res = executor.git_branch("test-git", "feature-branch")
    assert b_res["status"] == "PASS"
    assert b_res["action"] == "create"

    # Dirty worktree blocks branch switch
    (root / "dirty.txt").write_text("uncommitted change", encoding="utf-8")
    with pytest.raises(PermissionError, match="dirty worktree blocks branch operation"):
        executor.git_branch("test-git", "main")


def test_git_stage_rejects_deleted_directory_expansion(git_project):
    """A deleted tracked directory must not stage descendants unvalidated."""
    import shutil

    root, executor = git_project
    (root / "drop").mkdir()
    (root / "drop" / "public.txt").write_text("public\n", encoding="utf-8")
    (root / "drop" / "token.json").write_text('{"token": "SECRET"}', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add dir"], cwd=str(root), check=True, capture_output=True
    )
    shutil.rmtree(root / "drop")
    # Filesystem check passes (nothing exists), but the index still
    # represents the directory: staging it would expand recursively.
    with pytest.raises(ValueError, match="directory pathspec|exact relative file"):
        executor.git_stage("test-git", ["drop"])
    assert executor._staged_files(root) == set()
