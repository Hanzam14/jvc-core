"""Adversarial repository-local Git helper tests (Astra Finding 4).

Proves absence of side effects (no sentinel file creation), not merely
return codes, for: clean filters, process filters, textconv, external diff,
config includes, .gitattributes filter selection, and .gitattributes writes.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor
from jvc.execution.runner import build_safe_subprocess_env


@pytest.fixture
def malicious_repo(tmp_path):
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
    sentinel = tmp_path / "SENTINEL_FIRED.txt"
    if sentinel.exists():
        sentinel.unlink()

    route = Route(
        project_id="mal-test",
        aliases=("mal",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    executor = GovernedExecutor(registry=reg, recovery_store=tmp_path / "recovery")
    return root, executor, sentinel


def _sentinel_cmd(sentinel: Path) -> str:
    # A portable sentinel: appends a marker via the shell running inside git.
    return f"echo FIRED >> \"{sentinel}\" && cat"


def test_clean_filter_not_executed_on_stage(malicious_repo):
    root, executor, sentinel = malicious_repo
    subprocess.run(
        ["git", "config", "filter.evil.clean", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "filter.evil.smudge", "cat"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / ".git" / "info" / "attributes").write_text(
        "*.txt filter=evil\n", encoding="utf-8"
    )
    (root / "clean.txt").write_text("safe content", encoding="utf-8")

    with pytest.raises(PermissionError, match="unsafe|executable git attribute"):
        executor.git_stage("mal-test", ["clean.txt"])
    assert not sentinel.exists()
    assert executor._staged_files(root) == set()


def test_process_filter_not_executed_on_stage(malicious_repo):
    root, executor, sentinel = malicious_repo
    subprocess.run(
        ["git", "config", "filter.proc.process", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / ".git" / "info" / "attributes").write_text(
        "*.bin filter=proc\n", encoding="utf-8"
    )
    (root / "data.bin").write_bytes(b"\x00\x01binary")
    with pytest.raises(PermissionError, match="unsafe|executable git attribute"):
        executor.git_stage("mal-test", ["data.bin"])
    assert not sentinel.exists()


def test_textconv_not_executed_on_diff(malicious_repo):
    root, executor, sentinel = malicious_repo
    subprocess.run(
        ["git", "config", "diff.evil.textconv", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / "note.bin").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "note.bin"], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )
    (root / ".git" / "info" / "attributes").write_text(
        "*.bin diff=evil\n", encoding="utf-8"
    )
    (root / "note.bin").write_text("changed\n", encoding="utf-8")
    # check-attr still observes the selection, so JVC rejects fail-closed;
    # either way the helper must never execute.
    try:
        executor.git_diff("mal-test", path="note.bin")
    except PermissionError:
        pass
    assert not sentinel.exists()


def test_external_diff_not_executed(malicious_repo):
    root, executor, sentinel = malicious_repo
    (root / "a.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "a.txt"], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )
    (root / "a.txt").write_text("changed\n", encoding="utf-8")
    subprocess.run(
        ["git", "config", "diff.external", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    with pytest.raises(PermissionError, match="unsafe|executable git attribute"):
        executor.git_stage("mal-test", ["a.txt"])
    # Read-only diff is likewise denied on repos with external-diff helpers
    # (fail closed for reads too); --no-ext-diff remains defense in depth.
    with pytest.raises(PermissionError, match="unsafe repository-controlled"):
        executor.git_diff("mal-test", path="a.txt")
    assert not sentinel.exists()


def test_config_include_cannot_inject_helpers(malicious_repo):
    root, executor, sentinel = malicious_repo
    evil_inc = root / "evil.inc"
    sentinel_posix = sentinel.as_posix()
    evil_inc.write_text(
        '[filter "inc"]\n\tclean = echo FIRED >> "{}" && cat\n'.format(sentinel_posix),
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "config", "include.path", str(evil_inc)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / "clean.txt").write_text("safe content", encoding="utf-8")
    with pytest.raises(PermissionError, match="unsafe|executable git attribute"):
        executor.git_stage("mal-test", ["clean.txt"])
    assert not sentinel.exists()


def test_gitattributes_filter_selection_blocks_mutation(malicious_repo):
    root, executor, sentinel = malicious_repo
    (root / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    subprocess.run(
        ["git", "config", "filter.evil.clean", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "filter.evil.smudge", "cat"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / "clean.txt").write_text("safe content", encoding="utf-8")
    with pytest.raises(PermissionError, match="unsafe|executable git attribute"):
        executor.git_stage("mal-test", ["clean.txt"])
    assert not sentinel.exists()


def test_governed_write_to_gitattributes_rejected(malicious_repo):
    _, executor, _ = malicious_repo
    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR_CONTROL_PLANE"):
        executor.fs_write("mal-test", ".gitattributes", "*.txt filter=evil\n")
    with pytest.raises(PermissionError, match="REQUIRES_OPERATOR_CONTROL_PLANE"):
        executor.fs_write("mal-test", "sub/.gitattributes", "*.txt filter=evil\n")


def test_branch_switch_blocked_with_smudge_filter(malicious_repo):
    root, executor, sentinel = malicious_repo
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "filter.evil.smudge", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "filter.evil.clean", "cat"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / ".git" / "info" / "attributes").write_text(
        "*.txt filter=evil\n", encoding="utf-8"
    )
    with pytest.raises(PermissionError, match="unsafe|executable git attribute"):
        executor.git_branch("mal-test", "feature-x")
    assert not sentinel.exists()


def test_git_commit_neutralizes_ambient_hooks(malicious_repo):
    root, executor, sentinel = malicious_repo
    marker = sentinel.parent / "HOOK_RAN.txt"
    hooks_dir = root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "pre-commit").write_text(
        f"echo 'HOOK_FIRED' > '{marker}'\nexit 1\n", encoding="utf-8"
    )
    (root / "clean.txt").write_text("safe content", encoding="utf-8")
    executor.git_stage("mal-test", ["clean.txt"])
    res = executor.git_commit("mal-test", "safe commit without hook")
    assert res["status"] == "PASS"
    assert not marker.exists()


def test_fsmonitor_not_executed_on_status(malicious_repo):
    root, executor, sentinel = malicious_repo
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "core.fsmonitor", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    # Even read-only status is denied: fsmonitor would execute on status.
    with pytest.raises(PermissionError, match="unsafe repository-controlled"):
        executor.git_status("mal-test")
    with pytest.raises(PermissionError, match="unsafe repository-controlled"):
        executor.git_diff("mal-test", path="base.txt")
    assert not sentinel.exists()


def test_gpg_signing_program_not_executed_on_commit(malicious_repo):
    root, executor, sentinel = malicious_repo
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )
    (root / "change.txt").write_text("change\n", encoding="utf-8")
    executor.git_stage("mal-test", ["change.txt"])
    subprocess.run(
        ["git", "config", "commit.gpgsign", "true"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "gpg.program", _sentinel_cmd(sentinel)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    with pytest.raises(PermissionError, match="unsafe repository-controlled"):
        executor.git_commit("mal-test", "signed commit attempt")
    assert not sentinel.exists()


def test_core_worktree_redirection_denied(malicious_repo):
    root, executor, sentinel = malicious_repo
    outside = root.parent / "elsewhere"
    outside.mkdir()
    (outside / "planted.txt").write_text("outside content\n", encoding="utf-8")
    subprocess.run(
        ["git", "config", "core.worktree", str(outside)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    # The effective worktree no longer matches the validated root.
    with pytest.raises(PermissionError, match="worktree redirection|unsafe repository"):
        executor.git_status("mal-test")
    with pytest.raises(PermissionError, match="worktree redirection|unsafe repository"):
        executor.git_stage("mal-test", ["base.txt"])


def test_worktree_config_extension_denied(malicious_repo):
    root, executor, _ = malicious_repo
    subprocess.run(
        ["git", "config", "extensions.worktreeConfig", "true"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    with pytest.raises(PermissionError, match="unsafe repository-controlled"):
        executor.git_status("mal-test")


def test_includeif_directive_denied(malicious_repo):
    root, executor, sentinel = malicious_repo
    evil_inc = root / "evil2.inc"
    evil_inc.write_text(
        '[filter "inc2"]\n\tclean = echo FIRED >> "{}" && cat\n'.format(
            sentinel.as_posix()
        ),
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "config", "includeIf.gitdir:./.git.path", str(evil_inc)],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    (root / "clean.txt").write_text("safe content", encoding="utf-8")
    with pytest.raises(PermissionError, match="unsafe repository-controlled"):
        executor.git_stage("mal-test", ["clean.txt"])
    assert not sentinel.exists()


def test_corrupt_git_config_fails_closed(malicious_repo):
    root, executor, _ = malicious_repo
    (root / ".git" / "config").write_text("[broken\nno equals here\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="fail closed"):
        executor.git_status("mal-test")
    with pytest.raises(RuntimeError, match="fail closed"):
        executor.git_stage("mal-test", ["anything.txt"])


def test_branch_switch_replacing_protected_file_denied(tmp_path):
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
    (root / "app.txt").write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=str(root), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "switch", "-c", "protected-branch"], cwd=str(root), check=True, capture_output=True
    )
    # A branch that introduces a control-plane tracked file.
    (root / ".continuity").mkdir(exist_ok=True)
    (root / ".continuity" / "state.json").write_text('{"evil": true}', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(root), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add protected"], cwd=str(root), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "switch", "master" if (root / ".git" / "refs" / "heads" / "master").exists() else "main"],
        cwd=str(root),
        check=True,
        capture_output=True,
    )
    # Remove the now-untracked protected file so the worktree is clean and
    # the switch guard itself (not the dirty-worktree gate) is exercised.
    (root / ".continuity" / "state.json").unlink(missing_ok=True)
    try:
        (root / ".continuity").rmdir()
    except OSError:
        pass
    route = Route(
        project_id="branch-test",
        aliases=("branch",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]), recovery_store=tmp_path / "recovery"
    )
    with pytest.raises(PermissionError, match="control-plane|REQUIRES_OPERATOR"):
        executor.git_branch("branch-test", "protected-branch")


def test_build_safe_subprocess_env_strips_git_and_secrets():
    mock_env = {
        "GIT_DIR": "C:/fake/.git",
        "GIT_WORK_TREE": "C:/fake",
        "GIT_HOOKS_PATH": "C:/malicious/hooks",
        "GIT_EXTERNAL_DIFF": "C:/malicious/diff.exe",
        "OPENAI_API_KEY": "synthetic-value-001",
        "GITHUB_TOKEN": "synthetic-value-002",
        "AWS_SECRET_ACCESS_KEY": "synthetic-value-003",
        "SYSTEMROOT": r"C:\Windows" if os.name == "nt" else "/tmp",
    }
    with patch.dict(os.environ, mock_env, clear=False):
        safe_env = build_safe_subprocess_env()

    assert "GIT_DIR" not in safe_env
    assert "GIT_WORK_TREE" not in safe_env
    assert "GIT_HOOKS_PATH" not in safe_env
    assert "GIT_EXTERNAL_DIFF" not in safe_env
    assert "OPENAI_API_KEY" not in safe_env
    assert "GITHUB_TOKEN" not in safe_env
    assert "AWS_SECRET_ACCESS_KEY" not in safe_env
