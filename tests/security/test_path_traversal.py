"""Security tests for path traversal, drive escapes, and malformed path rejection."""

import pytest
from jvc.configuration import ProjectRegistry, Route
from jvc.execution.executor import GovernedExecutor


@pytest.fixture
def traversal_env(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    route = Route(
        project_id="traversal-proj",
        aliases=("trav",),
        root=root,
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([route])
    executor = GovernedExecutor(registry=reg, recovery_store=tmp_path / "recovery")
    return root, executor


def test_traversal_attempts_fail_closed(traversal_env):
    root, executor = traversal_env

    bad_paths = [
        "../outside.txt",
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\calc.exe",
        "sub/../../escape.txt",
        "%2e%2e/encoded.txt",
        "%2e%2e\\encoded.txt",
        "file\x00escape.txt",
        "file\r\nescape.txt",
        "C:/Windows/System32/drivers/etc/hosts",
        "D:\\other_drive.txt",
    ]

    for p in bad_paths:
        with pytest.raises(ValueError):
            executor.fs_write("traversal-proj", p, "content")
