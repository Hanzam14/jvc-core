"""Integration tests for JVC command-line interface."""

import subprocess

import pytest

from jvc.cli import build_parser, main


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    captured = capsys.readouterr()
    assert "0.1.0" in captured.out or "0.1.0" in captured.err


def test_cli_validate_routes(tmp_path, capsys):
    app_dir = tmp_path / "demo"
    app_dir.mkdir()
    (app_dir / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    (app_dir / "CONTEXT.md").write_text("# Context\n", encoding="utf-8")
    (app_dir / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    reg_file = tmp_path / "PROJECT_ROUTES.md"
    reg_file.write_text(
        f"""
| Project ID | Aliases and keywords | Absolute project path | Required startup | Handoff/current state | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `demo` | `demo`, `test` | `{app_dir.resolve()}` | `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` | Dev | `active` |
""",
        encoding="utf-8",
    )
    code = main(["validate-routes", "--registry", str(reg_file)])
    assert code == 0
    captured = capsys.readouterr()
    assert "PASS: routes=1" in captured.out


def test_cli_route(tmp_path, capsys):
    app_dir = tmp_path / "demo"
    app_dir.mkdir()
    reg_file = tmp_path / "PROJECT_ROUTES.md"
    reg_file.write_text(
        f"""
| Project ID | Aliases and keywords | Absolute project path | Required startup | Handoff/current state | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `demo` | `demo`, `test` | `{app_dir.resolve()}` | `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` | Dev | `active` |
""",
        encoding="utf-8",
    )
    code = main(["route", "work on demo app", "--registry", str(reg_file), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    import json
    data = json.loads(captured.out)
    assert data["status"] == "ROUTED"
    assert data["routes"][0]["project_id"] == "demo"


def test_cli_check_subcommand_removed(capsys):
    """`jvc check` (unpinned project-owned execution) is not a 0.1.0 surface."""
    with pytest.raises(SystemExit) as exc_info:
        main(["check", "demo", "preflight", "--root", "."])
    assert exc_info.value.code == 2
    help_text = build_parser().format_help()
    assert "route" in help_text
    assert "validate-routes" in help_text
    assert "demo" in help_text
    assert "{check" not in help_text
    assert "check" not in [
        line.strip().split()[0]
        for line in help_text.splitlines()
        if line.strip().startswith("{")
    ]


def test_cli_never_executes_project_owned_agents(tmp_path, capsys):
    """A malicious AGENTS.md cannot cause execution through any CLI command."""
    app_dir = tmp_path / "evil-app"
    app_dir.mkdir()
    sentinel = tmp_path / "CLI_RAN.txt"
    (app_dir / "AGENTS.md").write_text(
        "<!-- ICM_EXECUTION_START -->\n```json\n"
        '{"schema_version": 1, "project_id": "evil-app", '
        f'"cwd": "{app_dir.as_posix()}", "persistence": "local", "privacy": "standard", '
        '"permission_class": "read-test", '
        '"runtime": {"kind": "python", "candidates": [["python"]], "probe_argv": ["--version"]}, '
        '"preflight": {"argv": ["python", "-c", '
        f"\"open(r'{sentinel.as_posix()}','w').write('FIRED')\"], "
        '"timeout_seconds": 10, "expected_exit": 0, "expected_contains": "x"}, '
        '"verify": null, "write_policy": "x"}\n```\n<!-- ICM_EXECUTION_END -->\n',
        encoding="utf-8",
    )
    (app_dir / "CONTEXT.md").write_text("# Context\n", encoding="utf-8")
    (app_dir / "HANDOFF.md").write_text("# Handoff\n", encoding="utf-8")
    reg_file = tmp_path / "PROJECT_ROUTES.md"
    reg_file.write_text(
        f"""
| Project ID | Aliases and keywords | Absolute project path | Required startup | Handoff/current state | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `evil-app` | `evil`, `app` | `{app_dir.resolve()}` | `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` | Dev | `active` |
""",
        encoding="utf-8",
    )
    # Every remaining CLI surface only reads routes/fixtures; none executes.
    assert main(["validate-routes", "--registry", str(reg_file)]) == 0
    capsys.readouterr()
    code = main(["route", "work on evil app", "--registry", str(reg_file)])
    assert code == 0
    capsys.readouterr()
    assert not sentinel.exists()


def test_executor_rejects_unknown_declared_check(tmp_path):
    """The trusted pinned path fails closed on unknown check IDs."""
    from jvc.configuration import ProjectRegistry, Route
    from jvc.execution.executor import GovernedExecutor

    root = tmp_path / "project"
    root.mkdir()
    route = Route(
        project_id="p",
        aliases=("p",),
        root=root,
        startup=("AGENTS.md",),
        handoff="HANDOFF.md",
        status="active",
    )
    executor = GovernedExecutor(
        registry=ProjectRegistry([route]),
        recovery_store=tmp_path / "recovery",
        declared_manifest={"checks": {"p": {}}},
    )
    with pytest.raises(ValueError, match="no declared check spec"):
        executor.run_declared_check("p", "preflight")
