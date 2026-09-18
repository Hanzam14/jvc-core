"""Unit tests for configuration and project registry parsing."""

import pytest
from jvc.configuration import (
    ConfigurationError,
    GovernancePolicy,
    ProjectRegistry,
    Route,
    parse_registry_table,
)


def test_parse_registry_table(tmp_path):
    table = """
# Registry

| Project ID | Aliases and keywords | Absolute project path | Required startup | Handoff/current state | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `demo-app` | `demo-app`, `app` | `app_dir` | `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` | Active | `active` |
| `demo-lib` | `demo-lib`, `lib` | `lib_dir` | `AGENTS.md`, `CONTEXT.md`, `HANDOFF.md` | Library | `active` |
"""
    routes = parse_registry_table(table, base_dir=tmp_path)
    assert len(routes) == 2
    assert routes[0].project_id == "demo-app"
    assert "app" in routes[0].aliases
    assert routes[0].root == (tmp_path / "app_dir").resolve()


def test_registry_validation_errors(tmp_path):
    # Missing startup files and duplicate project_id
    r1 = Route(
        project_id="dup-id",
        aliases=("a",),
        root=tmp_path / "dir1",
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    r2 = Route(
        project_id="dup-id",
        aliases=("b",),
        root=tmp_path / "dir2",
        startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([r1, r2])
    res = reg.validate(check_startup_files=False, check_root_paths=False)
    assert res["status"] == "FAIL"
    assert any("duplicate project ID" in err for err in res["errors"])


def test_registry_startup_order_enforcement(tmp_path):
    # Invalid startup order: CONTEXT.md before AGENTS.md
    r = Route(
        project_id="bad-order",
        aliases=("bad",),
        root=tmp_path,
        startup=("CONTEXT.md", "AGENTS.md", "HANDOFF.md"),
        handoff="HANDOFF.md",
        status="active",
    )
    reg = ProjectRegistry([r])
    res = reg.validate(check_startup_files=False, check_root_paths=False)
    assert res["status"] == "FAIL"
    assert any("startup must route AGENTS.md -> CONTEXT.md -> HANDOFF.md in order" in err for err in res["errors"])


def test_governance_policy_defaults():
    policy = GovernancePolicy()
    assert policy.fail_closed is True
    assert policy.mutation["cas_required_for_overwrite"] is True
    assert policy.mutation["registered_routes_only"] is True
    assert ".git" in policy.protected_surfaces
