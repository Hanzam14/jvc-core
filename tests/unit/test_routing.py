"""Unit tests for deterministic project routing."""

from pathlib import Path
from jvc.configuration import Route
from jvc.routing import alias_present, normalize, resolve_query


def test_normalize():
    assert normalize("  My-Project_123 ! ") == "my project 123"
    assert normalize("hello   world") == "hello world"


def test_alias_present():
    assert alias_present("please work on app features", "app")
    assert alias_present("app", "app")
    assert not alias_present("apples are great", "app")
    assert not alias_present("pineapple juice", "app")


def test_routing_resolution(tmp_path):
    routes = [
        Route(
            project_id="frontend-app",
            aliases=("frontend", "web", "ui"),
            root=tmp_path / "frontend",
            startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
            handoff="HANDOFF.md",
            status="active",
        ),
        Route(
            project_id="backend-api",
            aliases=("backend", "api", "server"),
            root=tmp_path / "backend",
            startup=("AGENTS.md", "CONTEXT.md", "HANDOFF.md"),
            handoff="HANDOFF.md",
            status="active",
        ),
    ]

    # 1. Single match -> ROUTED
    r1 = resolve_query("fix button on frontend", routes)
    assert r1["status"] == "ROUTED"
    assert r1["routes"][0]["project_id"] == "frontend-app"

    # 2. Unknown -> UNKNOWN
    r2 = resolve_query("deploy mobile client", routes)
    assert r2["status"] == "UNKNOWN"
    assert len(r2["routes"]) == 0

    # 3. Ambiguous without multi marker -> AMBIGUOUS
    r3 = resolve_query("inspect frontend backend", routes)
    assert r3["status"] == "AMBIGUOUS"
    assert len(r3["routes"]) == 2

    # 4. Multi-route with marker -> MULTI_ROUTE
    r4 = resolve_query("integrate frontend and backend", routes)
    assert r4["status"] == "MULTI_ROUTE"
    assert len(r4["routes"]) == 2

    # 5. Exact project_id match
    r5 = resolve_query("status of backend-api", routes)
    assert r5["status"] == "ROUTED"
    assert r5["routes"][0]["project_id"] == "backend-api"
