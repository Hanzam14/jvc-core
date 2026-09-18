"""Deterministic project routing engine for JVC.

Routing resolves natural-language project requests against registered project
aliases using deterministic lexical matching. It does not use semantic AI or
probabilistic inference.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from jvc.configuration import Route
from jvc.contracts import ContractError, load_contract

MULTI_MARKERS = re.compile(
    r"\b(and|both|with|between|compare|connect|across)\b|[+/&]", re.IGNORECASE
)


def normalize(value: str) -> str:
    """Normalize query or alias text into single-spaced lowercase alphanumeric tokens."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def alias_present(query: str, alias: str) -> bool:
    """Return True if normalized alias appears as a whole token sequence in query."""
    normalized_alias = normalize(alias)
    if not normalized_alias:
        return False
    return (
        re.search(rf"(?:^|\s){re.escape(normalized_alias)}(?:$|\s)", query)
        is not None
    )


def route_payload(route: Route, matched: list[str]) -> dict[str, Any]:
    """Generate execution details and startup sequence for a matched route."""
    try:
        contract_data = load_contract(route.root / "AGENTS.md")
        contract = contract_data.to_dict()
        execution = {
            "cwd": contract["cwd"],
            "persistence": contract["persistence"],
            "privacy": contract["privacy"],
            "permission_class": contract["permission_class"],
            "runtime_kind": contract["runtime"]["kind"],
            "runtime_candidates": contract["runtime"]["candidates"],
            "preflight": contract["preflight"],
            "verify": contract["verify"],
            "write_policy": contract["write_policy"],
        }
    except (OSError, KeyError, ContractError) as exc:
        execution = {"status": "INVALID", "detail": str(exc)}

    return {
        "project_id": route.project_id,
        "root": str(route.root),
        "status": route.status,
        "matched_aliases": sorted(
            matched, key=lambda val: (-len(normalize(val)), val)
        ),
        "startup": [str(route.root / rel) for rel in route.startup],
        "handoff": route.handoff,
        "execution": execution,
    }


def resolve_query(
    query: str, routes: Iterable[Route]
) -> dict[str, Any]:
    """Deterministically resolve a query against the registered routes.

    Returns a dict with 'status' set to:
    - 'ROUTED': Exactly one route matched.
    - 'MULTI_ROUTE': Multiple routes matched with explicit multi-project intent markers.
    - 'AMBIGUOUS': Multiple routes matched without explicit multi-project intent.
    - 'UNKNOWN': No registered project matched.
    """
    normalized_query = normalize(query)
    matches: list[tuple[Route, list[str]]] = []

    for route in routes:
        # Also check exact project_id match as an implicit alias
        all_aliases = list(route.aliases)
        if route.project_id not in all_aliases:
            all_aliases.append(route.project_id)

        matched_aliases = [
            alias for alias in all_aliases if alias_present(normalized_query, alias)
        ]
        if matched_aliases:
            matches.append((route, matched_aliases))

    if not matches:
        return {
            "status": "UNKNOWN",
            "query": query,
            "routes": [],
            "message": "No registered project alias matched; load no project context.",
        }

    payloads = [route_payload(route, aliases) for route, aliases in matches]

    if len(payloads) == 1:
        return {
            "status": "ROUTED",
            "query": query,
            "routes": payloads,
            "message": "Read the returned root trio in order, then follow HANDOFF.md to the current stage. Load no unrelated context.",
        }

    if MULTI_MARKERS.search(query):
        return {
            "status": "MULTI_ROUTE",
            "query": query,
            "routes": payloads,
            "message": "Keep project contexts, authorities, and outputs separate.",
        }

    return {
        "status": "AMBIGUOUS",
        "query": query,
        "routes": payloads,
        "message": "Multiple projects matched without explicit multi-project intent; load no project context.",
    }


def format_human(report: dict[str, Any]) -> str:
    """Format a routing report for human display."""
    lines = [f"{report['status']}: {report['query']}"]
    for route in report.get("routes", []):
        execution = route.get("execution", {})
        lines.extend(
            [
                f"project_id: {route['project_id']}",
                f"root: {route['root']}",
                f"privacy_status: {route['status']}",
                "startup:",
                *[
                    f"  {idx}. {path}"
                    for idx, path in enumerate(route.get("startup", []), start=1)
                ],
                f"runtime: {execution.get('runtime_kind', 'INVALID')}",
                f"preflight: {execution.get('preflight')}",
                f"write_policy: {execution.get('write_policy', execution.get('detail'))}",
            ]
        )
    lines.append(str(report.get("message", "")))
    return "\n".join(lines)
