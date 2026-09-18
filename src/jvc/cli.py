"""Command-line interface for JVC."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jvc import __version__
from jvc.configuration import ProjectRegistry
from jvc.routing import format_human, resolve_query


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jvc",
        description="Local policy-controlled routing and execution layer for agent workflows across multiple projects.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # route
    route_cmd = subparsers.add_parser(
        "route",
        help="Deterministically resolve a natural-language request against registered projects",
    )
    route_cmd.add_argument("query", help="Project request query")
    route_cmd.add_argument(
        "--registry",
        type=Path,
        required=True,
        help="Path to Markdown or JSON project registry file",
    )
    route_cmd.add_argument("--json", action="store_true", help="Output JSON report")

    # validate-routes
    val_cmd = subparsers.add_parser(
        "validate-routes",
        help="Validate project routes, aliases, and startup sequences",
    )
    val_cmd.add_argument(
        "--registry",
        type=Path,
        required=True,
        help="Path to Markdown or JSON project registry file",
    )
    val_cmd.add_argument("--json", action="store_true", help="Output JSON report")

    # NOTE: `check` (project-owned command execution from AGENTS.md) is
    # intentionally deferred from 0.1.0. Project-controlled content must not
    # grant executable authority; declared checks run only through the
    # trusted pinned manifest path (GovernedExecutor.run_declared_check).
    # See CHANGELOG.

    # demo
    demo_cmd = subparsers.add_parser(
        "demo",
        help="Run the complete 15-step synthetic demo against temporary fixtures",
    )
    demo_cmd.add_argument(
        "--dir",
        type=Path,
        default=None,
        help="Optional directory for demo fixtures",
    )

    # NOTE: the `serve` (HTTP/JSON-RPC) command is intentionally deferred
    # from 0.1.0 to avoid shipping a network attack surface. See CHANGELOG.

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "route":
        try:
            reg = ProjectRegistry.from_file(args.registry)
            report = resolve_query(args.query, reg.list_routes())
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(format_human(report))
            return 0 if report.get("status") in {"ROUTED", "MULTI_ROUTE"} else 2
        except Exception as exc:
            print(f"Error resolving route: {exc}", file=sys.stderr)
            return 1

    if args.command == "validate-routes":
        try:
            reg = ProjectRegistry.from_file(args.registry)
            report = reg.validate()
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                if report["status"] == "PASS":
                    print(
                        f"PASS: routes={report['route_count']}; aliases={report['alias_count']}"
                    )
                else:
                    print("FAIL:")
                    for err in report["errors"]:
                        print(f"- {err}")
            return 0 if report.get("status") == "PASS" else 1
        except Exception as exc:
            print(f"Error validating routes: {exc}", file=sys.stderr)
            return 1

    if args.command == "demo":
        from jvc.demo import main as demo_main
        return demo_main()

    return 0


if __name__ == "__main__":
    sys.exit(main())
