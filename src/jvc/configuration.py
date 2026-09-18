"""Configuration, route registry, and governance policy loaders for JVC."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

PROJECT_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TABLE_HEADER = "| Project ID | Aliases and keywords | Absolute project path | Required startup | Handoff/current state | Status |"
ALLOWED_LIFECYCLE_STATUSES = {"active", "held", "complete", "superseded"}
ALLOWED_CAPABILITY_CLASSES = {"standard", "restricted-tooling", "private-content"}
ALLOWED_STATUSES = ALLOWED_LIFECYCLE_STATUSES | ALLOWED_CAPABILITY_CLASSES
REQUIRED_STARTUP = ("AGENTS.md", "CONTEXT.md", "HANDOFF.md")


class ConfigurationError(ValueError):
    """Raised when configuration, routing, or policy parsing fails."""


@dataclass(frozen=True)
class Route:
    """Canonical registered project route."""

    project_id: str
    aliases: tuple[str, ...]
    root: Path
    startup: tuple[str, ...]
    handoff: str
    status: str

    @property
    def lifecycle(self) -> str:
        if self.status in {"held", "complete", "superseded"}:
            return self.status
        return "active"

    @property
    def capability_class(self) -> str:
        if self.status in {"restricted-tooling", "private-content"}:
            return self.status
        return "standard"


def _code_values(cell: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in re.findall(r"`([^`]+)`", cell) if value.strip())


def _split_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_registry_table(text: str, base_dir: Path | None = None) -> list[Route]:
    """Parse a Markdown registry table into a list of Route objects."""
    lines = text.splitlines()
    header_index = -1
    for i, line in enumerate(lines):
        if TABLE_HEADER.replace(" ", "") in line.replace(" ", "") or (
            "| Project ID |" in line and "| Status |" in line
        ):
            header_index = i
            break

    if header_index == -1:
        raise ConfigurationError("registered-projects table header was not found")

    routes: list[Route] = []
    # Header separator is at header_index + 1; rows start at header_index + 2
    for line in lines[header_index + 2 :]:
        stripped = line.strip()
        if not stripped or not stripped.startswith("|"):
            break
        cells = _split_row(stripped)
        if len(cells) != 6:
            raise ConfigurationError(f"route row must have 6 columns: {line}")
        project_ids = _code_values(cells[0])
        roots = _code_values(cells[2])
        if len(project_ids) != 1 or len(roots) != 1:
            raise ConfigurationError(
                f"route row requires one project ID and one path: {line}"
            )
        aliases = tuple(
            alias.strip().lower()
            for alias in cells[1].replace("`", "").split(",")
            if alias.strip()
        )
        raw_root = roots[0]
        root_path = Path(raw_root)
        if not root_path.is_absolute() and base_dir is not None:
            root_path = (base_dir / root_path).resolve()

        routes.append(
            Route(
                project_id=project_ids[0],
                aliases=aliases,
                root=root_path,
                startup=_code_values(cells[3]),
                handoff=cells[4],
                status=cells[5].replace("`", "").strip().lower(),
            )
        )

    if not routes:
        raise ConfigurationError("registered-projects table contains no routes")
    return routes


class ProjectRegistry:
    """Project registry maintaining active project routes and mappings."""

    def __init__(self, routes: Iterable[Route]) -> None:
        self._route_list: list[Route] = list(routes)
        self._routes: dict[str, Route] = {}
        self._aliases: dict[str, str] = {}
        for r in self._route_list:
            if r.project_id not in self._routes:
                self._routes[r.project_id] = r
            for a in r.aliases:
                self._aliases[a] = r.project_id

    @classmethod
    def from_file(cls, path: Path) -> ProjectRegistry:
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() in {".json"}:
            data = json.loads(text)
            routes = []
            for item in data.get("routes", []):
                routes.append(
                    Route(
                        project_id=item["project_id"],
                        aliases=tuple(a.lower() for a in item.get("aliases", [])),
                        root=Path(item["root"]).resolve(),
                        startup=tuple(item.get("startup", REQUIRED_STARTUP)),
                        handoff=item.get("handoff", "HANDOFF.md"),
                        status=str(item.get("status", "active")).replace("`", "").strip().lower(),
                    )
                )
            return cls(routes)
        return cls(parse_registry_table(text, base_dir=path.parent))

    def get(self, project_id: str) -> Route | None:
        return self._routes.get(project_id)

    def list_routes(self) -> list[Route]:
        return list(self._route_list)

    def validate(
        self,
        check_startup_files: bool = True,
        check_root_paths: bool = True,
    ) -> dict[str, Any]:
        """Validate route constraints without modifying any files."""
        errors: list[str] = []
        ids: set[str] = set()
        aliases: dict[str, str] = {}
        roots: dict[str, str] = {}

        for route in self._route_list:
            if not PROJECT_ID_RE.fullmatch(route.project_id):
                errors.append(f"{route.project_id}: invalid project ID")
            if route.project_id in ids:
                errors.append(f"{route.project_id}: duplicate project ID")
            ids.add(route.project_id)

            if route.status not in ALLOWED_STATUSES:
                errors.append(f"{route.project_id}: unsupported status {route.status!r}")

            root_key = (
                str(route.root.resolve()).casefold()
                if check_root_paths and route.root.exists()
                else str(route.root).casefold()
            )
            if root_key in roots:
                errors.append(f"{route.project_id}: root duplicates {roots[root_key]}")
            roots[root_key] = route.project_id

            if check_root_paths and not route.root.is_dir():
                errors.append(f"{route.project_id}: project root does not exist: {route.root}")

            try:
                positions = tuple(
                    route.startup.index(filename) for filename in REQUIRED_STARTUP
                )
            except ValueError:
                positions = ()

            if (
                not positions
                or route.startup[0] != "AGENTS.md"
                or positions != tuple(sorted(positions))
            ):
                errors.append(
                    f"{route.project_id}: startup must route AGENTS.md -> CONTEXT.md -> HANDOFF.md in order"
                )

            if check_startup_files:
                for relative in route.startup:
                    resolved = route.root / relative
                    if not resolved.is_file():
                        errors.append(f"{route.project_id}: startup file missing: {relative}")

            if not route.aliases:
                errors.append(f"{route.project_id}: at least one alias is required")
            for alias in route.aliases:
                owner = aliases.get(alias)
                if owner and owner != route.project_id:
                    errors.append(f"{route.project_id}: alias {alias!r} already belongs to {owner}")
                aliases[alias] = route.project_id

        return {
            "status": "PASS" if not errors else "FAIL",
            "route_count": len(self._routes),
            "alias_count": len(aliases),
            "errors": errors,
        }


@dataclass
class GovernancePolicy:
    """Security and mutation governance policy."""

    schema_version: int = 1
    policy_id: str = "jvc-governed-execution-v1"
    fail_closed: bool = True
    model_facing: dict[str, bool] = field(
        default_factory=lambda: {
            "raw_shell": False,
            "generic_command": False,
            "operator_authorization": False,
            "caller_authority_upgrade_fields": False,
        }
    )
    mutation: dict[str, bool] = field(
        default_factory=lambda: {
            "registered_routes_only": True,
            "canonical_containment_required": True,
            "mandatory_secret_deny": True,
            "cas_required_for_overwrite": True,
            "recovery_after_authorization_only": True,
            "git_stage_exact_files_only": True,
        }
    )
    secret_classes: list[str] = field(
        default_factory=lambda: [
            ".env",
            ".env.*",
            "credential.*",
            "credentials.*",
            "secret.*",
            "secrets.*",
            "token.*",
            "tokens.*",
            "auth.*",
            "*.pem",
            "*.key",
            "*.ppk",
            "*.p12",
            "*.pfx",
            "ssh credentials",
            "recovery phrase",
            "recovery seed",
            "provider credential settings",
        ]
    )
    protected_surfaces: list[str] = field(
        default_factory=lambda: [
            ".git",
            ".continuity",
            "_config",
            "contracts",
        ]
    )

    @classmethod
    def from_file(cls, path: Path) -> GovernancePolicy:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return cls(
            schema_version=data.get("schema_version", 1),
            policy_id=data.get("policy_id", "jvc-governed-execution-v1"),
            fail_closed=data.get("fail_closed", True),
            model_facing=data.get("model_facing", {}),
            mutation=data.get("mutation", {}),
            secret_classes=data.get("secret_classes", []),
            protected_surfaces=data.get("protected_surfaces", []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "fail_closed": self.fail_closed,
            "model_facing": self.model_facing,
            "mutation": self.mutation,
            "secret_classes": self.secret_classes,
            "protected_surfaces": self.protected_surfaces,
        }
