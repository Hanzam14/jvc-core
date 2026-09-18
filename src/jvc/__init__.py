"""JVC: Local policy-controlled routing and execution layer for agent workflows across multiple projects."""

from __future__ import annotations

__version__ = "0.1.0"

from jvc.configuration import GovernancePolicy, ProjectRegistry, Route
from jvc.continuity.state import ContinuityManager, ContinuityState
from jvc.contracts import ExecutionContract, load_contract, validate_contract
from jvc.execution.executor import GovernedExecutor
from jvc.policy.boundaries import assert_permitted_path, is_control_plane_path, is_secret_path
from jvc.policy.guard import PrewriteGuard
from jvc.recovery.store import RecoveryStore
from jvc.routing import resolve_query

__all__ = [
    "ContinuityManager",
    "ContinuityState",
    "ExecutionContract",
    "GovernancePolicy",
    "GovernedExecutor",
    "PrewriteGuard",
    "ProjectRegistry",
    "RecoveryStore",
    "Route",
    "__version__",
    "assert_permitted_path",
    "is_control_plane_path",
    "is_secret_path",
    "load_contract",
    "resolve_query",
    "validate_contract",
]
