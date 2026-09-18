"""Resumable project continuity, state revision control, and handoff integrity."""

from jvc.continuity.state import (
    ConflictError,
    ContinuityError,
    ContinuityManager,
    ContinuityState,
)

__all__ = [
    "ConflictError",
    "ContinuityError",
    "ContinuityManager",
    "ContinuityState",
]
