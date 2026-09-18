"""Policy and boundary enforcement subsystem for JVC."""

from jvc.policy.authority import (
    decode_and_verify_capability,
    generate_operator_key,
    resolve_trusted_executable,
    sign_capability,
    validate_and_consume_capability,
)
from jvc.policy.boundaries import (
    assert_permitted_path,
    canonical_target,
    is_control_plane_path,
    is_secret_path,
    is_within,
    normalize_path,
)
from jvc.policy.guard import PrewriteGuard

__all__ = [
    "PrewriteGuard",
    "assert_permitted_path",
    "canonical_target",
    "decode_and_verify_capability",
    "generate_operator_key",
    "is_control_plane_path",
    "is_secret_path",
    "is_within",
    "normalize_path",
    "resolve_trusted_executable",
    "sign_capability",
    "validate_and_consume_capability",
]
