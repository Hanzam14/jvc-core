"""Host-owned operator authority, HMAC capability signing, and trusted executable identity."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


OPERATOR_KEY_BYTES = 32
OPERATOR_SECRET_ENV_VAR = "JVC_OPERATOR_SECRET_HEX"


def validate_operator_key(secret: Any) -> bytes:
    """Validate an operator secret: 32 bytes, non-empty, non-degenerate.

    Rejects empty, short, long, non-bytes, and all-zero keys. Raises
    ``ValueError`` (programmer/host configuration error — loud, not silent).
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != OPERATOR_KEY_BYTES:
        raise ValueError(
            f"operator secret must be exactly {OPERATOR_KEY_BYTES} bytes, "
            f"got {type(secret).__name__} of length {len(secret) if isinstance(secret, (bytes, bytearray)) else '?'}"
        )
    raw = bytes(secret)
    if raw == b"\x00" * OPERATOR_KEY_BYTES:
        raise ValueError("operator secret must not be all-zero (weak key)")
    return raw


def load_operator_secret_from_env(
    var: str = OPERATOR_SECRET_ENV_VAR, environ: Any = None
) -> bytes:
    """Load an externally provisioned operator secret (documented protocol).

    Reads ``var`` (default ``JVC_OPERATOR_SECRET_HEX``) as 64 lowercase or
    uppercase hex characters, validates it via :func:`validate_operator_key`,
    and returns the raw bytes. The secret is NEVER written to disk by this
    function and never persisted automatically by JVC. Missing or malformed
    values raise ``ValueError``.
    """
    source = environ if environ is not None else os.environ
    raw_value = source.get(var, "")
    text = str(raw_value).strip()
    if len(text) != 64:
        raise ValueError(
            f"environment operator secret {var!r} must be 64 hex characters"
        )
    try:
        secret = bytes.fromhex(text)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"environment operator secret {var!r} must be 64 hex characters"
        ) from exc
    return validate_operator_key(secret)


def generate_operator_key(
    output_path: Path,
    *,
    forbidden_roots: list[Path],
    overwrite: bool = False,
    hardening_report: dict[str, Any] | None = None,
) -> bytes:
    """Generate and write a cryptographically strong 256-bit operator key.

    Host-only API. ``forbidden_roots`` (governed project roots) is REQUIRED:
    there is no safe default, and omitting it is a ``TypeError`` so callers
    cannot accidentally provision a trust key where agents can reach it.

    Trust model (0.1.0):
    - The key file MUST live outside all governed project roots; placement
      inside a governed root is refused so ordinary agent operations can
      never read, overwrite, or delete it through the governed interface.
    - Existing keys are never silently overwritten. Pass ``overwrite=True``
      only from an explicit rotation path (see :func:`rotate_operator_key`).
    - Permissions are hardened best-effort and the outcome is OBSERVABLE via
      ``hardening_report`` (chmod result + Windows ACL result). ACL failure
      is a WARNING for 0.1.0 (provisioning still succeeds); see
      ``docs/capabilities.md``. The secret is never printed or logged.
    """
    resolved = output_path.resolve()
    for root in [Path(r).resolve() for r in forbidden_roots]:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise ValueError(
            f"refusing unsafe trust-root placement inside governed root {root}: {resolved}"
        )
    if resolved.exists() and not overwrite:
        raise FileExistsError(
            f"trust key already exists: {resolved}; use rotate_operator_key() for explicit rotation"
        )
    key = secrets.token_bytes(32)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive, durable creation: fail if a concurrent provisioner won.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if not overwrite else os.O_TRUNC)
    fd = os.open(str(resolved), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            _sync_file(stream.fileno())
    except BaseException:
        # Do not leave a half-written key behind on overwrite rotations.
        raise
    report = _harden_key_permissions(resolved)
    if hardening_report is not None:
        hardening_report.update(report)
    _sync_dir(resolved.parent)
    return key


def rotate_operator_key(
    output_path: Path,
    *,
    forbidden_roots: list[Path],
    hardening_report: dict[str, Any] | None = None,
) -> bytes:
    """Explicitly rotate an existing trust key with atomic replacement.

    Requires an existing key file; refuses to create the initial key so
    rotation and provisioning cannot be confused. The new key is written to
    a temporary file, synced, and atomically moved over the old key: an
    interrupted rotation leaves the previous key intact.
    """
    resolved = output_path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(
            f"no existing trust key to rotate: {resolved}; provision first"
        )
    for root in [Path(r).resolve() for r in forbidden_roots]:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise ValueError(
            f"refusing unsafe trust-root placement inside governed root {root}: {resolved}"
        )
    key = secrets.token_bytes(32)
    fd, temp_raw = tempfile.mkstemp(
        prefix=f".{resolved.name}.", suffix=".rotate", dir=resolved.parent
    )
    temp_path = Path(temp_raw)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            _sync_file(stream.fileno())
        try:
            os.chmod(str(temp_path), 0o600)
        except OSError:
            pass
        from jvc.recovery.store import durable_replace

        durable_replace(temp_path, resolved)
        _sync_dir(resolved.parent)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
    report = _harden_key_permissions(resolved)
    if hardening_report is not None:
        hardening_report.update(report)
    return key


def _harden_key_permissions(path: Path) -> dict[str, Any]:
    """Harden a trust key file and report the observable outcome.

    Returns ``{"chmod_ok": bool, "acl": {"attempted": bool, "hardened": bool,
    "detail": str}}``. Failures are reported, never raised: ACL hardening
    failure is a WARNING for 0.1.0 (provisioning succeeds; the operator must
    verify restrictive permissions out of band).
    """
    report: dict[str, Any] = {
        "chmod_ok": True,
        "acl": {"attempted": False, "hardened": False, "detail": "not attempted"},
    }
    try:
        os.chmod(str(path), 0o600)
    except OSError as exc:
        report["chmod_ok"] = False
        report["acl"]["detail"] = f"chmod failed: {exc}"
    if os.name == "nt":
        report["acl"]["attempted"] = True
        try:
            username = os.environ.get("USERNAME")
            if not username:
                report["acl"]["detail"] = "USERNAME unavailable; ACL not applied"
                return report
            proc = subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:F",
                    "Administrators:F",
                ],
                capture_output=True,
                timeout=15,
            )
            if proc.returncode == 0:
                report["acl"]["hardened"] = True
                report["acl"]["detail"] = "icacls inheritance removed; user+Administrators only"
            else:
                report["acl"]["detail"] = (
                    f"icacls exited {proc.returncode}: "
                    f"{proc.stderr.decode('utf-8', errors='replace')[:300]}"
                )
        except Exception as exc:
            report["acl"]["detail"] = f"icacls invocation failed: {exc}"
    else:
        report["acl"]["detail"] = "POSIX mode 0600 applied; no ACL step"
    return report


def sign_capability(claims: dict[str, Any], secret: bytes) -> str:
    """Sign operator capability claims using HMAC-SHA256."""
    secret = validate_operator_key(secret)
    body = _b64(canonical_json_bytes(claims))
    signature = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def decode_and_verify_capability(token: str, secret: bytes) -> dict[str, Any]:
    """Verify HMAC signature and decode capability claims."""
    secret = validate_operator_key(secret)
    try:
        body, sig = token.split(".", 1)
    except ValueError as exc:
        raise PermissionError("malformed capability token") from exc

    expected = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise PermissionError("invalid capability signature")

    try:
        value = json.loads(_unb64(body).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise PermissionError("invalid capability claims encoding") from exc

    if not isinstance(value, dict):
        raise PermissionError("invalid capability claims structure")
    return value


def create_confirmation_request(
    confirmation_store: Path,
    project_id: str,
    operation: str,
    target: str,
    payload: dict[str, Any],
    expected_preimage_sha256: str | None,
    confirmation_class: str,
    reason: str,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    """Create a pending confirmation proposal record for operator review."""
    pending = confirmation_store / "pending"
    pending.mkdir(parents=True, exist_ok=True)

    cid = f"conf_{secrets.token_hex(12)}"
    now = int(time.time())
    payload_hash = sha256_bytes(canonical_json_bytes(payload))
    record = {
        "confirmation_id": cid,
        "project_id": project_id,
        "operation": operation,
        "target": target,
        "payload_sha256": payload_hash,
        "expected_preimage_sha256": (expected_preimage_sha256 or "").upper(),
        "nonce": secrets.token_urlsafe(24),
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "confirmation_class": confirmation_class,
        "reason": reason,
    }
    proposal_path = pending / f"{cid}.json"
    _durable_write_text(
        proposal_path, json.dumps(record, sort_keys=True, indent=2)
    )

    return {
        "status": "REQUIRES_CONFIRMATION",
        "op_class": "MUTATION_GATED",
        "confirmation_id": cid,
        "project_id": project_id,
        "operation": operation,
        "target": target,
        "confirmation_class": confirmation_class,
        "reason": reason,
        "proposed_payload": payload,
        "expires_at": record["expires_at"],
    }


class PersistenceError(OSError):
    """Raised when required file durability cannot be established."""


def _sync_file(fileno: int) -> None:
    """REQUIRED file durability: fsync a file descriptor.

    Any failure raises :class:`PersistenceError`. Callers that advertise
    durable-before-action semantics must treat this as denial, never as a
    warning. Test-injectable via monkeypatching
    ``jvc.policy.authority._sync_file``.
    """
    try:
        os.fsync(fileno)
    except OSError as exc:
        raise PersistenceError(f"file fsync failed: {exc}") from exc


def _sync_dir(directory: Path) -> str:
    """Best-effort parent-directory durability.

    Returns ``"synced"`` when the directory entry was synced, ``"unsupported"``
    when the platform cannot open/sync directories (e.g., Windows directory
    handles), and ``"failed"`` when the sync itself errored. Directory sync
    is explicitly best-effort and NEVER gates authorization: the documented
    durability guarantee covers file content (flush + fsync), not directory
    entries. Test-injectable via monkeypatching
    ``jvc.policy.authority._sync_dir``.
    """
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return "unsupported"
    try:
        try:
            os.fsync(fd)
        except OSError:
            return "failed"
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return "synced"


def validate_and_consume_capability(
    confirmation_store: Path,
    confirmation_id: str | None,
    token: str | None,
    project_id: str,
    operation: str,
    target: str,
    payload: dict[str, Any],
    preimage: str | None,
    secret: bytes,
) -> bool:
    """Validate, verify, and durably consume an operator capability token.

    Protections:
    - Verifies token signature against host operator secret.
    - Verifies all claims (confirmation_id, project, op, target, payload hash, preimage hash).
    - Verifies expiration timestamp.
    - Atomically consumes nonce via exclusive file creation to eliminate replay attacks and race conditions.
    - REQUIRED file persistence (flush + fsync) happens BEFORE True is
      returned. ANY persistence failure denies authorization: the nonce
      record is best-effort removed (preserving single-use: a denied
      authorization never executes its action, so a later retry is safe)
      and this function returns False.
    - Parent-directory sync is best-effort (see :func:`_sync_dir`) and does
      not gate authorization; the documented guarantee is file-content
      durability, not directory-entry durability.
    """
    if not confirmation_id or not token:
        return False

    try:
        secret = validate_operator_key(secret)
    except ValueError:
        return False

    pending = confirmation_store / "pending"
    consumed = confirmation_store / "consumed"
    consumed.mkdir(parents=True, exist_ok=True)

    proposal_path = pending / f"{confirmation_id}.json"
    if not proposal_path.is_file():
        return False

    try:
        proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False

    try:
        claims = decode_and_verify_capability(token, secret)
    except PermissionError:
        return False

    payload_hash = sha256_bytes(canonical_json_bytes(payload))
    expected = {
        "confirmation_id": confirmation_id,
        "project_id": project_id,
        "operation": operation,
        "target": target,
        "payload_sha256": payload_hash,
        "expected_preimage_sha256": (preimage or "").upper(),
        "nonce": proposal.get("nonce"),
        "expires_at": proposal.get("expires_at"),
    }

    if any(claims.get(k) != v or proposal.get(k) != v for k, v in expected.items()):
        return False

    if int(claims.get("expires_at", 0)) < int(time.time()):
        return False

    nonce = str(claims.get("nonce", ""))
    if not nonce:
        return False

    nonce_hash = sha256_bytes(nonce.encode("utf-8"))
    consumed_path = consumed / f"{nonce_hash}.json"

    # Atomic creation via exclusive open ('x') guarantees single-use across
    # processes sharing this trust store; the record is flushed and fsynced
    # BEFORE the privileged action executes so a crash cannot resurrect it.
    # Persistence failure DENIES authorization (see docstring).
    try:
        with open(consumed_path, "x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "confirmation_id": confirmation_id,
                        "consumed_at": int(time.time()),
                    }
                )
            )
            handle.flush()
            try:
                _sync_file(handle.fileno())
            except OSError:
                # Required persistence failed: deny authorization. Close
                # explicitly (Windows cannot unlink an open file), remove
                # the half-consumed record so a later retry is safe, and
                # return False. The privileged action never executes.
                try:
                    handle.close()
                except OSError:
                    pass
                try:
                    consumed_path.unlink(missing_ok=True)
                except OSError:
                    pass
                return False
    except (FileExistsError, OSError):
        return False
    _sync_dir(consumed)

    # Once atomically recorded in consumed, remove proposal from pending
    try:
        proposal_path.unlink(missing_ok=True)
    except OSError:
        pass

    return True


def _durable_write_text(path: Path, text: str) -> None:
    """Atomically and durably replace a small text document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temp_path = Path(temp_raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            _sync_file(stream.fileno())
        os.replace(temp_path, path)
        _sync_dir(path.parent)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


def assert_trust_store_outside_roots(store: Path, roots: list[Path]) -> Path:
    """Fail closed if a host-owned trust store sits inside a governed root."""
    resolved = store.resolve()
    for root in roots:
        base = Path(root).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            continue
        raise ValueError(
            f"trust store {resolved} must be host-owned outside governed root {base}"
        )
    return resolved


def is_within_store(candidate: Path, store: Path) -> bool:
    """Check whether a resolved path falls inside a host-owned store."""
    try:
        candidate.resolve().relative_to(store.resolve())
        return True
    except (ValueError, RuntimeError, OSError):
        return False


def resolve_trusted_executable(
    name: str, trusted_executables: dict[str, dict[str, str]]
) -> Path:
    """Resolve and verify cryptographic integrity of a trusted executable."""
    key = str(name).strip().lower().removesuffix(".exe")
    spec = trusted_executables.get(key)
    if not isinstance(spec, dict):
        raise ValueError(f"executable {name!r} is not in trusted executables list")

    path = Path(str(spec.get("path", ""))).resolve()
    expected_sha256 = str(spec.get("sha256", "")).upper()

    if not path.is_file():
        raise FileNotFoundError(f"approved executable missing: {path}")

    if len(expected_sha256) != 64:
        raise PermissionError(f"invalid SHA-256 pin for {key}")

    current_sha256 = sha256_file(path)
    if not hmac.compare_digest(current_sha256, expected_sha256):
        raise PermissionError(
            f"approved executable integrity mismatch for {key}: expected {expected_sha256}, observed {current_sha256}"
        )

    return path
