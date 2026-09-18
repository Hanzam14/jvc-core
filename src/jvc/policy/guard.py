"""Fail-closed pre-write capture, intent binding, verification, and receipt lifecycle.

Lifecycle:
    proposed -> approved -> applied -> verified
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from jvc.policy.boundaries import canonical_target, is_control_plane_path, is_secret_path

SCHEMA_VERSION = 1
LIFECYCLE_STATES = ("proposed", "approved", "applied", "verified")
VALID_TRANSITIONS = {
    "proposed": {"approved"},
    "approved": {"applied"},
    "applied": {"verified"},
    "verified": set(),
}


class GuardError(ValueError):
    """Raised for a failed pre-write invariant."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardError(f"cannot read guard manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise GuardError(f"guard manifest must contain an object: {path}")
    return data


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise GuardError(f"refusing to overwrite existing guard artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _rewrite_manifest(
    path: Path, before_bytes: bytes, manifest: dict[str, Any]
) -> None:
    current = path.read_bytes()
    if current != before_bytes:
        raise GuardError(f"guard manifest changed before lifecycle update: {path}")
    expected = canonical_json(manifest) + b"\n"
    path.write_bytes(expected)
    after = path.read_bytes()
    if sha256_bytes(after) != sha256_bytes(expected):
        raise GuardError(f"guard manifest post-write verification failed: {path}")


class PrewriteGuard:
    """Manages the prewrite verification and receipt lifecycle.

    Host-only API: not reachable from the CLI or any model-facing surface.
    Entry paths are boundary-validated; output manifests/receipts are
    host-chosen paths that must additionally pass secret/control-plane
    screening when they resolve inside the guarded root.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    @staticmethod
    def _check_output_path(root: Path, path: Path, what: str) -> None:
        try:
            path.resolve().relative_to(root)
        except (ValueError, RuntimeError):
            return  # Outside the guarded root: host's responsibility.
        rel = path.resolve().relative_to(root).as_posix()
        if is_secret_path(rel) or is_control_plane_path(rel):
            raise GuardError(
                f"protected guard {what} path rejected: {rel}"
            )

    def _validate_entries(self, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise GuardError("unsupported guard manifest schema_version")
        entries = manifest.get("entries")
        if not isinstance(entries, list) or not entries:
            raise GuardError("guard manifest entries must be a non-empty array")
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise GuardError("guard manifest entries must be objects")
            raw_path = entry.get("path")
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise GuardError("guard manifest entry path is required")
            target, canonical_rel = canonical_target(self.root, raw_path)
            if canonical_rel in seen:
                raise GuardError(f"duplicate guard path: {raw_path}")
            seen.add(canonical_rel)

            if is_secret_path(canonical_rel):
                raise GuardError(f"secret path present in guard manifest: {raw_path}")
            if is_control_plane_path(canonical_rel):
                raise GuardError(f"control plane path present in guard manifest: {raw_path}")

            expected_state = entry.get("expected_state")
            if expected_state not in {"present", "absent"}:
                raise GuardError(f"unsupported expected_state for {raw_path}")
            if expected_state == "present":
                if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
                    raise GuardError(f"present entry lacks a SHA-256 preimage: {raw_path}")
                if not isinstance(entry.get("byte_length"), int) or entry["byte_length"] < 0:
                    raise GuardError(f"present entry lacks a byte length: {raw_path}")
            elif "sha256" in entry or "byte_length" in entry:
                raise GuardError(f"absent entry cannot contain a preimage: {raw_path}")

            expected_sha256 = entry.get("expected_sha256")
            if expected_sha256 is not None and (
                not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            ):
                raise GuardError(f"entry has an invalid expected post-write SHA-256: {raw_path}")

        if manifest.get("guard_mode") == "strict-write" and manifest.get(
            "lifecycle_state"
        ) in {"approved", "applied", "verified"}:
            if manifest.get("intent_state") != "bound":
                raise GuardError("strict-write manifest requires a bound post-write intent")
            if any("expected_sha256" not in entry for entry in entries):
                raise GuardError("strict-write manifest entries must bind expected post-write hashes")

        return entries

    def capture(self, paths: list[str], output_manifest: Path) -> dict[str, Any]:
        """Capture fresh preimages of paths and write a proposed manifest."""
        self._check_output_path(self.root, output_manifest, "manifest")
        entries = []
        for p in paths:
            target, canonical_rel = canonical_target(self.root, p)
            if is_secret_path(canonical_rel) or is_control_plane_path(canonical_rel):
                raise GuardError(f"protected target rejected before capture: {p}")

            captured_at = utc_now()
            if not target.exists():
                entries.append(
                    {
                        "path": canonical_rel,
                        "expected_state": "absent",
                        "captured_at": captured_at,
                    }
                )
            elif not target.is_file():
                raise GuardError(f"guard paths must be files or absent: {p}")
            else:
                data = target.read_bytes()
                entries.append(
                    {
                        "path": canonical_rel,
                        "expected_state": "present",
                        "sha256": sha256_bytes(data),
                        "byte_length": len(data),
                        "captured_at": captured_at,
                    }
                )

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "manifest_id": str(uuid.uuid4()),
            "captured_at": utc_now(),
            "lifecycle_state": "proposed",
            "guard_mode": "strict-write",
            "intent_state": "unbound",
            "entries": entries,
        }
        _write_new_json(output_manifest, manifest)
        return manifest

    def bind_intent(
        self, manifest_path: Path, expected_hashes: dict[str, str]
    ) -> dict[str, Any]:
        """Bind expected post-write hashes to manifest while in 'proposed' state."""
        before_bytes = manifest_path.read_bytes()
        manifest = _read_json(manifest_path)
        entries = self._validate_entries(
            {**manifest, "intent_state": "bound", "lifecycle_state": "proposed"}
        )
        if manifest.get("lifecycle_state") != "proposed":
            raise GuardError("post-write intent can only be bound while lifecycle_state=proposed")

        normalized_intents = {}
        for k, v in expected_hashes.items():
            _, c_rel = canonical_target(self.root, k)
            normalized_intents[c_rel] = v.upper()

        entry_paths = {entry["path"] for entry in entries}
        if set(normalized_intents) != entry_paths:
            raise GuardError(
                "post-write intent must provide exactly one hash for every captured path"
            )

        for entry in manifest["entries"]:
            entry["expected_sha256"] = normalized_intents[entry["path"]]

        manifest["intent_state"] = "bound"
        _rewrite_manifest(manifest_path, before_bytes, manifest)
        return manifest

    def verify(self, manifest_path: Path) -> dict[str, Any]:
        """Verify that current on-disk state matches the preimages recorded in manifest."""
        manifest = _read_json(manifest_path)
        entries = self._validate_entries(manifest)
        failures: list[str] = []
        observations: list[dict[str, Any]] = []

        for entry in entries:
            target, _ = canonical_target(self.root, entry["path"])
            if entry["expected_state"] == "absent":
                exists = target.exists()
                if exists:
                    failures.append(f"preimage changed: expected absent but exists: {entry['path']}")
                observations.append({"path": entry["path"], "exists": exists})
            else:
                if not target.is_file():
                    failures.append(f"preimage changed: expected file missing: {entry['path']}")
                    observations.append({"path": entry["path"], "exists": False})
                else:
                    data = target.read_bytes()
                    current_hash = sha256_bytes(data)
                    current_len = len(data)
                    if (
                        current_hash != entry["sha256"]
                        or current_len != entry["byte_length"]
                    ):
                        failures.append(f"preimage changed: {entry['path']}")
                    observations.append(
                        {
                            "path": entry["path"],
                            "exists": True,
                            "sha256": current_hash,
                            "byte_length": current_len,
                        }
                    )

        return {
            "status": "PASS" if not failures else "FAIL",
            "manifest_id": manifest.get("manifest_id"),
            "lifecycle_state": manifest.get("lifecycle_state"),
            "failures": failures,
            "observations": observations,
        }

    def transition(self, manifest_path: Path, target_state: str) -> dict[str, Any]:
        """Advance lifecycle state along the valid transition sequence."""
        if target_state not in LIFECYCLE_STATES:
            raise GuardError(f"unsupported lifecycle state: {target_state}")
        before_bytes = manifest_path.read_bytes()
        manifest = _read_json(manifest_path)
        self._validate_entries(manifest)

        current_state = manifest.get("lifecycle_state")
        if target_state not in VALID_TRANSITIONS.get(current_state, set()):
            raise GuardError(
                f"invalid lifecycle transition: {current_state} -> {target_state}"
            )

        if target_state == "applied":
            if manifest.get("guard_mode") == "strict-write":
                if manifest.get("intent_state") != "bound":
                    raise GuardError(
                        "cannot mark strict-write action applied before binding post-write intent"
                    )

        manifest["lifecycle_state"] = target_state
        manifest[f"{target_state}_at"] = utc_now()
        _rewrite_manifest(manifest_path, before_bytes, manifest)
        return manifest

    def receipt(self, manifest_path: Path, output_receipt: Path) -> dict[str, Any]:
        """Generate verified post-write receipt completing applied -> verified transition."""
        self._check_output_path(self.root, output_receipt, "receipt")
        if output_receipt.exists():
            raise GuardError(f"refusing to overwrite existing receipt: {output_receipt}")
        before_manifest = manifest_path.read_bytes()
        manifest = _read_json(manifest_path)
        entries = self._validate_entries(manifest)

        if manifest.get("lifecycle_state") != "applied":
            raise GuardError(
                "receipt requires lifecycle_state=applied; approval is not application"
            )

        failures: list[str] = []
        changed_paths: list[str] = []
        observations: list[dict[str, Any]] = []

        for entry in entries:
            target, _ = canonical_target(self.root, entry["path"])
            expected_state = entry["expected_state"]
            if expected_state == "absent":
                if target.exists():
                    data = target.read_bytes()
                    post_hash = sha256_bytes(data)
                    expected_hash = entry.get("expected_sha256")
                    if expected_hash and post_hash != expected_hash:
                        failures.append(
                            f"post-write content differs from expected intent: {entry['path']}"
                        )
                    changed_paths.append(entry["path"])
                    observations.append(
                        {
                            "path": entry["path"],
                            "post_state": "present",
                            "post_sha256": post_hash,
                            "post_byte_length": len(data),
                            "changed": True,
                        }
                    )
                else:
                    failures.append(f"expected new file was not created: {entry['path']}")
            elif not target.is_file():
                failures.append(f"post-write file is missing: {entry['path']}")
            else:
                data = target.read_bytes()
                post_hash = sha256_bytes(data)
                expected_hash = entry.get("expected_sha256")
                if expected_hash and post_hash != expected_hash:
                    failures.append(
                        f"post-write content differs from expected intent: {entry['path']}"
                    )
                changed = (
                    post_hash != entry["sha256"] or len(data) != entry["byte_length"]
                )
                if manifest.get("guard_mode") == "strict-write" and not changed:
                    failures.append(f"write produced no changed postimage: {entry['path']}")
                if changed:
                    changed_paths.append(entry["path"])
                observations.append(
                    {
                        "path": entry["path"],
                        "post_state": "present",
                        "post_sha256": post_hash,
                        "post_byte_length": len(data),
                        "changed": changed,
                    }
                )

        if failures:
            return {
                "status": "FAIL",
                "manifest_id": manifest.get("manifest_id"),
                "failures": failures,
                "changed_paths": changed_paths,
            }

        verified_time = utc_now()
        record = {
            "schema_version": SCHEMA_VERSION,
            "manifest_id": manifest.get("manifest_id"),
            "receipt_state": "verified",
            "verified_at": verified_time,
            "changed_paths": sorted(set(changed_paths)),
            "observations": observations,
            "failures": [],
            "intent_binding": "bound",
        }
        _write_new_json(output_receipt, record)

        manifest["lifecycle_state"] = "verified"
        manifest["verified_at"] = verified_time
        _rewrite_manifest(manifest_path, before_manifest, manifest)

        return {"status": "PASS", **record}
