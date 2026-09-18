# Operator Capabilities & Authorization

Certain operations in JVC are classified as privileged and cannot be executed by tool-calling agents without explicit operator authorization.

---

## 1. Privileged Surfaces

The following operations require an operator capability:
1. **Control-Plane Modifications:** Modifying files in `.git/`, `.continuity/`, `_config/`, `contracts/`, `_promotions/`, or any `.gitattributes` file.
2. **HELD Project Mutations:** Writing to projects marked with `held` lifecycle status in the registry.

---

## 2. Proposal & Capability Lifecycle

1. **Proposal Creation:**
   When an agent requests a privileged write, the executor creates a pending proposal in `confirmations/pending/<confirmation_id>.json` (written atomically and durably):
   - Generates a unique 24-byte random `nonce`.
   - Records the exact target, payload SHA-256, and expiration timestamp (default: 300 seconds).

2. **Operator Signing:**
   The human operator or trusted host process signs the claims using HMAC-SHA256 and the provisioned 256-bit operator key:
   ```python
   token = sign_capability(claims, operator_secret)
   ```
   The operator key may be provisioned to a file with `generate_operator_key()` (host-only API; `forbidden_roots` is a REQUIRED argument so placement can never be accidentally omitted; refuses unsafe placement inside governed roots and refuses silent overwrite; rotation requires the explicit atomic `rotate_operator_key()` path, which preserves the old key if interrupted). Permission hardening is best-effort and OBSERVABLE via the `hardening_report` (`chmod` result + Windows `icacls` result): ACL hardening failure is a WARNING for 0.1.0 — provisioning succeeds and the operator must verify restrictive permissions out of band.
   
   Alternatively the key may be supplied from the environment via the documented protocol `load_operator_secret_from_env()` (default variable `JVC_OPERATOR_SECRET_HEX`, 64 hex characters, validated, never persisted automatically by JVC).

3. **Durable Single-Use Consumption:**
   When presented with the capability token:
   - JVC verifies the HMAC signature.
   - JVC checks that the current time is before `expires_at`.
   - JVC records the nonce hash in `confirmations/consumed/<nonce_hash>.json` using exclusive file creation (`open(path, 'x')`) followed by flush + fsync **before** the privileged action executes.
   - If the required file persistence (flush + fsync) fails for any reason, authorization is DENIED, the half-written record is removed, and the privileged action is NOT executed.
   - Parent-directory sync is best-effort (`synced` / `unsupported` / `failed`) and does not gate authorization. The documented guarantee is therefore file-content durability, not directory-entry durability: on platforms without directory sync (e.g., Windows), a power loss in the narrow window between file sync and directory persistence could lose the record. Plan privileged operations accordingly.
   - If the nonce was already consumed, the operation is immediately denied.
   - The pending proposal is deleted.

---

## 3. Exact Guarantee and Limits

Capability single-use is guaranteed **within one configured trust store under the supported local-host model**: concurrent consumers sharing the same store produce exactly one winner.

Separate or restored trust stores do not share state, and JVC does not claim installation-wide single-use across arbitrary stores. The trust (confirmation) store and recovery store are host-owned and MUST resolve outside every governed project root; the executor refuses to initialize otherwise, and ordinary governed operations cannot reach them.
