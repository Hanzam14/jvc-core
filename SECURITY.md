# Security Policy

## Reporting Security Issues

The public repository and its dedicated security reporting channel are not yet established. Until a dedicated security reporting address is published, open a GitHub Security Advisory after the public repository is created. Do not open a public issue for a suspected boundary bypass.

---

## Threat Model & Boundary Assumptions

### Trusted Plane (Host & Operator)
- Host operator operating environment and shell.
- Host configuration files and governance policies.
- Cryptographic HMAC operator authorization keys (provisioned outside all governed roots).
- Pinned executable identities (e.g., system Git, Python binaries with verified SHA-256 hashes).
- Host-owned recovery store, capability trust store, and interprocess lock directory (all outside governed roots).

### Untrusted / Lower-Trust Plane (Tool-Calling Agents)
- Model-facing tool execution requests (e.g., file writes, Git staging, branch switching).
- Project contents, dependencies, scripts, and Markdown files.
- Natural-language queries.

---

## Security Guarantees & Non-Guarantees

### What JVC Provides (within its documented scope):
1. **Path Containment:** Actions mediated through JVC cannot escape the canonical resolved project root.
2. **Secret-Pattern Denial:** Listed secret filename patterns (`.env`, `credentials.*`, `*.pem`, `*.key`, `id_rsa`, `token.json`, `auth.json`, `*.p12`, `*.pfx`, and related) are denied before read, write, stage, or diff operations. This is a denylist, not a secret detector.
3. **Lock-Serialized Preimage Checks:** Stale writes are rejected; concurrent writers presenting the same preimage serialize under an interprocess lock so exactly one succeeds. Locking failures fail closed.
4. **Preimage Recovery:** All successful writes are preceded by a verified backup image plus a durable write-ahead journal record; interrupted transactions are reconciled or flagged `RECOVERY_REQUIRED` on restart.
5. **Explicit Git Helper Policy:** Ambient hooks and environment are neutralized; repository-local executable helpers (filters, textconv, external diff, includes) are rejected for mutations and neutralized for bounded diff.
6. **Bounded Inspection:** Git read surfaces require explicit file paths (no repository-wide diff) and enforce byte bounds.

### What JVC Does NOT Guarantee:
1. **Unrestricted Shell Sandbox:** JVC does **not** sandbox arbitrary commands run outside of JVC by a process that already has unrestricted local user shell access.
2. **Kernel Isolation:** JVC is a policy and verification engine, not a hypervisor or OS container.
3. **Universal Replay Prevention:** Capability single-use is guaranteed within one configured trust store on the local host only.
4. **Complete Confidentiality Scanning:** Filename denylists and path validation bound the diff interface; they do not detect secrets by content.
5. **Network Security:** There is no network-facing interface in 0.1.0.
