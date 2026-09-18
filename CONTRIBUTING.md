# Contributing to JVC

We welcome contributions to JVC. Please follow these guidelines to maintain code quality, security boundaries, and determinism.

---

## Development Setup

1. **Clone and Install:**
   ```bash
   git clone <repository_url>
   cd jvc
   pip install -e ".[dev]"
   ```

2. **Run Test Suite:**
   ```bash
   pytest -v
   ```

---

## Core Invariants to Preserve

1. **Determinism:** Routing decisions and policy validations must be deterministic and rule-based. Avoid introducing non-deterministic heuristics or generative LLM calls into the core policy layer.
2. **Fail-Closed Security:** Any missing, ambiguous, or tampered policy file, contract, or executable pin must immediately fail closed with a descriptive error.
3. **Durable Writes & Rollbacks:** Direct destructive writes are forbidden. All modifications must use lock-serialized preimage checks, safe temporary file creation, fsync, atomic replacement, and the write-ahead journal.
4. **Preimage Checks:** Every modification to an existing file must be validated against its caller-declared preimage hash inside the per-target interprocess lock.
5. **No Ambient Leaks:** The subprocess runner must maintain environment sanitization, stripping ambient API keys and Git variables.

---

## Pull Request Guidelines

- Ensure 100% of unit, integration, and security tests pass.
- Add tests covering new invariants, boundary cases, or path validation checks.
- Keep commits focused, clean, and well-described.
