# Operating Guide for Agents in JVC

Welcome, agent. You are operating within the JVC repository.

---

## Required Startup Sequence

When resuming or starting work in JVC:
1. Read `AGENTS.md` (this file).
2. Read `README.md` and `ARCHITECTURE.md`.
3. Check status via `pytest tests/ -v`.

---

## Invariants & Rules

1. **Do Not Touch Real Production Projects:**
   - All work in JVC must operate against local test fixtures and mock repositories.
   - Do not write outside the repository root.

2. **Preserve Determinism:**
   - Do not replace deterministic lexical matching or schema validation with LLM prompts or heuristic guesses.

3. **Maintain Preimage Safety:**
   - Every file edit must provide an expected preimage hash.
   - Every write must pass through the atomic replacement and recovery store mechanisms.

4. **Preserve Test Integrity:**
   - Do not weaken, skip, or delete assertions merely to make tests pass.
   - Run the full test suite (`pytest`) before committing any change.
