# Provenance Manifest (0.1.0 candidate)

This manifest inventories every meaningful source/specification file shipped in this candidate: origin class, known upstream source, licensing/attribution status, and the basis for each statement. It supports — but does not replace — human ownership/rights attestation. Nothing here is legal advice or legal clearance.

Working statement: **the candidate was derived/generalized from the maintainer-controlled private JVC implementation during OSS extraction, with further files newly authored in this repository during remediation. No third-party source is knowingly vendored, per the inventory below. On 2026-09-20, maintainer hanzam14 confirmed ownership of the inventoried code/docs or permission to release them under Apache-2.0. This records the maintainer's statement, not independent verification.**

Origin classes:
- `extracted/generalized` — derived from the maintainer-controlled private JVC during OSS extraction; adapted for standalone public use. Basis: extraction record (single-purpose derivation task, no third-party inputs in scope).
- `newly-authored` — written in this repository during remediation; no private source beyond the surrounding interfaces. Basis: authored against Astra findings in this checkout.
- `generated` — produced by deterministic tooling from the above (no independent authorship).
- `standard/tool-generated` — conventional configuration/metadata with no creative content.
- `tests` — synthetic verification material authored in this repository; fixtures use only RFC 2606-reserved example domains (`example.invalid`) and invented names.
- `docs` — methodology/operator documentation written during extraction and remediation from the maintainer's implementation.
- `schemas` — original schema text using the standard JSON Schema vocabulary (a specification, not vendored code).
- `ci` — workflow wiring around public actions referenced at run time, not vendored.

Third-party source vendored: **none known**. The CI workflow references public GitHub Actions (`actions/checkout@v4`, `actions/setup-python@v5`) by version tag at workflow run time; no third-party code is vendored into this repository.

---

## 1. Package source (`src/jvc/`)

| Path | Origin | Upstream | License/attribution | Basis |
| --- | --- | --- | --- | --- |
| `src/jvc/__init__.py` | `extracted/generalized` | none | no attribution obligation known | Package exports written for the OSS layout. |
| `src/jvc/cli.py` | `extracted/generalized` + `newly-authored` (unpinned `check` and deferred `serve` removed here) | none | no attribution obligation known | CLI surface decisions recorded in CHANGELOG. |
| `src/jvc/configuration.py` | `extracted/generalized` | none | no attribution obligation known | Registry/policy schemas for the OSS layout. |
| `src/jvc/routing.py` | `extracted/generalized` | none | no attribution obligation known | Lexical router. |
| `src/jvc/contracts.py` | `extracted/generalized` | none | no attribution obligation known | Execution contracts (host-only execution path; see `docs/public-api.md`). |
| `src/jvc/demo.py` | `extracted/generalized` | none | no attribution obligation known | Synthetic fixtures; reserved `example.invalid` identity only. |
| `src/jvc/policy/boundaries.py` | `extracted/generalized` + `newly-authored` (control-plane additions) | none | no attribution obligation known | Boundary rules evolved in this checkout. |
| `src/jvc/policy/guard.py` | `extracted/generalized` + `newly-authored` (output-path screening) | none | no attribution obligation known | Guard lifecycle + hardening in this checkout. |
| `src/jvc/policy/authority.py` | `extracted/generalized` + `newly-authored` (durability, provisioning) | none | no attribution obligation known | Trust code evolved in this checkout. |
| `src/jvc/policy/locks.py` | `newly-authored` | none | no attribution obligation known | Written in this checkout for the remediation. |
| `src/jvc/execution/executor.py` | `extracted/generalized` + `newly-authored` (locks, journal, safe-git, bounded diff) | none | no attribution obligation known | Largest remediation surface in this checkout. |
| `src/jvc/execution/runner.py` | `extracted/generalized` | none | no attribution obligation known | Declared-check runner. |
| `src/jvc/recovery/store.py` | `extracted/generalized` + `newly-authored` (journal, durability) | none | no attribution obligation known | Journal design written in this checkout. |
| `src/jvc/continuity/state.py` | `extracted/generalized` + `newly-authored` (lock serialization, decision semantics) | none | no attribution obligation known | Revision protocol evolved in this checkout. |
| `src/jvc/policy/__init__.py`, `src/jvc/execution/__init__.py`, `src/jvc/recovery/__init__.py`, `src/jvc/continuity/__init__.py` | `extracted/generalized` | none | no attribution obligation known | Trivial package markers/exports. |
| `src/jvc/execution/server.py` | — | — | — | **Removed** in remediation; ships in no 0.1.0 artifact. |

## 2. Schemas (`schemas/`)

| Path | Origin | Upstream | License/attribution | Basis |
| --- | --- | --- | --- | --- |
| `schemas/governance-policy.schema.json` | `schemas` (original text, `extracted/generalized`) | none; JSON Schema vocabulary is a standard specification | no attribution obligation known | Original schema text for the OSS layout. |
| `schemas/icm-execution-contract.schema.json` | `schemas` (original text, `extracted/generalized`) | none (same vocabulary note) | no attribution obligation known | Original schema text for the OSS layout. |
| `schemas/trusted-executables.schema.json` | `schemas` (original text, `extracted/generalized`) | none (same vocabulary note) | no attribution obligation known | Original schema text for the OSS layout. |

## 3. Examples (`examples/two-projects/`)

| Path | Origin | Upstream | License/attribution | Basis |
| --- | --- | --- | --- | --- |
| `PROJECT_ROUTES.md`, `demo-app/{AGENTS,CONTEXT,HANDOFF}.md`, `demo-library/{AGENTS,CONTEXT,HANDOFF}.md` | `extracted/generalized` | none | no attribution obligation known | Fully synthetic demo projects; no real project data. |

## 4. Documentation

| Path | Origin | Upstream | License/attribution | Basis |
| --- | --- | --- | --- | --- |
| `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `AGENTS.md` | `docs` (extraction + remediation) | none | no attribution obligation known | Methodology wording derived from the maintainer's implementation; behaviors verified by the test suite in this checkout. |
| `docs/security-model.md`, `docs/capabilities.md`, `docs/recovery.md`, `docs/configuration.md`, `docs/quickstart.md`, `docs/releasing.md`, `docs/licensing-review.md`, `docs/public-api.md` | `docs` (extraction + remediation) | none | no attribution obligation known | License comparison is explanatory; the official Apache-2.0 text is now included separately in LICENSE. |
| `docs/provenance.md` (this file) | `docs` (`newly-authored`) | none | — | Written in this checkout. |

## 5. Build / config

| Path | Origin | Upstream | License/attribution | Basis |
| --- | --- | --- | --- | --- |
| `pyproject.toml` | `extracted/generalized` | none | no attribution obligation known | Build metadata; neutral author field, no contact claimed. |
| `MANIFEST.in` | `newly-authored` | none | — | Explicit sdist policy written in this checkout. |
| `.gitattributes` | `standard/tool-generated` | none | — | Conventional LF normalization only. |
| `.gitignore` | `standard/tool-generated` | none | — | Conventional Python ignores. |
| `.github/workflows/ci.yml` | `ci` (extraction + remediation) | references public actions at run time, not vendored | follow action pinning at release setup | Workflow wiring; no third-party code in repo. |
| `scripts/release_acceptance.py` | `newly-authored` (developer tooling; excluded from artifacts) | none | — | Isolated-install harness written in this checkout. |

## 6. Tests (`tests/`)

All files under `tests/` are class `tests`: synthetic verification material authored during extraction and remediation in this repository. Local Git identities are `Test User <test@example.invalid>` / `Demo User <demo@example.invalid>` (`example.invalid` is RFC 2606-reserved; no real identity referenced). Fixtures are self-contained under temporary directories. Tests ship in the git checkout and CI only — not in wheel/sdist artifacts (see `MANIFEST.in` and `docs/releasing.md`).

---

## 7. Unresolved questions (human gates)

1. Apache-2.0 was selected under maintainer delegation on 2026-09-20; `LICENSE` contains the official text from https://www.apache.org/licenses/LICENSE-2.0.txt. The ownership/permission attestation is recorded below.
2. On 2026-09-20, hanzam14 explicitly confirmed ownership of the inventoried JVC code/docs or permission to release them under Apache-2.0. This maintainer attestation is not independent proof of title or a legal opinion.
3. Public repository: <https://github.com/Hanzam14/jvc-core>. Maintainer contact and security reporting channel: SECURITY.md (GitHub private vulnerability reporting). No placeholders are claimed anywhere in this candidate.
4. The commit author identity used for local history is recorded in the release report; no invented maintainer domain is used.
5. No file above has a known third-party upstream requiring attribution; if review surfaces one, it will be listed here before publication.
