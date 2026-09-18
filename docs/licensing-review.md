# Licensing Review & Candidate Comparison

> [!IMPORTANT]
> The repository maintainer has **not** selected a final open-source license yet.
> A `LICENSE` file is intentionally omitted pending an explicit human decision after provenance review.
> This document compares candidates WITHOUT declaring either legally cleared.
> Nothing here is legal advice.

---

## 1. Candidate Licenses Comparison

### Option A: MIT License
- **Type:** Permissive, short, widely recognized.
- **Key Characteristics:**
  - Grants permission to use, copy, modify, merge, publish, distribute, sublicense, and sell.
  - Requires only preserving the copyright notice and permission notice in all copies or substantial portions.
  - Does **not** contain an express patent license grant.
  - Minimal redistribution overhead.
- **Status for JVC:** **PLAUSIBLE**, subject to the provenance inventory (`docs/provenance.md`) and human review. No legal certainty is claimed.

### Option B: Apache License 2.0 (Apache-2.0)
- **Type:** Permissive with comprehensive patent and trademark provisions.
- **Key Characteristics:**
  - Includes an explicit, royalty-free patent license grant from every contributor.
  - Contains a patent retaliation clause (patent license terminates if a recipient initiates patent litigation alleging infringement).
  - Explicitly states that trademark rights are not granted.
  - Requires attribution, copy of the license, notice of modifications, and preservation of `NOTICE` files.
- **Status for JVC:** **PLAUSIBLE**, subject to the provenance inventory (`docs/provenance.md`) and human review. No legal certainty is claimed.

---

## 2. Third-Party Provenance Summary

Per the file-level inventory in `docs/provenance.md`:
- **Python Standard Library:** Core functionality uses only the standard library (`hashlib`, `json`, `os`, `pathlib`, `subprocess`, `tempfile`, `hmac`, `re`, `secrets`, `argparse`).
- **Dependencies:** JVC has **zero mandatory runtime external dependencies**.
- **Optional Development Dependencies:** `pytest`, `build`, `wheel` (used exclusively for local testing and packaging).
- **Third-Party Code:** No third-party source code is knowingly vendored in this public candidate, subject to the provenance inventory. See `docs/provenance.md` for per-file origin, confidence, and unresolved questions.

### Constraint Assessment
No retained material is known to create copyleft or redistribution constraints. Both MIT and Apache-2.0 remain **PLAUSIBLE**; neither is declared "100% viable" or "completely cleared." Final selection remains a human decision after provenance review.

---

## 3. Decision Guidance for the Human Maintainer

- Choose **MIT** if the primary goal is maximum simplicity, minimal legal text, and standard adoption in the Python ecosystem.
- Choose **Apache-2.0** if you desire explicit patent grants and protection against patent retaliation.
