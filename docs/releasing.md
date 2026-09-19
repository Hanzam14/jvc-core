# Packaging & Releasing Guide

This document describes the build, verification, and release process for JVC.

> Apache-2.0 is selected and `LICENSE` ships in both distributions. The maintainer's ownership/permission attestation was recorded on 2026-09-20. Publication requires the final commit, artifact hashes, verified security-reporting route, and external clean-machine evidence to be explicitly approved.

---

## 1. Building Distribution Archives

JVC uses `pyproject.toml` with standard `setuptools` build backend.

To build both wheel and sdist:

```bash
python -m pip install --upgrade build
python -m build
```

The build artifacts will be placed in `dist/`:
- `dist/jvc-0.1.0-py3-none-any.whl`
- `dist/jvc-0.1.0.tar.gz`

## 2. Explicit Inclusion Policy (`MANIFEST.in`)

The wheel contains the `jvc` package from `src/jvc/` plus standard distribution metadata and the license text. The sdist additionally ships user-facing material only:

- INCLUDE: top-level docs (`README`, `SECURITY`, `ARCHITECTURE`, …), `docs/`, `schemas/`, `examples/`.
- EXCLUDE: `tests/`, `scripts/`, `.github/` (developer/verification material that lives in the git checkout and CI, not in the artifact), build residue, caches.
- The deferred server module is excluded by name AND asserted absent by archive audits, even if the file ever reappears in the tree.

---

## 2. Archive Audit Checklist

Before releasing any artifact:
1. **Archive Inspection:**
   - Enumerate all files in the wheel:
     ```bash
     python -m zipfile -l dist/jvc-0.1.0-py3-none-any.whl
     ```
   - Confirm package code, standard distribution metadata, and license text are included (no server module ships in 0.1.0).
   - Confirm no test temporary files, caches, or `.continuity/` state exist.
2. **Privacy Scan:**
   - Verify no machine-specific user-profile paths or private portfolio names are present in the archives.
3. **Isolated Install Acceptance (required):**
   - Run the deterministic harness, which builds the wheel/sdist, creates a brand-new temporary virtual environment, installs the wheel, unsets `PYTHONPATH`, and invokes the installed CLI from outside the checkout:
     ```bash
     python scripts/release_acceptance.py
     ```
   - The harness verifies `jvc --version`, `jvc --help`, `jvc demo`, and that the imported package resolves to the installed environment (never the source checkout).
4. **External Clean-Machine Test (required release gate for 0.1.0):**
   - A true fresh-user/VM install test remains a human release step; it is required for this release and is not claimed by the local harness.
