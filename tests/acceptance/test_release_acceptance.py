"""Acceptance test running the isolated-install harness (Astra Finding 10).

Runs scripts/release_acceptance.py end-to-end: build, fresh venv, wheel
install, outside-checkout CLI execution with PYTHONPATH unset, archive
audit, and installed-import verification.
"""

import subprocess
import sys
from pathlib import Path


def test_isolated_install_acceptance(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "release_acceptance.py"
    assert script.is_file()
    keep = tmp_path / "accept-work"
    proc = subprocess.run(
        [sys.executable, str(script), "--keep", str(keep)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, f"harness failed:\n{proc.stdout[-4000:]}\n{proc.stderr[-4000:]}"
    assert "ISOLATED INSTALL ACCEPTANCE: PASS" in proc.stdout
