"""Acceptance test verifying packaging, wheel and sdist building, and archive inspection."""

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def test_build_and_archive_contents(tmp_path):
    pkg_root = Path(__file__).resolve().parents[2]
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()

    # Build wheel and sdist using python -m build
    cmd = [
        sys.executable,
        "-m",
        "build",
        "--sdist",
        "--wheel",
        "--outdir",
        str(dist_dir),
        str(pkg_root),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"build failed: {proc.stderr}\n{proc.stdout}"

    wheels = list(dist_dir.glob("*.whl"))
    sdists = list(dist_dir.glob("*.tar.gz"))
    assert len(wheels) == 1, "Expected exactly 1 wheel file"
    assert len(sdists) == 1, "Expected exactly 1 sdist file"

    wheel_path = wheels[0]
    sdist_path = sdists[0]

    # Inspect wheel contents
    with zipfile.ZipFile(wheel_path) as z:
        names = z.namelist()
        # Verify required package files exist
        assert any(n.startswith("jvc/__init__.py") for n in names)
        assert any(n.startswith("jvc/routing.py") for n in names)
        assert any(n.startswith("jvc/contracts.py") for n in names)
        assert any(n.startswith("jvc/execution/executor.py") for n in names)
        assert any(n.startswith("jvc/policy/boundaries.py") for n in names)
        assert any(n.startswith("jvc/recovery/store.py") for n in names)
        assert any(n.startswith("jvc/continuity/state.py") for n in names)

        # Invariant: No private paths or secrets in archive
        for n in names:
            lower = n.lower()
            assert "thrive" not in lower
            assert "hermes" not in lower
            assert "client-web" not in lower
            assert "hoybos" not in lower
            assert not lower.endswith(".key")
            assert not lower.endswith(".pem")

        # Invariant: deferred 0.1.0 surfaces must not ship
        assert not any("execution/server.py" in n for n in names)

    # Inspect sdist contents
    with tarfile.open(sdist_path, "r:gz") as tar:
        tar_names = tar.getnames()
        assert any(n.endswith("pyproject.toml") for n in tar_names)
        assert any(n.endswith("README.md") for n in tar_names)
        for n in tar_names:
            lower = n.lower()
            assert "thrive" not in lower
            assert "hermes" not in lower
            assert "hoybos" not in lower
            assert not lower.endswith(".key")
