"""Pytest configuration and shared fixtures for JVC tests."""

import sys
from pathlib import Path

# Ensure src is on sys.path
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
