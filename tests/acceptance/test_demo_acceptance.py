"""Acceptance test verifying the full 15-step synthetic demo end-to-end."""

from jvc.demo import run_demo


def test_full_synthetic_demo_acceptance(tmp_path):
    results = run_demo(base_dir=tmp_path)
    assert len(results) == 15
    for step, res in results.items():
        assert res["status"] == "PASS", f"Demo Step {step} failed: {res['name']} ({res['detail']})"
