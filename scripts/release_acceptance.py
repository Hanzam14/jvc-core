"""Isolated-install acceptance harness for the JVC 0.1.0 candidate.

Proves (locally, deterministically):
1. build-output purge verified, then fresh wheel + sdist build;
2. archive NAME + CONTENT audit of BOTH wheel and sdist (server absent,
   banned/private markers absent from member contents, not just names);
3. sdist unpacks and rebuilds to an equivalent wheel (host build backend);
4. genuinely new venv creation (refuses to reuse; refuses checkout-inside dirs);
5. wheel installation into that venv;
6. CLI execution from OUTSIDE the repository with PYTHONPATH unset;
7. `jvc --version`, `jvc --help`, `jvc demo` exit codes and outputs;
8. the imported package resolves to the installed environment, never the checkout
   (canonical path comparison, not string containment).

Terminology: ISOLATED INSTALL ACCEPTANCE. This is not a clean-machine test;
an external fresh-user/VM run remains a recommended human release gate.

Usage:
    python scripts/release_acceptance.py [--keep DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPO_NORM = os.path.normcase(str(REPO_ROOT.resolve()))

# Name-level markers (case-insensitive substring on member names).
BANNED_NAME_MARKERS = (
    "thrive",
    "hermes",
    "client-web",
    "hoybos",
    "jvc-oss-staging",
)
BANNED_SUFFIXES = (".key", ".pem", ".pfx", ".p12")

# Content-level patterns scanned inside text-decodable archive members.
BANNED_CONTENT_RES = [
    re.compile(r"thrive|hermes|client-web-business|native-ai-ads", re.IGNORECASE),
    re.compile(r"Hoybos"),
    re.compile(r"JVC-OSS-STAGING"),
    re.compile(r"jvc-core\.org"),
    re.compile(r"github\.com/placeholder"),
    re.compile(r"C:\\(Users|Projects)\\", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]{10,}"),
    re.compile(r"gho_[A-Za-z0-9]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"start_executor_server"),
]

# Wheel members that must exist; sdist must contain the same package set.
REQUIRED_WHEEL_MEMBERS = (
    "jvc/__init__.py",
    "jvc/cli.py",
    "jvc/configuration.py",
    "jvc/routing.py",
    "jvc/contracts.py",
    "jvc/demo.py",
    "jvc/policy/boundaries.py",
    "jvc/policy/guard.py",
    "jvc/policy/locks.py",
    "jvc/policy/authority.py",
    "jvc/execution/executor.py",
    "jvc/execution/runner.py",
    "jvc/recovery/store.py",
    "jvc/continuity/state.py",
)

REQUIRED_SDIST_TOPICS = (
    "pyproject.toml",
    "README.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "MANIFEST.in",
    "docs/provenance.md",
    "docs/security-model.md",
    "docs/public-api.md",
    "schemas/governance-policy.schema.json",
)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    if not cond:
        raise SystemExit(f"ACCEPTANCE FAILED at: {name} {detail}")


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def purge_verified(path: Path, label: str) -> None:
    if path.is_dir() or path.is_file():
        shutil.rmtree(path, ignore_errors=True) if path.is_dir() else path.unlink(
            missing_ok=True
        )
    check(f"purged {label}", not path.exists(), str(path))


def audit_member_content(name: str, data: bytes, archive: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return  # Binary member: names/suffixes are still checked.
    for rx in BANNED_CONTENT_RES:
        match = rx.search(text)
        check(
            f"{archive} content clean: {name}",
            match is None,
            f"pattern {rx.pattern!r} matched" if match else "",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated-install acceptance for JVC.")
    parser.add_argument("--keep", type=Path, default=None, help="Keep work dir for inspection")
    args = parser.parse_args()

    if args.keep is not None:
        keep = Path(args.keep).resolve()
        # Never operate inside the source checkout.
        try:
            keep.relative_to(REPO_ROOT.resolve())
            inside = True
        except ValueError:
            inside = False
        check("keep dir outside checkout", not inside, str(keep))
        # Never silently reuse an existing environment.
        check("keep dir is new or empty", not keep.exists() or not any(keep.iterdir()), str(keep))
        work = keep
    else:
        work = Path(tempfile.mkdtemp(prefix="jvc-accept-"))
    work.mkdir(parents=True, exist_ok=True)
    dist_dir = work / "dist"
    dist_dir.mkdir(exist_ok=True)
    outside = work / "outside"
    outside.mkdir(exist_ok=True)
    print(f"work dir: {work}")

    # 1. Purge build outputs (verified) and build fresh artifacts.
    print("--- purging build outputs ---")
    purge_verified(REPO_ROOT / "build", "build/")
    purge_verified(REPO_ROOT / "src" / "jvc.egg-info", "src/jvc.egg-info")
    print("--- building wheel + sdist ---")
    proc = run(
        [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(dist_dir)],
        cwd=str(REPO_ROOT),
        timeout=300,
    )
    check("build exit code", proc.returncode == 0, proc.stderr[-2000:] if proc.returncode else "")
    wheels = list(dist_dir.glob("*.whl"))
    sdists = list(dist_dir.glob("*.tar.gz"))
    check("exactly one wheel", len(wheels) == 1, str([w.name for w in wheels]))
    check("exactly one sdist", len(sdists) == 1, str([s.name for s in sdists]))
    wheel, sdist = wheels[0], sdists[0]

    # 2. Archive name + content audit of BOTH archives.
    print("--- auditing wheel ---")
    with zipfile.ZipFile(wheel) as zf:
        wheel_names = zf.namelist()
        wheel_blobs = {n: zf.read(n) for n in wheel_names}
    for required in REQUIRED_WHEEL_MEMBERS:
        check(f"wheel has {required}", required in wheel_names)
    for n in wheel_names:
        lower = n.lower()
        check(f"wheel name clean: {n}", not any(m in lower for m in BANNED_NAME_MARKERS))
        check(f"wheel suffix ok: {n}", not lower.endswith(BANNED_SUFFIXES))
        check("wheel excludes deferred server", "server.py" not in lower, n)
    for n, blob in wheel_blobs.items():
        audit_member_content(n, blob, "wheel")

    print("--- auditing sdist ---")
    with tarfile.open(sdist, "r:gz") as tf:
        sdist_members = tf.getmembers()
        sdist_names = tf.getnames()
        sdist_blobs = {m.name: tf.extractfile(m).read() for m in sdist_members if m.isfile()}
    top = sdist_names[0].split("/")[0] if sdist_names else ""
    for required in REQUIRED_SDIST_TOPICS:
        check(f"sdist has {required}", f"{top}/{required}" in sdist_names, required)
    for n in sdist_names:
        lower = n.lower()
        check(f"sdist name clean: {n}", not any(m in lower for m in BANNED_NAME_MARKERS))
        check("sdist excludes deferred server", "server.py" not in lower, n)
    for n, blob in sdist_blobs.items():
        audit_member_content(n, blob, "sdist")

    # 3. Sdist rebuild parity: unpack the sdist and rebuild a wheel from it
    # with the host backend; the package member set must match.
    print("--- sdist rebuild parity ---")
    unpack_dir = work / "sdist-unpack"
    with tarfile.open(sdist, "r:gz") as tf:
        tf.extractall(unpack_dir)
    rebuilt_dir = work / "rebuilt"
    rebuilt_dir.mkdir(exist_ok=True)
    proc = run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation",
         "--outdir", str(rebuilt_dir), str(unpack_dir / top)],
        cwd=str(REPO_ROOT),
        timeout=300,
    )
    check("sdist rebuild exit code", proc.returncode == 0, proc.stderr[-2000:] if proc.returncode else "")
    rebuilt = list(rebuilt_dir.glob("*.whl"))
    check("rebuilt exactly one wheel", len(rebuilt) == 1)
    with zipfile.ZipFile(rebuilt[0]) as zf:
        rebuilt_names = {n for n in zf.namelist() if n.startswith("jvc/")}
        rebuilt_hashes = {
            n: hashlib.sha256(zf.read(n)).hexdigest()
            for n in zf.namelist()
            if n.startswith("jvc/") and n.endswith(".py")
        }
    wheel_pkg = {n for n in wheel_names if n.startswith("jvc/")}
    check("sdist rebuild package parity (names)", rebuilt_names == wheel_pkg,
          str(rebuilt_names.symmetric_difference(wheel_pkg))[:500])
    wheel_hashes = {
        n: hashlib.sha256(blob).hexdigest()
        for n, blob in wheel_blobs.items()
        if n.startswith("jvc/") and n.endswith(".py")
    }
    check("sdist rebuild package parity (contents)", rebuilt_hashes == wheel_hashes,
          str([n for n in wheel_hashes if wheel_hashes.get(n) != rebuilt_hashes.get(n)])[:500])

    # 4. Genuinely new venv (refuse reuse).
    print("--- creating fresh venv ---")
    venv_dir = work / "venv"
    check("venv dir is new", not venv_dir.exists(), str(venv_dir))
    venv.create(venv_dir, with_pip=True)
    vpy = venv_python(venv_dir)
    check("venv python exists", vpy.is_file(), str(vpy))

    # 5. Install wheel (no index access needed beyond pip's own bootstrap).
    print("--- installing wheel ---")
    proc = run([str(vpy), "-m", "pip", "install", "--no-index", str(wheel)], timeout=300)
    check("pip install exit code", proc.returncode == 0, proc.stderr[-2000:] if proc.returncode else "")

    # 6/7. Outside-checkout CLI runs with PYTHONPATH unset.
    print("--- outside-checkout CLI execution ---")
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONPATH"}
    env.pop("PYTHONPATH", None)
    env.pop("__PYVENV_LAUNCHER__", None)
    check("PYTHONPATH absent", "PYTHONPATH" not in env)

    jvc_bin = venv_dir / ("Scripts/jvc.exe" if os.name == "nt" else "bin/jvc")
    check("console script installed", jvc_bin.is_file(), str(jvc_bin))
    proc = run([str(jvc_bin), "--version"], cwd=str(outside), env=env, timeout=60)
    check("jvc --version", proc.returncode == 0 and "0.1.0" in (proc.stdout + proc.stderr), proc.stdout.strip())

    proc = run([str(jvc_bin), "--help"], cwd=str(outside), env=env, timeout=60)
    check("jvc --help lists demo", proc.returncode == 0 and "demo" in proc.stdout, proc.stdout[:200])
    check("no serve command advertised", "serve" not in proc.stdout.lower())
    check("no check command advertised", "\n  check " not in f"\n{proc.stdout}")

    proc = run([str(jvc_bin), "demo"], cwd=str(outside), env=env, timeout=300)
    check("jvc demo exit 0", proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:])
    check("demo all steps passed", "ALL 15 STEPS PASSED" in proc.stdout)

    # 8. Import resolves to installed env, never the checkout (canonical).
    print("--- verifying installed import path ---")
    probe = "import jvc; print(jvc.__file__)"
    proc = run([str(vpy), "-c", probe], cwd=str(outside), env=env, timeout=60)
    check("import probe exit 0", proc.returncode == 0, proc.stderr[-1000:])
    imported_norm = os.path.normcase(str(Path(proc.stdout.strip()).resolve()))
    venv_norm = os.path.normcase(str(venv_dir.resolve()))
    check("import not from checkout", not imported_norm.startswith(REPO_NORM + os.sep), imported_norm)
    check("import from isolated venv", imported_norm.startswith(venv_norm + os.sep), imported_norm)

    print("==================================================")
    print("ISOLATED INSTALL ACCEPTANCE: PASS")
    print("EXTERNAL CLEAN MACHINE: NOT RUN (recommended human release gate)")
    print("==================================================")
    if args.keep is None:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
