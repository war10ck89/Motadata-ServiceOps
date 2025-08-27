#!/usr/bin/env python3
"""
python_validate.py
A no-nonsense validator for a local Python install.
- Verifies version/arch, PATH, pip presence/CLI, SSL, internet reachability to PyPI,
  write access to site-packages, venv creation with pip, and (on Windows) py-launcher.
- Prints a compact report with OK/WARN/FAIL and exits non-zero if critical checks fail.
"""

import os
import sys
import ssl
import json
import time
import site
import shutil
import queue
import tempfile
import platform
import subprocess
import urllib.request
from pathlib import Path
from textwrap import shorten
from sysconfig import get_paths
import venv
import struct

CRITICAL_FAIL = False
REPORT = []  # list of dicts {name,status,detail}

def add(name, status, detail=""):
    global CRITICAL_FAIL
    REPORT.append({"name": name, "status": status, "detail": detail})
    if status == "FAIL" and name in {
        "Python executable reachable",
        "pip module import",
        "pip CLI",
        "SSL trust / HTTPS",
        "Venv creation + pip",
    }:
        CRITICAL_FAIL = True

def run(cmd, timeout=20):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            shell=False,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 999, "", str(e)

def check_basics():
    exe = sys.executable
    ver = sys.version.split()[0]
    arch = f"{8*struct.calcsize('P')}-bit"
    impl = platform.python_implementation()
    plat = platform.platform()
    add(
        "Python version",
        "OK",
        f"{impl} {ver} ({arch}) on {plat}\nExecutable: {exe}",
    )

def check_executable_on_path():
    exe_dir = Path(sys.executable).parent
    path_dirs = [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep)]
    on_path = any(exe_dir.samefile(p) if p.exists() else False for p in path_dirs)
    add(
        "Python dir in PATH (this session)",
        "OK" if on_path else "WARN",
        f"{'Found' if on_path else 'Not found'}: {exe_dir}",
    )
    # Confirm executable runs
    rc, out, err = run([sys.executable, "-V"])
    add("Python executable reachable", "OK" if rc == 0 else "FAIL", out or err)

def check_py_launcher_windows():
    if os.name != "nt":
        add("Windows py launcher", "OK", "Not applicable")
        return
    rc, out, err = run(["py", "-3", "-V"])
    if rc == 0 and out:
        add("Windows py launcher", "OK", out)
    else:
        add("Windows py launcher", "WARN", err or "py launcher not found")

def check_pip():
    # Import
    try:
        import pip  # noqa: F401
        add("pip module import", "OK", f"pip {pip.__version__}")
    except Exception as e:
        add("pip module import", "FAIL", repr(e))
        return
    # CLI
    rc, out, err = run([sys.executable, "-m", "pip", "--version"])
    add("pip CLI", "OK" if rc == 0 else "FAIL", out or err)

def check_ssl():
    # Basic HTTPS GET to PyPI index (small response). 5s timeout.
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen("https://pypi.org/simple/", timeout=5, context=ctx) as r:
            ok = (200 <= r.status < 300)
            add("SSL trust / HTTPS", "OK" if ok else "FAIL", f"HTTP {r.status}")
    except Exception as e:
        add("SSL trust / HTTPS", "FAIL", f"{type(e).__name__}: {e}")

def check_write_user_site():
    # Try writing a temp file to user site-packages
    target = Path(site.getusersitepackages())
    try:
        target.mkdir(parents=True, exist_ok=True)
        tmp = target / f".write_test_{int(time.time()*1000)}.tmp"
        tmp.write_text("ok", encoding="utf-8")
        tmp.unlink(missing_ok=True)
        add("Write access to USER_SITE", "OK", f"{target}")
    except Exception as e:
        add("Write access to USER_SITE", "WARN", f"{target} -> {e}")

def check_sys_site_paths():
    paths = get_paths()
    pure = Path(paths.get("purelib", ""))
    plat = Path(paths.get("platlib", ""))
    add("System site-packages (pure/plat)", "OK", f"{pure}\n{plat}")

def check_env_vars():
    noisy = []
    for key in ("PYTHONHOME", "PYTHONPATH"):
        val = os.environ.get(key)
        if val:
            noisy.append(f"{key}={val}")
    if noisy:
        add("Env vars that can break installs", "WARN", "; ".join(noisy))
    else:
        add("Env vars that can break installs", "OK", "None set")

def check_venv_with_pip():
    # Create a throwaway venv and ensure pip runs inside it.
    root = Path(tempfile.mkdtemp(prefix="pyval_venv_"))
    vdir = root / "venv"
    try:
        venv.EnvBuilder(with_pip=True, clear=True).create(vdir)
        bin_dir = vdir / ("Scripts" if os.name == "nt" else "bin")
        vpy = bin_dir / ("python.exe" if os.name == "nt" else "python")
        rc, out, err = run([str(vpy), "-m", "pip", "--version"], timeout=40)
        add("Venv creation + pip", "OK" if rc == 0 else "FAIL", out or err)
    except Exception as e:
        add("Venv creation + pip", "FAIL", f"{type(e).__name__}: {e}")
    finally:
        try:
            shutil.rmtree(root, ignore_errors=True)
        except Exception:
            pass

def check_network_download_head():
    # Non-fatal: try a small HEAD-like fetch via urllib to files.pythonhosted.org
    url = "https://files.pythonhosted.org/"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            add("Internet reachability (PyPI CDN)", "OK", f"HTTP {r.status}")
    except Exception as e:
        add("Internet reachability (PyPI CDN)", "WARN", f"{type(e).__name__}: {e}")

def format_report():
    # Pretty print without external packages
    name_w = max(len(r["name"]) for r in REPORT) + 2
    status_w = max(len(r["status"]) for r in REPORT) + 2
    lines = []
    lines.append("=" * (name_w + status_w + 60))
    lines.append("Python Installation Validation Report")
    lines.append("-" * (name_w + status_w + 60))
    for r in REPORT:
        status = r["status"]
        tag = {"OK": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(status, "")
        detail = r["detail"].replace("\r", "")
        first, *rest = detail.splitlines() or [""]
        lines.append(f"{r['name']:<{name_w}} {status:<{status_w}} {tag} {first}")
        for more in rest:
            lines.append(f"{'':<{name_w}} {'':<{status_w}}    {more}")
    lines.append("-" * (name_w + status_w + 60))
    oks = sum(1 for r in REPORT if r["status"] == "OK")
    warns = sum(1 for r in REPORT if r["status"] == "WARN")
    fails = sum(1 for r in REPORT if r["status"] == "FAIL")
    lines.append(f"Summary: OK={oks}  WARN={warns}  FAIL={fails}")
    lines.append("=" * (name_w + status_w + 60))
    return "\n".join(lines)

def main():
    check_basics()
    check_executable_on_path()
    check_py_launcher_windows()
    check_env_vars()
    check_pip()
    check_ssl()
    check_network_download_head()
    check_write_user_site()
    check_sys_site_paths()
    check_venv_with_pip()

    print(format_report())
    sys.exit(1 if CRITICAL_FAIL else 0)

if __name__ == "__main__":
    main()
