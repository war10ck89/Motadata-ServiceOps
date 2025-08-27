#!/usr/bin/env python3
# genApiSpec.py
# =====================================================================================
# Purpose:
#   Interactive configuration helper for ServiceOps integrations.
#
# Key features you asked for:
#   • CLI modes:
#       -s | -set  -> Configure code config data (interactive)
#       -r | -run  -> Execute use case (placeholder for future logic)
#
#   • Progress bar UX:
#       - Start the progress bar AFTER capturing inputs.
#       - While running checks, show a two-line ASCII bar:
#             |=============-----------------|
#             0                                                     100
#       - When we need to print human-readable output (e.g., step results,
#         summary), we PAUSE the bar, print text, then RESUME the bar continuing
#         from where it left off.
#
#   • Logging:
#       - Log file lives under: <script_dir>/logs/
#       - Filename format: dd_mm_yyyy_hh_mm_ss_GAS.log
#       - Log format: [timestamp] [LEVEL] message
#       - ALL inputs (including PASSWORD) are logged in CLEAR TEXT in the log file
#         (per your explicit request). Console output is concise; errors go to console.
#
#   • URL/port validation and final URL build:
#       - Base URL must start with http/https, NO trailing slash, NO path/query/fragment,
#         and MUST NOT include a port.
#       - Port must be numeric [1..65535].
#       - If port is 80 or 443 → keep URL as-is; else append :<port>.
#
#   • Credentials capture and normalization:
#       - Username, Password (hidden input), Basic Authorization, API Key.
#       - Normalize:
#           Basic Authorization -> always "Basic <token>" and token must be non-empty.
#           API Key            -> always "Apikey <token>" and token must be non-empty.
#
#   • Connectivity/auth checks:
#       - Ping host to test reachability + compute simple average RTT from output.
#       - HTTP(S) latency check using urllib.
#       - OAuth token fetch (POST /api/oauth/token) using multipart/form-data.
#
#   • HTTPS behavior (important):
#       - ALL API calls/latency checks to HTTPS endpoints DISABLE SSL verification
#         (so self-signed/insecure certs are accepted).
#       - We ALSO provide a SEPARATE SSL validity test (verified handshake) and place
#         the result in the summary as:
#             SSL Valid: Yes / No / NA (for HTTP)
#         This test does NOT affect the behavior of API calls.
#
#   • Config file persistence:
#       - File: <script_dir>/config.properties
#       - Pre-write policy:
#           • If file doesn’t exist → create and write.
#           • If exists and empty → write.
#           • If exists and NOT empty → create backup folder:
#                 <script_dir>/backup/dd-Mmm-YYYY-hh_mm-GAS/
#             Copy existing file there, then empty the original and write new content.
#       - Contents written:
#             url:<final_url>
#             token:<Basic ....>
#             apikey:<Apikey ....>
#             username:<username>
#             password:<password>
#
#   • Summary printed to console at the end:
#       URL, SSL Valid, Accessibility, Avg Latency, Username, Basic Authorization,
#       API Key, Credentials OK/Not OK.
# =====================================================================================

import sys
import os
import re
import ipaddress
import ssl
import json
import time
import getpass
import logging
import platform
import subprocess
import shutil
import socket
import random
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from typing import Tuple, Optional, List, Dict, Any

# -------------------------------- Paths & Globals --------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
OP_CODE    = "GAS"
LOG_TS     = time.strftime("%d_%m_%Y_%H_%M_%S")        # dd_mm_yyyy_hh_mm_ss
LOG_DIR    = SCRIPT_DIR / "logs"
LOG_FILE   = LOG_DIR / f"{LOG_TS}_{OP_CODE}.log"

# -------------------------------- Progress Bar -----------------------------------------

class ProgressBar:
    """
    Two-line ASCII progress bar that supports pause/resume to show text in between.

        |====-----|
        0                                      100
    """
    def __init__(self, width: int = 33):
        self.width        = max(10, width)
        self.total_steps  = 1
        self.current      = 0
        self.active       = False

    def _bar_line(self) -> str:
        filled = int(self.current / max(1, self.total_steps) * self.width)
        filled = min(filled, self.width)
        return "|" + ("=" * filled) + ("-" * (self.width - filled)) + "|"

    def _baseline(self) -> str:
        return "0".ljust(self.width + 3) + "100"

    def start(self, total_steps: int, title: Optional[str] = None):
        self.total_steps = max(1, total_steps)
        self.current     = 0
        self.active      = True
        if title:
            print(title)
        print(self._bar_line())
        print(self._baseline(), flush=True)

    def update(self, step_msg: Optional[str] = None, step_inc: int = 1):
        if not self.active:
            return
        self.current = min(self.current + max(0, step_inc), self.total_steps)
        print(self._bar_line() + (f"  {step_msg}" if step_msg else ""), flush=True)

    def pause_and_print(self, text: str):
        if not text.endswith("\n"):
            text += "\n"
        sys.stdout.write(text)
        sys.stdout.flush()

    def resume(self, title: Optional[str] = None):
        if not self.active:
            return
        if title:
            print(title)
        print(self._bar_line())
        print(self._baseline(), flush=True)

    def finish(self, final_msg: str = "EXECUTION END: SUCCESS"):
        if not self.active:
            return
        self.current = self.total_steps
        print(self._bar_line() + f"  {final_msg}")
        print(self._baseline(), flush=True)
        self.active = False

# -------------------------------- Logging ----------------------------------------------

def _build_logger() -> logging.Logger:
    """
    File logger (DEBUG) + console logger (ERROR). Normal progress is printed by ProgressBar.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("genApiSpec")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.ERROR)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger

LOGGER = _build_logger()
BAR    = ProgressBar(width=33)

# -------------------------------- CLI Helpers ------------------------------------------

def help_and_exit(code: int = 2):
    print(
        "Invalid argument specified.\n\n"
        "Usage:\n"
        "  py -3 genApiSpec.py -s | -set    # Configure code config parameters\n"
        "  py -3 genApiSpec.py -r | -run    # Execute the code for your usecase\n"
    )
    LOGGER.error("Invalid argument. Displayed usage help.")
    sys.exit(code)

def exit_immediately():
    LOGGER.info("User requested exit with '$'.")
    LOGGER.info("EXECUTION END: ABORT")
    print("\nEXECUTION END: ABORT")
    sys.exit(1)

# ---------- Secret/Normal Prompt (robust; handles flaky getpass/IDEs/TTY issues) --------

def _win_masked_input(prompt_text: str) -> str:
    """
    Windows-only masked input using msvcrt (no echo/echo '*').
    Works reliably even when getpass is flaky or TTY is emulated.
    """
    import msvcrt  # type: ignore
    sys.stdout.write(prompt_text)
    sys.stdout.flush()
    buf = []
    while True:
        ch = msvcrt.getwch()
        # Handle special keys (arrows, etc.) which come as prefix + next char
        if ch in ("\x00", "\xe0"):
            _ = msvcrt.getwch()  # swallow the next char
            continue
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            break
        if ch == "\x03":  # Ctrl-C
            raise KeyboardInterrupt
        if ch == "\x16":  # Ctrl-V (ignore paste to avoid dumping secrets)
            continue
        if ch == "\b":    # Backspace
            if buf:
                buf.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        # Normal char
        buf.append(ch)
        sys.stdout.write("*")
        sys.stdout.flush()
    return "".join(buf)

def prompt(prompt_text: str, secret: bool = False) -> str:
    """
    - Always prints "To exit execution enter $" before asking.
    - If secret:
        * First prints the prompt text (so it never gets swallowed).
        * Try getpass on real TTYs; if it fails or no TTY, use Windows masked input
          (msvcrt) or visible input with a warning.
    - '$' exits immediately.
    """
    print("To exit execution enter $")
    try:
        if not secret:
            val = input(prompt_text)
        else:
            # Ensure the prompt text is visible even if getpass writes to stderr
            # or the console suppresses its prompt.
            if sys.platform.startswith("win"):
                # Prefer robust Windows masked input
                try:
                    val = _win_masked_input(prompt_text)
                except Exception:
                    # As a last resort, fall back to getpass or visible input
                    try:
                        sys.stdout.write(prompt_text)
                        sys.stdout.flush()
                        val = getpass.getpass("")  # empty prompt (we already printed)
                    except Exception:
                        print("(Password will be visible here; secure input unsupported.)")
                        val = input(prompt_text)
            else:
                # Non-Windows: try getpass on TTYs
                if sys.stdin.isatty() and sys.stdout.isatty():
                    try:
                        sys.stdout.write(prompt_text)  # print prompt ourselves
                        sys.stdout.flush()
                        val = getpass.getpass("")      # empty prompt to avoid duplicates
                    except Exception:
                        print("(Password will be visible here; secure input unsupported.)")
                        val = input(prompt_text)
                else:
                    # No TTY (IDE/pipe) → visible input with notice
                    print("(Password will be visible here; secure input unsupported.)")
                    val = input(prompt_text)
    except (KeyboardInterrupt, EOFError):
        print()
        exit_immediately()

    v = (val or "").strip()
    if v == "$":
        exit_immediately()
    return v

# ----------------------------- URL/Port Validation -------------------------------------

_URL_SCHEME_RE = re.compile(r"^(http|https)://", re.IGNORECASE)
_DOMAIN_RE     = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9]"
    r"(?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(?:\."
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)

def validate_base_url(raw: str) -> str:
    s = raw.strip()
    if not _URL_SCHEME_RE.search(s):
        raise ValueError("URL must start with http:// or https://")
    if s.endswith("/"):
        raise ValueError("URL must not end with '/'")
    parsed = urlparse(s)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL scheme must be http or https")
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("URL must not contain path, params, query or fragment")
    if ":" in parsed.netloc:
        raise ValueError("Do not include port in the URL. Provide the port separately.")
    host = parsed.netloc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _DOMAIN_RE.match(host):
            raise ValueError("Host must be a valid IPv4 or domain (e.g., support.example.com)")
    return s

def validate_port(raw: str) -> int:
    if not raw.isdigit():
        raise ValueError("Port must be numeric.")
    p = int(raw)
    if p < 1 or p > 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return p

def build_final_base_url(base_url: str, port: int) -> str:
    if port in (80, 443):
        return base_url
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}:{port}"

# ----------------------------- Credential Normalization --------------------------------

def normalize_basic_auth(value: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("Basic Authorization value cannot be empty.")
    low   = v.lower()
    token = v
    if low.startswith("basic"):
        token = v[5:].strip()
    if not token:
        raise ValueError("Basic Authorization token cannot be empty.")
    return "Basic " + token

def normalize_api_key(value: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("API Key cannot be empty.")
    low   = v.lower()
    token = v
    if low.startswith("apikey"):
        token = v[6:].strip()
    if not token:
        raise ValueError("API Key token cannot be empty.")
    return "Apikey " + token

# ----------------------------- HTTPS Helpers -------------------------------------------

def https_unverified_context_for(url: str) -> Optional[ssl.SSLContext]:
    """
    For API calls/latency on HTTPS, return an UNVERIFIED context (self-signed OK).
    For HTTP, return None.
    """
    try:
        scheme = urlparse(url).scheme.lower()
    except Exception:
        scheme = ""
    if scheme == "https":
        return ssl._create_unverified_context()
    return None

def check_ssl_valid(url: str, timeout_sec: int = 6) -> str:
    """
    VERIFIED handshake for summary only. Returns: "Yes", "No", or "NA" for HTTP.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return "NA"
    host = parsed.hostname or ""
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()  # verified
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                _ = ssock.getpeercert()
        return "Yes"
    except Exception as e:
        LOGGER.debug(f"SSL validity check failed: {type(e).__name__}: {e}")
        return "No"

# ----------------------------- Network/HTTP Tests --------------------------------------

def ping_host(host: str, count: int = 2, timeout_sec: int = 4) -> Tuple[bool, float]:
    import re as _re
    system = platform.system().lower()
    if "windows" in system:
        cmd     = ["ping", "-n", str(count), "-w", str(timeout_sec * 1000), host]
        time_re = _re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", _re.IGNORECASE)
    else:
        cmd     = ["ping", "-c", str(count), "-W", str(timeout_sec), host]
        time_re = _re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", _re.IGNORECASE)
    try:
        proc  = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec * (count + 1))
        out   = proc.stdout + "\n" + proc.stderr
        times = [float(x) for x in time_re.findall(out)]
        avg   = sum(times) / len(times) if times else -1.0
        return (proc.returncode == 0, avg)
    except Exception:
        return (False, -1.0)

def measure_http_latency(url: str, timeout_sec: int = 6) -> float:
    req = Request(url, headers={"User-Agent": "genApiSpec/1.0"})
    ctx = https_unverified_context_for(url)  # unverified for HTTPS
    start = time.perf_counter()
    with urlopen(req, timeout=timeout_sec, context=ctx) as resp:
        resp.read(1)
    end = time.perf_counter()
    return (end - start) * 1000.0

def oauth_bearer_token(base_url: str, username: str, password: str, basic_auth_header: str,
                       timeout_sec: int = 15) -> Tuple[bool, dict, int]:
    """
    POST {base_url}/api/oauth/token  (multipart/form-data)
    Headers:
      Authorization: Basic <...>
      Content-Type: multipart/form-data
    Form:
      username=<user>, password=<pass>, grant_type=password
    Uses UNVERIFIED SSL for HTTPS (self-signed OK).
    """
    endpoint = f"{base_url}/api/oauth/token"

    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    parts = []
    def add_field(name: str, value: str):
        parts.append(f"--{boundary}\r\n"
                     f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                     f"{value}\r\n")
    add_field("username", username)
    add_field("password", password)
    add_field("grant_type", "password")
    body = ("".join(parts) + f"--{boundary}--\r\n").encode("utf-8")

    headers = {
        "Authorization": basic_auth_header,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "genApiSpec/1.0"
    }

    req = Request(endpoint, data=body, headers=headers, method="POST")
    ctx = https_unverified_context_for(endpoint)  # unverified for HTTPS
    try:
        with urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            status = resp.getcode()
            raw    = resp.read()
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                parsed = {}
            ok = (status == 200) and isinstance(parsed, dict) and ("access_token" in parsed)
            return ok, parsed, status
    except Exception as e:
        return False, {"error": type(e).__name__, "detail": str(e)}, -1

# ----------------------------- Configure Mode ------------------------------------------

class ConfigureMode:
    def __init__(self):
        self.url_input   = ""
        self.port        = 0
        self.username    = ""
        self.password    = ""
        self.basic_auth  = ""
        self.api_key     = ""
        self.final_url   = ""
        self.summary     = {}

    def run(self):
        LOGGER.info(f"Op Code = {OP_CODE}")
        LOGGER.info("Operation = Configure Code Config Data")

        try:
            self.collect_inputs()  # all inputs logged to FILE (plain text)

            # Start progress AFTER inputs
            total_steps = 9  # includes SSL validity check
            BAR.start(total_steps, title="==== Running Connectivity & Auth Checks ====")

            # Final URL
            self.final_url = build_final_base_url(self.url_input, self.port)
            LOGGER.info(f"Final Base URL: {self.final_url}")
            BAR.update("Prepared base URL")

            # SSL validity (verified; does NOT affect API behaviors)
            ssl_ok = check_ssl_valid(self.final_url)
            BAR.pause_and_print(f"SSL Validity (verified): {ssl_ok}")
            BAR.resume()
            BAR.update("SSL validity checked")

            # Ping
            host = urlparse(self.final_url).hostname or ""
            ping_ok, ping_avg = ping_host(host, count=2, timeout_sec=4)
            if ping_ok:
                LOGGER.info(f"Ping success. Avg reply time: {ping_avg:.2f} ms")
                BAR.pause_and_print(f"Ping: SUCCESS (avg {ping_avg:.2f} ms)")
            else:
                LOGGER.error("Ping failed.")
                BAR.pause_and_print("Ping: FAILED")
            BAR.resume()
            BAR.update("Ping check done")

            # Latency
            latency_ms = -1.0
            if ping_ok:
                try:
                    latency_ms = measure_http_latency(self.final_url, timeout_sec=6)
                    LOGGER.info(f"HTTP latency to base URL: {latency_ms:.2f} ms")
                    BAR.pause_and_print(f"HTTP Latency: {latency_ms:.2f} ms")
                except Exception as e:
                    LOGGER.error(f"HTTP latency measurement failed: {e}")
                    BAR.pause_and_print(f"HTTP Latency: FAILED ({e})")
            else:
                BAR.pause_and_print("Skipping HTTP latency due to ping failure.")
            BAR.resume()
            BAR.update("Latency check done")

            # Credentials (OAuth token)
            cred_ok    = False
            http_status = -1
            if ping_ok and latency_ms >= 0:
                cred_ok, payload, http_status = oauth_bearer_token(
                    self.final_url, self.username, self.password, self.basic_auth
                )
                if cred_ok:
                    LOGGER.info("Credentials validated successfully (access_token received).")
                    BAR.pause_and_print("Credentials: OK (access_token received)")
                else:
                    LOGGER.error(f"Credential validation failed. HTTP status: {http_status}; payload: {payload}")
                    BAR.pause_and_print(f"Credentials: NOT OK (HTTP {http_status})")
            else:
                LOGGER.error("Skipping credential validation due to previous failures.")
                BAR.pause_and_print("Credentials: SKIPPED")
            BAR.resume()
            BAR.update("Credential check done")

            # Summary
            self.summary = {
                "URL":                self.final_url,
                "SSLValid":           ssl_ok,  # Yes / No / NA
                "Accessibility":      "Reachable" if ping_ok else "Not reachable",
                "AvgLatencyMs":       f"{latency_ms:.2f}" if latency_ms >= 0 else "N/A",
                "Username":           self.username,
                "BasicAuthorization": self.basic_auth,
                "ApiKey":             self.api_key,
                "Credentials":        "OK" if cred_ok else "Not OK"
            }
            LOGGER.info(
                "SUMMARY | URL=%s | SSLValid=%s | Accessibility=%s | LatencyMs=%s | Username=%s | BasicAuth=%s | ApiKey=%s | Credentials=%s",
                self.summary["URL"], self.summary["SSLValid"], self.summary["Accessibility"],
                self.summary["AvgLatencyMs"], self.summary["Username"],
                self.summary["BasicAuthorization"], self.summary["ApiKey"],
                self.summary["Credentials"]
            )
            BAR.pause_and_print(
                "\n===== SUMMARY =====\n"
                f"URL: {self.summary['URL']}\n"
                f"SSL Valid: {self.summary['SSLValid']} (HTTP = NA)\n"
                f"Accessibility: {self.summary['Accessibility']}\n"
                f"Avg. Latency: {self.summary['AvgLatencyMs']} ms\n"
                f"Username: {self.summary['Username']}\n"
                f"Basic Authorization: {self.summary['BasicAuthorization']}\n"
                f"API Key: {self.summary['ApiKey']}\n"
                f"Credentials: {self.summary['Credentials']}\n"
                "===================\n"
            )
            BAR.resume()
            BAR.update("Summary displayed")

            # Persist config if all passed
            if ping_ok and latency_ms >= 0 and self.summary["Credentials"] == "OK":
                self.write_config()
                LOGGER.info("Config File Configured")
                BAR.update("Config file written")
                LOGGER.info("EXECUTION END: SUCCESS")
                BAR.finish("EXECUTION END: SUCCESS")
                sys.exit(0)
            else:
                LOGGER.info("EXECUTION END: ABORT")
                BAR.finish("EXECUTION END: ABORT")
                sys.exit(1)

        except Exception as e:
            LOGGER.error(f"Unhandled error: {e}", exc_info=True)
            print(f"\n[ERROR] {e}")
            print("EXECUTION END: ABORT")
            try:
                BAR.finish("EXECUTION END: ABORT")
            except Exception:
                pass
            sys.exit(1)

    def collect_inputs(self):
        # URL
        while True:
            raw = prompt("Please provide the URL of ServiceOps Target. (Example: https://support.motadata.com)\n> ")
            try:
                self.url_input = validate_base_url(raw)
                LOGGER.info("Captured URL: %s", self.url_input)
                break
            except ValueError as ve:
                LOGGER.error(str(ve))
                print(str(ve))

        # Port
        while True:
            raw = prompt("Please provide the port of ServiceOps Target. (Example: 80 or 443)\n> ")
            try:
                self.port = validate_port(raw)
                LOGGER.info("Captured Port: %s", self.port)
                break
            except ValueError as ve:
                LOGGER.error(str(ve))
                print(str(ve))

        # Username
        while True:
            u = prompt("Please provide the integration super admin user's Logon name from ServiceOps.\n> ")
            if u:
                self.username = u
                LOGGER.info("Captured Username: %s", self.username)
                break
            else:
                msg = "Username cannot be empty."
                LOGGER.error(msg)
                print(msg)

        # Password (masked on Windows; falls back if needed). Logged to FILE in clear text.
        while True:
            p = prompt("Please provide the integration super admin user's password from ServiceOps.\n> ")
            if p:
                self.password = p
                LOGGER.info("Captured Password: %s", self.password)  # plaintext in FILE
                break
            else:
                msg = "Password cannot be empty."
                LOGGER.error(msg)
                print(msg)

        # Basic Authorization (normalize to "Basic <token>")
        while True:
            b = prompt(
                "Please provide the REST Integration - Basic Authorization value for the above user from ServiceOps.\n"
                "Go to Settings > Integrations > REST Integration > Specific user > Above user logon name\n"
                "Copy the value of Basic Authorization field.\n> "
            )
            try:
                self.basic_auth = normalize_basic_auth(b)
                LOGGER.info("Captured Basic Authorization: %s", self.basic_auth)  # plaintext in FILE
                break
            except ValueError as ve:
                LOGGER.error(str(ve))
                print(str(ve))

        # API Key (normalize to "Apikey <token>")
        while True:
            k = prompt(
                "Please provide the API Integration - API Key value for the above user from ServiceOps.\n"
                "Go to Settings > Integrations > API Integration > Specific user > Above user logon name\n"
                "Copy the value of API Key field.\n> "
            )
            try:
                self.api_key = normalize_api_key(k)
                LOGGER.info("Captured API Key: %s", self.api_key)  # plaintext in FILE
                break
            except ValueError as ve:
                LOGGER.error(str(ve))
                print(str(ve))

    def write_config(self):
        """
        Backup policy:
          - If config.properties doesn't exist: create & write.
          - If exists and empty: write.
          - If exists and NOT empty: backup to ./backup/<dd-Mmm-YYYY-hh_mm-GAS>/ then empty original and write.
        """
        cfg_path = SCRIPT_DIR / "config.properties"
        try:
            content = (
                f"url:{self.final_url}\n"
                f"token:{self.basic_auth}\n"
                f"apikey:{self.api_key}\n"
                f"username:{self.username}\n"
                f"password:{self.password}\n"
            )

            if not cfg_path.exists():
                LOGGER.info("config.properties not found. Creating new file.")
                cfg_path.touch()
            else:
                size = cfg_path.stat().st_size
                if size == 0:
                    LOGGER.info("config.properties exists and is empty. Proceeding.")
                else:
                    backup_root = SCRIPT_DIR / "backup"
                    ts         = time.strftime("%d-%b-%Y-%H_%M-GAS")  # dd-Mmm-YYYY-hh_mm-GAS
                    backup_dir = backup_root / ts
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    backup_file = backup_dir / cfg_path.name
                    shutil.copy2(cfg_path, backup_file)
                    LOGGER.info("Backed up existing config to: %s", backup_file)
                    # Empty original
                    open(cfg_path, "w", encoding="utf-8").close()
                    LOGGER.info("Emptied existing config.properties.")

            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(content)
            LOGGER.info("Wrote configuration to: %s", cfg_path)

        except Exception as e:
            LOGGER.error(f"Failed while preparing/writing config file: {e}", exc_info=True)
            raise

# ----------------------------- Run Mode (placeholder) -----------------------------------

class RunMode:
    def run(self):
        BAR.start(2, title="==== Running Use Case (placeholder) ====")
        BAR.update("Initializing")
        time.sleep(0.2)
        BAR.pause_and_print("No logic implemented yet for -r | -run.")
        BAR.resume()
        BAR.update("Done")
        BAR.finish("EXECUTION END: SUCCESS")
        sys.exit(0)

# -------------------------------- Main --------------------------------------------------

def main():
    if len(sys.argv) != 2:
        help_and_exit()

    arg = sys.argv[1].strip().lower()
    if arg in ("-s", "-set"):
        ConfigureMode().run()
    elif arg in ("-r", "-run"):
        RunMode().run()
    else:
        help_and_exit()

if __name__ == "__main__":
    main()
