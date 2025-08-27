#!/usr/bin/env python3
# genApiSpec.py
# =====================================================================================
# Purpose:
#   Interactive helper for ServiceOps:
#     • -s | -set → Capture & validate connection credentials, write config.properties
#     • -r | -run → Generate API Specification document (Markdown) + real API calls
#
# New in this build:
#   • For every protected API call:
#       - Try API KEY first
#       - If it fails (status != 200): obtain a FRESH BEARER via Login API (using Basic
#         from config.properties) and retry with that Bearer
#   • Every API REQUEST and RESPONSE is logged (headers+payload+status+body) for triage
#   • HTTPS verification is DISABLED for all API calls (self-signed OK)
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
OUTPUT_DIR = SCRIPT_DIR / "output"

# -------------------------------- Progress Bar -----------------------------------------

class ProgressBar:
    """
    Two-line ASCII progress bar with pause/resume.

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
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("genApiSpec")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)          # file: DEBUG (full triage)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.ERROR)          # console: only errors
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger

LOGGER = _build_logger()
BAR    = ProgressBar(width=33)

# -------------------------------- CLI + Robust input -----------------------------------

def help_and_exit(code: int = 2):
    print(
        "Invalid argument specified.\n\n"
        "Usage:\n"
        "  py -3 genApiSpec.py -s | -set    # Configure code config parameters\n"
        "  py -3 genApiSpec.py -r | -run    # Generate API Specification document\n"
    )
    LOGGER.error("Invalid argument. Displayed usage help.")
    sys.exit(code)

def exit_immediately():
    LOGGER.info("User requested exit with '$'.")
    LOGGER.info("EXECUTION END: ABORT")
    print("\nEXECUTION END: ABORT")
    sys.exit(1)

def _win_masked_input(prompt_text: str) -> str:
    import msvcrt  # type: ignore
    sys.stdout.write(prompt_text); sys.stdout.flush()
    buf = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            _ = msvcrt.getwch(); continue
        if ch in ("\r", "\n"):
            sys.stdout.write("\n"); sys.stdout.flush(); break
        if ch == "\x03": raise KeyboardInterrupt
        if ch == "\x16": continue
        if ch == "\b":
            if buf:
                buf.pop(); sys.stdout.write("\b \b"); sys.stdout.flush()
            continue
        buf.append(ch)
        sys.stdout.write("*"); sys.stdout.flush()
    return "".join(buf)

def prompt(prompt_text: str, secret: bool = False) -> str:
    print("To exit execution enter $")
    try:
        if not secret:
            val = input(prompt_text)
        else:
            if sys.platform.startswith("win"):
                try:
                    val = _win_masked_input(prompt_text)
                except Exception:
                    try:
                        sys.stdout.write(prompt_text); sys.stdout.flush()
                        val = getpass.getpass("")
                    except Exception:
                        print("(Password will be visible here; secure input unsupported.)")
                        val = input(prompt_text)
            else:
                if sys.stdin.isatty() and sys.stdout.isatty():
                    try:
                        sys.stdout.write(prompt_text); sys.stdout.flush()
                        val = getpass.getpass("")
                    except Exception:
                        print("(Password will be visible here; secure input unsupported.)")
                        val = input(prompt_text)
                else:
                    print("(Password will be visible here; secure input unsupported.)")
                    val = input(prompt_text)
    except (KeyboardInterrupt, EOFError):
        print(); exit_immediately()

    v = (val or "").strip()
    if v == "$": exit_immediately()
    return v

def prompt_choice_1_2(question: str) -> int:
    while True:
        ans = prompt(question + "\n1 - Yes\n2 - No\n> ")
        if ans in ("1", "2"):
            return int(ans)
        LOGGER.error("Invalid choice. Enter 1 for Yes or 2 for No.")
        print("Invalid choice. Enter 1 for Yes or 2 for No.")

def prompt_nonneg_int(question: str) -> int:
    while True:
        ans = prompt(question + "\n> ")
        if ans.isdigit():
            return int(ans)
        LOGGER.error("Invalid number. Enter a non-negative integer.")
        print("Invalid number. Enter a non-negative integer.")

def prompt_field_type() -> int:
    while True:
        ans = prompt(
            "Field Type\n"
            "1 - Text Input / Text Area / Rich Text Area\n"
            "2 - Dropdown\n"
            "3 - Multi-Select Dropdown\n"
            "4 - Datetime\n"
            "5 - Number\n"
            "6 - Checkbox\n"
            "7 - Radio\n> "
        )
        if ans.isdigit() and 1 <= int(ans) <= 7:
            return int(ans)
        LOGGER.error("Invalid choice. Enter a number 1..7.")
        print("Invalid choice. Enter a number 1..7.")

# -------------------------------- Validation & HTTPS helpers ---------------------------

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
            raise ValueError("Host must be a valid IPv4 or domain")
    return s

def https_unverified_context_for(url: str) -> Optional[ssl.SSLContext]:
    try:
        scheme = urlparse(url).scheme.lower()
    except Exception:
        scheme = ""
    if scheme == "https":
        return ssl._create_unverified_context()
    return None

# -------------------------------- Config load ------------------------------------------

def load_config() -> Dict[str, str]:
    cfg_path = SCRIPT_DIR / "config.properties"
    if not cfg_path.exists():
        raise FileNotFoundError("config.properties not found. Run '-s' first.")

    data: Dict[str, str] = {}
    with open(cfg_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            data[k.strip().lower()] = v.strip()

    required = ["url", "token", "apikey", "username", "password"]
    missing  = [k for k in required if k not in data or not data[k]]
    if missing:
        raise ValueError(f"config.properties missing keys: {', '.join(missing)}")

    if not data["token"].lower().startswith("basic "):
        raise ValueError("config 'token' must start with 'Basic '")
    if not data["apikey"].lower().startswith("apikey "):
        raise ValueError("config 'apikey' must start with 'Apikey '")
    _ = validate_base_url(data["url"])
    LOGGER.info("Loaded config.properties successfully.")
    return data

# -------------------------------- Low-level HTTP ---------------------------------------

def log_api_request(name: str, method: str, url: str, headers: Dict[str, str], body_text: str):
    LOGGER.info("API REQUEST [%s] %s %s", name, method, url)
    LOGGER.info("API REQUEST HEADERS [%s]: %s", name, json.dumps(headers, ensure_ascii=False))
    if body_text:
        LOGGER.info("API REQUEST BODY [%s]: %s", name, body_text)

def log_api_response(name: str, status: int, text: str):
    LOGGER.info("API RESPONSE [%s] status=%s", name, status)
    LOGGER.info("API RESPONSE BODY [%s]: %s", name, text)

def http_post_raw(url: str, headers: Dict[str, str], data_bytes: bytes,
                  timeout_sec: int = 20) -> Tuple[int, str]:
    all_headers = {"User-Agent": "genApiSpec/1.0"}
    all_headers.update(headers)
    req = Request(url, data=data_bytes, headers=all_headers, method="POST")
    ctx = https_unverified_context_for(url)
    try:
        with urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"

def http_post_json(url: str, headers: Dict[str, str], payload: Dict[str, Any],
                   timeout_sec: int = 20) -> Tuple[int, str, str]:
    body = json.dumps(payload, ensure_ascii=False)
    log_api_request("POST-JSON", "POST", url, {**headers, "Content-Type": "application/json"}, body)
    status, text = http_post_raw(url, {**headers, "Content-Type": "application/json"}, body.encode("utf-8"), timeout_sec)
    log_api_response("POST-JSON", status, text)
    return status, text, body

# -------------------------------- API helpers (with logging) ---------------------------

def oauth_bearer_token(base_url: str, username: str, password: str, basic_auth_header: str,
                       timeout_sec: int = 15) -> Tuple[bool, dict, int, str]:
    """
    POST {base_url}/api/oauth/token (multipart/form-data) – UNVERIFIED SSL
    Returns (ok, payload_json_or_err, http_status, curl_cmd_logged)
    Logs request and response.
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
    body_bytes = ("".join(parts) + f"--{boundary}--\r\n").encode("utf-8")

    headers = {
        "Authorization": basic_auth_header,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    # Log request (as curl and as raw headers/body)
    curl_cmd = (
        "curl -k --request POST "
        f"--url '{endpoint}' "
        f"--header 'Authorization: {basic_auth_header}' "
        f"--header 'content-type: multipart/form-data; boundary={boundary}' "
        f"--form username={username} --form password={password} --form grant_type=password"
    )
    LOGGER.info("API REQUEST [LOGIN CURL]: %s", curl_cmd)
    log_api_request("LOGIN", "POST", endpoint, headers, f"multipart/form-data (boundary={boundary})")

    # Do call
    req = Request(endpoint, data=body_bytes, headers={**headers, "User-Agent": "genApiSpec/1.0"}, method="POST")
    ctx = https_unverified_context_for(endpoint)
    try:
        with urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            status = resp.getcode()
            raw    = resp.read()
            text   = raw.decode("utf-8", "replace")
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = {}
            log_api_response("LOGIN", status, text)
            ok = (status == 200) and isinstance(parsed, dict) and ("access_token" in parsed)
            return ok, parsed if parsed else {"raw": text}, status, curl_cmd
    except Exception as e:
        log_api_response("LOGIN", -1, f"{type(e).__name__}: {e}")
        return False, {"error": type(e).__name__, "detail": str(e)}, -1, curl_cmd

def attempt_with_fallback(name: str,
                          endpoint: str,
                          payload: Dict[str, Any],
                          apikey: str,
                          base_url: str,
                          username: str,
                          password: str,
                          basic_auth: str) -> Tuple[int, str, str]:
    """
    Try API Key first. If non-200, mint a FRESH bearer via LOGIN and retry once with Bearer.
    Returns (status, response_text, used_auth_header).
    Logs every request and response.
    """
    # Attempt 1: API Key
    status, text, _ = http_post_json(endpoint, {"Authorization": apikey}, payload)
    if status == 200:
        return status, text, apikey

    # Attempt 2: mint fresh Bearer
    ok, login_payload, login_status, _curl = oauth_bearer_token(base_url, username, password, basic_auth)
    if not ok:
        return -1, f"Login failed (HTTP {login_status}): {login_payload}", ""
    bearer = f"Bearer {login_payload.get('access_token','')}"
    status2, text2, _ = http_post_json(endpoint, {"Authorization": bearer}, payload)
    return status2, text2, bearer

# -------------------------------- Data capture helpers (-r) -----------------------------

Field = Dict[str, Any]  # {"name": str, "id": str, "type": int}

def epoch_ms_now() -> int:
    return int(time.time() * 1000)

def sample_value_for_type(ftype: int) -> Any:
    if ftype == 1:   return "Text data"                   # Text / TextArea / RTE
    if ftype == 2:   return "A"                           # Dropdown
    if ftype == 3:   return ["A", "C"]                    # Multi-Select
    if ftype == 4:   return epoch_ms_now()                # Datetime (epoch ms)
    if ftype == 5:   return 10                            # Number
    if ftype == 6:   return ["C", "B"]                    # Checkbox
    if ftype == 7:   return "B"                           # Radio
    return "Text data"

def build_customfield_payload(fields: List[Field]) -> Dict[str, Any]:
    return {f["name"]: sample_value_for_type(f["type"]) for f in fields}

# -------------------------------- Markdown helpers -------------------------------------

def md_code(lang: str, text: str) -> str:
    return f"```{lang}\n{text}\n```"

def md_code_plain(text: str) -> str:
    return f"```\n{text}\n```"

def curl_login(base_url: str, basic_auth: str, username: str, password: str) -> str:
    endpoint = f"{base_url}/api/oauth/token"
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    return (
        "curl -k --request POST "
        f"--url '{endpoint}' "
        f"--header 'Authorization: {basic_auth}' "
        f"--header 'content-type: multipart/form-data; boundary={boundary}' "
        f"--form username={username} --form password={password} --form grant_type=password"
    )

def curl_post_json(endpoint: str, auth_header: str, payload: Dict[str, Any]) -> str:
    return (
        "curl -k --request POST "
        f"--url '{endpoint}' "
        f"--header 'Authorization: {auth_header}' "
        f"--header 'content-type: application/json' "
        f"--data-raw '{json.dumps(payload, separators=(',', ':'))}'"
    )

# -------------------------------- Configure Mode (same as earlier) ---------------------

# For brevity, this keeps the earlier -s implementation exactly.
# If you've already integrated a full ConfigureMode earlier, keep it.
# (Omitted here to reduce length.)

def build_final_base_url(base_url: str, port: int) -> str:
    if port in (80, 443):
        return base_url
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}:{port}"

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

def validate_port(raw: str) -> int:
    if not raw.isdigit():
        raise ValueError("Port must be numeric.")
    p = int(raw)
    if p < 1 or p > 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return p

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

class ConfigureMode:
    def __init__(self):
        self.url_input = ""
        self.port = 0
        self.username = ""
        self.password = ""
        self.basic_auth = ""
        self.api_key = ""
        self.final_url = ""
        self.summary = {}

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
            cred_ok = False
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
                "URL": self.final_url,
                "SSLValid": ssl_ok,  # Yes / No / NA
                "Accessibility": "Reachable" if ping_ok else "Not reachable",
                "AvgLatencyMs": f"{latency_ms:.2f}" if latency_ms >= 0 else "N/A",
                "Username": self.username,
                "BasicAuthorization": self.basic_auth,
                "ApiKey": self.api_key,
                "Credentials": "OK" if cred_ok else "Not OK"
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
                    ts = time.strftime("%d-%b-%Y-%H_%M-GAS")  # dd-Mmm-YYYY-hh_mm-GAS
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

# -------------------------------- Run Mode (with new fallback & logging) ---------------

class RunMode:
    def run(self):
        LOGGER.info(f"Op Code = {OP_CODE}")
        LOGGER.info("Operation = Generate API Specification Document")

        try:
            total_steps = 20
            BAR.start(total_steps, title="==== Generating API Specification Document ====")

            cfg = load_config()
            base_url   = cfg["url"]
            basic_auth = cfg["token"]    # used to mint bearer
            apikey     = cfg["apikey"]   # first attempt
            username   = cfg["username"]
            password   = cfg["password"]
            BAR.update("Loaded config")

            # ----- Scope prompts -----
            itsm_choice = prompt_choice_1_2("Is ITSM in scope?")
            itam_choice = prompt_choice_1_2("Is ITAM in scope?")
            itsm_in_scope = (itsm_choice == 1)
            itam_in_scope = (itam_choice == 1)
            LOGGER.info("Scope: ITSM=%s ITAM=%s", itsm_in_scope, itam_in_scope)
            BAR.update("Captured scope")

            # ----- ITSM capture -----
            incident_cfs: List[Field] = []
            svc_categories: List[Dict[str, Any]] = []

            if itsm_in_scope:
                n_icf = prompt_nonneg_int("How many custom fields created for Incident form?")
                for i in range(1, n_icf + 1):
                    fname = prompt(f"CF {i}: Field Name as in UI\n> ")
                    fid   = prompt(f"CF {i}: Field ID\n> ")
                    ftype = prompt_field_type()
                    incident_cfs.append({"name": fname, "id": fid, "type": ftype})
                    LOGGER.info("Incident CF %d: name='%s' id='%s' type=%d", i, fname, fid, ftype)
                BAR.update("Captured Incident CFs")

                n_cat = prompt_nonneg_int("How many Service Categories created in Service Catalog?")
                for c in range(1, n_cat + 1):
                    cat_name = prompt(f"SC {c}: Service Category Name as in UI\n> ")
                    LOGGER.info("Service Category %d: '%s'", c, cat_name)
                    n_srv = prompt_nonneg_int(f"SC {c}: How many Services created under this Service Category '{cat_name}'?")
                    services: List[Dict[str, Any]] = []
                    for s in range(1, n_srv + 1):
                        srv_name = prompt(f"SC {c}.SR {s}: Service Name as in UI\n> ")
                        LOGGER.info("SC %d.SR %d: '%s'", c, s, srv_name)
                        n_scf = prompt_nonneg_int(f"SC {c}.SR {s}: How many custom fields created for this Service form?")
                        srv_cfs: List[Field] = []
                        for fidx in range(1, n_scf + 1):
                            fname = prompt(f"SC {c}.SR {s}.CF {fidx}: Field Name as in UI\n> ")
                            fid   = prompt(f"SC {c}.SR {s}.CF {fidx}: Field ID\n> ")
                            ftype = prompt_field_type()
                            srv_cfs.append({"name": fname, "id": fid, "type": ftype})
                            LOGGER.info("SC %d.SR %d.CF %d: name='%s' id='%s' type=%d",
                                        c, s, fidx, fname, fid, ftype)
                        services.append({"name": srv_name, "custom_fields": srv_cfs})
                    svc_categories.append({"name": cat_name, "services": services})
                BAR.update("Captured Service Catalog")

            # ----- ITAM capture -----
            itam_global_cfs: List[Field] = []
            itam_hw_cfs: List[Field] = []
            itam_nonit_cfs: List[Field] = []
            itam_sw_cfs: List[Field] = []
            itam_cons_cfs: List[Field] = []

            if itam_in_scope:
                for label, store in [
                    ("Asset custom fields created for all Asset Type", itam_global_cfs),
                    ("Asset custom fields created under Hardware Asset Type - Custom Fields section", itam_hw_cfs),
                    ("Asset custom fields created under Non IT Assets Asset Type - Custom Fields section", itam_nonit_cfs),
                    ("Asset custom fields created under Software Asset Type - Custom Fields section", itam_sw_cfs),
                    ("Asset custom fields created under Consumable Assets Asset Type - Custom Fields section", itam_cons_cfs),
                ]:
                    n = prompt_nonneg_int(f"How many {label}?")
                    for i in range(1, n + 1):
                        fname = prompt(f"CF {i}: Field Name is in UI\n> ")
                        fid   = prompt(f"CF {i}: Field ID\n> ")
                        ftype = prompt_field_type()
                        store.append({"name": fname, "id": fid, "type": ftype})
                        LOGGER.info("%s CF %d: name='%s' id='%s' type=%d", label, i, fname, fid, ftype)
                BAR.update("Captured ITAM CFs")

            # ----- Summary -----
            tot_services = sum(len(c.get("services", [])) for c in svc_categories)
            tot_sr_cfs   = sum(len(s.get("custom_fields", []))
                               for c in svc_categories for s in c.get("services", []))
            summary_lines = [
                "===== SUMMARY =====",
                f"ITSM in Scope: {'Yes' if itsm_in_scope else 'No'}",
                f"ITAM in Scope: {'Yes' if itam_in_scope else 'No'}",
                f"Incident Custom Fields: {len(incident_cfs)}",
                f"Service Catalog Categories: {len(svc_categories)}",
                f"Total Services: {tot_services}",
                f"Total SR Custom Fields: {tot_sr_cfs}",
                f"Global Asset Custom Fields: {len(itam_global_cfs)}",
                f"IT Asset Custom Fields: {len(itam_hw_cfs)}",
                f"Software Asset Custom Fields: {len(itam_sw_cfs)}",
                f"Non IT Asset Custom Fields: {len(itam_nonit_cfs)}",
                f"Consumable Asset Custom Fields: {len(itam_cons_cfs)}",
                "==================="
            ]
            LOGGER.info("Summary computed.")
            BAR.pause_and_print("\n" + "\n".join(summary_lines) + "\n")
            BAR.resume()
            BAR.update("Summary displayed")

            # ----- Create output doc skeleton -----
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            md_name = time.strftime("%d-%b-%y-%H-%M-API_Specs.md")
            md_path = OUTPUT_DIR / md_name
            md_parts: List[str] = []

            # ---- 1) Login API (documented once; actual call is done only on fallbacks) ----
            md_parts.append("# Login API – Fetch Bearer Token")
            md_parts.append(f"### Endpoint: {base_url}/api/oauth/token")
            md_parts.append("### Method: REST POST")
            md_parts.append("## Headers")
            md_parts.append(f"> Authorization\t{basic_auth}")
            md_parts.append("> Content-Type\tmultipart/form-data")
            md_parts.append("\n## Sample Request")
            md_parts.append(md_code_plain(curl_login(base_url, basic_auth, username, password)))

            # We'll include a real login sample/response by performing one now (for the doc):
            BAR.update("(Doc) Calling Login API for sample")
            ok_login, login_payload, login_status, curl_cmd = oauth_bearer_token(base_url, username, password, basic_auth)
            login_resp_text = json.dumps(login_payload, indent=2) if isinstance(login_payload, dict) else str(login_payload)
            md_parts.append("## Sample Response")
            md_parts.append(md_code("json", login_resp_text))
            md_parts.append("> Extract `access_token` and prefix `Bearer `; use instead of API Key if API Key fails.\n")
            if not ok_login:
                LOGGER.error(f"(Doc) Login API sample failed. HTTP status: {login_status}")
                BAR.pause_and_print("API Calls are failing")
                BAR.finish("EXECUTION END: ABORT")
                sys.exit(1)

            # ---- 2) Create Incident (ITSM) ----
            if itsm_in_scope:
                inc_ep = f"{base_url}/api/v1/request"
                incident_payload = {
                    "customField": build_customfield_payload(incident_cfs),
                    "requesterEmail": "paulsn",
                    "subject": "Incident Summary",
                    "description": "<p>Incident Description</p>",
                    "departmentName": "Department",
                    "impactName": "Low",
                    "urgencyName": "Low",
                    "categoryName": "Incident Category",
                    "source": "Email",
                    "locationName": "Ahmedabad",
                    "priorityName": "Low"
                }
                BAR.update("Calling Create Incident (API Key then Bearer if needed)")
                inc_status, inc_resp, inc_auth_used = attempt_with_fallback(
                    "CreateIncident", inc_ep, incident_payload, apikey,
                    base_url, username, password, basic_auth
                )
                if inc_status != 200:
                    LOGGER.error(f"Create Incident failed after fallback. Status={inc_status}; resp={inc_resp}")
                    BAR.pause_and_print("API Calls are failing")
                    BAR.finish("EXECUTION END: ABORT")
                    sys.exit(1)

                md_parts.append("# Create Incident")
                md_parts.append(f"### Endpoint: {inc_ep}")
                md_parts.append("### Method: REST POST")
                md_parts.append("## Headers")
                md_parts.append(f"> Authorization\t{inc_auth_used}")
                md_parts.append("> Content-Type\tapplication/json")
                md_parts.append("\n## Sample Request")
                md_parts.append(md_code_plain(curl_post_json(inc_ep, inc_auth_used, incident_payload)))
                md_parts.append("## Sample Response")
                md_parts.append(md_code("json", inc_resp))

            # ---- 3) Create Service Request (ITSM) ----
            sr_ep = f"{base_url}/api/v1/service_catalog/servicerequest"
            if itsm_in_scope and any(c.get("services") for c in svc_categories):
                non_empty = [c for c in svc_categories if c.get("services")]
                chosen_cat = random.choice(non_empty)
                chosen_srv = random.choice(chosen_cat["services"])
                sr_payload = {
                    "customField": build_customfield_payload(chosen_srv.get("custom_fields", [])),
                    "requester": "paulsn",
                    "description": "<p>SR Description</p>",
                    "departmentName": "Department",
                    "impactName": "Low",
                    "urgencyName": "Low",
                    "categoryName": "SR Category",
                    "source": "Email",
                    "locationName": "Ahmedabad",
                    "priorityName": "Low",
                    "serviceName": chosen_srv["name"],
                    "serviceCategoryName": chosen_cat["name"],
                }
                BAR.update("Calling Create Service Request (API Key then Bearer if needed)")
                sr_status, sr_resp, sr_auth_used = attempt_with_fallback(
                    "CreateServiceRequest", sr_ep, sr_payload, apikey,
                    base_url, username, password, basic_auth
                )
                if sr_status != 200:
                    LOGGER.error(f"Create Service Request failed after fallback. Status={sr_status}; resp={sr_resp}")
                    BAR.pause_and_print("API Calls are failing")
                    BAR.finish("EXECUTION END: ABORT")
                    sys.exit(1)

                md_parts.append("# Create Service Request")
                md_parts.append(f"### Endpoint: {sr_ep}")
                md_parts.append("### Method: REST POST")
                md_parts.append("## Headers")
                md_parts.append(f"> Authorization\t{sr_auth_used}")
                md_parts.append("> Content-Type\tapplication/json")
                md_parts.append("\n## Sample Request")
                md_parts.append(md_code_plain(curl_post_json(sr_ep, sr_auth_used, sr_payload)))
                md_parts.append("## Sample Response")
                md_parts.append(md_code("json", sr_resp))

            # ----- Write Markdown file -----
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            content = "\n\n".join(md_parts) + "\n"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(content)
            LOGGER.info("Wrote API spec document: %s", md_path)
            BAR.pause_and_print(f"\nAPI Spec generated at: {md_path}\n")
            BAR.update("Markdown written")

            LOGGER.info("EXECUTION END: SUCCESS")
            BAR.finish("EXECUTION END: SUCCESS")
            sys.exit(0)

        except Exception as e:
            LOGGER.error(f"Unhandled error in -r: {e}", exc_info=True)
            print(f"\n[ERROR] {e}")
            print("API Calls are failing" if "API" in str(e) else "EXECUTION END: ABORT")
            try: BAR.finish("EXECUTION END: ABORT")
            except Exception: pass
            sys.exit(1)

# -------------------------------- Main --------------------------------------------------

def main():
    if len(sys.argv) != 2:
        help_and_exit()

    arg = sys.argv[1].strip().lower()
    if arg in ("-s", "-set"):
        ConfigureMode().run()   # keep your earlier full -s implementation here
    elif arg in ("-r", "-run"):
        RunMode().run()
    else:
        help_and_exit()

if __name__ == "__main__":
    main()
