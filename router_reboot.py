#!/usr/bin/env python3
"""
router_reboot.py

Flow:
  1) Preflight GET "/" (browser-like warm-up)
  2) POST "/" with TPLINK.GENERAL.LOGIN_PASSWORD=<md5(password)>
     - If ERROR=004, warm-up again and retry once
     - If ERROR=006, exit with auth error
  3) POST "/?_t=<TOKEN>" with SYSTEM.GENERAL.HW_RESET=1

Usage:
    python router_reboot.py --ip 192.168.1.100 --password MySecretPassword
"""

import argparse
import hashlib
import re
import sys
from typing import Dict

import requests

DEFAULT_TIMEOUT = 8.0  # seconds

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"

# Headers used for AJAX-style requests (login + reboot)
AJAX_HEADERS_BASE = {
    "User-Agent": UA,
    "Accept": "text/plain, */*; q=0.01",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Requested-With": "XMLHttpRequest",
    "Accept-Language": "en-GB,en;q=0.5",
    "Connection": "keep-alive",
    "Accept-Encoding": "gzip, deflate",
}

# Headers for the preflight page load
PREFLIGHT_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.5",
    "Connection": "keep-alive",
    "Accept-Encoding": "gzip, deflate",
}


def md5_lower_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest().lower()


def parse_kv_text(text: str) -> Dict[str, str]:
    """
    Router responds as plain key=value lines, e.g.:
        ERROR=000
        TOKEN=abc...
    """
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def preflight(session: requests.Session, base_url: str) -> None:
    """Warm up the session like a browser would."""
    try:
        session.get(
            f"{base_url}/",
            headers=PREFLIGHT_HEADERS,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=False,  # avoid surprise auth redirects
        )
    except Exception:
        # Non-fatal: we still try to log in
        pass


def login_get_token(session: requests.Session, base_url: str, pwd_md5: str) -> str:
    """POST login; return TOKEN or raise."""
    headers = dict(AJAX_HEADERS_BASE)
    headers["Origin"] = base_url
    headers["Referer"] = f"{base_url}/"

    # Send form body as a plain string (requests sets Content-Length; no chunked)
    body = f"TPLINK.GENERAL.LOGIN_PASSWORD={pwd_md5}"

    resp = session.post(
        f"{base_url}/",
        data=body,
        headers=headers,
        timeout=DEFAULT_TIMEOUT,
        allow_redirects=False,
    )
    resp.raise_for_status()
    text = resp.text
    kv = parse_kv_text(text)

    err = kv.get("ERROR")
    if not err:
        raise RuntimeError(f"Login response missing ERROR. Raw:\n{text}")

    if err == "000":
        token = kv.get("TOKEN")
        if not token:
            # fallback regex (just in case)
            m = re.search(r"(?m)^TOKEN=(\S+)\s*$", text)
            token = m.group(1) if m else None
        if not token:
            raise RuntimeError(f"Login OK but TOKEN missing. Raw:\n{text}")
        return token

    if err == "006":
        attempts = kv.get("LOGIN_TIMES")
        msg = "Incorrect password (ERROR=006)."
        if attempts is not None:
            msg += f" LOGIN_TIMES={attempts}."
        raise PermissionError(msg)

    # Pass other codes to caller (e.g., 004 warm-up required)
    raise RuntimeError(f"Login failed with ERROR={err}. Raw:\n{text}")


def reboot(session: requests.Session, base_url: str, token: str) -> None:
    headers = dict(AJAX_HEADERS_BASE)
    headers["Origin"] = base_url
    headers["Referer"] = f"{base_url}/"

    body = "SYSTEM.GENERAL.HW_RESET=1"

    resp = session.post(
        f"{base_url}/?_t={token}",
        data=body,
        headers=headers,
        timeout=DEFAULT_TIMEOUT,
        allow_redirects=False,
    )
    resp.raise_for_status()
    text = resp.text
    kv = parse_kv_text(text)
    if kv.get("ERROR") != "000":
        raise RuntimeError(f"Reboot failed or unexpected response. Raw:\n{text}")


def main():
    p = argparse.ArgumentParser(description="TP-Link: login (MD5) and reboot via token.")
    p.add_argument("--ip", required=True, help="Router IP/host, e.g. 192.168.1.100")
    p.add_argument("--password", required=True, help="Router password (plaintext)")
    args = p.parse_args()

    base_url = f"http://{args.ip}"
    pwd_md5 = md5_lower_hex(args.password)

    session = requests.Session()

    print(f"[+] Target router: {base_url}")
    print("[+] Preflight warm-up...")
    preflight(session, base_url)

    # First login attempt
    try:
        print("[+] Logging in...")
        token = login_get_token(session, base_url, pwd_md5)
    except PermissionError as e:
        print(f"[!] {e}")
        sys.exit(4)
    except RuntimeError as e:
        msg = str(e)
        if "ERROR=004" in msg:
            print("[!] Router returned ERROR=004. Warming up and retrying once...")
            preflight(session, base_url)
            try:
                token = login_get_token(session, base_url, pwd_md5)
            except Exception as e2:
                print(f"[!] Login failed after retry: {e2}")
                sys.exit(2)
        else:
            print(f"[!] Login failed: {e}")
            sys.exit(2)

    print("[+] TOKEN obtained.")
    try:
        print("[+] Sending reboot command...")
        reboot(session, base_url, token)
    except Exception as e:
        print(f"[!] Reboot request failed: {e}")
        sys.exit(3)

    print("[+] Reboot command accepted (ERROR=000). The router should be rebooting now.")


if __name__ == "__main__":
    main()
