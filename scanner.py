#!/usr/bin/env python3
"""sitecheck: passive website security checker for small business sites."""
import argparse
import socket
import ssl
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

TIMEOUT = 8
UA = {"User-Agent": "sitecheck/0.1 (passive security checker)"}
SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}
VERIFY = True
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADER_RULES = {
    "Strict-Transport-Security": (
        "Medium",
        "Add 'Strict-Transport-Security: max-age=31536000' to force HTTPS.",
    ),
    "Content-Security-Policy": (
        "Medium",
        "Add a Content-Security-Policy header to limit which scripts can run.",
    ),
    "X-Frame-Options": (
        "Low",
        "Add 'X-Frame-Options: DENY' to block clickjacking.",
    ),
    "X-Content-Type-Options": (
        "Low",
        "Add 'X-Content-Type-Options: nosniff' to stop MIME type guessing.",
    ),
}

# (path, severity, title, fix, detector). Detector gets (response, soft404).
PATH_RULES = [
    (
        "/.git/HEAD", "High", "Git repository is public",
        "Block access to the /.git/ folder in the web server. Remove it from the web root.",
        lambda r, s: r.status_code == 200 and r.text.startswith("ref:"),
    ),
    (
        "/.env", "High", "Environment file is public",
        "Move .env outside the web root. Change every password and key inside it.",
        lambda r, s: r.status_code == 200
        and "=" in r.text[:2000]
        and "<html" not in r.text[:500].lower(),
    ),
    (
        "/phpinfo.php", "Medium", "phpinfo page is public",
        "Delete phpinfo.php. It shows server paths and configuration.",
        lambda r, s: r.status_code == 200 and "phpinfo()" in r.text,
    ),
    (
        "/admin", "Low", "Admin path is reachable",
        "Restrict /admin by IP address or add a second login factor.",
        lambda r, s: r.status_code in (200, 401) and not s,
    ),
]


def add(findings, sev, title, fix):
    findings.append((sev, title, fix))


def check_tls(host, port, findings):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        add(findings, "High", f"TLS certificate failed verification: {e.verify_message}",
            "Install a valid certificate. Let's Encrypt issues free certificates.")
        return None
    except (OSError, ssl.SSLError) as e:
        add(findings, "High", f"HTTPS connection failed: {e}",
            "Enable HTTPS on port 443.")
        return None

    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    days = int((expires - datetime.now(timezone.utc).timestamp()) // 86400)
    if days < 0:
        add(findings, "High", f"Certificate expired {-days} days ago", "Renew the certificate now.")
    elif days < 14:
        add(findings, "High", f"Certificate expires in {days} days", "Renew the certificate now.")
    elif days < 30:
        add(findings, "Medium", f"Certificate expires in {days} days", "Renew the certificate soon.")
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        add(findings, "High", f"Old TLS version in use: {version}",
            "Disable TLS 1.0 and 1.1. Allow TLS 1.2 and 1.3 only.")
    return {"version": version, "days": days}


def check_headers(resp, findings):
    for name, (sev, fix) in HEADER_RULES.items():
        if name not in resp.headers:
            add(findings, sev, f"Missing header: {name}", fix)
    server = resp.headers.get("Server", "")
    if any(ch.isdigit() for ch in server):
        add(findings, "Low", f"Server header shows version: {server}",
            "Hide the version. Apache: 'ServerTokens Prod'. Nginx: 'server_tokens off;'.")
    if "X-Powered-By" in resp.headers:
        add(findings, "Low", f"X-Powered-By header shows technology: {resp.headers['X-Powered-By']}",
            "Remove the X-Powered-By header.")


def check_cookies(resp, findings):
    try:
        cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        cookies = []
    for raw in cookies:
        parts = [p.strip().lower() for p in raw.split(";")]
        name = raw.split("=", 1)[0].strip()
        if "secure" not in parts:
            add(findings, "Medium", f"Cookie '{name}' has no Secure flag",
                "Add the Secure flag. The browser then sends the cookie over HTTPS only.")
        if "httponly" not in parts:
            add(findings, "Medium", f"Cookie '{name}' has no HttpOnly flag",
                "Add the HttpOnly flag. JavaScript then cannot read the cookie.")
        if not any(p.startswith("samesite") for p in parts):
            add(findings, "Low", f"Cookie '{name}' has no SameSite attribute",
                "Add 'SameSite=Lax' to reduce cross-site request risk.")


def check_http_redirect(host, findings):
    try:
        r = requests.get(f"http://{host}", headers=UA, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return
    loc = r.headers.get("Location", "")
    if not (r.status_code in (301, 302, 307, 308) and loc.startswith("https://")):
        add(findings, "Medium", "HTTP does not redirect to HTTPS",
            "Redirect all port 80 traffic to HTTPS with a 301 response.")


def check_paths(base, findings):
    soft404 = False
    try:
        probe = requests.get(f"{base}/sitecheck-{uuid.uuid4().hex[:10]}", headers=UA,
                             timeout=TIMEOUT, allow_redirects=False, verify=VERIFY)
        soft404 = probe.status_code == 200
    except requests.RequestException:
        pass
    for path, sev, title, fix, detect in PATH_RULES:
        try:
            r = requests.get(base + path, headers=UA, timeout=TIMEOUT, allow_redirects=False, verify=VERIFY)
        except requests.RequestException:
            continue
        if detect(r, soft404):
            add(findings, sev, f"{title}: {path}", fix)


def build_report(url, tls, findings):
    findings.sort(key=lambda f: SEV_ORDER[f[0]])
    counts = {s: sum(1 for f in findings if f[0] == s) for s in SEV_ORDER}
    lines = [
        "# sitecheck report",
        "",
        f"- Target: {url}",
        f"- Date: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
    ]
    if tls:
        lines.append(f"- TLS version: {tls['version']}")
        lines.append(f"- Certificate days left: {tls['days']}")
    lines += [
        f"- Findings: {counts['High']} High, {counts['Medium']} Medium, {counts['Low']} Low",
        "",
    ]
    if not findings:
        lines.append("No issues found by these checks. This does not prove the site is secure.")
    for i, (sev, title, fix) in enumerate(findings, 1):
        lines += [f"## {i}. [{sev}] {title}", f"Fix: {fix}", ""]
    return "\n".join(lines)


def main():
    global VERIFY
    p = argparse.ArgumentParser(description="Passive website security checker.")
    p.add_argument("url", help="Example: example.com or https://example.com")
    p.add_argument("--i-own-this", action="store_true",
                   help="Confirm you own the site or have written permission to test it.")
    p.add_argument("-o", "--output", help="Write the report to this file.")
    a = p.parse_args()

    if not a.i_own_this:
        sys.exit("Refused. Use --i-own-this only for sites you own or have written permission to test.")

    url = a.url if "://" in a.url else "https://" + a.url
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    base = f"{u.scheme}://{u.netloc}"
    findings = []
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror as e:
        print(f"Cannot resolve {host}: {e}", file=sys.stderr)
        sys.exit(2)

    tls = None
    if u.scheme == "https":
        tls = check_tls(host, port, findings)
        if tls is None:
            VERIFY = False
        check_http_redirect(host, findings)
    else:
        add(findings, "High", "Site is served over HTTP only", "Enable HTTPS and redirect HTTP to it.")

    resp = None
    try:
        resp = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=True, verify=VERIFY)
    except requests.RequestException as e:
        if not findings:
            print(f"Cannot reach {url}: {e}", file=sys.stderr)
            sys.exit(2)
        print(f"Page request failed: {e}", file=sys.stderr)

    if resp is not None:
        check_headers(resp, findings)
        check_cookies(resp, findings)
        check_paths(base, findings)

    report = build_report(url, tls, findings)
    print(report)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(report)
    sys.exit(1 if any(f[0] == "High" for f in findings) else 0)


if __name__ == "__main__":
    main()