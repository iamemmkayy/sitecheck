# sitecheck report

- Target: https://pdfnest.com.ng
- Date: 2026-10-20 08:29 UTC
- TLS version: TLSv1.3
- Certificate days left: 65
- Findings: 0 High, 1 Medium, 2 Low

## 1. [Medium] Missing header: Content-Security-Policy
Fix: Add a Content-Security-Policy header to limit which scripts can run.

## 2. [Low] Missing header: X-Frame-Options
Fix: Add 'X-Frame-Options: DENY' to block clickjacking.

## 3. [Low] Missing header: X-Content-Type-Options
Fix: Add 'X-Content-Type-Options: nosniff' to stop MIME type guessing.
