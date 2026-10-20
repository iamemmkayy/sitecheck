\# sitecheck



A passive security checker for small business websites. It sends normal HTTP requests and prints a plain-language report. Each finding has a severity and a one-line fix.



\## Legal notice

Use this tool only on sites you own or have written permission to test. The tool refuses to run without the `--i-own-this` flag.



\## What it checks

\- HTTP security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options

\- TLS certificate validity, expiry date, and protocol version

\- HTTP to HTTPS redirect

\- Cookie flags: Secure, HttpOnly, SameSite

\- Public sensitive paths: `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/admin`

\- Server and X-Powered-By version leaks



\## What it does not do

It does not exploit anything. It does not brute-force paths. It sends about 10 requests per scan.



\## Install

&#x20;   pip install -r requirements.txt



\## Use

&#x20;   python scanner.py example.com --i-own-this

&#x20;   python scanner.py example.com --i-own-this -o report.md



Exit code is 1 if the scan finds a High issue. Exit code is 0 otherwise.



\## Sample report

(Paste real output from your test scan here.)



\## License

MIT

