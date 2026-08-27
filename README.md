# WAF - Python Web Application Firewall

A lightweight reverse-proxy Web Application Firewall written in pure Python (no external
dependencies). Sits in front of a backend server, inspects every request, scores it against
a rule engine, and blocks anything that crosses the threshold.

## Features
- SQL Injection, XSS, LFI, RFI, Command Injection, Path Traversal detection
- SSRF, CRLF, NoSQL Injection, LDAP Injection, XPath Injection, SSTI, XXE detection
- Host header injection, open redirect, HTTP parameter pollution, request smuggling checks
- File upload validation, insecure deserialization checks, component disclosure filtering
- CSRF heuristic checks, rate limiting / brute-force protection
- Multipart + JSON body parsing, request normalization, structured logging

## Project structure
```
proxy.py   - TCP reverse proxy: accepts connections, parses HTTP, forwards to backend
waf.py     - WAF engine: rule sets + request/response inspection logic
logs/      - runtime logs (proxy.log, waf_alerts.log)
```

## Running
```bash
python3 proxy.py
```
Configure HOST, PORT, and IN_SCOPE_HOST / IN_SCOPE_PORT (your backend) at the top of proxy.py.

## How it works
Every request is scored against the rule engine in waf.py. If the cumulative score crosses
BLOCK_THRESHOLD, the request is blocked and logged to logs/waf_alerts.log with a unique UID.
