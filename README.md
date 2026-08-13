# WAF - Python Web Application Firewall

A lightweight reverse-proxy Web Application Firewall written in pure Python.
Detects and blocks common web attacks (SQLi, XSS, LFI/RFI, SSRF, SSTI, XXE, and more)
before requests reach the backend server.

## Status: Work in progress
- [x] Proxy scaffold (socket handling, request parsing)
- [ ] Detection rule engine
- [ ] Full request inspection pipeline

More details coming as the rule engine is built out.
