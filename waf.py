import email
import html
import ipaddress
import json
import logging
import os
import re
import time
import urllib.parse
import uuid

from collections import defaultdict, deque
from email import policy


class WAF:

    # ============================================================
    # GLOBAL CONFIGURATION
    # ============================================================

    MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024       # 10 MB
    MAX_PARAMETER_VALUE_LENGTH = 1024 * 1024       # 1 MB

    # Score at which a request is blocked.
    BLOCK_THRESHOLD = 8

    # Generic rate limiting.
    RATE_LIMIT_WINDOW = 60
    RATE_LIMIT_MAX_REQUESTS = 120

    # Authentication endpoint rate limiting.
    AUTH_RATE_LIMIT_WINDOW = 60
    AUTH_RATE_LIMIT_MAX_REQUESTS = 15

    # Common Unix + Windows command tokens.
    COMMAND_TOKENS = (
        r"id|whoami|uname|hostname|ifconfig|ipconfig|ip|"
        r"pwd|ls|dir|env|set|printenv|ps|tasklist|systeminfo|"
        r"netstat|cat|type|curl|wget|bash|sh|cmd|powershell|"
        r"certutil|net|findstr|nslookup|ping|tracert|route"
    )

    STATE_CHANGING_METHODS = {
        "POST",
        "PUT",
        "PATCH",
        "DELETE"
    }

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(self):

        # Existing vulnerability families.
        self.sqli_rules = self.load_sqli_rules()
        self.xss_rules = self.load_xss_rules()
        self.lfi_rules = self.load_lfi_rules()
        self.rfi_rules = self.load_rfi_rules()
        self.command_injection_rules = (
            self.load_command_injection_rules()
        )
        self.path_traversal_rules = (
            self.load_path_traversal_rules()
        )
        self.ssrf_rules = self.load_ssrf_rules()
        self.crlf_rules = self.load_crlf_rules()

        # Additional injection families.
        self.nosql_rules = self.load_nosql_rules()
        self.ldap_rules = self.load_ldap_rules()
        self.xpath_rules = self.load_xpath_rules()
        self.ssti_rules = self.load_ssti_rules()
        self.xxe_rules = self.load_xxe_rules()

        # HTTP/application-level attacks.
        self.host_header_rules = (
            self.load_host_header_rules()
        )
        self.open_redirect_rules = (
            self.load_open_redirect_rules()
        )
        self.hpp_rules = self.load_hpp_rules()
        self.request_smuggling_rules = (
            self.load_request_smuggling_rules()
        )
        self.file_upload_rules = (
            self.load_file_upload_rules()
        )
        self.deserialization_rules = (
            self.load_deserialization_rules()
        )

        # Component/version disclosure.
        self.component_rules = (
            self.load_component_rules()
        )

        # Response-side security checks.
        self.response_rules = (
            self.load_response_rules()
        )

        self.max_request_body_size = (
            self.MAX_REQUEST_BODY_SIZE
        )

        self.max_parameter_value_length = (
            self.MAX_PARAMETER_VALUE_LENGTH
        )

        self.block_threshold = (
            self.BLOCK_THRESHOLD
        )

        # Rate limiting.
        self.enable_rate_limiting = True

        # CSRF is monitor-only by default because
        # generic WAF cannot know every application's
        # legitimate CSRF implementation.
        self.csrf_monitor_only = True

        self.rate_counters = defaultdict(
            deque
        )

        self.logger = (
            self.setup_waf_logger()
        )

        self._add_rule_defaults()

    # ============================================================
    # SQL INJECTION
    # ============================================================

    def load_sqli_rules(self):

        return [

            {
                "id": "SQLI-101",
                "name": "Boolean-based SQL Injection",
                "pattern": (
                    r"(\bor\b|\band\b)\s+"
                    r"['\"]?\d+['\"]?\s*=\s*"
                    r"['\"]?\d+"
                ),
                "severity": "HIGH",
                "category": "SQLI",
                "confidence": 0.92,
            },

            {
                "id": "SQLI-102",
                "name": "UNION SELECT SQL Injection",
                "pattern": (
                    r"\bunion\s+"
                    r"(?:all\s+)?select\b"
                ),
                "severity": "HIGH",
                "category": "SQLI",
                "confidence": 0.97,
            },

            {
                "id": "SQLI-103",
                "name": "Error-based SQL Injection",
                "pattern": (
                    r"\b(?:extractvalue|updatexml)"
                    r"\s*\("
                ),
                "severity": "HIGH",
                "category": "SQLI",
                "confidence": 0.95,
            },

            {
                "id": "SQLI-104",
                "name": "Stacked SQL Query",
                "pattern": (
                    r";\s*(?:select|insert|update|"
                    r"delete|drop|alter)\b"
                ),
                "severity": "CRITICAL",
                "category": "SQLI",
                "confidence": 0.98,
            },

            {
                "id": "SQLI-105",
                "name": "Time-based SQL Injection",
                "pattern": (
                    r"\b(?:sleep|benchmark|pg_sleep)"
                    r"\s*\(|"
                    r"\bwaitfor\s+delay\b"
                ),
                "severity": "CRITICAL",
                "category": "SQLI",
                "confidence": 0.98,
            },

            {
                "id": "SQLI-106",
                "name": "SQL Comment Injection",
                "pattern": (
                    r"(?:--[ \t]|#[ \t]|/\*.*?\*/)"
                ),
                "severity": "MEDIUM",
                "category": "SQLI",
                "confidence": 0.80,
            },

            {
                "id": "SQLI-107",
                "name": "SQL Tautology",
                "pattern": (
                    r"(?:['\"]?\s*(?:or|and)\s+"
                    r"['\"]?\w+['\"]?\s*=\s*"
                    r"['\"]?\w+)"
                ),
                "severity": "HIGH",
                "category": "SQLI",
                "confidence": 0.86,
            },

            {
                "id": "SQLI-108",
                "name": "Information Schema Access",
                "pattern": (
                    r"\binformation_schema\b"
                ),
                "severity": "HIGH",
                "category": "SQLI",
                "confidence": 0.93,
            },

            {
                "id": "SQLI-109",
                "name": "SQL Database Function",
                "pattern": (
                    r"\b(?:version|database|"
                    r"current_user|schema)"
                    r"\s*\(\s*\)"
                ),
                "severity": "MEDIUM",
                "category": "SQLI",
                "confidence": 0.84,
            },
        ]

    # ============================================================
    # XSS
    # ============================================================

    def load_xss_rules(self):

        return [

            {
                "id": "XSS-201",
                "name": "Script Tag Injection",
                "pattern": (
                    r"<\s*script\b[^>]*>"
                    r".*?"
                    r"<\s*/\s*script\s*>"
                ),
                "severity": "CRITICAL",
                "category": "XSS",
                "confidence": 0.99,
            },

            {
                "id": "XSS-202",
                "name": "Event Handler Injection",
                "pattern": (
                    r"\bon[a-z]+\s*="
                ),
                "severity": "HIGH",
                "category": "XSS",
                "confidence": 0.92,
            },

            {
                "id": "XSS-203",
                "name": "JavaScript Protocol",
                "pattern": (
                    r"\bjavascript\s*:"
                ),
                "severity": "CRITICAL",
                "category": "XSS",
                "confidence": 0.98,
            },

            {
                "id": "XSS-204",
                "name": "IMG Event XSS",
                "pattern": (
                    r"<\s*img\b[^>]+"
                    r"\bon[a-z]+\s*="
                ),
                "severity": "HIGH",
                "category": "XSS",
                "confidence": 0.98,
            },

            {
                "id": "XSS-205",
                "name": "SVG Event XSS",
                "pattern": (
                    r"<\s*svg\b[^>]*"
                    r"\bon[a-z]+\s*="
                ),
                "severity": "HIGH",
                "category": "XSS",
                "confidence": 0.98,
            },

            {
                "id": "XSS-206",
                "name": "Iframe Injection",
                "pattern": (
                    r"<\s*iframe\b[^>]*>"
                ),
                "severity": "HIGH",
                "category": "XSS",
                "confidence": 0.95,
            },

            {
                "id": "XSS-207",
                "name": "Object/Embed Injection",
                "pattern": (
                    r"<\s*(?:object|embed)\b[^>]*>"
                ),
                "severity": "HIGH",
                "category": "XSS",
                "confidence": 0.93,
            },
        ]

    # ============================================================
    # LFI
    # ============================================================

    def load_lfi_rules(self):

        return [

            {
                "id": "LFI-301",
                "name": "Directory Traversal",
                "pattern": (
                    r"(?:\.\./|\.\.\\|"
                    r"%2e%2e%2f|%2e%2e%5c)"
                ),
                "severity": "HIGH",
                "category": "LFI",
                "confidence": 0.96,
            },

            {
                "id": "LFI-302",
                "name": "Linux Sensitive File Inclusion",
                "pattern": (
                    r"(?:/etc/(?:passwd|shadow|hosts)|"
                    r"/proc/self/environ)"
                ),
                "severity": "CRITICAL",
                "category": "LFI",
                "confidence": 0.99,
            },

            {
                "id": "LFI-303",
                "name": "Windows Sensitive File Inclusion",
                "pattern": (
                    r"(?:boot\.ini|win\.ini|system32|"
                    r"drivers/etc/hosts)"
                ),
                "severity": "CRITICAL",
                "category": "LFI",
                "confidence": 0.98,
            },

            {
                "id": "LFI-304",
                "name": "PHP/URL Wrapper",
                "pattern": (
                    r"(?:php://|file://|zip://|"
                    r"data://|expect://)"
                ),
                "severity": "CRITICAL",
                "category": "LFI",
                "confidence": 0.99,
            },

            {
                "id": "LFI-305",
                "name": "Null Byte Injection",
                "pattern": (
                    r"(?:%00|\x00)"
                ),
                "severity": "HIGH",
                "category": "LFI",
                "confidence": 0.95,
            },
        ]

    # ============================================================
    # RFI
    # ============================================================

    def load_rfi_rules(self):

        return [

            {
                "id": "RFI-401",
                "name": "HTTP/HTTPS Remote File Inclusion",
                "pattern": (
                    r"^https?://[^\s<>\"']+"
                ),
                "severity": "CRITICAL",
                "category": "RFI",
                "confidence": 0.86,
            },

            {
                "id": "RFI-402",
                "name": "FTP Remote File Inclusion",
                "pattern": (
                    r"^ftp://[^\s<>\"']+"
                ),
                "severity": "HIGH",
                "category": "RFI",
                "confidence": 0.90,
            },

            {
                "id": "RFI-403",
                "name": "Protocol-relative Inclusion",
                "pattern": (
                    r"^//[a-z0-9.-]+(?:[:/]|$)"
                ),
                "severity": "HIGH",
                "category": "RFI",
                "confidence": 0.88,
            },

            {
                "id": "RFI-404",
                "name": "Encoded Remote URL",
                "pattern": (
                    r"(?:https?|ftp)%3a%2f%2f"
                ),
                "severity": "CRITICAL",
                "category": "RFI",
                "confidence": 0.97,
            },

            {
                "id": "RFI-405",
                "name": "Double Encoded Remote URL",
                "pattern": (
                    r"(?:https?|ftp)"
                    r"%253a%252f%252f"
                ),
                "severity": "CRITICAL",
                "category": "RFI",
                "confidence": 0.98,
            },
        ]

    # ============================================================
    # COMMAND INJECTION
    # ============================================================

    def load_command_injection_rules(self):

        t = self.COMMAND_TOKENS

        return [

            {
                "id": "CMD-301",
                "name": "Command Separator Injection",
                "pattern": (
                    rf"(?:;|&&|\|\||&)\s*"
                    rf"(?:{t})\b"
                ),
                "severity": "CRITICAL",
                "category": "COMMAND_INJECTION",
                "confidence": 0.97,
            },

            {
                "id": "CMD-302",
                "name": "Pipe Command Injection",
                "pattern": (
                    rf"\|\s*(?:{t})\b"
                ),
                "severity": "HIGH",
                "category": "COMMAND_INJECTION",
                "confidence": 0.94,
            },

            {
                "id": "CMD-303",
                "name": "Command Substitution",
                "pattern": (
                    rf"\$\(\s*(?:{t})\b"
                ),
                "severity": "CRITICAL",
                "category": "COMMAND_INJECTION",
                "confidence": 0.98,
            },

            {
                "id": "CMD-304",
                "name": "Backtick Command Execution",
                "pattern": (
                    rf"`\s*(?:{t})\b"
                ),
                "severity": "CRITICAL",
                "category": "COMMAND_INJECTION",
                "confidence": 0.98,
            },

            {
                "id": "CMD-305",
                "name": "Newline Command Injection",
                "pattern": (
                    rf"(?:\r|\n)\s*"
                    rf"(?:{t})\b"
                ),
                "severity": "HIGH",
                "category": "COMMAND_INJECTION",
                "confidence": 0.95,
            },

            {
                "id": "CMD-306",
                "name": "Windows Shell Invocation",
                "pattern": (
                    r"(?:cmd(?:\.exe)?\s*/c|"
                    r"powershell(?:\.exe)?\s+"
                    r"-(?:command|enc|encodedcommand))"
                ),
                "severity": "CRITICAL",
                "category": "COMMAND_INJECTION",
                "confidence": 0.98,
            },
        ]

    # ============================================================
    # PATH TRAVERSAL
    # ============================================================

    def load_path_traversal_rules(self):

        return [

            {
                "id": "PATH-501",
                "name": "Directory Traversal",
                "pattern": (
                    r"(?:\.\./|\.\.\\|"
                    r"%2e%2e%2f|%2e%2e%5c)"
                ),
                "severity": "HIGH",
                "category": "PATH_TRAVERSAL",
                "confidence": 0.96,
            },

            {
                "id": "PATH-502",
                "name": "Sensitive Unix Path",
                "pattern": (
                    r"(?:/etc/(?:passwd|shadow|hosts)|"
                    r"/proc/self/environ)"
                ),
                "severity": "CRITICAL",
                "category": "PATH_TRAVERSAL",
                "confidence": 0.99,
            },

            {
                "id": "PATH-503",
                "name": "Sensitive Windows Path",
                "pattern": (
                    r"(?:\\windows\\system32\\|"
                    r"/windows/system32/|boot\.ini|win\.ini)"
                ),
                "severity": "CRITICAL",
                "category": "PATH_TRAVERSAL",
                "confidence": 0.98,
            },
        ]

    # ============================================================
    # SSRF
    # ============================================================

    def load_ssrf_rules(self):

        return [

            {
                "id": "SSRF-601",
                "name": "Localhost SSRF",
                "pattern": (
                    r"^(?:https?|ftp)://"
                    r"(?:localhost|"
                    r"127(?:\.\d{1,3}){3}|"
                    r"0\.0\.0\.0|\[::1\])"
                    r"(?::\d+)?(?:[/?#]|$)"
                ),
                "severity": "HIGH",
                "category": "SSRF",
                "confidence": 0.98,
            },

            {
                "id": "SSRF-602",
                "name": "Private Network SSRF",
                "pattern": (
                    r"^(?:https?|ftp)://"
                    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                    r"192\.168\.\d{1,3}\.\d{1,3}|"
                    r"172\.(?:1[6-9]|2\d|3[0-1])\."
                    r"\d{1,3}\.\d{1,3})"
                    r"(?::\d+)?(?:[/?#]|$)"
                ),
                "severity": "HIGH",
                "category": "SSRF",
                "confidence": 0.98,
            },

            {
                "id": "SSRF-603",
                "name": "Cloud Metadata SSRF",
                "pattern": (
                    r"^(?:https?|http)://"
                    r"169\.254\.169\.254"
                    r"(?::\d+)?(?:[/?#]|$)"
                ),
                "severity": "CRITICAL",
                "category": "SSRF",
                "confidence": 0.99,
            },

            {
                "id": "SSRF-604",
                "name": "IPv6 Loopback SSRF",
                "pattern": (
                    r"^(?:https?|http)://"
                    r"(?:\[?::1\]?|"
                    r"\[?0:0:0:0:0:0:0:1\]?)"
                    r"(?::\d+)?(?:[/?#]|$)"
                ),
                "severity": "HIGH",
                "category": "SSRF",
                "confidence": 0.99,
            },
        ]

    # ============================================================
    # CRLF
    # ============================================================

    def load_crlf_rules(self):

        return [

            {
                "id": "CRLF-701",
                "name": "CRLF Injection",
                "pattern": (
                    r"(?:%0d|%0a|\r|\n)"
                ),
                "severity": "HIGH",
                "category": "CRLF_INJECTION",
                "confidence": 0.94,
            }
        ]

    # ============================================================
    # NoSQL INJECTION
    # ============================================================

    def load_nosql_rules(self):

        return [

            {
                "id": "NOSQL-801",
                "name": "MongoDB Operator Injection",
                "pattern": (
                    r"(?i)(?:[\"']?\$"
                    r"(?:where|regex|ne|gt|gte|lt|lte|"
                    r"in|nin|exists|or|and|expr)"
                    r"[\"']?\s*:)"
                ),
                "severity": "HIGH",
                "category": "NOSQL_INJECTION",
                "confidence": 0.96,
            },

            {
                "id": "NOSQL-802",
                "name": "MongoDB JavaScript Operator",
                "pattern": (
                    r"(?i)\$(?:where|function)\b"
                ),
                "severity": "CRITICAL",
                "category": "NOSQL_INJECTION",
                "confidence": 0.98,
            },

            {
                "id": "NOSQL-803",
                "name": "NoSQL Expression Injection",
                "pattern": (
                    r"(?i)(?:"
                    r"\$(?:ne|gt|gte|lt|lte|in|nin|exists)"
                    r"\s*[:=]|"
                    r"\bwhere\b\s*[:=]|"
                    r"\bregex\b\s*[:=])"
                ),
                "severity": "HIGH",
                "category": "NOSQL_INJECTION",
                "confidence": 0.90,
            },
        ]

    # ============================================================
    # LDAP INJECTION
    # ============================================================

    def load_ldap_rules(self):

        return [

            {
                "id": "LDAP-901",
                "name": "LDAP Filter Injection",
                "pattern": (
                    r"(?i)(?:"
                    r"\(\s*[!|&]"
                    r"|\*\s*\)"
                    r"|\)\s*\("
                    r"|\(\s*\w+\s*=\s*\*\s*\)"
                    r")"
                ),
                "severity": "HIGH",
                "category": "LDAP_INJECTION",
                "confidence": 0.91,
            },

            {
                "id": "LDAP-902",
                "name": "LDAP Wildcard Manipulation",
                "pattern": (
                    r"(?i)(?:"
                    r"\*\)"
                    r"|\)\s*\(\w+="
                    r"|\(\w+=\*[^)]*\)"
                    r")"
                ),
                "severity": "HIGH",
                "category": "LDAP_INJECTION",
                "confidence": 0.93,
            },
        ]

    # ============================================================
    # XPath INJECTION
    # ============================================================

    def load_xpath_rules(self):

        return [

            {
                "id": "XPATH-1001",
                "name": "XPath Boolean Injection",
                "pattern": (
                    r"(?i)(?:"
                    r"['\"]\s*(?:or|and)\s+"
                    r"['\"]?[^=\s]+\s*=\s*"
                    r"['\"]?[^'\"]+"
                    r")"
                ),
                "severity": "HIGH",
                "category": "XPATH_INJECTION",
                "confidence": 0.90,
            },

            {
                "id": "XPATH-1002",
                "name": "XPath Function Injection",
                "pattern": (
                    r"(?i)\b(?:contains|substring|"
                    r"string-length|starts-with|"
                    r"count|name|local-name)"
                    r"\s*\("
                ),
                "severity": "MEDIUM",
                "category": "XPATH_INJECTION",
                "confidence": 0.80,
            },
        ]

    # ============================================================
    # SSTI
    # ============================================================

    def load_ssti_rules(self):

        return [

            {
                "id": "SSTI-1101",
                "name": "Jinja/Twig Template Expression",
                "pattern": (
                    r"(?:"
                    r"\{\{[^{}]{1,200}\}\}"
                    r"|\{%[^%]{1,200}%\}"
                    r"|\{#[^#]{1,200}#\}"
                    r")"
                ),
                "severity": "HIGH",
                "category": "SSTI",
                "confidence": 0.88,
            },

            {
                "id": "SSTI-1102",
                "name": "Template Object Access",
                "pattern": (
                    r"(?i)(?:__class__|__mro__|"
                    r"__subclasses__|__globals__|"
                    r"__builtins__)"
                ),
                "severity": "CRITICAL",
                "category": "SSTI",
                "confidence": 0.99,
            },

            {
                "id": "SSTI-1103",
                "name": "Expression Language Injection",
                "pattern": (
                    r"(?:\$\{[^{}]{1,200}\}"
                    r"|#\{[^{}]{1,200}\})"
                ),
                "severity": "HIGH",
                "category": "SSTI",
                "confidence": 0.86,
            },

            {
                "id": "SSTI-1104",
                "name": "ERB Template Expression",
                "pattern": (
                    r"<%=?[^%]{1,200}%>"
                ),
                "severity": "HIGH",
                "category": "SSTI",
                "confidence": 0.88,
            },
        ]

    # ============================================================
    # XXE
    # ============================================================

    def load_xxe_rules(self):

        return [

            {
                "id": "XXE-1201",
                "name": "XML DOCTYPE Declaration",
                "pattern": (
                    r"(?is)<!DOCTYPE\s+"
                    r"[^\[]+"
                    r"(?:\[[\s\S]{0,500}\]\s*)?>"
                ),
                "severity": "HIGH",
                "category": "XXE",
                "confidence": 0.88,
            },

            {
                "id": "XXE-1202",
                "name": "XML External Entity",
                "pattern": (
                    r"(?is)<!ENTITY\s+\w+\s+"
                    r"(?:SYSTEM|PUBLIC)\s+[\"']"
                ),
                "severity": "CRITICAL",
                "category": "XXE",
                "confidence": 0.99,
            },

            {
                "id": "XXE-1203",
                "name": "External Entity File/URL Target",
                "pattern": (
                    r"(?is)\bSYSTEM\s+[\"']"
                    r"(?:file:|https?://|ftp:|php://)"
                ),
                "severity": "CRITICAL",
                "category": "XXE",
                "confidence": 0.99,
            },
        ]

    # ============================================================
    # HOST HEADER INJECTION
    # ============================================================

    def load_host_header_rules(self):

        return [

            {
                "id": "HOST-1301",
                "name": "Suspicious Host Header",
                "pattern": (
                    r"(?i)(?:@|%40|[\r\n]|\s)"
                ),
                "severity": "HIGH",
                "category": "HOST_HEADER_INJECTION",
                "confidence": 0.92,
                "contexts": {"host"},
            },

            {
                "id": "HOST-1302",
                "name": "Malformed Host Header",
                "pattern": (
                    r"(?i)^[^/:]+"
                    r"(?::\d+){2,}$"
                ),
                "severity": "HIGH",
                "category": "HOST_HEADER_INJECTION",
                "confidence": 0.90,
                "contexts": {"host"},
            },
        ]

    # ============================================================
    # OPEN REDIRECT
    # ============================================================

    def load_open_redirect_rules(self):

        return [

            {
                "id": "REDIRECT-1401",
                "name": "Absolute External Redirect",
                "pattern": (
                    r"(?i)^(?:https?:)?//"
                    r"(?:[a-z0-9.-]+)"
                    r"(?::\d+)?(?:/|$)"
                ),
                "severity": "HIGH",
                "category": "OPEN_REDIRECT",
                "confidence": 0.82,
                "contexts": {
                    "query",
                    "body",
                    "json",
                    "multipart"
                },
            },

            {
                "id": "REDIRECT-1402",
                "name": "Encoded External Redirect",
                "pattern": (
                    r"(?i)(?:https?)"
                    r"%3a%2f%2f|"
                    r"%2f%2f[a-z0-9.-]+"
                ),
                "severity": "HIGH",
                "category": "OPEN_REDIRECT",
                "confidence": 0.90,
                "contexts": {
                    "query",
                    "body",
                    "json",
                    "multipart"
                },
            },
        ]

    # ============================================================
    # HTTP PARAMETER POLLUTION
    # ============================================================

    def load_hpp_rules(self):

        return [

            {
                "id": "HPP-1501",
                "name": "HTTP Parameter Pollution",
                "pattern": r".+",
                "severity": "MEDIUM",
                "category": "HPP",
                "confidence": 0.70,
                "contexts": {
                    "query",
                    "body"
                },
            }
        ]

    # ============================================================
    # REQUEST SMUGGLING
    # ============================================================

    def load_request_smuggling_rules(self):

        return [

            {
                "id": "SMUG-1601",
                "name": "Transfer-Encoding and Content-Length Conflict",
                "pattern": r".+",
                "severity": "CRITICAL",
                "category": "HTTP_REQUEST_SMUGGLING",
                "confidence": 0.99,
                "contexts": {"smuggling"},
            },

            {
                "id": "SMUG-1602",
                "name": "Duplicate Content-Length",
                "pattern": r".+",
                "severity": "CRITICAL",
                "category": "HTTP_REQUEST_SMUGGLING",
                "confidence": 0.99,
                "contexts": {"smuggling"},
            },

            {
                "id": "SMUG-1603",
                "name": "Suspicious Transfer-Encoding",
                "pattern": (
                    r"(?i)(?:chunked\s*,|,\s*chunked|"
                    r"identity\s*,|,\s*identity)"
                ),
                "severity": "HIGH",
                "category": "HTTP_REQUEST_SMUGGLING",
                "confidence": 0.93,
                "contexts": {"smuggling"},
            },
        ]

    # ============================================================
    # FILE UPLOAD
    # ============================================================

    def load_file_upload_rules(self):

        return [

            {
                "id": "UPLOAD-1701",
                "name": "Executable Upload Extension",
                "pattern": (
                    r"(?i)\."
                    r"(?:php[0-9]?|phtml|phar|"
                    r"asp|aspx|jsp|jspx|cgi|"
                    r"pl|py|sh|exe|dll)"
                    r"(?:\.|$)"
                ),
                "severity": "HIGH",
                "category": "FILE_UPLOAD",
                "confidence": 0.92,
                "contexts": {"filename"},
            },

            {
                "id": "UPLOAD-1702",
                "name": "Double Extension Upload",
                "pattern": (
                    r"(?i)\."
                    r"[a-z0-9]{1,10}\."
                    r"(?:php|phtml|asp|aspx|"
                    r"jsp|jspx|exe|sh)"
                    r"(?:$|\.)"
                ),
                "severity": "HIGH",
                "category": "FILE_UPLOAD",
                "confidence": 0.94,
                "contexts": {"filename"},
            },

            {
                "id": "UPLOAD-1703",
                "name": "Null Byte Filename",
                "pattern": (
                    r"(?:%00|\x00)"
                ),
                "severity": "HIGH",
                "category": "FILE_UPLOAD",
                "confidence": 0.97,
                "contexts": {"filename"},
            },
        ]

    # ============================================================
    # INSECURE DESERIALIZATION
    # ============================================================

    def load_deserialization_rules(self):

        return [

            {
                "id": "DESER-1801",
                "name": "PHP Serialized Object",
                "pattern": (
                    r'(?i)(?:^|[;&])'
                    r'O:\d+:"[^"]+":\d+:\{'
                ),
                "severity": "HIGH",
                "category": "INSECURE_DESERIALIZATION",
                "confidence": 0.95,
            },

            {
                "id": "DESER-1802",
                "name": "Java Serialization Stream",
                "pattern": (
                    r"\xac\xed\x00\x05"
                ),
                "severity": "HIGH",
                "category": "INSECURE_DESERIALIZATION",
                "confidence": 0.99,
            },

            {
                "id": "DESER-1803",
                "name": "Python Pickle Signature",
                "pattern": (
                    r"(?i)(?:gAS"
                    r"[A-Za-z0-9_-]{10,}|"
                    r"c__main__\n)"
                ),
                "severity": "HIGH",
                "category": "INSECURE_DESERIALIZATION",
                "confidence": 0.85,
            },
        ]

    # ============================================================
    # COMPONENT DISCLOSURE
    # ============================================================

    def load_component_rules(self):

        return [

            {
                "id": "COMP-1901",
                "name": "Old Technology Version Disclosure",
                "pattern": (
                    r"(?i)(?:"
                    r"Apache/1\.|"
                    r"Apache/2\.0|"
                    r"PHP/[4-5]\.|"
                    r"OpenSSL/[01]\.|"
                    r"nginx/0\."
                    r")"
                ),
                "severity": "LOW",
                "category": "VULNERABLE_COMPONENT_DISCLOSURE",
                "confidence": 0.65,
                "contexts": {"header"},
            }
        ]

    # ============================================================
    # RESPONSE SECURITY RULES
    # ============================================================

    def load_response_rules(self):

        return [

            {
                "id": "RESP-2001",
                "name": "Missing X-Content-Type-Options",
                "severity": "LOW",
                "category": "SECURITY_MISCONFIGURATION",
                "confidence": 0.70,
            },

            {
                "id": "RESP-2002",
                "name": "Missing Content-Security-Policy",
                "severity": "LOW",
                "category": "SECURITY_MISCONFIGURATION",
                "confidence": 0.65,
            },

            {
                "id": "RESP-2003",
                "name": "Missing Referrer-Policy",
                "severity": "LOW",
                "category": "SECURITY_MISCONFIGURATION",
                "confidence": 0.70,
            },

            {
                "id": "RESP-2004",
                "name": "Missing Frame Protection",
                "severity": "LOW",
                "category": "SECURITY_MISCONFIGURATION",
                "confidence": 0.75,
            },

            {
                "id": "RESP-2005",
                "name": "Cookie Missing Secure Flag",
                "severity": "MEDIUM",
                "category": "CRYPTOGRAPHIC_FAILURES",
                "confidence": 0.90,
            },

            {
                "id": "RESP-2006",
                "name": "Cookie Missing HttpOnly",
                "severity": "MEDIUM",
                "category": "IDENTIFICATION_AUTHENTICATION",
                "confidence": 0.85,
            },

            {
                "id": "RESP-2007",
                "name": "Cookie Missing SameSite",
                "severity": "LOW",
                "category": "CSRF",
                "confidence": 0.75,
            },

            {
                "id": "RESP-2008",
                "name": "Verbose Server Header",
                "severity": "LOW",
                "category": "SECURITY_MISCONFIGURATION",
                "confidence": 0.65,
            },
        ]

    # ============================================================
    # DEFAULT RULE PROPERTIES
    # ============================================================

    def _add_rule_defaults(self):

        all_sets = (

            self.sqli_rules,
            self.xss_rules,
            self.lfi_rules,
            self.rfi_rules,
            self.command_injection_rules,
            self.path_traversal_rules,
            self.ssrf_rules,
            self.crlf_rules,

            self.nosql_rules,
            self.ldap_rules,
            self.xpath_rules,
            self.ssti_rules,
            self.xxe_rules,

            self.host_header_rules,
            self.open_redirect_rules,
            self.hpp_rules,
            self.request_smuggling_rules,
            self.file_upload_rules,
            self.deserialization_rules,
            self.component_rules,
        )

        default_contexts = {

            "path",
            "query",
            "body",
            "json",
            "multipart",
            "filename",
            "header",
            "cookie",
            "host",
            "smuggling",
        }

        for ruleset in all_sets:

            for rule in ruleset:

                rule.setdefault(
                    "confidence",
                    0.85
                )

                rule.setdefault(
                    "contexts",
                    default_contexts
                )

    # ============================================================
    # LOGGER
    # ============================================================

    def setup_waf_logger(self):

        os.makedirs(
            "logs",
            exist_ok=True
        )

        logger = logging.getLogger(
            "WAF_ALERTS"
        )

        logger.setLevel(
            logging.INFO
        )

        if not logger.handlers:

            file_handler = logging.FileHandler(
                "logs/waf_alerts.log"
            )

            console_handler = (
                logging.StreamHandler()
            )

            formatter = logging.Formatter(

                "[%(asctime)s] WAF_EVENT | "
                "UID=%(uid)s | "
                "Rule=%(rule_id)s | "
                "Category=%(category)s | "
                "Severity=%(severity)s | "
                "Client=%(client)s | "
                "Method=%(method)s | "
                "Path=%(path)s | "
                "Score=%(score)s | "
                "Confidence=%(confidence)s"
            )

            file_handler.setFormatter(
                formatter
            )

            console_handler.setFormatter(
                formatter
            )

            logger.addHandler(
                file_handler
            )

            logger.addHandler(
                console_handler
            )

        return logger

    # ============================================================
    # NORMALIZATION
    # ============================================================

    def normalize_variants(
        self,
        data,
        max_decode=3
    ):

        raw = (
            ""
            if data is None
            else str(data)
        )

        variants = [
            raw
        ]

        current = raw

        for _ in range(max_decode):

            decoded = (
                urllib.parse.unquote(
                    current
                )
            )

            if decoded == current:
                break

            variants.append(
                decoded
            )

            current = decoded

        html_decoded = (
            html.unescape(
                current
            )
        )

        if html_decoded not in variants:

            variants.append(
                html_decoded
            )

        lowered = (
            html_decoded.lower()
        )

        if lowered not in variants:

            variants.append(
                lowered
            )

        return variants

    def normalize(
        self,
        data,
        max_decode=3
    ):

        variants = (
            self.normalize_variants(
                data,
                max_decode
            )
        )

        return (
            variants[-1]
            if variants
            else ""
        )

    # ============================================================
    # GENERAL HELPERS
    # ============================================================

    def safe_text(self, value):

        value = (
            ""
            if value is None
            else str(value)
        )

        return value[
            :self.max_parameter_value_length
        ]

    def severity_weight(
        self,
        severity
    ):

        return {

            "LOW": 1,
            "MEDIUM": 3,
            "HIGH": 6,
            "CRITICAL": 10,

        }.get(
            str(
                severity
            ).upper(),
            1
        )

    def iter_headers(
        self,
        headers
    ):

        if not headers:
            return []

        if isinstance(
            headers,
            dict
        ):

            return list(
                headers.items()
            )

        return list(
            headers
        )

    def get_header(
        self,
        headers,
        name,
        default=""
    ):

        if not headers:
            return default

        target = (
            name.lower()
        )

        for key, value in self.iter_headers(
            headers
        ):

            if (
                str(key).lower()
                == target
            ):

                return value

        return default

    def get_all_headers(
        self,
        headers,
        name
    ):

        result = []

        target = (
            name.lower()
        )

        for key, value in self.iter_headers(
            headers
        ):

            if (
                str(key).lower()
                == target
            ):

                result.append(
                    str(value)
                )

        return result

    def rule_context_matches(
        self,
        rule,
        context
    ):

        contexts = rule.get(
            "contexts"
        )

        if not contexts:
            return True

        return (
            context
            in contexts
        )

    def scan_rule(
        self,
        rule,
        value,
        context
    ):

        if not self.rule_context_matches(
            rule,
            context
        ):

            return False

        value = self.safe_text(
            value
        )

        for variant in (
            self.normalize_variants(
                value
            )
        ):

            try:

                if re.search(

                    rule["pattern"],

                    variant,

                    re.IGNORECASE
                    | re.DOTALL

                ):

                    return True

            except re.error:

                self.logger.exception(

                    "Invalid regex in rule %s",

                    rule.get(
                        "id"
                    )
                )

                return False

        return False

    # ============================================================
    # JSON FLATTENING
    # ============================================================

    def flatten_json(
        self,
        data,
        parent_key=""
    ):

        pairs = []

        if isinstance(
            data,
            dict
        ):

            for key, value in (
                data.items()
            ):

                full_key = (

                    f"{parent_key}.{key}"

                    if parent_key

                    else str(key)
                )

                pairs.extend(

                    self.flatten_json(

                        value,

                        full_key
                    )
                )

        elif isinstance(
            data,
            list
        ):

            for index, value in enumerate(
                data
            ):

                full_key = (
                    f"{parent_key}[{index}]"
                )

                pairs.extend(

                    self.flatten_json(

                        value,

                        full_key
                    )
                )

        else:

            pairs.append(

                (
                    parent_key,

                    ""
                    if data is None
                    else str(data)
                )
            )

        return pairs

    # ============================================================
    # MULTIPART PARSER
    # ============================================================

    def parse_multipart(
        self,
        body,
        content_type
    ):

        params = []

        if not body or not content_type:
            return params

        try:

            raw_message = (

                f"Content-Type: "
                f"{content_type}\r\n"

                "MIME-Version: 1.0\r\n\r\n"

                f"{body}"
            )

            message = (
                email.message_from_string(
                    raw_message,
                    policy=policy.compat32
                )
            )

            if not message.is_multipart():
                return params

            for part in (
                message.get_payload()
            ):

                field_name = (
                    part.get_param(
                        "name",
                        header="Content-Disposition"
                    )
                )

                filename = (
                    part.get_param(
                        "filename",
                        header="Content-Disposition"
                    )
                )

                payload_bytes = (
                    part.get_payload(
                        decode=True
                    )
                )

                value = ""

                if payload_bytes is not None:

                    value = (
                        payload_bytes.decode(
                            "utf-8",
                            errors="ignore"
                        )
                    )

                if field_name:

                    params.append(
                        (
                            field_name,
                            value
                        )
                    )

                if filename:

                    params.append(
                        (
                            "filename",
                            filename
                        )
                    )

        except Exception:

            pass

        return params

    # ============================================================
    # REQUEST COMPONENT EXTRACTION
    # ============================================================

    def extract_request_components(
        self,
        path,
        body,
        headers=None
    ):

        components = []

        # --------------------------------------------------------
        # URL PATH + QUERY
        # --------------------------------------------------------

        try:

            parsed = (
                urllib.parse.urlsplit(
                    path or ""
                )
            )

            components.append(

                (
                    "path",
                    "<path>",
                    parsed.path or ""
                )
            )

            for key, value in (
                urllib.parse.parse_qsl(

                    parsed.query,

                    keep_blank_values=True
                )
            ):

                components.append(

                    (
                        "query",
                        str(key),
                        self.safe_text(
                            value
                        )
                    )
                )

        except Exception:

            components.append(

                (
                    "path",
                    "<path>",
                    self.safe_text(
                        path
                    )
                )
            )

        # --------------------------------------------------------
        # HEADERS + COOKIES
        # --------------------------------------------------------

        for key, value in (
            self.iter_headers(
                headers
            )
        ):

            key_string = str(
                key
            )

            context = (

                "cookie"

                if key_string.lower()
                == "cookie"

                else "header"
            )

            components.append(

                (
                    context,
                    key_string,
                    self.safe_text(
                        value
                    )
                )
            )

        # --------------------------------------------------------
        # HOST
        # --------------------------------------------------------

        host = self.get_header(
            headers,
            "Host",
            ""
        )

        if host:

            components.append(

                (
                    "host",
                    "Host",
                    self.safe_text(
                        host
                    )
                )
            )

        # --------------------------------------------------------
        # BODY
        # --------------------------------------------------------

        if not body:
            return components

        content_type = str(

            self.get_header(

                headers,

                "Content-Type",

                ""
            )

        ).lower()

        try:

            if (
                "application/json"
                in content_type
            ):

                parsed_json = (
                    json.loads(
                        body
                    )
                )

                for key, value in (
                    self.flatten_json(
                        parsed_json
                    )
                ):

                    components.append(

                        (
                            "json",
                            key,
                            self.safe_text(
                                value
                            )
                        )
                    )

            elif (
                "multipart/form-data"
                in content_type
            ):

                for key, value in (
                    self.parse_multipart(
                        body,
                        content_type
                    )
                ):

                    context = (

                        "filename"

                        if key
                        == "filename"

                        else "multipart"
                    )

                    components.append(

                        (
                            context,
                            key,
                            self.safe_text(
                                value
                            )
                        )
                    )

            elif (
                "application/x-www-form-urlencoded"
                in content_type
            ):

                # Only trust key=value&key=value parsing when the
                # request actually declares itself as form-encoded.
                # Previously this branch was the catch-all "else",
                # which meant raw/XML/text bodies with no "="
                # character (e.g. Content-Type missing, mislabeled,
                # or a raw payload like "SELECT * FROM users") had
                # their entire content dumped into parse_qsl's KEY
                # while the scanned VALUE came back as "" - making
                # every rule blind to that payload. Restricting this
                # branch to genuine urlencoded bodies and adding an
                # explicit raw-body fallback below closes that gap.

                for key, value in (

                    urllib.parse.parse_qsl(

                        body,

                        keep_blank_values=True
                    )
                ):

                    components.append(

                        (
                            "body",
                            str(key),
                            self.safe_text(
                                value
                            )
                        )
                    )

            else:

                # Unknown, missing, or non-form content type
                # (text/plain, application/xml, GraphQL, SOAP,
                # a mislabeled JSON body, or no Content-Type at
                # all). Scan the raw body as a single component
                # instead of guessing at key=value structure, so
                # payloads without "=" still get matched against
                # every rule.

                components.append(

                    (
                        "body",
                        "<raw>",
                        self.safe_text(
                            body
                        )
                    )
                )

        except Exception:

            components.append(

                (
                    "body",
                    "<raw>",
                    self.safe_text(
                        body
                    )
                )
            )

        return components

    # ============================================================
    # BACKWARDS COMPATIBILITY
    # ============================================================

    def extract_parameters(
        self,
        path,
        body,
        headers=None
    ):

        return [

            (
                name,
                value
            )

            for context, name, value

            in self.extract_request_components(

                path,
                body,
                headers
            )

            if context in {

                "query",
                "body",
                "json",
                "multipart",
                "filename"
            }
        ]

    # ============================================================
    # FILE-INCLUSION PARAMETER HELPER
    # ============================================================

    def is_file_inclusion_parameter(
        self,
        parameter
    ):

        names = {

            "page",
            "file",
            "filename",
            "filepath",
            "path",
            "include",
            "require",
            "template",
            "view",
            "module",
            "document",
            "doc",
            "folder",
            "dir",
            "directory",
            "resource",
            "load",
            "url",
            "uri",
            "source",
            "src",
            "redirect",
            "redirect_to",
            "redirecturl",
            "next",
            "return",
            "returnurl",
            "return_url",
            "continue",
            "dest",
            "destination",
            "target",
            "image",
            "img",
            "avatar",
            "download",
            "content",
            "show",
            "config",
            "conf",
            "site",
            "data",
        }

        return (
            str(parameter).lower()
            in names
        )

    # ============================================================
    # RFI DETECTION
    # ============================================================

    def detect_rfi(
        self,
        path,
        body,
        headers=None
    ):

        findings = []

        components = (
            self.extract_request_components(
                path,
                body,
                headers
            )
        )

        for context, name, value in components:

            if context not in {

                "query",
                "body",
                "json",
                "multipart",
                "filename"

            }:

                continue

            likely_inclusion = (
                self.is_file_inclusion_parameter(
                    name
                )
            )

            for rule in self.rfi_rules:

                if self.scan_rule(
                    rule,
                    value,
                    context
                ):

                    copy = dict(
                        rule
                    )

                    if likely_inclusion:

                        copy["confidence"] = min(

                            1.0,

                            copy.get(
                                "confidence",
                                0.85
                            ) + 0.03
                        )

                    findings.append(
                        copy
                    )

        return findings

    # ============================================================
    # COMMAND INJECTION DETECTION
    # ============================================================

    def detect_command_injection(
        self,
        path,
        body,
        headers=None
    ):

        findings = []

        components = (
            self.extract_request_components(
                path,
                body,
                headers
            )
        )

        for context, name, value in components:

            scan_context = (

                "header"

                if context
                in {
                    "header",
                    "cookie"
                }

                else context
            )

            for rule in (
                self.command_injection_rules
            ):

                if self.scan_rule(
                    rule,
                    value,
                    scan_context
                ):

                    findings.append(
                        dict(rule)
                    )

        return findings

    # ============================================================
    # HPP DETECTION
    # ============================================================

    def detect_duplicate_parameters(
        self,
        path,
        body,
        headers=None
    ):

        findings = []

        try:

            parsed = (
                urllib.parse.urlsplit(
                    path or ""
                )
            )

            query_pairs = (
                urllib.parse.parse_qsl(

                    parsed.query,

                    keep_blank_values=True
                )
            )

            body_pairs = (
                urllib.parse.parse_qsl(

                    body or "",

                    keep_blank_values=True
                )
            )

            for source, pairs in (

                (
                    "query",
                    query_pairs
                ),

                (
                    "body",
                    body_pairs
                )
            ):

                counts = (
                    defaultdict(int)
                )

                for name, value in pairs:

                    counts[
                        name.lower()
                    ] += 1

                for name, count in (
                    counts.items()
                ):

                    if count > 1:

                        rule = dict(
                            self.hpp_rules[0]
                        )

                        rule["parameter"] = (
                            name
                        )

                        rule["occurrences"] = (
                            count
                        )

                        rule["confidence"] = min(

                            0.95,

                            0.65
                            + count * 0.08
                        )

                        findings.append(
                            rule
                        )

        except Exception:

            pass

        return findings

    # ============================================================
    # ADVANCED SSRF DETECTION
    # ============================================================

    def detect_ssrf_special(
        self,
        value
    ):

        findings = []

        text = self.safe_text(
            value
        ).strip()

        if not re.match(

            r"(?i)^(?:https?|ftp)://",

            text
        ):

            return findings

        try:

            parsed = (
                urllib.parse.urlsplit(
                    text
                )
            )

            hostname = (
                parsed.hostname
            )

            if not hostname:
                return findings

            normalized_host = (
                hostname
                .strip("[]")
                .lower()
            )

            numeric_ip = None

            # Decimal IPv4 representation.
            if normalized_host.isdigit():

                number = int(
                    normalized_host
                )

                if (
                    0
                    <= number
                    <= 0xFFFFFFFF
                ):

                    numeric_ip = (
                        ipaddress.ip_address(
                            number
                        )
                    )

            if numeric_ip is not None:

                ip = numeric_ip

            else:

                ip = (
                    ipaddress.ip_address(
                        normalized_host
                    )
                )

            if ip.is_loopback:

                rid = "SSRF-605"
                severity = "HIGH"
                name = "Loopback IP SSRF"

            elif ip.is_private:

                rid = "SSRF-606"
                severity = "HIGH"
                name = "Private IP SSRF"

            elif ip.is_link_local:

                rid = "SSRF-607"
                severity = "HIGH"
                name = "Link-local SSRF"

            elif ip.is_reserved:

                rid = "SSRF-608"
                severity = "MEDIUM"
                name = "Reserved IP SSRF"

            else:

                return findings

            findings.append(

                {
                    "id": rid,
                    "name": name,
                    "pattern": "",
                    "severity": severity,
                    "category": "SSRF",
                    "confidence": 0.98,
                }
            )

        except ValueError:

            pass

        return findings

    # ============================================================
    # HOST HEADER
    # ============================================================

    def detect_host_header(
        self,
        headers
    ):

        findings = []

        host_values = (
            self.get_all_headers(
                headers,
                "Host"
            )
        )

        for host in host_values:

            for rule in (
                self.host_header_rules
            ):

                if self.scan_rule(
                    rule,
                    host,
                    "host"
                ):

                    findings.append(
                        dict(rule)
                    )

            if (
                "@"
                in host
                or "%40"
                in host.lower()
            ):

                findings.append(

                    {
                        "id":
                            "HOST-1303",

                        "name":
                            "Host Header Userinfo Injection",

                        "pattern":
                            "",

                        "severity":
                            "HIGH",

                        "category":
                            "HOST_HEADER_INJECTION",

                        "confidence":
                            0.97,
                    }
                )

        return findings

    # ============================================================
    # HTTP REQUEST SMUGGLING
    # ============================================================

    def detect_request_smuggling(
        self,
        headers
    ):

        findings = []

        content_lengths = (
            self.get_all_headers(
                headers,
                "Content-Length"
            )
        )

        transfer_encodings = (
            self.get_all_headers(
                headers,
                "Transfer-Encoding"
            )
        )

        if len(content_lengths) > 1:

            normalized = {
                value.strip()
                for value
                in content_lengths
            }

            if (
                len(normalized) > 1
                or len(content_lengths) > 1
            ):

                findings.append(
                    dict(
                        self.request_smuggling_rules[1]
                    )
                )

        if (
            content_lengths
            and transfer_encodings
        ):

            findings.append(
                dict(
                    self.request_smuggling_rules[0]
                )
            )

        for te in transfer_encodings:

            if re.search(

                r"(?i)(?:"
                r"chunked\s*,|"
                r",\s*chunked|"
                r"identity\s*,|"
                r",\s*identity"
                r")",

                te
            ):

                findings.append(
                    dict(
                        self.request_smuggling_rules[2]
                    )
                )

        return findings

    # ============================================================
