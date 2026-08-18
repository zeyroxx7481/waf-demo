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
