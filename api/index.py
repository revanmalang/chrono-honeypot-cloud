"""Chrono-Honeypot Cloud: Serverless Polymorphic Deception Engine.

A defensive, standard-library-only honeypot for Vercel's Python runtime.

Pipeline (one stateless invocation per request):

    RequestContext -> BehavioralProfiler -> DeceptionEngine -> AdaptiveTarpit
                                                 \\-> ThreatIntelExporter (stdout + webhooks)

Nothing in here executes, fetches or stores attacker-supplied input. Every
response is a synthetic decoy; every reflected value is escaped.

Deploy only on infrastructure you own. All configuration is via environment
variables (see README.md).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import random
import re
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qsl, unquote, unquote_plus

SCHEMA_VERSION = "chrono-honeypot/1.0"
SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_NAMES = tuple(SEVERITY_ORDER)


# ============================================================================
# 0. Utilities and configuration
# ============================================================================
def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _log(level: str, message: str, **fields: Any) -> None:
    """Emit one JSON line to stdout (collected by Vercel Runtime Logs)."""
    record = {"level": level, "msg": message, "ts": _utc_now(), **fields}
    try:
        sys.stdout.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        sys.stdout.flush()
    except Exception:  # logging must never break the request path
        pass


def _clean(text: str, limit: int = 96) -> str:
    """Make attacker-controlled text safe and short for logs."""
    return "".join(ch if ch.isprintable() else "." for ch in str(text))[:limit]


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = float(default)
    return max(low, min(high, value))


def _env_severity(name: str, default: str) -> str:
    value = _env_str(name, default).lower()
    return value if value in SEVERITY_ORDER else default


def _env_url(name: str) -> str:
    value = _env_str(name)
    if value and not value.lower().startswith(("https://", "http://")):
        _log("warning", "ignored_invalid_url", env=name)
        return ""
    return value


def _max_severity(*levels: str) -> str:
    return max(levels, key=lambda lv: SEVERITY_ORDER.get(lv, 0)) if levels else "info"


@dataclass(frozen=True)
class Config:
    secret: str
    sensor_id: str
    decoy_org: str
    mutation_window: int
    tarpit_enabled: bool
    tarpit_max: float
    budget: float
    webhook_timeout: float
    chat_min_severity: str
    siem_min_severity: str
    discord_url: str
    slack_url: str
    siem_url: str
    siem_auth: str
    siem_hmac_secret: str
    siem_format: str
    log_cleartext: bool
    canary_key_id: str
    canary_secret: str
    max_body: int

    @classmethod
    def from_env(cls) -> "Config":
        secret = _env_str("HONEYPOT_SECRET")
        if len(secret) < 16:
            _log("warning", "weak_or_missing_HONEYPOT_SECRET", hint="set a random value of 32+ characters")
            secret = secret or "chrono-honeypot-insecure-default-secret"
        region = _env_str("VERCEL_REGION", "local")
        env_name = _env_str("VERCEL_ENV", "local")
        siem_format = _env_str("SIEM_FORMAT", "json").lower()
        return cls(
            secret=secret,
            sensor_id=_env_str("SENSOR_ID", f"chrono-{env_name}-{region}")[:64],
            decoy_org=_env_str("DECOY_ORG", "Aurora Logistics")[:48] or "Aurora Logistics",
            mutation_window=int(_env_num("MUTATION_WINDOW_SECONDS", 3600, 0, 604800)),
            tarpit_enabled=_env_bool("TARPIT_ENABLED", True),
            tarpit_max=_env_num("TARPIT_MAX_SECONDS", 4.0, 0.0, 8.0),
            budget=_env_num("FUNCTION_BUDGET_SECONDS", 8.0, 2.0, 55.0),
            webhook_timeout=_env_num("WEBHOOK_TIMEOUT_SECONDS", 2.0, 0.5, 5.0),
            chat_min_severity=_env_severity("WEBHOOK_MIN_SEVERITY", "medium"),
            siem_min_severity=_env_severity("SIEM_MIN_SEVERITY", "low"),
            discord_url=_env_url("DISCORD_WEBHOOK_URL"),
            slack_url=_env_url("SLACK_WEBHOOK_URL"),
            siem_url=_env_url("SIEM_WEBHOOK_URL"),
            siem_auth=_env_str("SIEM_AUTH_HEADER"),
            siem_hmac_secret=_env_str("SIEM_HMAC_SECRET"),
            siem_format=siem_format if siem_format in {"json", "splunk-hec"} else "json",
            log_cleartext=_env_bool("LOG_CLEARTEXT_CREDENTIALS", False),
            canary_key_id=_env_str("CANARY_AWS_ACCESS_KEY_ID"),
            canary_secret=_env_str("CANARY_AWS_SECRET_ACCESS_KEY"),
            max_body=int(_env_num("MAX_BODY_BYTES", 65536, 1024, 1048576)),
        )


CONFIG = Config.from_env()


# ============================================================================
# 1. Data model and MITRE ATT&CK catalogue
# ============================================================================
class Intent(str, Enum):
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal_lfi"
    CREDENTIAL_STUFFING = "credential_stuffing"
    API_EXPLOITATION = "api_exploitation"
    RCE = "command_injection_rce"
    XSS = "cross_site_scripting"
    SSRF = "server_side_request_forgery"
    RECONNAISSANCE = "reconnaissance"
    BENIGN = "benign_or_unknown"


class SkillLevel(str, Enum):
    AUTOMATED_SCANNER = "automated_scanner"
    SCRIPT_KIDDIE = "script_kiddie"
    APT = "advanced_persistent_threat"
    UNKNOWN = "unknown"


# technique id -> (tactic id, tactic name, technique name)
MITRE_CATALOG: dict[str, tuple[str, str, str]] = {
    "T1190": ("TA0001", "Initial Access", "Exploit Public-Facing Application"),
    "T1078": ("TA0001", "Initial Access", "Valid Accounts"),
    "T1059": ("TA0002", "Execution", "Command and Scripting Interpreter"),
    "T1083": ("TA0007", "Discovery", "File and Directory Discovery"),
    "T1110.001": ("TA0006", "Credential Access", "Brute Force: Password Guessing"),
    "T1110.004": ("TA0006", "Credential Access", "Brute Force: Credential Stuffing"),
    "T1552.001": ("TA0006", "Credential Access", "Unsecured Credentials: Credentials In Files"),
    "T1552.005": ("TA0006", "Credential Access", "Unsecured Credentials: Cloud Instance Metadata API"),
    "T1595.002": ("TA0043", "Reconnaissance", "Active Scanning: Vulnerability Scanning"),
    "T1595.003": ("TA0043", "Reconnaissance", "Active Scanning: Wordlist Scanning"),
}


@dataclass(frozen=True)
class Finding:
    intent: Intent
    technique: str
    severity: str
    mitre: tuple[str, ...]
    evidence: str
    canonical: bool = False  # textbook payload -> script-kiddie hint
    advanced: bool = False  # precise or evasive payload -> APT hint


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str


@dataclass
class Profile:
    skill: SkillLevel
    confidence: float
    findings: list[Finding]
    primary_intent: Intent
    severity: str
    evasion: list[str]
    scores: dict[str, int]
    credentials: Optional[Credentials] = None

    @property
    def intents(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.intent.value not in seen:
                seen.append(finding.intent.value)
        return seen

    @property
    def techniques(self) -> set[str]:
        return {f.technique for f in self.findings}


@dataclass
class DecoyResponse:
    status: int
    body: bytes
    content_type: str
    decoy_type: str
    headers: dict[str, str] = field(default_factory=dict)
    sim_delay: float = 0.0
    persona: str = ""
    honey_trace: str = ""


# ============================================================================
# 2. Request context (parsing and normalisation)
# ============================================================================
@dataclass
class RequestContext:
    method: str
    raw_target: str
    path: str
    query_pairs: list[tuple[str, str]]
    body_pairs: list[tuple[str, str]]
    json_keys: list[str]
    body_size: int
    headers: dict[str, str]
    header_names: list[str]
    client_ip: str
    user_agent: str
    fingerprint: str
    epoch: int
    started: float
    decode_rounds: int
    request_surface: str  # decoded path + query + body
    full_surface: str  # request_surface + selected headers
    geo: dict[str, str]

    @property
    def values(self) -> list[tuple[str, str]]:
        return self.query_pairs + self.body_pairs

    @property
    def wants_json(self) -> bool:
        return (
            "json" in self.headers.get("accept", "")
            or "json" in self.headers.get("content-type", "")
            or self.path.lower().startswith("/api")
        )


def deep_decode(text: str, max_rounds: int = 3) -> tuple[str, int]:
    """Iteratively URL-decode and normalise; returns (text, decode rounds)."""
    rounds = 0
    for _ in range(max_rounds):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text, rounds = decoded, rounds + 1
    return unicodedata.normalize("NFKC", text).replace("\x00", ""), rounds


def _flatten_json(node: Any, prefix: str, out: list[tuple[str, str]], keys: list[str], depth: int = 0) -> None:
    if len(out) >= 200 or depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            keys.append(str(key))
            _flatten_json(value, f"{prefix}.{key}" if prefix else str(key), out, keys, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node[:50]):
            _flatten_json(value, f"{prefix}[{index}]", out, keys, depth + 1)
    else:
        out.append((prefix, str(node)[:2048]))


def _parse_body(content_type: str, raw: bytes) -> tuple[list[tuple[str, str]], list[str]]:
    text = raw.decode("utf-8", errors="replace")
    ctype = content_type.split(";")[0].strip().lower()
    pairs: list[tuple[str, str]] = []
    keys: list[str] = []
    if not text:
        return pairs, keys
    if ctype.endswith("json") or text.lstrip().startswith(("{", "[")):
        try:
            _flatten_json(json.loads(text), "", pairs, keys)
            return pairs, keys
        except (ValueError, RecursionError):
            pass
    if ctype == "application/x-www-form-urlencoded" or ("=" in text and "\n" not in text[:200]):
        try:
            return parse_qsl(text, keep_blank_values=True, max_num_fields=100), keys
        except ValueError:
            pass
    return [("_body", text[:4096])], keys


def _client_ip(headers: dict[str, str], fallback: str) -> str:
    for name in ("x-vercel-forwarded-for", "x-real-ip", "x-forwarded-for"):
        candidate = headers.get(name, "").split(",")[0].strip()
        if candidate:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return fallback


def build_context(req: BaseHTTPRequestHandler, cfg: Config, started: float) -> RequestContext:
    raw_target = req.path[:4096]
    path_part, _, query_part = raw_target.partition("?")
    query_part = query_part.split("#", 1)[0]
    headers = {k.lower(): v[:2048] for k, v in req.headers.items()}
    header_names = [k for k, _ in req.headers.items()][:64]

    try:
        length = max(0, min(int(headers.get("content-length", "0") or 0), cfg.max_body))
    except ValueError:
        length = 0
    try:
        raw_body = req.rfile.read(length) if length else b""
    except OSError:
        raw_body = b""

    query_pairs: list[tuple[str, str]] = []
    try:
        query_pairs = parse_qsl(query_part, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        query_pairs = [("_query", query_part[:2048])]
    body_pairs, json_keys = _parse_body(headers.get("content-type", ""), raw_body)

    path, r1 = deep_decode(path_part)
    query_text, r2 = deep_decode(query_part)
    body_text, r3 = deep_decode(raw_body.decode("utf-8", errors="replace")[:8192])
    request_surface = "\n".join(p for p in (path, query_text, body_text) if p)[:16384]

    ua = headers.get("user-agent", "")
    header_blob = "\n".join(
        deep_decode(headers.get(name, ""))[0]
        for name in ("user-agent", "referer", "cookie", "x-forwarded-for", "x-forwarded-host", "x-api-key", "authorization")
    )
    ip = _client_ip(headers, req.client_address[0] if req.client_address else "0.0.0.0")
    fingerprint = hmac.new(cfg.secret.encode(), f"{ip}|{ua}".encode(), hashlib.sha256).hexdigest()[:16]
    epoch = int(time.time() // cfg.mutation_window) if cfg.mutation_window > 0 else 0
    geo = {
        "country": headers.get("x-vercel-ip-country", ""),
        "region": headers.get("x-vercel-ip-country-region", ""),
        "city": unquote(headers.get("x-vercel-ip-city", "")),
    }
    return RequestContext(
        method=(req.command or "GET").upper()[:16],
        raw_target=raw_target,
        path=path[:1024],
        query_pairs=query_pairs,
        body_pairs=body_pairs,
        json_keys=json_keys,
        body_size=len(raw_body),
        headers=headers,
        header_names=header_names,
        client_ip=ip,
        user_agent=ua,
        fingerprint=fingerprint,
        epoch=epoch,
        started=started,
        decode_rounds=max(r1, r2, r3),
        request_surface=request_surface,
        full_surface=(request_surface + "\n" + header_blob)[:24576],
        geo={k: v for k, v in geo.items() if v},
    )


# ============================================================================
# 3. Behavioral profiler (stateless, edge-ready)
# ============================================================================
def _sig(intent: Intent, technique: str, pattern: str, severity: str, mitre: tuple[str, ...],
         canonical: bool = False, advanced: bool = False) -> tuple[Intent, str, "re.Pattern[str]", str, tuple[str, ...], bool, bool]:
    return (intent, technique, re.compile(pattern, re.IGNORECASE | re.DOTALL), severity, mitre, canonical, advanced)


SIGNATURES = (
    # --- SQL injection -------------------------------------------------------
    _sig(Intent.SQL_INJECTION, "union_based", r"\bunion\b[\s/*+()]*(?:all\b[\s/*+()]*)?select\b", "high", ("T1190",)),
    _sig(Intent.SQL_INJECTION, "boolean_tautology", r"['\"]\s*(?:or|and)\s+['\"]?\w{1,20}['\"]?\s*=\s*['\"]?\w{1,20}", "high", ("T1190",), canonical=True),
    _sig(Intent.SQL_INJECTION, "boolean_numeric", r"\b(?:or|and)\s+\d{1,6}\s*=\s*\d{1,6}\b", "high", ("T1190",), canonical=True),
    _sig(Intent.SQL_INJECTION, "quote_break_comment", r"['\"]\s*(?:--|#|/\*)", "medium", ("T1190",), canonical=True),
    _sig(Intent.SQL_INJECTION, "time_based_blind", r"\b(?:sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay|dbms_pipe\.receive_message", "high", ("T1190",), advanced=True),
    _sig(Intent.SQL_INJECTION, "error_based", r"\b(?:extractvalue|updatexml|floor\s*\(\s*rand|convert\s*\(\s*int)\b", "high", ("T1190",), advanced=True),
    _sig(Intent.SQL_INJECTION, "schema_enumeration", r"information_schema|sqlite_master|pg_catalog|sysobjects|all_tables|@@version|\bversion\s*\(\s*\)", "high", ("T1190",), advanced=True),
    _sig(Intent.SQL_INJECTION, "stacked_or_destructive", r";\s*(?:drop|insert|update|delete|exec|declare)\b|xp_cmdshell", "critical", ("T1190", "T1059"), advanced=True),
    # --- Path traversal / LFI -------------------------------------------------
    _sig(Intent.PATH_TRAVERSAL, "directory_traversal", r"(?:\.\.[/\\])+", "high", ("T1190", "T1083"), canonical=True),
    _sig(Intent.PATH_TRAVERSAL, "traversal_filter_bypass", r"\.\.\.\.[/\\]{2}|\.\.;/", "high", ("T1190", "T1083"), advanced=True),
    _sig(Intent.PATH_TRAVERSAL, "system_file_access", r"/etc/(?:passwd|shadow|hosts|group)|/proc/(?:self|\d+)/(?:environ|cmdline)|(?:boot|win)\.ini|/windows/system32", "high", ("T1190", "T1083"), canonical=True),
    _sig(Intent.PATH_TRAVERSAL, "php_stream_wrapper", r"php://(?:filter|input)|data://|expect://|phar://|zip://", "high", ("T1190",), advanced=True),
    # --- Sensitive file probing (reconnaissance) -------------------------------
    _sig(Intent.RECONNAISSANCE, "sensitive_file_probe",
         r"(?:^|[/\\=\s])\.(?:env(?:\.[\w-]+)?|git/(?:config|head)|htpasswd|aws/credentials|ssh/id_rsa|bash_history)(?![\w.-])"
         r"|wp-config\.php(?:\.\w+)?|(?:^|[/\\=])(?:backup|dump|database|db)\.(?:sql|zip|tar\.gz)",
         "medium", ("T1595.003", "T1552.001")),
    # --- Command injection / RCE -----------------------------------------------
    _sig(Intent.RCE, "shell_command_chaining",
         r"(?:[;&|`]|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|php|powershell|cmd|ping|nslookup|echo|env|ifconfig|pwd)\b(?!\s*=)",
         "critical", ("T1190", "T1059"), canonical=True),
    _sig(Intent.RCE, "shell_binary_reference", r"/bin/(?:ba|z|da)?sh\b|cmd\.exe|powershell(?:\.exe)?\s+-", "high", ("T1059",), canonical=True),
    _sig(Intent.RCE, "log4shell_jndi", r"\$\{(?:jndi|\$\{|lower:|upper:|env:|sys:)[^}\n]{0,120}", "critical", ("T1190", "T1059"), advanced=True),
    _sig(Intent.RCE, "shellshock", r"\(\)\s*\{\s*[:;]\s*\}\s*;", "critical", ("T1190", "T1059"), canonical=True),
    _sig(Intent.RCE, "template_injection", r"\{\{[^}\n]{0,80}(?:\d+\s*\*\s*\d+|__class__|config|self)[^}\n]{0,80}\}\}|\$\{\d+\s*\*\s*\d+\}|<%=", "high", ("T1190", "T1059"), advanced=True),
    # --- XSS -------------------------------------------------------------------
    _sig(Intent.XSS, "script_injection", r"<\s*script\b|<\s*(?:img|svg|iframe|body)[^>]{0,80}\bon\w+\s*=|javascript\s*:", "medium", ("T1190",), canonical=True),
    # --- SSRF ------------------------------------------------------------------
    _sig(Intent.SSRF, "internal_resource_fetch",
         r"(?:https?|gopher|dict|ftp)://(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.169\.254|\[::1\]|metadata\.google\.internal)|file:///",
         "high", ("T1190", "T1552.005")),
    # --- API exploitation ------------------------------------------------------
    _sig(Intent.API_EXPLOITATION, "nosql_operator_injection", r"\$(?:ne|gt|lt|gte|lte|regex|where|nin|exists)\b", "high", ("T1190",), canonical=True),
    _sig(Intent.API_EXPLOITATION, "prototype_pollution", r"__proto__|constructor\s*[.\[]\s*prototype", "high", ("T1190",), advanced=True),
    _sig(Intent.API_EXPLOITATION, "graphql_introspection", r"__schema\b|__type\b|IntrospectionQuery", "medium", ("T1190",)),
)

RECON_PATH_RE = re.compile(
    r"^/(?:wp-(?:admin|login\.php|content|includes|json)|xmlrpc\.php|phpmyadmin|pma|adminer(?:\.php)?|admin(?:istrator)?(?:/|$)|manager/html|"
    r"server-(?:status|info)|cgi-bin|actuator|console|jenkins|solr|vendor/phpunit|\.git|\.svn|\.ds_store|\.aws|\.ssh|"
    r"(?:config|install|setup|info|phpinfo|test|debug)\.php|swagger|api-docs|graphql|telescope|_profiler|boaform|hnap1|owa|autodiscover|"
    r"backup|dump|db\.sql|database\.sql|\.env)",
    re.IGNORECASE,
)
SCANNER_UA_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|nuclei|gobuster|dirbuster|\bdirb\b|wfuzz|ffuf|feroxbuster|acunetix|nessus|openvas|burpsuite|zaproxy|"
    r"zgrab|arachni|whatweb|wpscan|hydra|metasploit|jaeles|katana|censys|shodan|netsparker|appscan|w3af|skipfish|commix|xsstrike",
    re.IGNORECASE,
)
GENERIC_CLIENT_RE = re.compile(
    r"^(?:curl|wget|python-requests|python-urllib|aiohttp|go-http-client|java/|okhttp|libwww-perl|scrapy|node-fetch|axios|postmanruntime|insomnia)",
    re.IGNORECASE,
)
IDOR_RE = re.compile(r"^/api/(?:v\d+/)?(?:users?|accounts?|orders?|invoices?|customers?|profiles?)/(\d+)/?$", re.IGNORECASE)
HONEY_TOKEN_RE = re.compile(r"nlr_live_([0-9a-f]{8})([a-z0-9]{16})([0-9a-f]{6})")
MASS_ASSIGNMENT_KEYS = {
    "isadmin", "is_admin", "admin", "role", "roles", "is_superuser", "isstaff", "is_staff",
    "permissions", "privileges", "verified", "balance",
}
SQL_KEYWORDS = {"union", "select", "from", "where", "insert", "update", "delete", "drop", "sleep", "having", "group", "order"}
EVASION_HEADERS = ("x-original-url", "x-rewrite-url", "x-custom-ip-authorization", "x-originating-ip", "x-remote-addr", "x-http-method-override")


def _is_pass_key(key: str) -> bool:
    last = re.split(r"[.\[]", key.lower())[-1]
    return any(token in last for token in ("pass", "pwd"))


def _is_user_key(key: str) -> bool:
    last = re.split(r"[.\[]", key.lower())[-1]
    return last == "log" or any(token in last for token in ("user", "login", "email", "mail", "uname", "account"))


def extract_credentials(pairs: list[tuple[str, str]]) -> Optional[Credentials]:
    user: Optional[str] = None
    password: Optional[str] = None
    for key, value in pairs:
        if password is None and _is_pass_key(key):
            password = value
        elif user is None and _is_user_key(key):
            user = value
    if user is not None and password is not None:
        return Credentials(user[:128], password[:256])
    return None


def _b64_json(segment: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        data = json.loads(raw.decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def sign_honey_token(secret: str, body: str) -> str:
    return hmac.new(secret.encode(), f"tok:{body}".encode(), hashlib.sha256).hexdigest()[:6]


def find_honey_token(text: str, secret: str) -> Optional[str]:
    """Return the harvesting fingerprint prefix if `text` holds a valid honey-token."""
    for match in HONEY_TOKEN_RE.finditer(text):
        body = match.group(1) + match.group(2)
        if hmac.compare_digest(sign_honey_token(secret, body), match.group(3)):
            return match.group(1)
    return None


class BehavioralProfiler:
    """Classifies skill level and intent from a single request (no state needed)."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def analyze(self, ctx: RequestContext) -> Profile:
        findings = self._signature_findings(ctx) + self._structural_findings(ctx)
        unique: dict[tuple[Intent, str], Finding] = {}
        for finding in findings:
            unique.setdefault((finding.intent, finding.technique), finding)
        ordered = sorted(unique.values(), key=lambda f: -SEVERITY_ORDER[f.severity])

        evasion = self._evasion(ctx, ordered)
        skill, confidence, scores = self._assess_skill(ctx, ordered, evasion)
        severity = max((f.severity for f in ordered), default="info")
        if skill is SkillLevel.APT and severity in {"medium", "high"}:
            severity = _SEVERITY_NAMES[SEVERITY_ORDER[severity] + 1]

        priority = [Intent.RCE, Intent.SQL_INJECTION, Intent.PATH_TRAVERSAL, Intent.SSRF,
                    Intent.API_EXPLOITATION, Intent.XSS, Intent.CREDENTIAL_STUFFING, Intent.RECONNAISSANCE]
        primary = Intent.BENIGN
        if ordered:
            top_rank = SEVERITY_ORDER[ordered[0].severity]
            candidates = {f.intent for f in ordered if SEVERITY_ORDER[f.severity] == top_rank}
            primary = next((i for i in priority if i in candidates), ordered[0].intent)

        creds = extract_credentials(ctx.values) if ctx.method in {"POST", "PUT", "PATCH"} else None
        return Profile(skill, confidence, ordered, primary, severity, evasion, scores, creds)

    # -- detection -------------------------------------------------------------
    def _signature_findings(self, ctx: RequestContext) -> list[Finding]:
        out: list[Finding] = []
        for intent, technique, pattern, severity, mitre, canonical, advanced in SIGNATURES:
            match = pattern.search(ctx.full_surface)
            if match:
                out.append(Finding(intent, technique, severity, mitre, _clean(match.group(0)), canonical, advanced))
        return out

    def _structural_findings(self, ctx: RequestContext) -> list[Finding]:
        out: list[Finding] = []
        path = ctx.path.lower()
        if RECON_PATH_RE.search(path):
            out.append(Finding(Intent.RECONNAISSANCE, "wordlist_probe", "low", ("T1595.003", "T1595.002"), _clean(ctx.path)))
        if SCANNER_UA_RE.search(ctx.user_agent):
            out.append(Finding(Intent.RECONNAISSANCE, "scanner_user_agent", "low", ("T1595.002",), _clean(ctx.user_agent, 60)))

        if ctx.method in {"POST", "PUT", "PATCH"}:
            creds = extract_credentials(ctx.values)
            if creds:
                stuffing = "@" in creds.username
                out.append(Finding(
                    Intent.CREDENTIAL_STUFFING,
                    "credential_stuffing" if stuffing else "password_guessing",
                    "medium", ("T1110.004",) if stuffing else ("T1110.001",),
                    "user=" + _clean(creds.username, 40),
                ))
            hits = sorted({k for k in ctx.json_keys if k.lower() in MASS_ASSIGNMENT_KEYS})
            if hits:
                out.append(Finding(Intent.API_EXPLOITATION, "mass_assignment", "medium", ("T1190",), _clean(",".join(hits)), canonical=True))

        bearer = re.match(r"bearer\s+([\w-]+)\.([\w-]*)\.([\w-]*)", ctx.headers.get("authorization", ""), re.IGNORECASE)
        if bearer:
            header = _b64_json(bearer.group(1))
            if str(header.get("alg", "")).lower() in {"none", "null"}:
                out.append(Finding(Intent.API_EXPLOITATION, "jwt_alg_none", "high", ("T1190", "T1078"), "alg=none", advanced=True))
            if re.search(r"\.\./|['\";|]|\bunion\b", str(header.get("kid", "")), re.IGNORECASE):
                out.append(Finding(Intent.API_EXPLOITATION, "jwt_kid_injection", "high", ("T1190",), _clean("kid=" + str(header.get("kid"))), advanced=True))

        if IDOR_RE.match(path):
            out.append(Finding(Intent.API_EXPLOITATION, "object_id_enumeration", "low", ("T1190",), _clean(ctx.path)))
        if ctx.method not in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}:
            out.append(Finding(Intent.RECONNAISSANCE, "http_method_probe", "low", ("T1595.002",), ctx.method))

        origin = find_honey_token(ctx.full_surface, self.cfg.secret)
        if origin:
            out.append(Finding(Intent.API_EXPLOITATION, "honey_token_reuse", "critical", ("T1078", "T1552.001"),
                               f"token harvested by fingerprint prefix {origin}", advanced=True))
        return out

    def _evasion(self, ctx: RequestContext, findings: list[Finding]) -> list[str]:
        signals: list[str] = []
        raw = ctx.raw_target
        if ctx.decode_rounds >= 2:
            signals.append("multi_layer_url_encoding")
        if re.search(r"%u[0-9a-f]{4}|%c0%a[fe]|%e0%80%[a-f0-9]{2}", raw, re.IGNORECASE):
            signals.append("unicode_or_overlong_encoding")
        if "%00" in raw or "\x00" in raw:
            signals.append("null_byte_injection")
        sql_context = any(f.intent is Intent.SQL_INJECTION for f in findings)
        if sql_context and re.search(r"/\*.*?\*/", ctx.request_surface, re.DOTALL):
            signals.append("sql_comment_obfuscation")
        if sql_context and re.search(r"0x[0-9a-f]{6,}|\bchar\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\)|\bchr\s*\(\d+\)", ctx.request_surface, re.IGNORECASE):
            signals.append("hex_or_char_encoding")
        if sql_context and any(
            word.lower() in SQL_KEYWORDS and not (word.islower() or word.isupper())
            for word in re.findall(r"[A-Za-z]{4,}", ctx.request_surface)
        ):
            signals.append("mixed_case_keywords")
        if any(name in ctx.headers for name in EVASION_HEADERS):
            signals.append("access_control_bypass_headers")
        return signals

    def _assess_skill(self, ctx: RequestContext, findings: list[Finding], evasion: list[str]) -> tuple[SkillLevel, float, dict[str, int]]:
        scores = {"scanner": 0, "script": 0, "apt": 0}
        ua = ctx.user_agent
        if not ua:
            scores["scanner"] += 2
        if SCANNER_UA_RE.search(ua):
            scores["scanner"] += 5
        elif GENERIC_CLIENT_RE.search(ua):
            scores["script"] += 2
            scores["scanner"] += 1
        if ua.lower().startswith("mozilla/") and "accept-language" in ctx.headers and "accept-encoding" in ctx.headers:
            scores["apt"] += 1
        elif "accept-language" not in ctx.headers:
            scores["scanner"] += 1
        if len(evasion) >= 2:
            scores["apt"] += 3
        elif evasion:
            scores["apt"] += 1
        for finding in findings:
            scores["script"] += 2 if finding.canonical else 0
            scores["apt"] += 2 if finding.advanced else 0
            scores["scanner"] += 1 if finding.technique == "wordlist_probe" else 0
        attack_intents = {f.intent for f in findings if f.intent is not Intent.RECONNAISSANCE}
        if len(attack_intents) >= 3:
            scores["scanner"] += 3  # shotgun payloads are typical for fuzzers

        if not findings and not evasion:
            return SkillLevel.UNKNOWN, 0.5, scores
        ranked = sorted(scores.values(), reverse=True)
        confidence = round(min(0.97, 0.5 + (ranked[0] - ranked[1]) * 0.08), 2)
        if scores["scanner"] >= 4 and scores["scanner"] >= scores["apt"]:
            return SkillLevel.AUTOMATED_SCANNER, confidence, scores
        if scores["apt"] >= 4 and scores["apt"] > scores["script"]:
            return SkillLevel.APT, confidence, scores
        if attack_intents:
            return SkillLevel.SCRIPT_KIDDIE, confidence, scores
        return SkillLevel.AUTOMATED_SCANNER, confidence, scores


# ============================================================================
# 4. Polymorphic deception generator
# ============================================================================
@dataclass(frozen=True)
class Persona:
    name: str
    framework: str
    server: str
    powered_by: str
    db: str
    cookie: str
    webroot: str
    extra_headers: tuple[tuple[str, str], ...] = ()


PERSONAS: tuple[Persona, ...] = (
    Persona("lamp-wordpress", "php", "Apache/2.4.41 (Ubuntu)", "PHP/7.4.3", "mysql", "PHPSESSID", "/var/www/html"),
    Persona("express-postgres", "node", "nginx/1.18.0 (Ubuntu)", "Express", "postgres", "connect.sid", "/app/src"),
    Persona("django-sqlite", "python", "gunicorn/20.1.0", "", "sqlite", "sessionid", "/srv/app",
            (("X-Frame-Options", "DENY"), ("Vary", "Cookie"))),
    Persona("iis-aspnet-mssql", "aspnet", "Microsoft-IIS/10.0", "ASP.NET", "mssql", "ASP.NET_SessionId", "C:\\inetpub\\wwwroot",
            (("X-AspNet-Version", "4.0.30319"),)),
    Persona("tomcat-spring-mysql", "java", "Apache-Coyote/1.1", "", "mysql", "JSESSIONID", "/opt/tomcat/webapps/ROOT"),
)

FILE_TARGETS = tuple(
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in (
        (r"/etc/passwd(?![\w-])", "passwd"),
        (r"/etc/shadow(?![\w-])", "shadow"),
        (r"/proc/(?:self|\d+)/environ", "proc_environ"),
        (r"(?:^|[/\\=\s])\.env(?:\.[\w-]+)?(?![\w.-])", "env"),
        (r"\.git/config", "git_config"),
        (r"wp-config\.php", "wp_config"),
        (r"\.htpasswd", "htpasswd"),
        (r"(?:win|boot)\.ini", "win_ini"),
        (r"\.aws/credentials", "aws_credentials"),
        (r"(?:^|[/\\=])(?:backup|dump|database|db)\.sql", "backup_sql"),
    )
)
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_FIRST = ("Adi", "Bima", "Citra", "Dewi", "Eko", "Farah", "Gita", "Hendra", "Indah", "Joko", "Kirana", "Lukman", "Maya", "Nando", "Putri", "Rizky")
_LAST = ("Pratama", "Santoso", "Wijaya", "Hidayat", "Lestari", "Saputra", "Nugroho", "Kusuma", "Rahman", "Setiawan")


def resolve_file_target(surface: str) -> Optional[str]:
    for pattern, name in FILE_TARGETS:
        if pattern.search(surface):
            return name
    return None


class HoneyFactory:
    """Deterministic (per attacker fingerprint + time epoch) honey-token and data generator."""

    def __init__(self, cfg: Config, fingerprint: str, epoch: int) -> None:
        self.cfg, self.fingerprint, self.epoch = cfg, fingerprint, epoch
        self.org = cfg.decoy_org
        self.slug = re.sub(r"[^a-z0-9]+", "_", cfg.decoy_org.lower()).strip("_") or "app"
        self.domain = self.slug.replace("_", "-") + ".corp"

    @property
    def trace(self) -> str:
        return self.fingerprint[:8]

    def rng(self, purpose: str) -> random.Random:
        digest = hmac.new(self.cfg.secret.encode(), f"{self.fingerprint}|{self.epoch}|{purpose}".encode(), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))

    @staticmethod
    def chars(rng: random.Random, length: int, alphabet: str) -> str:
        return "".join(rng.choice(alphabet) for _ in range(length))

    def password(self, rng: random.Random, length: int = 18) -> str:
        return self.chars(rng, length, "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    def hex(self, rng: random.Random, length: int) -> str:
        return self.chars(rng, length, "0123456789abcdef")

    def b64(self, rng: random.Random, nbytes: int) -> str:
        return base64.b64encode(rng.getrandbits(8 * nbytes).to_bytes(nbytes, "big")).decode()

    def bcrypt(self, rng: random.Random) -> str:
        return "$2b$12$" + self.chars(rng, 53, _BCRYPT_ALPHABET)

    def aws_pair(self, rng: random.Random) -> tuple[str, str]:
        if self.cfg.canary_key_id and self.cfg.canary_secret:
            return self.cfg.canary_key_id, self.cfg.canary_secret
        return ("AKIA" + self.chars(rng, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), self.chars(rng, 40, _B64_ALPHABET))

    def api_key(self, rng: random.Random) -> str:
        body = self.trace + self.chars(rng, 16, "abcdefghijklmnopqrstuvwxyz0123456789")
        return f"nlr_live_{body}{sign_honey_token(self.cfg.secret, body)}"

    def users(self, count: int = 8, start_id: int = 1) -> list[dict[str, Any]]:
        rng = self.rng("users")
        roles = ("viewer", "viewer", "editor", "manager", "admin", "superadmin")
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        rows: list[dict[str, Any]] = []
        for index in range(count):
            first, last = rng.choice(_FIRST), rng.choice(_LAST)
            username = f"{first}.{last}".lower()
            rows.append({
                "id": start_id + index,
                "username": username,
                "email": f"{username}@{self.domain}",
                "role": roles[rng.randrange(len(roles))],
                "password_hash": self.bcrypt(rng),
                "api_key": self.api_key(rng),
                "last_login": (base + timedelta(minutes=rng.randrange(600000))).strftime("%Y-%m-%d %H:%M:%S"),
            })
        return rows


def db_error(db: str, fragment: str) -> tuple[str, str, str]:
    """(message, error code, SQLSTATE) imitating the persona's database engine."""
    if db == "mysql":
        return (f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version "
                f"for the right syntax to use near '{fragment}' at line 1", "ER_PARSE_ERROR", "42000")
    if db == "postgres":
        return (f'syntax error at or near "{fragment}"', "42601", "42601")
    if db == "mssql":
        return (f"Unclosed quotation mark after the character string '{fragment}'.", "102", "42000")
    return (f'near "{fragment}": syntax error', "SQLITE_ERROR", "HY000")


_PAGE_CSS = ("body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f1f1f1;color:#1d2327;margin:0}"
             "main{max-width:420px;margin:8vh auto;background:#fff;padding:24px;border:1px solid #c3c4c7}"
             "main.wide{max-width:860px}label{display:block;margin:12px 0}input{width:100%;padding:8px;box-sizing:border-box}"
             "button{padding:8px 16px;background:#2271b1;color:#fff;border:0}table{border-collapse:collapse;width:100%}"
             "td,th{border:1px solid #ddd;padding:6px;font-size:13px;text-align:left}")


class DeceptionEngine:
    """Chooses a persona and mutates the response to match what the attacker is trying."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    # -- public API ------------------------------------------------------------
    def respond(self, ctx: RequestContext, profile: Profile) -> DecoyResponse:
        persona = PERSONAS[self._seed_rng(ctx, "persona").randrange(len(PERSONAS))]
        honey = HoneyFactory(self.cfg, ctx.fingerprint, ctx.epoch)
        techniques = profile.techniques
        target = resolve_file_target(ctx.request_surface)
        intent = profile.primary_intent

        if "honey_token_reuse" in techniques:
            decoy = self._json(200, {"authenticated": True, "scope": "admin", "data": honey.users(5)}, "authorized_data_lure")
        elif intent is Intent.RCE:
            decoy = self._rce(ctx, profile, persona, honey)
        elif intent is Intent.SQL_INJECTION:
            decoy = self._sqli(ctx, profile, persona, honey)
        elif intent is Intent.PATH_TRAVERSAL or target:
            decoy = self._serve_file(target, persona, honey)
        elif intent is Intent.SSRF:
            decoy = self._ssrf(ctx, honey)
        elif intent is Intent.XSS:
            decoy = self._page(200, "Search", f"<p>No results for <b>{html.escape(ctx.request_surface[:120])}</b>.</p>", "reflected_xss_lure")
        else:
            decoy = self._route(ctx, profile, persona, honey)

        decoy.persona, decoy.honey_trace = persona.name, honey.trace
        sid = honey.hex(self._seed_rng(ctx, "sid"), 32)
        base = {"Server": persona.server, "Set-Cookie": f"{persona.cookie}={sid}; Path=/; HttpOnly", "Cache-Control": "no-store"}
        if persona.powered_by:
            base["X-Powered-By"] = persona.powered_by
        base.update(dict(persona.extra_headers))
        decoy.headers = {**base, **decoy.headers}
        return decoy

    def _seed_rng(self, ctx: RequestContext, purpose: str) -> random.Random:
        return HoneyFactory(self.cfg, ctx.fingerprint, ctx.epoch).rng(purpose)

    # -- response builders -----------------------------------------------------
    @staticmethod
    def _json(status: int, payload: Any, decoy_type: str, headers: Optional[dict[str, str]] = None, sim_delay: float = 0.0) -> DecoyResponse:
        return DecoyResponse(status, json.dumps(payload, indent=2).encode(), "application/json; charset=utf-8", decoy_type, headers or {}, sim_delay)

    @staticmethod
    def _text(status: int, text: str, decoy_type: str, content_type: str = "text/plain; charset=utf-8") -> DecoyResponse:
        return DecoyResponse(status, text.encode("utf-8", errors="replace"), content_type, decoy_type)

    def _page(self, status: int, title: str, body: str, decoy_type: str, wide: bool = False,
              headers: Optional[dict[str, str]] = None) -> DecoyResponse:
        document = (f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{html.escape(title)} | {html.escape(self.cfg.decoy_org)}</title>"
                    f"<style>{_PAGE_CSS}</style></head><body><main class=\"{'wide' if wide else ''}\">{body}</main></body></html>")
        return DecoyResponse(status, document.encode(), "text/html; charset=utf-8", decoy_type, headers or {})

    @staticmethod
    def _table(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return "<p>No records found.</p>"
        head = "".join(f"<th>{html.escape(str(k))}</th>" for k in rows[0])
        body = "".join("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in row.values()) + "</tr>" for row in rows)
        return f"<table><tr>{head}</tr>{body}</table>"

    # -- SQL injection ---------------------------------------------------------
    def _sqli(self, ctx: RequestContext, profile: Profile, persona: Persona, honey: HoneyFactory) -> DecoyResponse:
        techniques = profile.techniques
        evidence = next((f.evidence for f in profile.findings if f.intent is Intent.SQL_INJECTION), "")
        if "time_based_blind" in techniques:
            match = re.search(r"(?:sleep|pg_sleep)\s*\(\s*(\d{1,3})|delay\s*'\d+:\d+:(\d{1,3})", ctx.request_surface, re.IGNORECASE)
            seconds = float(next((g for g in match.groups() if g), 2)) if match else 2.0
            if ctx.wants_json:
                return self._json(200, {"status": "ok", "results": []}, "simulated_blind_sqli", sim_delay=seconds)
            decoy = self._page(200, "Products", "<p>0 results.</p>", "simulated_blind_sqli")
            decoy.sim_delay = seconds
            return decoy
        if "schema_enumeration" in techniques and ("union_based" in techniques):
            tables = [{"table_name": t} for t in ("users", "customers", "payments", "api_keys", "sessions", "audit_log")]
            return self._json(200, {"status": "ok", "data": tables}, "fake_schema_dump") if ctx.wants_json else \
                self._page(200, "Results", self._table(tables), "fake_schema_dump", wide=True)
        if "union_based" in techniques or {"boolean_tautology", "boolean_numeric"} & techniques:
            if self._tautology_is_false(ctx.request_surface):
                return self._json(200, {"status": "ok", "count": 0, "data": []}, "boolean_false") if ctx.wants_json else \
                    self._page(200, "Results", "<p>No records found.</p>", "boolean_false")
            rows = honey.users(6)
            return self._json(200, {"status": "ok", "count": len(rows), "data": rows}, "fake_table_dump") if ctx.wants_json else \
                self._page(200, "Results", self._table(rows), "fake_table_dump", wide=True)
        return self._sql_error(ctx, persona, evidence)

    @staticmethod
    def _tautology_is_false(surface: str) -> bool:
        match = re.search(r"\b(?:or|and)\s+(\d{1,6})\s*=\s*(\d{1,6})\b", surface, re.IGNORECASE)
        return bool(match and match.group(1) != match.group(2) and re.search(r"\band\b", match.group(0), re.IGNORECASE))

    def _sql_error(self, ctx: RequestContext, persona: Persona, fragment: str) -> DecoyResponse:
        message, code, sqlstate = db_error(persona.db, fragment[:40])
        if ctx.wants_json:
            payload = {"status": "error", "message": message, "code": code, "sqlState": sqlstate,
                       "sql": f"SELECT id, username, email FROM users WHERE id = '{fragment[:40]}'"}
            return self._json(500, payload, "fake_sql_error")
        safe = html.escape(message)
        root = html.escape(persona.webroot)
        templates = {
            "php": f"<br />\n<b>Warning</b>:  mysqli_query(): (42000/1064): {safe} in <b>{root}/includes/db.php</b> on line <b>42</b><br />\n",
            "node": f"<pre>error: {safe}<br> &nbsp; &nbsp;at Parser.parseErrorMessage ({root}/node_modules/pg-protocol/dist/parser.js:287:98)</pre>",
            "python": f"<h1>OperationalError at {html.escape(ctx.path[:80])}</h1><pre class=\"exception_value\">{safe}</pre>",
            "aspnet": f"<h1>Server Error in '/' Application.</h1><h2><i>{safe}</i></h2><b>Exception Details: </b>System.Data.SqlClient.SqlException: {safe}",
            "java": f"<h1>HTTP Status 500 &ndash; Internal Server Error</h1><p><b>Message</b> bad SQL grammar; nested exception is java.sql.SQLSyntaxErrorException: {safe}</p>",
        }
        return self._page(500, "Error", templates.get(persona.framework, safe), "fake_sql_error")

    # -- file disclosure -------------------------------------------------------
    def _serve_file(self, target: Optional[str], persona: Persona, honey: HoneyFactory) -> DecoyResponse:
        builders = {
            "passwd": self._f_passwd, "proc_environ": self._f_proc_environ, "env": self._f_env, "git_config": self._f_git_config,
            "wp_config": self._f_wp_config, "htpasswd": self._f_htpasswd, "win_ini": self._f_win_ini,
            "aws_credentials": self._f_aws_credentials, "backup_sql": self._f_backup_sql,
        }
        builder = builders.get(target or "")
        if builder is None:
            message = ("Warning: include(): Failed opening for inclusion in " + persona.webroot + "/index.php on line 12"
                       if persona.framework == "php" else "Not Found")
            return self._text(404 if persona.framework != "php" else 200, message, "fake_file_error")
        return self._text(200, builder(persona, honey), f"fake_file:{target}")

    def _f_passwd(self, persona: Persona, honey: HoneyFactory) -> str:
        return ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/bash\n"
                f"{'mysql' if persona.db == 'mysql' else 'postgres'}:x:112:116::/nonexistent:/bin/false\n")

    def _f_env(self, persona: Persona, honey: HoneyFactory) -> str:
        rng = honey.rng("env")
        key_id, secret = honey.aws_pair(rng)
        db_pass, host = honey.password(rng), f"db-{rng.choice(('prod', 'primary', 'master'))}-01.internal"
        db_user, db_name = f"{honey.slug}_app", honey.slug
        frameworks: dict[str, list[tuple[str, str]]] = {
            "php": [("APP_NAME", honey.org), ("APP_ENV", "production"), ("APP_KEY", "base64:" + honey.b64(rng, 32)), ("APP_DEBUG", "false"),
                    ("DB_CONNECTION", "mysql"), ("DB_HOST", host), ("DB_PORT", "3306"), ("DB_DATABASE", db_name), ("DB_USERNAME", db_user), ("DB_PASSWORD", db_pass)],
            "node": [("NODE_ENV", "production"), ("PORT", "3000"), ("DATABASE_URL", f"postgres://{db_user}:{db_pass}@{host}:5432/{db_name}"),
                     ("JWT_SECRET", honey.hex(rng, 64)), ("REDIS_URL", f"redis://:{honey.password(rng)}@redis-01.internal:6379/0")],
            "python": [("DJANGO_SETTINGS_MODULE", "config.settings.production"), ("SECRET_KEY", honey.chars(rng, 50, _B64_ALPHABET)), ("DEBUG", "False"),
                       ("DATABASE_URL", "sqlite:////srv/app/db.sqlite3"), ("ALLOWED_HOSTS", "*")],
            "aspnet": [("ASPNETCORE_ENVIRONMENT", "Production"),
                       ("ConnectionStrings__Default", f"Server={host};Database={db_name};User Id={db_user};Password={db_pass};"),
                       ("Jwt__Key", honey.hex(rng, 64))],
            "java": [("SPRING_PROFILES_ACTIVE", "prod"), ("SPRING_DATASOURCE_URL", f"jdbc:mysql://{host}:3306/{db_name}"),
                     ("SPRING_DATASOURCE_USERNAME", db_user), ("SPRING_DATASOURCE_PASSWORD", db_pass), ("JWT_SECRET", honey.hex(rng, 64))],
        }
        rows = frameworks[persona.framework] + [
            ("AWS_ACCESS_KEY_ID", key_id), ("AWS_SECRET_ACCESS_KEY", secret), ("AWS_DEFAULT_REGION", "ap-southeast-1"),
            ("AWS_BUCKET", f"{honey.slug.replace('_', '-')}-prod-assets"), ("INTERNAL_API_TOKEN", honey.api_key(rng)),
            ("MAIL_HOST", "smtp.internal"), ("MAIL_USERNAME", f"noreply@{honey.domain}"), ("MAIL_PASSWORD", honey.password(rng)),
        ]
        return "\n".join(f"{k}={v}" for k, v in rows) + "\n"

    def _f_proc_environ(self, persona: Persona, honey: HoneyFactory) -> str:
        rng = honey.rng("proc")
        key_id, secret = honey.aws_pair(rng)
        pairs = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/var/www", "APP_ENV=production",
                 f"DB_PASSWORD={honey.password(rng)}", f"AWS_ACCESS_KEY_ID={key_id}", f"AWS_SECRET_ACCESS_KEY={secret}"]
        return "\x00".join(pairs)

    def _f_git_config(self, persona: Persona, honey: HoneyFactory) -> str:
        token = honey.api_key(honey.rng("git"))
        return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
                f"[remote \"origin\"]\n\turl = https://deploy-bot:{token}@git.{honey.domain}/platform/backend.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n")

    def _f_wp_config(self, persona: Persona, honey: HoneyFactory) -> str:
        rng = honey.rng("wpconfig")
        salts = "\n".join(f"define( '{name}', '{honey.chars(rng, 64, _B64_ALPHABET)}' );"
                          for name in ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY"))
        return (f"<?php\ndefine( 'DB_NAME', '{honey.slug}_wp' );\ndefine( 'DB_USER', '{honey.slug}_wp' );\n"
                f"define( 'DB_PASSWORD', '{honey.password(rng)}' );\ndefine( 'DB_HOST', 'db-prod-01.internal' );\n"
                f"define( 'DB_CHARSET', 'utf8mb4' );\n{salts}\n$table_prefix = 'wp_';\ndefine( 'WP_DEBUG', false );\n")

    def _f_htpasswd(self, persona: Persona, honey: HoneyFactory) -> str:
        rng = honey.rng("htpasswd")
        return f"admin:$apr1${honey.chars(rng, 8, _BCRYPT_ALPHABET)}${honey.chars(rng, 22, _BCRYPT_ALPHABET)}\n"

    @staticmethod
    def _f_win_ini(persona: Persona, honey: HoneyFactory) -> str:
        return "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n"

    def _f_aws_credentials(self, persona: Persona, honey: HoneyFactory) -> str:
        key_id, secret = honey.aws_pair(honey.rng("awscreds"))
        return f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\nregion = ap-southeast-1\n"

    def _f_backup_sql(self, persona: Persona, honey: HoneyFactory) -> str:
        rows = ",\n".join(
            "({id},'{username}','{email}','{password_hash}','{role}','{api_key}')".format(**u) for u in honey.users(6)
        )
        return ("-- MySQL dump 10.13  Distrib 8.0.33, for Linux (x86_64)\n--\n"
                f"-- Host: localhost    Database: {honey.slug}\n-- ------------------------------------------------------\n"
                "-- Server version\t8.0.33-0ubuntu0.20.04.2\n\nDROP TABLE IF EXISTS `users`;\n"
                "CREATE TABLE `users` (\n  `id` int NOT NULL AUTO_INCREMENT,\n  `username` varchar(64) NOT NULL,\n  `email` varchar(128) NOT NULL,\n"
                "  `password_hash` char(60) NOT NULL,\n  `role` varchar(16) NOT NULL,\n  `api_key` varchar(64) DEFAULT NULL,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB;\n\n"
                f"LOCK TABLES `users` WRITE;\nINSERT INTO `users` VALUES\n{rows};\nUNLOCK TABLES;\n")

    # -- command injection, SSRF -------------------------------------------------
    def _rce(self, ctx: RequestContext, profile: Profile, persona: Persona, honey: HoneyFactory) -> DecoyResponse:
        if "template_injection" in profile.techniques:
            match = re.search(r"(\d{1,4})\s*\*\s*(\d{1,4})", ctx.request_surface)
            if match:
                return self._text(200, str(int(match.group(1)) * int(match.group(2))), "simulated_ssti")
        command_match = re.search(r"(?:[;&|`]|\$\()\s*([^;&|`)\n]{1,80})", ctx.request_surface)
        command = (command_match.group(1).strip().lower() if command_match else "")
        host = f"web-{honey.hex(honey.rng('host'), 4)}"
        outputs: tuple[tuple[str, str], ...] = (
            ("id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"),
            ("whoami", "www-data\n"),
            ("uname", f"Linux {host} 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"),
            ("cat /etc/passwd", self._f_passwd(persona, honey)),
            ("ls", "index.php\nuploads\nwp-config.php\n.env\nbackup.sql\n"),
            ("pwd", persona.webroot + "\n"),
            ("ifconfig", "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.4.17  netmask 255.255.255.0  broadcast 10.0.4.255\n"),
        )
        output = next((out for prefix, out in outputs if command == prefix or command.startswith(prefix + " ")), "")
        if ctx.wants_json:
            return self._json(200, {"status": "ok", "output": output}, "simulated_command_output")
        return self._text(200, output, "simulated_command_output")

    def _ssrf(self, ctx: RequestContext, honey: HoneyFactory) -> DecoyResponse:
        rng = honey.rng("ssrf")
        surface = ctx.request_surface
        if "169.254.169.254" in surface or "metadata.google.internal" in surface.lower():
            match = re.search(r"security-credentials/?([\w.-]*)", surface)
            if match and match.group(1):
                key_id, secret = honey.aws_pair(rng)
                expiry = (datetime.now(timezone.utc) + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
                creds = {"Code": "Success", "Type": "AWS-HMAC", "AccessKeyId": key_id, "SecretAccessKey": secret,
                         "Token": "IQoJb3JpZ2luX2Vj" + honey.b64(rng, 210), "Expiration": expiry}
                return self._json(200, creds, "fake_metadata_credentials")
            if match:
                return self._text(200, "ec2-app-instance-role", "fake_metadata_role")
            return self._text(200, "ami-id\nhostname\ninstance-id\ninstance-type\niam/\nlocal-ipv4\nplacement/\nsecurity-groups\n", "fake_metadata_index")
        return self._page(200, "Internal Console", "<h2>Internal Admin Console</h2><p>Build 4.12.3 &mdash; authorised personnel only.</p>", "fake_internal_service")

    # -- routing for "ordinary" lure paths -----------------------------------------
    def _route(self, ctx: RequestContext, profile: Profile, persona: Persona, honey: HoneyFactory) -> DecoyResponse:
        path = (ctx.path.rstrip("/") or "/").lower()
        if ctx.method == "OPTIONS":
            return DecoyResponse(204, b"", "text/plain", "options", {"Allow": "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Origin": "*"})
        if path == "/robots.txt":
            return self._text(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /internal/\nDisallow: /api/v1/users\n", "robots_lure")
        if path in {"/wp-login.php", "/wp-admin/admin-ajax.php"}:
            return self._login(ctx, profile, persona, honey, wordpress=True)
        if path == "/wp-admin":
            if "wordpress_logged_in" in ctx.headers.get("cookie", ""):
                return self._dashboard(honey)
            return DecoyResponse(302, b"", "text/html", "redirect_to_login", {"Location": "/wp-login.php"})
        if path == "/xmlrpc.php":
            if ctx.method == "POST":
                fault = ("<?xml version=\"1.0\"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member>"
                         "<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member></struct></value></fault></methodResponse>")
                return self._text(200, fault, "fake_xmlrpc", "text/xml; charset=UTF-8")
            return self._text(405, "XML-RPC server accepts POST requests only.", "fake_xmlrpc")
        if path in {"/admin", "/administrator", "/login", "/signin", "/admin/login", "/phpmyadmin", "/pma", "/adminer", "/adminer.php"}:
            title = "phpMyAdmin" if path in {"/phpmyadmin", "/pma"} else "Adminer" if path.startswith("/adminer") else "Admin Console"
            return self._login(ctx, profile, persona, honey, wordpress=False, title=title)
        if path in {"/admin/dashboard", "/dashboard"}:
            return self._dashboard(honey)
        if re.fullmatch(r"/api(?:/v\d+)?/(?:auth/)?(?:login|signin|token)", path):
            return self._api_login(ctx, profile, honey)
        if re.fullmatch(r"/api(?:/v\d+)?/users", path):
            if ctx.method == "POST":
                data = dict(ctx.body_pairs[:20])
                data.setdefault("role", "user")
                return self._json(201, {"id": 1337, "created": True, **data}, "mass_assignment_echo")
            rows = honey.users(10)
            return self._json(200, {"data": rows, "meta": {"page": 1, "per_page": 10, "total": 482}}, "fake_user_list")
        idor = IDOR_RE.match(path)
        if idor:
            ident = int(idor.group(1))
            if ident > 500:
                return self._json(404, {"error": "Not Found"}, "idor_not_found")
            return self._json(200, honey.users(1, start_id=ident)[0], "fake_user_record")
        if path in {"/graphql", "/api/graphql"}:
            types = [{"name": n} for n in ("Query", "Mutation", "User", "Order", "Payment", "ApiKey")]
            return self._json(200, {"data": {"__schema": {"queryType": {"name": "Query"}, "types": types}}}, "fake_graphql_schema")
        if path == "/actuator/env":
            rng = honey.rng("actuator")
            key_id, secret = honey.aws_pair(rng)
            props = {"aws.accessKeyId": {"value": key_id}, "aws.secretKey": {"value": secret},
                     "spring.datasource.password": {"value": honey.password(rng)}}
            return self._json(200, {"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment", "properties": props}]}, "fake_actuator_env")
        if path == "/actuator/health":
            return self._json(200, {"status": "UP"}, "fake_actuator_health")
        if path == "/":
            body = (f"<h2>{html.escape(honey.org)} Customer Portal</h2><p>Service status: operational.</p>"
                    "<!-- TODO: remove /backup.sql and /admin before go-live -->")
            return self._page(200, "Home", body, "portal_index")
        return self._not_found(ctx, persona)

    def _not_found(self, ctx: RequestContext, persona: Persona) -> DecoyResponse:
        path = html.escape(ctx.path[:120])
        templates = {
            "php": f"<h1>Not Found</h1><p>The requested URL {path} was not found on this server.</p><hr><address>{html.escape(persona.server)} Server</address>",
            "node": f"<pre>Cannot {html.escape(ctx.method)} {path}</pre>",
            "python": "<h1>Not Found</h1><p>The requested resource was not found on this server.</p>",
            "aspnet": "<h2>404 - File or directory not found.</h2><h3>The resource you are looking for might have been removed.</h3>",
            "java": "<h1>HTTP Status 404 &ndash; Not Found</h1><p><b>Description</b> The origin server did not find a current representation for the target resource.</p>",
        }
        return self._page(404, "Not Found", templates[persona.framework], "persona_404")

    def _login_outcome(self, creds: Optional[Credentials]) -> bool:
        if creds is None:
            return False
        digest = hmac.new(self.cfg.secret.encode(), f"login|{creds.username}|{creds.password}".encode(), hashlib.sha256).digest()
        return digest[0] % 6 == 0  # ~1 in 6 deterministic "successes" keeps automated tools engaged

    def _login(self, ctx: RequestContext, profile: Profile, persona: Persona, honey: HoneyFactory,
               wordpress: bool, title: str = "Admin Console") -> DecoyResponse:
        error = ""
        if ctx.method == "POST":
            creds = profile.credentials
            if self._login_outcome(creds):
                sid = honey.hex(honey.rng("session"), 32)
                cookie = f"wordpress_logged_in_{sid[:8]}={sid}" if wordpress else f"{persona.cookie}={sid}"
                return DecoyResponse(302, b"", "text/html", "fake_login_success",
                                     {"Location": "/wp-admin/" if wordpress else "/admin/dashboard", "Set-Cookie": cookie + "; Path=/; HttpOnly"})
            user = html.escape(creds.username[:64]) if creds else ""
            if wordpress:
                known = creds is not None and creds.username.lower() in {"admin", "administrator", "webmaster"}
                error = (f"<b>Error:</b> The password you entered for the username <b>{user}</b> is incorrect." if known
                         else f"<b>Error:</b> The username <b>{user}</b> is not registered on this site.")
            else:
                error = "Invalid username or password."
        fields = ("log", "pwd") if wordpress else ("username", "password")
        notice = f'<p style="color:#b32d2e">{error if wordpress else html.escape(error)}</p>' if error else ""
        body = (f"<h2>{html.escape(title if not wordpress else 'Log In')}</h2>{notice}<form method=\"post\">"
                f"<label>Username or Email Address<input name=\"{fields[0]}\" autocomplete=\"off\"></label>"
                f"<label>Password<input name=\"{fields[1]}\" type=\"password\"></label><button type=\"submit\">Log In</button></form>")
        return self._page(200, title, body, "fake_login_wordpress" if wordpress else "fake_login_admin")

    def _api_login(self, ctx: RequestContext, profile: Profile, honey: HoneyFactory) -> DecoyResponse:
        if ctx.method != "POST":
            return self._json(405, {"error": "Method Not Allowed"}, "api_login_method")
        if not self._login_outcome(profile.credentials):
            return self._json(401, {"error": "Invalid credentials"}, "fake_api_login_fail")
        rng = honey.rng("jwt")
        enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")  # noqa: E731
        now = int(time.time())
        token = ".".join((enc({"alg": "HS256", "typ": "JWT"}), enc({"sub": rng.randrange(2, 400), "role": "user", "iat": now, "exp": now + 3600}),
                          honey.chars(rng, 43, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")))
        return self._json(200, {"token": token, "token_type": "Bearer", "expires_in": 3600}, "fake_api_login_success")

    def _dashboard(self, honey: HoneyFactory) -> DecoyResponse:
        body = (f"<h2>{html.escape(honey.org)} &mdash; Dashboard</h2><p>Active users: 482 &middot; Open orders: 37</p><ul>"
                "<li><a href=\"/api/v1/users\">Export users (JSON)</a></li><li><a href=\"/backup.sql\">Latest database backup</a></li>"
                "<li><a href=\"/.env\">Environment configuration</a></li></ul>")
        return self._page(200, "Dashboard", body, "fake_dashboard", wide=True)


# ============================================================================
# 5. Adaptive serverless tarpit
# ============================================================================
class AdaptiveTarpit:
    """Delays responses based on attacker skill while staying inside the function time budget."""

    FACTORS = {SkillLevel.AUTOMATED_SCANNER: 1.0, SkillLevel.SCRIPT_KIDDIE: 0.55, SkillLevel.APT: 0.1, SkillLevel.UNKNOWN: 0.0}

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def plan(self, ctx: RequestContext, profile: Profile, decoy: DecoyResponse) -> float:
        rng = random.Random(int(ctx.fingerprint, 16) ^ int(time.time() * 1000))
        wanted = 0.0
        if profile.skill is not SkillLevel.UNKNOWN:
            wanted = 0.08 + rng.random() * 0.22  # believable baseline latency
            if self.cfg.tarpit_enabled:
                wanted += self.cfg.tarpit_max * self.FACTORS[profile.skill] * (0.85 + rng.random() * 0.3)
        wanted = max(wanted, decoy.sim_delay)  # simulated SLEEP() from a "vulnerable" backend
        headroom = ctx.started + self.cfg.budget - time.monotonic() - self.cfg.webhook_timeout - 0.5
        return round(max(0.0, min(wanted, headroom)), 3)

    @staticmethod
    def wait(seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


# ============================================================================
# 6. Cloud threat-intelligence exporter
# ============================================================================
_SEVERITY_COLORS = {"info": 0x95A5A6, "low": 0x3498DB, "medium": 0xF1C40F, "high": 0xE67E22, "critical": 0xE74C3C}
_LOGGED_HEADERS = ("host", "accept", "accept-language", "accept-encoding", "content-type", "content-length",
                   "referer", "origin", "x-forwarded-for", "x-real-ip", "x-http-method-override", "sec-fetch-site", "sec-ch-ua")


class ThreatIntelExporter:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    # -- event construction ------------------------------------------------------
    def build_event(self, ctx: RequestContext, profile: Profile, decoy: DecoyResponse, delay: float) -> dict[str, Any]:
        techniques: list[dict[str, str]] = []
        seen: set[str] = set()
        for finding in profile.findings:
            for tid in finding.mitre:
                if tid not in seen and tid in MITRE_CATALOG:
                    seen.add(tid)
                    tactic_id, tactic, name = MITRE_CATALOG[tid]
                    techniques.append({"tactic_id": tactic_id, "tactic": tactic, "technique_id": tid, "technique_name": name})

        event: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "@timestamp": _utc_now(),
            "event_id": str(uuid.uuid4()),
            "sensor": {"id": self.cfg.sensor_id, "region": _env_str("VERCEL_REGION", "local"),
                       "commit": _env_str("VERCEL_GIT_COMMIT_SHA")[:7]},
            "source": {"ip": ctx.client_ip, "fingerprint": ctx.fingerprint, "geo": ctx.geo},
            "http": {
                "method": ctx.method, "path": _clean(ctx.path, 512), "user_agent": _clean(ctx.user_agent, 256),
                "headers": self._headers(ctx), "header_order": ctx.header_names[:32], "body_bytes": ctx.body_size,
                "parameters": self._parameters(ctx),
            },
            "classification": {
                "skill_level": profile.skill.value, "confidence": profile.confidence,
                "primary_intent": profile.primary_intent.value, "intents": profile.intents, "severity": profile.severity,
                "evasion": profile.evasion, "scores": profile.scores,
                "evidence": [{"intent": f.intent.value, "technique": f.technique, "severity": f.severity, "match": f.evidence}
                             for f in profile.findings[:12]],
            },
            "mitre_attack": {"matrix": "enterprise", "techniques": techniques},
            "deception": {"persona": decoy.persona, "mutation_epoch": ctx.epoch, "decoy_type": decoy.decoy_type,
                          "response_status": decoy.status, "honey_trace": decoy.honey_trace, "tarpit_delay_ms": int(delay * 1000)},
        }
        if profile.credentials:
            creds = profile.credentials
            record: dict[str, Any] = {"username": _clean(creds.username, 64), "password_length": len(creds.password),
                                      "password_sha256_prefix": hashlib.sha256(creds.password.encode()).hexdigest()[:12]}
            if self.cfg.log_cleartext:
                record["password"] = _clean(creds.password, 128)
            event["credentials"] = record
        return event

    def _headers(self, ctx: RequestContext) -> dict[str, str]:
        logged = {name: _clean(ctx.headers[name], 200) for name in _LOGGED_HEADERS if name in ctx.headers}
        if "authorization" in ctx.headers:
            logged["authorization"] = f"<redacted scheme={_clean(ctx.headers['authorization'].split(' ')[0], 16)} length={len(ctx.headers['authorization'])}>"
        if "cookie" in ctx.headers:
            names = ",".join(part.split("=")[0].strip() for part in ctx.headers["cookie"].split(";"))[:120]
            logged["cookie"] = f"<redacted names={_clean(names, 120)}>"
        return logged

    def _parameters(self, ctx: RequestContext) -> dict[str, dict[str, str]]:
        def redact(pairs: list[tuple[str, str]]) -> dict[str, str]:
            out: dict[str, str] = {}
            for key, value in pairs[:20]:
                if _is_pass_key(key) and not self.cfg.log_cleartext:
                    out[_clean(key, 64)] = "<redacted>"
                elif key == "_body" and re.search(r"pass|pwd|secret|token", value, re.IGNORECASE) and not self.cfg.log_cleartext:
                    out[key] = "<omitted: possible credential>"
                else:
                    out[_clean(key, 64)] = _clean(value, 200)
            return out
        return {"query": redact(ctx.query_pairs), "body": redact(ctx.body_pairs)}

    # -- delivery ----------------------------------------------------------------
    def dispatch(self, event: dict[str, Any]) -> list[threading.Thread]:
        """Write the event to stdout and start webhook deliveries (non-blocking)."""
        try:
            sys.stdout.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
            sys.stdout.flush()
        except Exception:
            pass
        severity = SEVERITY_ORDER[event["classification"]["severity"]]
        jobs: list[tuple[str, str, bytes, dict[str, str]]] = []
        try:
            if self.cfg.discord_url and severity >= SEVERITY_ORDER[self.cfg.chat_min_severity]:
                jobs.append(("discord", self.cfg.discord_url, self._json_bytes(self._discord_payload(event)), {}))
            if self.cfg.slack_url and severity >= SEVERITY_ORDER[self.cfg.chat_min_severity]:
                jobs.append(("slack", self.cfg.slack_url, self._json_bytes(self._slack_payload(event)), {}))
            if self.cfg.siem_url and severity >= SEVERITY_ORDER[self.cfg.siem_min_severity]:
                jobs.append(("siem", self.cfg.siem_url, *self._siem_request(event)))
        except Exception as exc:  # payload building must never break the request
            _log("error", "webhook_payload_failed", error=repr(exc))
        threads = [threading.Thread(target=self._post, args=job, daemon=True) for job in jobs]
        for thread in threads:
            thread.start()
        return threads

    def join(self, threads: list[threading.Thread], deadline: float) -> None:
        for thread in threads:
            remaining = deadline - time.monotonic() - 0.2
            thread.join(timeout=max(0.05, min(self.cfg.webhook_timeout + 0.5, remaining)))

    def _post(self, name: str, url: str, body: bytes, extra_headers: dict[str, str]) -> None:
        headers = {"Content-Type": "application/json", "User-Agent": "Chrono-Honeypot/1.0", **extra_headers}
        try:
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=self.cfg.webhook_timeout) as response:  # noqa: S310 (URL is operator-supplied)
                response.read(512)
        except urllib.error.HTTPError as exc:
            _log("warning", "webhook_http_error", target=name, status=exc.code)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            _log("warning", "webhook_failed", target=name, error=_clean(repr(exc), 160))

    @staticmethod
    def _json_bytes(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, separators=(",", ":")).encode()

    @staticmethod
    def _summary(event: dict[str, Any]) -> tuple[str, str, str, str]:
        cls, http = event["classification"], event["http"]
        title = f"[{cls['severity'].upper()}] {cls['primary_intent']} by {cls['skill_level']}"
        target = f"{http['method']} {http['path'][:180]}"
        mitre = ", ".join(f"{t['technique_id']} {t['technique_name']}" for t in event["mitre_attack"]["techniques"]) or "n/a"
        evidence = "; ".join(f"{e['technique']}: {e['match']}" for e in cls["evidence"][:4]) or "n/a"
        return title, target, mitre, evidence

    def _discord_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        title, target, mitre, evidence = self._summary(event)
        geo = ", ".join(event["source"]["geo"].values()) or "unknown geo"
        evidence = evidence.replace("```", "'''")[:900]
        return {
            "username": "Chrono-Honeypot",
            "allowed_mentions": {"parse": []},
            "embeds": [{
                "title": title[:250], "description": f"`{target.replace('`', chr(39))}`"[:1000],
                "color": _SEVERITY_COLORS[event["classification"]["severity"]], "timestamp": event["@timestamp"],
                "fields": [
                    {"name": "Source", "value": f"{event['source']['ip']} ({geo})"[:1000], "inline": True},
                    {"name": "Confidence", "value": str(event["classification"]["confidence"]), "inline": True},
                    {"name": "MITRE ATT&CK", "value": mitre[:1000], "inline": False},
                    {"name": "Evidence", "value": f"```{evidence}```", "inline": False},
                    {"name": "Deception", "value": f"{event['deception']['persona']} / {event['deception']['decoy_type']}"[:1000], "inline": False},
                ],
                "footer": {"text": f"event {event['event_id']} | {event['sensor']['id']}"},
            }],
        }

    def _slack_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        def esc(text: str) -> str:
            return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        title, target, mitre, evidence = self._summary(event)
        text = (f"*{esc(title)}*\n`{esc(target).replace('`', chr(39))}`\n*Source:* {esc(event['source']['ip'])}\n"
                f"*MITRE:* {esc(mitre)}\n*Evidence:* {esc(evidence)[:800]}")
        return {"text": title[:150], "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}]}

    def _siem_request(self, event: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
        payload: dict[str, Any] = event
        if self.cfg.siem_format == "splunk-hec":
            payload = {"time": time.time(), "host": self.cfg.sensor_id, "source": "chrono-honeypot", "sourcetype": "_json", "event": event}
        body = self._json_bytes(payload)
        headers: dict[str, str] = {}
        if self.cfg.siem_auth:
            headers["Authorization"] = self.cfg.siem_auth
        if self.cfg.siem_hmac_secret:
            headers["X-Chrono-Signature"] = "sha256=" + hmac.new(self.cfg.siem_hmac_secret.encode(), body, hashlib.sha256).hexdigest()
        return body, headers


# ============================================================================
# 7. Vercel entrypoint
# ============================================================================
PROFILER = BehavioralProfiler(CONFIG)
ENGINE = DeceptionEngine(CONFIG)
TARPIT = AdaptiveTarpit(CONFIG)
EXPORTER = ThreatIntelExporter(CONFIG)

_FALLBACK = DecoyResponse(
    503, b"<html><head><title>503 Service Temporarily Unavailable</title></head><body><h1>Service Temporarily Unavailable</h1></body></html>",
    "text/html; charset=utf-8", "fallback_503", {"Server": "nginx/1.18.0 (Ubuntu)", "Cache-Control": "no-store", "Retry-After": "30"},
)


class handler(BaseHTTPRequestHandler):
    """Vercel discovers a class named `handler`; every HTTP verb is routed to the engine."""

    timeout = 5.0  # bounds slow-body reads (slowloris)
    error_message_format = "<html><head><title>%(code)d %(message)s</title></head><body><h1>%(message)s</h1></body></html>"
    error_content_type = "text/html"

    def _dispatch(self) -> None:
        started = time.monotonic()
        deadline = started + CONFIG.budget
        decoy = _FALLBACK
        try:
            ctx = build_context(self, CONFIG, started)
            profile = PROFILER.analyze(ctx)
            decoy = ENGINE.respond(ctx, profile)
            delay = TARPIT.plan(ctx, profile, decoy)
            threads = EXPORTER.dispatch(EXPORTER.build_event(ctx, profile, decoy, delay))
            TARPIT.wait(delay)
            EXPORTER.join(threads, deadline)
        except Exception as exc:  # the honeypot must always answer, never leak a traceback
            _log("error", "pipeline_failure", error=_clean(repr(exc), 300))
        self._send(decoy)

    def _send(self, decoy: DecoyResponse) -> None:
        try:
            body = b"" if decoy.status == 204 else decoy.body
            self.send_response_only(decoy.status)
            self.send_header("Date", self.date_time_string())
            self.send_header("Content-Type", decoy.content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in decoy.headers.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # the client gave up (common with scanners)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - silence default stderr access log
        return


for _verb in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "PROPFIND", "TRACE"):
    setattr(handler, f"do_{_verb}", handler._dispatch)


if __name__ == "__main__":  # local, safe testing: python api/index.py
    port = int(os.environ.get("PORT", "8000"))
    _log("info", "local_server_start", url=f"http://127.0.0.1:{port}", note="bound to loopback only")
    ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
