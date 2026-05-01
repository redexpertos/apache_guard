#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detector y respuesta automática ante IPs con muchos errores 4xx y señales en error_log.

Arquitectura:
- Lectura incremental por archivo (offset en bytes)
- Agregación por IP en memoria
- Decisión basada en comportamiento (4xx + error_log)
- Integración con CSF
- Persistencia de estado en SQLite
"""

from __future__ import print_function

import collections
import fnmatch
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime

# =========================
# CONFIGURACIÓN
# =========================

LOG_DIR = "/usr/local/apache/domlogs"
ERROR_LOG_PATH = "/usr/local/apache/logs/error_log"
STATE_DB = "/var/tmp/apache_4xx_guard_state.sqlite3"
APP_LOG = "/var/log/apache_4xx_guard.log"

TOP_N_IPS = 10
THRESHOLD_4XX = 20
THRESHOLD_AUTHZ_DENIED = 5
THRESHOLD_MODSEC_ALERT = 10
BLOCK_DURATION_SECONDS = 3600
TOP_ROUTES_TO_LOG = 3
THRESHOLD_DISTINCT_DOMAINS = 6
THRESHOLD_SAME_RESOURCE_HITS = 30
THRESHOLD_KNOWN_MALICIOUS = 5
THRESHOLD_SUSPICIOUS_RESOURCES = 15

# Señales de scraping masivo: solo observación, no bloqueo directo
SCRAPING_TOTAL_REQUESTS = 100
SCRAPING_DISTINCT_ROUTES = 20
SCRAPING_SAME_RESOURCE_HITS = 30
SCRAPING_MIN_SCORE = 2

WHITELIST_IPS = {
    "127.0.0.1",
    "190.60.193.106",
    "201.217.197.114",
    "190.254.1.234",
    "192.211.56.74",
}

WHITELIST_IP_PREFIXES = [
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
]

BASE_DIR = "/var/log/apache_guard"
CUSTOM_KNOWN_MALICIOUS_FILE = BASE_DIR + "/known_malicious.txt"
CUSTOM_KNOWN_MALICIOUS_EXACT_FILE = BASE_DIR + "/known_malicious_exact.txt"
CUSTOM_SUSPICIOUS_FILE = BASE_DIR + "/suspicious.txt"
CUSTOM_SENSITIVE_DENY_EXACT_FILE = BASE_DIR + "/sensitive_deny_exact.txt"
SNAPSHOT_DIR = BASE_DIR + "/snapshots"

EXCLUDED_EXACT_NAMES = set()
EXCLUDED_SUBSTRINGS = ["bytes_log", "bkup", "bytes", "ftp_log"]

CSF_BIN = "/usr/sbin/csf"

KNOWN_MALICIOUS_EXACT = set()
KNOWN_MALICIOUS_PATTERNS = []

SUSPICIOUS_URI_REGEXES = [
    re.compile(r"^/[A-Za-z0-9_-]{1,10}\.php(?:\?.*)?$")
]

LOG_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/(?P<httpver>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

ERROR_CLIENT_RE = re.compile(r'\[client\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?::\d+)?\]')
ERROR_PROXY_URI_RE = re.compile(r'proxy:http://127\.0\.0\.1:(?P<port>\d+)(?P<uri>/\S*)')
ERROR_LOCAL_URI_RE = re.compile(r'client denied by server configuration:\s+(?P<path>/\S+)')
MODSEC_RULE_RE = re.compile(r'\[id\s+"(?P<rule_id>\d+)"\]')
MODSEC_HOST_RE = re.compile(r'\[hostname\s+"(?P<hostname>[^"]+)"\]')
MODSEC_URI_RE = re.compile(r'\[uri\s+"(?P<uri>[^"]+)"\]')
MODSEC_MSG_RE = re.compile(r'\[msg\s+"(?P<msg>[^"]+)"\]')
MODSEC_SEVERITY_RE = re.compile(r'\[severity\s+"(?P<severity>[^"]+)"\]')
AUTOINDEX_PATH_RE = re.compile(r'Cannot serve directory\s+(?P<path>/\S+):')

# =========================
# LOGGING
# =========================

def setup_logging():
    logger = logging.getLogger("apache_4xx_guard")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(APP_LOG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    return logger

# =========================
# ESTADO SQLITE
# =========================

def init_db():
    conn = sqlite3.connect(STATE_DB)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS log_state (
            path TEXT PRIMARY KEY,
            inode INTEGER,
            offset INTEGER,
            updated_at INTEGER
        )
        """
    )
    conn.commit()
    return conn


def get_state(conn, path):
    cur = conn.cursor()
    cur.execute("SELECT inode, offset FROM log_state WHERE path=?", (path,))
    row = cur.fetchone()
    if row:
        return {"inode": row[0], "offset": row[1]}
    return None


def save_state(conn, path, inode, offset):
    now_ts = int(time.time())
    cur = conn.cursor()
    cur.execute(
        "UPDATE log_state SET inode=?, offset=?, updated_at=? WHERE path=?",
        (inode, offset, now_ts, path),
    )
    if cur.rowcount == 0:
        cur.execute(
            "INSERT INTO log_state(path, inode, offset, updated_at) VALUES (?, ?, ?, ?)",
            (path, inode, offset, now_ts),
        )
    conn.commit()

# =========================
# LECTURA INCREMENTAL
# =========================

def read_new_lines(conn, path, logger):
    try:
        st = os.stat(path)
    except Exception:
        return []

    inode = st.st_ino
    size = st.st_size
    state = get_state(conn, path)

    if not state:
        save_state(conn, path, inode, size)
        return []

    offset = state["offset"]

    if state["inode"] != inode or size < offset:
        offset = 0

    if size == offset:
        save_state(conn, path, inode, size)
        return []

    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
        new_offset = f.tell()

    save_state(conn, path, inode, new_offset)
    return data.decode("utf-8", "ignore").splitlines()

# =========================
# UTILIDADES DE CLASIFICACIÓN
# =========================

def is_whitelisted_ip(ip):
    if ip in WHITELIST_IPS:
        return True
    for prefix in WHITELIST_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def load_indicator_file(path):
    items = []
    if not os.path.isfile(path):
        return items

    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                items.append(line)
    except Exception:
        return []

    return items


def load_indicator_sets(logger):
    exact_matches = set(KNOWN_MALICIOUS_EXACT).union(load_indicator_file(CUSTOM_KNOWN_MALICIOUS_EXACT_FILE))
    known_patterns = list(KNOWN_MALICIOUS_PATTERNS) + load_indicator_file(CUSTOM_KNOWN_MALICIOUS_FILE)
    suspicious_patterns = load_indicator_file(CUSTOM_SUSPICIOUS_FILE)
    sensitive_deny_exact = set(load_indicator_file(CUSTOM_SENSITIVE_DENY_EXACT_FILE))

    logger.info("Loaded: %d exact matches", len(exact_matches))
    logger.info("Loaded: %d known_malicious patterns", len(known_patterns))
    logger.info("Loaded: %d suspicious patterns", len(suspicious_patterns))
    logger.info("Loaded: %d sensitive deny exact matches", len(sensitive_deny_exact))
    logger.info(
        "Loaded summary: %d known_malicious patterns | %d exact matches | %d suspicious patterns | %d sensitive deny exact",
        len(known_patterns), len(exact_matches), len(suspicious_patterns), len(sensitive_deny_exact)
    )

    return exact_matches, known_patterns, suspicious_patterns, sensitive_deny_exact

# =========================
# SNAPSHOTS
# =========================

def snapshot_file_daily(path, logger):
    if not os.path.isfile(path):
        return

    os.makedirs(SNAPSHOT_DIR, exist_ok=True)

    date_tag = datetime.now().strftime("%Y%m%d")
    base_name = os.path.basename(path)
    snapshot_name = "{}.{}.snapshot".format(base_name, date_tag)
    snapshot_path = os.path.join(SNAPSHOT_DIR, snapshot_name)

    if os.path.exists(snapshot_path):
        return

    try:
        shutil.copy2(path, snapshot_path)
        logger.info("Snapshot created: %s", snapshot_path)
    except Exception as exc:
        logger.exception("No se pudo crear snapshot de %s: %s", path, exc)


def run_daily_snapshots(logger):
    files_to_snapshot = [
        CUSTOM_KNOWN_MALICIOUS_FILE,
        CUSTOM_KNOWN_MALICIOUS_EXACT_FILE,
        CUSTOM_SUSPICIOUS_FILE,
        CUSTOM_SENSITIVE_DENY_EXACT_FILE,
        APP_LOG,
    ]

    for path in files_to_snapshot:
        snapshot_file_daily(path, logger)

# =========================
# CLASIFICACIÓN DE URI
# =========================

def classify_uri(uri, exact_matches, known_patterns, suspicious_patterns):
    if not uri:
        return "normal"

    if uri in exact_matches:
        return "known_malicious"

    for pattern in known_patterns:
        if fnmatch.fnmatch(uri, pattern):
            return "known_malicious"

    for pattern in suspicious_patterns:
        if fnmatch.fnmatch(uri, pattern):
            return "suspicious"

    for regex in SUSPICIOUS_URI_REGEXES:
        if regex.match(uri):
            return "suspicious"

    return "normal"


def classify_user_agent(user_agent):
    if not user_agent:
        return "anomalous"

    ua_raw = user_agent.strip()
    ua = ua_raw.lower()

    if not ua:
        return "anomalous"

    if len(ua) < 4:
        return "anomalous"

    if ua.isdigit():
        return "anomalous"

    if ua.startswith("/") or ua.startswith("./") or ua.startswith("../"):
        return "anomalous"

    http_library_markers = [
        "curl",
        "python-requests",
        "httpx",
        "aiohttp",
        "urllib",
        "go-http-client",
        "wget",
    ]

    for marker in http_library_markers:
        if marker in ua:
            return "http_library"

    known_bot_markers = [
        "googlebot",
        "bingbot",
        "baiduspider",
        "ahrefsbot",
        "semrushbot",
        "mj12bot",
        "dotbot",
        "yandexbot",
        "applebot",
        "facebookexternalhit",
        "meta-externalagent",
        "gptbot",
        "claudebot",
    ]

    for marker in known_bot_markers:
        if marker in ua:
            return "known_bot"

    if "bot" in ua or "crawler" in ua or "spider" in ua:
        return "generic_bot"

    if "mozilla" in ua:
        return "browser"

    return "anomalous"

# =========================
# PARSER ACCESS STYLE
# =========================

def parse_access_line(line, domain, exact_matches, known_patterns, suspicious_patterns):
    m = LOG_PATTERN.match(line)
    if not m:
        return None

    uri = m.group("uri")
    uri_class = classify_uri(uri, exact_matches, known_patterns, suspicious_patterns)

    user_agent = m.group("user_agent") or ""
    user_agent_family = classify_user_agent(user_agent)

    return {
        "source": "access_log",
        "ip": m.group("ip"),
        "method": m.group("method"),
        "uri": uri,
        "status": int(m.group("status")),
        "domain": domain,
        "uri_class": uri_class,
        "user_agent": user_agent,
        "user_agent_family": user_agent_family,
    }

# =========================
# PARSER ERROR LOG
# =========================

def _extract_uri_from_local_path(path):
    if not path:
        return None

    markers = ["/public_html", "/var/www/html"]
    for marker in markers:
        idx = path.find(marker)
        if idx >= 0:
            suffix = path[idx + len(marker):]
            return suffix or "/"

    return path


def parse_error_log_line(line, exact_matches, known_patterns, suspicious_patterns, sensitive_deny_exact):
    ip_match = ERROR_CLIENT_RE.search(line)
    if not ip_match:
        return None

    ip = ip_match.group("ip")

    if "client denied by server configuration" in line or "AH01630" in line:
        proxy_match = ERROR_PROXY_URI_RE.search(line)
        local_match = ERROR_LOCAL_URI_RE.search(line)
        uri = None
        domain = None
        event_type = "AUTHZ_DENIED"
        resource_class = "normal"

        if proxy_match:
            uri = proxy_match.group("uri")
            domain = "proxy_backend:{}".format(proxy_match.group("port"))
        elif local_match:
            uri = _extract_uri_from_local_path(local_match.group("path"))
            domain = "local_fs"

        if uri == "/403.shtml":
            return None

        if uri:
            resource_class = classify_uri(uri, exact_matches, known_patterns, suspicious_patterns)
            if uri in sensitive_deny_exact:
                event_type = "SENSITIVE_FILE_DENIED"

        return {
            "source": "error_log",
            "ip": ip,
            "event_type": event_type,
            "uri": uri,
            "domain": domain,
            "status": None,
            "method": None,
            "uri_class": resource_class,
            "modsec_rule_id": None,
            "severity": None,
            "raw_message": line,
        }

    if "[security2:error]" in line:
        rule_match = MODSEC_RULE_RE.search(line)
        host_match = MODSEC_HOST_RE.search(line)
        uri_match = MODSEC_URI_RE.search(line)
        msg_match = MODSEC_MSG_RE.search(line)
        severity_match = MODSEC_SEVERITY_RE.search(line)
        uri = uri_match.group("uri") if uri_match else None
        resource_class = classify_uri(uri, exact_matches, known_patterns, suspicious_patterns) if uri else "normal"

        return {
            "source": "error_log",
            "ip": ip,
            "event_type": "MODSEC_ALERT",
            "uri": uri,
            "domain": host_match.group("hostname") if host_match else None,
            "status": None,
            "method": None,
            "uri_class": resource_class,
            "modsec_rule_id": rule_match.group("rule_id") if rule_match else None,
            "severity": severity_match.group("severity") if severity_match else None,
            "raw_message": msg_match.group("msg") if msg_match else line,
        }

    if "AH01276:" in line and "Cannot serve directory" in line:
        path_match = AUTOINDEX_PATH_RE.search(line)
        return {
            "source": "error_log",
            "ip": ip,
            "event_type": "AUTOINDEX_DENIED",
            "uri": None,
            "domain": "autoindex",
            "status": None,
            "method": None,
            "uri_class": "normal",
            "modsec_rule_id": None,
            "severity": None,
            "raw_message": path_match.group("path") if path_match else line,
        }

    return None

# =========================
# AGREGACIÓN
# =========================

def aggregate(events):
    stats = {}

    for e in events:
        ip = e["ip"]
        uri_class = e.get("uri_class", "normal")

        if ip not in stats:
            stats[ip] = {
                "total": 0,
                "2xx": 0,
                "3xx": 0,
                "4xx": 0,
                "5xx": 0,
                "routes": collections.Counter(),
                "domains": collections.Counter(),
                "known_malicious": 0,
                "suspicious": 0,
                "uri_classes": collections.Counter(),
                "authz_denied_count": 0,
                "modsec_alert_count": 0,
                "autoindex_denied_count": 0,
                "sensitive_denied_count": 0,
                "error_routes": collections.Counter(),
                "error_domains": collections.Counter(),
                "modsec_rule_ids": collections.Counter(),
                "user_agents": collections.Counter(),
                "user_agent_families": collections.Counter(),
            }

        if e.get("source") == "error_log":
            event_type = e.get("event_type")
            error_uri = e.get("uri")
            error_domain = e.get("domain") or "unknown"
            error_route = error_uri or e.get("raw_message") or "unknown"

            if event_type == "AUTHZ_DENIED":
                stats[ip]["authz_denied_count"] += 1
            elif event_type == "SENSITIVE_FILE_DENIED":
                stats[ip]["authz_denied_count"] += 1
                stats[ip]["sensitive_denied_count"] += 1
            elif event_type == "MODSEC_ALERT":
                stats[ip]["modsec_alert_count"] += 1
            elif event_type == "AUTOINDEX_DENIED":
                stats[ip]["autoindex_denied_count"] += 1

            if error_uri:
                stats[ip]["error_routes"][error_route] += 1
                stats[ip]["error_domains"][error_domain] += 1
                stats[ip]["uri_classes"][uri_class] += 1
                if uri_class == "known_malicious":
                    stats[ip]["known_malicious"] += 1
                elif uri_class == "suspicious":
                    stats[ip]["suspicious"] += 1

            if e.get("modsec_rule_id"):
                stats[ip]["modsec_rule_ids"][e["modsec_rule_id"]] += 1

        else:
            code = e["status"]
            group = str(code)[0] + "xx"
            route = e["method"] + " " + e["uri"]
            domain = e.get("domain") or "unknown"

            stats[ip]["total"] += 1
            stats[ip][group] += 1
            stats[ip]["routes"][route] += 1
            stats[ip]["domains"][domain] += 1
            stats[ip]["uri_classes"][uri_class] += 1

            user_agent = e.get("user_agent") or ""
            user_agent_key = user_agent if user_agent else "unknown"
            user_agent_family = e.get("user_agent_family") or "anomalous"
            stats[ip]["user_agents"][user_agent_key] += 1
            stats[ip]["user_agent_families"][user_agent_family] += 1

            if uri_class == "known_malicious":
                stats[ip]["known_malicious"] += 1
            elif uri_class == "suspicious":
                stats[ip]["suspicious"] += 1

    return stats

# =========================
# DETECCIÓN DE SCRAPING MASIVO
# =========================

def detect_scraping_signal(stats_ip):
    """
    Calcula señales simples de scraping masivo por IP.

    Esta función NO decide bloqueo, NO invoca CSF y NO modifica reglas existentes.
    Solo expone contexto operativo para observación y decisiones futuras.
    """
    total = stats_ip["total"]
    distinct_routes = len(stats_ip["routes"])
    top_route_hits = stats_ip["routes"].most_common(1)[0][1] if stats_ip["routes"] else 0

    high_volume = total >= SCRAPING_TOTAL_REQUESTS
    high_variation = distinct_routes >= SCRAPING_DISTINCT_ROUTES
    concentrated_hits = top_route_hits >= SCRAPING_SAME_RESOURCE_HITS

    scraping_score = 0

    if high_volume:
        scraping_score += 1

    if high_variation:
        scraping_score += 1

    if concentrated_hits:
        scraping_score += 1

    return {
        "is_scraping_suspected": scraping_score >= SCRAPING_MIN_SCORE,
        "scraping_score": scraping_score,
        "high_volume": high_volume,
        "high_variation": high_variation,
        "concentrated_hits": concentrated_hits,
        "top_route_hits": top_route_hits,
        "distinct_routes": distinct_routes,
        "total_requests": total,
    }



# =========================
# EVALUACIÓN DE BOT DECLARADO
# =========================

def evaluate_declared_bot_policy(stats_ip, scraping):
    """
    Evalúa el contexto del user-agent cuando existe señal de scraping.

    Esta función NO valida legitimidad real del bot.
    Sin reverse DNS / forward DNS solo podemos interpretar lo que el cliente declara
    en el user-agent. Por eso la salida usa el término declared, no validated.
    """
    family_counts = stats_ip.get("user_agent_families", collections.Counter())
    user_agent_counts = stats_ip.get("user_agents", collections.Counter())

    dominant_family = family_counts.most_common(1)[0][0] if family_counts else "anomalous"
    dominant_user_agent = user_agent_counts.most_common(1)[0][0] if user_agent_counts else "unknown"
    distinct_families = len(family_counts)

    if not scraping.get("is_scraping_suspected"):
        return {
            "declared_bot_policy": "not_applicable",
            "declared_bot_reason": "no_scraping_signal",
            "dominant_user_agent_family": dominant_family,
            "dominant_user_agent": dominant_user_agent,
            "distinct_user_agent_families": distinct_families,
        }

    if dominant_family == "known_bot":
        return {
            "declared_bot_policy": "declared_known_bot",
            "declared_bot_reason": "scraping_with_known_bot_user_agent",
            "dominant_user_agent_family": dominant_family,
            "dominant_user_agent": dominant_user_agent,
            "distinct_user_agent_families": distinct_families,
        }

    if dominant_family in ("generic_bot", "http_library", "anomalous"):
        return {
            "declared_bot_policy": "suspicious_automation",
            "declared_bot_reason": "scraping_with_non_browser_automation",
            "dominant_user_agent_family": dominant_family,
            "dominant_user_agent": dominant_user_agent,
            "distinct_user_agent_families": distinct_families,
        }

    if dominant_family == "browser":
        return {
            "declared_bot_policy": "browser_scraping",
            "declared_bot_reason": "scraping_with_browser_user_agent",
            "dominant_user_agent_family": dominant_family,
            "dominant_user_agent": dominant_user_agent,
            "distinct_user_agent_families": distinct_families,
        }

    return {
        "declared_bot_policy": "unknown",
        "declared_bot_reason": "unclassified_user_agent_context",
        "dominant_user_agent_family": dominant_family,
        "dominant_user_agent": dominant_user_agent,
        "distinct_user_agent_families": distinct_families,
    }


# =========================
# CSF
# =========================

def is_blocked(ip):
    result = subprocess.run([CSF_BIN, "-g", ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = result.stdout.decode("utf-8", "ignore")
    return "DENY" in text


def block_ip(ip, reason):
    cmd = [CSF_BIN, "-td", ip, str(BLOCK_DURATION_SECONDS), reason]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

# =========================
# MAIN
# =========================

def ensure_base_dir():
    os.makedirs(BASE_DIR, exist_ok=True)


def main():
    ensure_base_dir()
    logger = setup_logging()
    logger.info("Inicio ejecución")
    run_daily_snapshots(logger)

    exact_matches, known_patterns, suspicious_patterns, sensitive_deny_exact = load_indicator_sets(logger)

    conn = init_db()
    events = []

    for name in os.listdir(LOG_DIR):
        if name in EXCLUDED_EXACT_NAMES:
            continue
        if any(x in name for x in EXCLUDED_SUBSTRINGS):
            continue

        path = os.path.join(LOG_DIR, name)
        if not os.path.isfile(path):
            continue

        lines = read_new_lines(conn, path, logger)
        domain = os.path.basename(path)
        for line in lines:
            parsed = parse_access_line(line, domain, exact_matches, known_patterns, suspicious_patterns)
            if parsed:
                events.append(parsed)

    if os.path.isfile(ERROR_LOG_PATH):
        error_lines = read_new_lines(conn, ERROR_LOG_PATH, logger)
        for line in error_lines:
            parsed_error = parse_error_log_line(line, exact_matches, known_patterns, suspicious_patterns, sensitive_deny_exact)
            if parsed_error:
                events.append(parsed_error)

    if not events:
        logger.info("Sin eventos nuevos")
        return

    stats = aggregate(events)
    top_ips = sorted(
        stats.keys(),
        key=lambda x: -(stats[x]["total"] + stats[x]["authz_denied_count"] + stats[x]["modsec_alert_count"])
    )[:TOP_N_IPS]

    for ip in top_ips:
        s = stats[ip]
        scraping = detect_scraping_signal(s)
        declared_bot = evaluate_declared_bot_policy(s, scraping)

        if is_whitelisted_ip(ip):
            logger.info("WHITELIST %s", ip)
            continue

        if is_blocked(ip):
            logger.info("YA BLOQUEADO %s", ip)
            continue

        all_domains = set(s["domains"].keys()) | set(s["error_domains"].keys())
        distinct_domains_total = len(all_domains)
        top_domains = " | ".join(["{} {}".format(c, d) for d, c in s["domains"].most_common(3)])
        top_error_domains = " | ".join(["{} {}".format(c, d) for d, c in s["error_domains"].most_common(3)])
        top_route_items = s["routes"].most_common(TOP_ROUTES_TO_LOG)
        top_routes = " | ".join(["{} {}".format(c, r) for r, c in top_route_items])
        max_same_resource_hits = top_route_items[0][1] if top_route_items else 0
        top_error_routes = " | ".join(["{} {}".format(c, r) for r, c in s["error_routes"].most_common(TOP_ROUTES_TO_LOG)])
        top_modsec = " | ".join(["{} {}".format(c, r) for r, c in s["modsec_rule_ids"].most_common(3)])
        top_user_agent_families = " | ".join(["{} {}".format(c, f) for f, c in s["user_agent_families"].most_common(3)])
        top_user_agents = " | ".join(["{} {}".format(c, ua) for ua, c in s["user_agents"].most_common(3)])
        distinct_user_agent_families = len(s["user_agent_families"])
        dominant_user_agent = s["user_agents"].most_common(1)[0][0] if s["user_agents"] else "unknown"

        logger.info(
            "Analizando %s dominios_total=%s 2xx=%s 3xx=%s 4xx=%s 5xx=%s conocidos=%s sospechosos=%s authz=%s modsec=%s autoindex=%s sensitive=%s max_recurso=%s top_dominios=%s top_error_dominios=%s top_rutas=%s top_error=%s top_modsec=%s top_user_agent_families=%s top_user_agents=%s distinct_user_agent_families=%s dominant_user_agent=%s scraping_score=%s scraping=%s high_vol=%s high_var=%s conc_hits=%s distinct_routes=%s scraping_top_route_hits=%s dominant_ua_family=%s declared_bot_policy=%s declared_bot_reason=%s",
            ip,
            distinct_domains_total,
            s["2xx"],
            s["3xx"],
            s["4xx"],
            s["5xx"],
            s["known_malicious"],
            s["suspicious"],
            s["authz_denied_count"],
            s["modsec_alert_count"],
            s["autoindex_denied_count"],
            s["sensitive_denied_count"],
            max_same_resource_hits,
            top_domains,
            top_error_domains,
            top_routes,
            top_error_routes,
            top_modsec,
            top_user_agent_families,
            top_user_agents,
            distinct_user_agent_families,
            dominant_user_agent,
            scraping["scraping_score"],
            scraping["is_scraping_suspected"],
            scraping["high_volume"],
            scraping["high_variation"],
            scraping["concentrated_hits"],
            scraping["distinct_routes"],
            scraping["top_route_hits"],
            declared_bot["dominant_user_agent_family"],
            declared_bot["declared_bot_policy"],
            declared_bot["declared_bot_reason"],
        )

        should_block = False
        block_reason = None

        if s["sensitive_denied_count"] >= 1:
            should_block = True
            block_reason = "sensitive_denied>=1"
        elif s["known_malicious"] >= THRESHOLD_KNOWN_MALICIOUS:
            should_block = True
            block_reason = "known_malicious>={}".format(THRESHOLD_KNOWN_MALICIOUS)
        elif s["4xx"] > THRESHOLD_4XX:
            should_block = True
            block_reason = "4xx>{}".format(THRESHOLD_4XX)
        elif s["suspicious"] >= THRESHOLD_SUSPICIOUS_RESOURCES:
            should_block = True
            block_reason = "suspicious>={}".format(THRESHOLD_SUSPICIOUS_RESOURCES)
        elif s["authz_denied_count"] >= THRESHOLD_AUTHZ_DENIED and (s["known_malicious"] > 0 or s["suspicious"] > 0):
            should_block = True
            block_reason = "authz_denied>={}_with_malicious_context".format(THRESHOLD_AUTHZ_DENIED)
        elif s["modsec_alert_count"] >= THRESHOLD_MODSEC_ALERT and (s["4xx"] > 0 or s["authz_denied_count"] > 0):
            should_block = True
            block_reason = "modsec>={}_with_error_context".format(THRESHOLD_MODSEC_ALERT)
        elif distinct_domains_total >= THRESHOLD_DISTINCT_DOMAINS and (s["4xx"] > 0 or s["authz_denied_count"] > 0):
            should_block = True
            block_reason = "distinct_domains>={}_with_error_context".format(THRESHOLD_DISTINCT_DOMAINS)
        elif max_same_resource_hits >= THRESHOLD_SAME_RESOURCE_HITS and (s["known_malicious"] > 0 or s["suspicious"] > 0 or s["4xx"] > 0):
            should_block = True
            block_reason = "same_resource_hits>={}".format(THRESHOLD_SAME_RESOURCE_HITS)

        if should_block:
            logger.info(
                "BLOQUEANDO %s motivo=%s dominios_total=%s max_recurso=%s top_dominios=%s top_error_dominios=%s rutas=%s error_rutas=%s modsec=%s",
                ip,
                block_reason,
                distinct_domains_total,
                max_same_resource_hits,
                top_domains,
                top_error_domains,
                top_routes,
                top_error_routes,
                top_modsec,
            )
            block_ip(ip, block_reason)

    logger.info("Fin ejecución")


if __name__ == "__main__":
    main()
