#!/usr/bin/env python3
"""
Competition Scanner — Fused 6-layer architecture for online service vuln detection.

Layer 1: Controller      — orchestration, time budget, concurrency
Layer 2: Surface          — HTTP fingerprinting (18 paths, header/body extraction)
Layer 3: Nuclei           — template scan results (pre-loaded or live)
Layer 4: Agent            — LLM product identification + PoC generation (Nuclei misses only)
Layer 5: Verifier         — execute PoC, record request/response, confirm exploitation
Layer 6: Reporter         — competition-format output (JSON + CSV)

Design principles (from Fusion v1/v2 experiments):
  - TRUST Nuclei hits (precision=100% in experiments)
  - Use no-think LLM (35B-A3B, 5-15s/call vs 2-5min think mode)
  - FALLBACK: never miss a target (FN cost > FP cost in competition)
  - Verifier executes real PoC and records evidence
"""

import argparse
import base64
import csv
import json
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════

LLM_BASE_URL = "http://127.0.0.1:8200/v1"
LLM_MODEL = "qwen36-35b-a3b"
LLM_API_KEY = "EMPTY"
LLM_TIMEOUT = 60

LOCAL_TUNNEL_PORT = 18080
TARGETS_FILE = "/data/lqy/testinfo/vulhub-300/blind-targets.txt"
RESULTS_DIR_BASE = "/data/lqy/framework/competition/results"

VULHUB_SSH_HOST = "210.45.70.6"
VULHUB_SSH_PORT = 22022
VULHUB_SSH_USER = "lqy"
VULHUB_SSH_PASS = "lqylqy123"

REQUEST_TIMEOUT = 15
VERIFY_TIMEOUT = 20
KG_PATH = "/data/lqy/framework/competition/vuln_kg.json"
NEO4J_URI = "bolt://127.0.0.1:17687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "neo4j@openspg"

VULHUB_FP_DIR = "/data/lqy/framework/blackbox-docker/vulhub_fingerprints"

_counter_lock = threading.Lock()
_scan_counter = 0
_vuln_kg = None  # JSON KG (fallback)
_neo4j_driver = None  # Neo4j driver (primary)
_vulhub_fps_by_product = {}  # product_name_lower → [fp_dict, ...]
_nuclei_bin = ""  # path to nuclei binary
_surper_templates = ""  # path to surper-666/nuclei templates
_use_nmap = True
_use_live_nuclei = False
_no_httpx = False
_no_sqlmap = False


# ═══════════════════════════════════════════════════════════════
# Layer 1: Controller
# ═══════════════════════════════════════════════════════════════

def setup_logging(results_dir):
    logger = logging.getLogger("competition")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    fh = logging.FileHandler(os.path.join(results_dir, "scan.log"))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def ensure_tunnel(logger):
    r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
    if f":{LOCAL_TUNNEL_PORT} " in r.stdout:
        logger.info(f"Tunnel already on port {LOCAL_TUNNEL_PORT}")
        return None
    cmd = [
        "sshpass", "-p", VULHUB_SSH_PASS,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=30", "-N",
        "-L", f"{LOCAL_TUNNEL_PORT}:127.0.0.1:80",
        "-p", str(VULHUB_SSH_PORT),
        f"{VULHUB_SSH_USER}@{VULHUB_SSH_HOST}",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    if proc.poll() is not None:
        raise RuntimeError("SSH tunnel failed")
    logger.info("SSH tunnel established")
    return proc


def read_targets(path):
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"http://(t-[a-f0-9]+\.rce\.lab)(/.*)?", line)
            if m:
                host = m.group(1)
                token = host.split(".")[0]
                targets.append({"token": token, "host": host,
                                "url": line, "path": m.group(2) or "/"})
            elif line.startswith("http"):
                targets.append({"token": line, "host": line.replace("http://","").rstrip("/"),
                                "url": line, "path": "/"})
    return targets


# ═══════════════════════════════════════════════════════════════
# Layer 2: Surface — HTTP fingerprinting
# ═══════════════════════════════════════════════════════════════

SURFACE_PATHS = [
    "/", "/login", "/admin", "/api", "/api/v1",
    "/manager/html", "/console", "/webtools/control/main",
    "/struts/", "/ws/v1/cluster/info", "/geoserver/web/",
    "/_cat/indices", "/nacos/", "/solr/admin/info/system",
    "/actuator", "/jolokia/", "/druid/index.html",
    "/index.action", "/robots.txt",
]


def http_request(host, path="/", method="GET", headers=None, data=None,
                 timeout=REQUEST_TIMEOUT, tunnel_port=None):
    port = tunnel_port or LOCAL_TUNNEL_PORT
    url = f"http://127.0.0.1:{port}{path}"
    cmd = ["curl", "-s", "-i",
           "-H", f"Host: {host}",
           "--connect-timeout", "8",
           "--max-time", str(timeout)]
    if method != "GET":
        cmd.extend(["-X", method])
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if data:
        cmd.extend(["-d", data])
    cmd.append(url)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 5)
        raw = proc.stdout
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) != 2:
            parts = raw.split("\n\n", 1)
        resp_headers = parts[0] if parts else raw
        resp_body = parts[1] if len(parts) > 1 else ""
        status = 0
        first_line = resp_headers.split("\n")[0] if resp_headers else ""
        sm = re.search(r"(\d{3})", first_line)
        if sm:
            status = int(sm.group(1))
        return {
            "status": status, "headers": resp_headers, "body": resp_body,
            "raw": raw, "curl": " ".join(cmd), "error": None
        }
    except subprocess.TimeoutExpired:
        return {"status": 0, "headers": "", "body": "", "raw": "",
                "curl": " ".join(cmd), "error": "timeout"}
    except Exception as e:
        return {"status": 0, "headers": "", "body": "", "raw": "",
                "curl": " ".join(cmd), "error": str(e)}


def surface_fingerprint(host, logger, token=""):
    probes = {}
    for path in SURFACE_PATHS:
        p = http_request(host, path)
        if p["status"] > 0:
            probes[path] = {
                "status": p["status"],
                "headers": p["headers"][:600],
                "body": p["body"][:2000],
            }
        if len(probes) >= 8:
            break
    if not probes:
        for path in SURFACE_PATHS[:3]:
            p = http_request(host, path)
            probes[path] = {
                "status": p["status"],
                "headers": p["headers"][:600],
                "body": p["body"][:2000],
            }

    server = ""; title = ""; powered_by = ""; cookies = []
    for pd in probes.values():
        for line in pd["headers"].split("\n"):
            ll = line.lower().strip()
            if ll.startswith("server:") and not server:
                server = line.split(":", 1)[1].strip()
            elif ll.startswith("x-powered-by:") and not powered_by:
                powered_by = line.split(":", 1)[1].strip()
            elif ll.startswith("set-cookie:"):
                cookies.append(line.split(":", 1)[1].strip()[:100])
        if not title:
            m = re.search(r"<title>(.*?)</title>", pd["body"], re.I | re.S)
            if m:
                title = m.group(1).strip()[:200]

    return {
        "server": server, "title": title, "powered_by": powered_by,
        "cookies": cookies[:3], "probes": probes,
        "reachable": any(pd["status"] > 0 for pd in probes.values()),
    }


# ═══════════════════════════════════════════════════════════════
# Layer 2.5: TCP Protocol Probing — non-HTTP service detection
# ═══════════════════════════════════════════════════════════════

def tcp_probe(host, port, send_data=None, timeout=5):
    """Open a TCP connection, optionally send data, read banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if send_data:
            sock.sendall(send_data)
        banner = b""
        try:
            banner = sock.recv(4096)
        except socket.timeout:
            pass
        sock.close()
        return banner
    except Exception:
        return b""


def _probe_redis(host, port=6379):
    """Redis: send PING, check for +PONG."""
    banner = tcp_probe(host, port, b"PING\r\n")
    text = banner.decode("utf-8", errors="replace")
    if "+PONG" in text or "redis" in text.lower():
        version = ""
        info_data = tcp_probe(host, port, b"INFO server\r\n")
        m = re.search(r"redis_version:(\S+)", info_data.decode("utf-8", errors="replace"))
        if m:
            version = m.group(1)
        return {"service": "redis", "banner": text[:200], "version": version, "port": port}
    return None


def _probe_mysql(host, port=3306):
    """MySQL: read greeting packet to get version."""
    banner = tcp_probe(host, port)
    if len(banner) > 5:
        try:
            version_end = banner.index(b"\x00", 5)
            version = banner[5:version_end].decode("utf-8", errors="replace")
            return {"service": "mysql", "banner": version, "version": version, "port": port}
        except (ValueError, IndexError):
            pass
        text = banner.decode("utf-8", errors="replace")
        if "mysql" in text.lower() or "mariadb" in text.lower():
            return {"service": "mysql", "banner": text[:200], "version": "", "port": port}
    return None


def _probe_ssh(host, port=22):
    """SSH: read version banner."""
    banner = tcp_probe(host, port)
    text = banner.decode("utf-8", errors="replace").strip()
    if text.startswith("SSH-"):
        version = text.split("-")[-1] if "-" in text else ""
        return {"service": "ssh", "banner": text[:200], "version": version, "port": port}
    return None


def _probe_ftp(host, port=21):
    """FTP: read welcome banner."""
    banner = tcp_probe(host, port)
    text = banner.decode("utf-8", errors="replace").strip()
    if text.startswith("220") or "ftp" in text.lower():
        m = re.search(r"(\d+\.\d+\.\d+\S*)", text)
        version = m.group(1) if m else ""
        return {"service": "ftp", "banner": text[:200], "version": version, "port": port}
    return None


def _probe_memcached(host, port=11211):
    """Memcached: send version command."""
    banner = tcp_probe(host, port, b"version\r\n")
    text = banner.decode("utf-8", errors="replace").strip()
    if text.startswith("VERSION") or "memcached" in text.lower():
        version = text.replace("VERSION ", "").strip()
        return {"service": "memcached", "banner": text[:200], "version": version, "port": port}
    return None


def _probe_generic(host, port):
    """Generic banner grab for unknown services."""
    banner = tcp_probe(host, port)
    if not banner:
        return None
    text = banner.decode("utf-8", errors="replace").strip()[:200]
    service = "unknown"
    if "activemq" in text.lower() or b"\x00\x00\x00" in banner[:4]:
        service = "activemq"
    elif "dubbo" in text.lower():
        service = "dubbo"
    elif "mongodb" in text.lower() or port == 27017:
        service = "mongodb"
    elif "docker" in text.lower() or port == 2375:
        service = "docker-api"
    elif "ldap" in text.lower() or port == 389:
        service = "ldap"
    elif "smtp" in text.lower() or text.startswith("220") and port == 25:
        service = "smtp"
    return {"service": service, "banner": text, "version": "", "port": port}


SERVICE_PROBES = {
    6379: _probe_redis,
    3306: _probe_mysql,
    22: _probe_ssh,
    21: _probe_ftp,
    11211: _probe_memcached,
}


def multi_protocol_fingerprint(host, ports, logger=None):
    """Probe a list of ports for non-HTTP services. Returns list of detected services."""
    results = []
    for port in ports:
        if port in (80, 443, 8080, 8443, 8161, 8888, 9090):
            continue
        probe_fn = SERVICE_PROBES.get(port, _probe_generic)
        try:
            result = probe_fn(host, port)
            if result:
                results.append(result)
                if logger:
                    logger.debug(f"TCP probe {host}:{port} → {result['service']} "
                                 f"v={result.get('version','')}")
        except Exception as e:
            if logger:
                logger.debug(f"TCP probe {host}:{port} error: {e}")
    return results


# ═══════════════════════════════════════════════════════════════
# Layer 2.5: Default Credential + Active PoC Probing
# ═══════════════════════════════════════════════════════════════

DEFAULT_CREDS = {
    "apache activemq": [("GET", "/admin/", "admin", "admin")],
    "activemq": [("GET", "/admin/", "admin", "admin")],
    "tomcat": [("GET", "/manager/html", "tomcat", "tomcat"),
               ("GET", "/manager/html", "admin", "admin")],
    "apache tomcat": [("GET", "/manager/html", "tomcat", "tomcat")],
    "grafana": [("GET", "/api/org", "admin", "admin")],
    "jenkins": [("GET", "/api/json", "admin", "admin")],
    "rabbitmq": [("GET", "/api/overview", "guest", "guest")],
    "nacos": [("POST", "/nacos/v1/auth/login", "nacos", "nacos")],
    "phpmyadmin": [("GET", "/", "root", "")],
    "zabbix": [("POST_JSON", "/api_jsonrpc.php", "Admin", "zabbix")],
    "oracle weblogic server": [("GET", "/console/login/LoginForm.jsp", "weblogic", "welcome1")],
    "weblogic": [("GET", "/console/login/LoginForm.jsp", "weblogic", "welcome1")],
    "sonatype nexus repository manager 3": [("GET", "/service/rest/v1/status", "admin", "admin123")],
    "nexus": [("GET", "/service/rest/v1/status", "admin", "admin123")],
    "couchdb": [("GET", "/", "admin", "password")],
    "elasticsearch": [("GET", "/", "", "")],
    "mongo-express": [("GET", "/", "admin", "pass")],
    "apache superset": [("GET", "/api/v1/me/", "admin", "admin")],
    "superset": [("GET", "/api/v1/me/", "admin", "admin")],
    "airflow": [("GET", "/api/v1/dags", "airflow", "airflow")],
    "apache airflow": [("GET", "/api/v1/dags", "airflow", "airflow")],
    "apache solr": [("GET", "/solr/admin/info/system", "", "")],
    "solr": [("GET", "/solr/admin/info/system", "", "")],
    "druid": [("GET", "/druid/index.html", "", "")],
    "apache druid": [("GET", "/druid/index.html", "", "")],
    "kibana": [("GET", "/api/status", "", "")],
    "jupyter": [("GET", "/api", "", "")],
    "minio": [("GET", "/minio/health/live", "", "")],
    "redis": [("GET", "/", "", "")],
}

_VERSION_PATTERNS = [
    re.compile(r'"version"\s*:\s*"([^"]+)"'),
    re.compile(r'[Vv]ersion[:\s]+([0-9]+\.[0-9]+[.\w-]*)'),
    re.compile(r'<version>([0-9]+\.[0-9]+[.\w-]*)</version>'),
    re.compile(r'Server:\s*\S+/([0-9]+\.[0-9]+[.\w-]*)'),
]


def probe_default_credentials(host, product_name, logger):
    """Test common default credentials for known products.

    Returns {"authenticated": bool, "credentials": "user:pass",
             "response_snippet": str, "version": str or None}
    """
    product_lower = product_name.lower().strip()
    creds_list = DEFAULT_CREDS.get(product_lower)
    if not creds_list:
        return {"authenticated": False, "credentials": "", "response_snippet": "", "version": None}

    for method, path, user, passwd in creds_list:
        headers = {"Host": host}
        data = None

        if user:
            token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"

        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = f"username={user}&password={passwd}"
            resp = http_request(host, path, method="POST", headers=headers, data=data, timeout=8)
        elif method == "POST_JSON":
            headers["Content-Type"] = "application/json"
            if "zabbix" in product_lower:
                data = json.dumps({"jsonrpc": "2.0", "method": "user.login",
                                   "params": {"user": user, "password": passwd}, "id": 1})
            resp = http_request(host, path, method="POST", headers=headers, data=data, timeout=8)
        else:
            resp = http_request(host, path, method="GET", headers=headers, timeout=8)

        status = resp.get("status", 0)
        body = resp.get("body", "")
        resp_headers = resp.get("headers", "")
        full_text = resp_headers + "\n" + body

        authenticated = False
        if status in (200, 302, 301):
            if status == 200 and len(body) > 50:
                if "login" not in body.lower()[:200] or "welcome" in body.lower() or "dashboard" in body.lower():
                    authenticated = True
            elif status in (302, 301) and "login" not in (resp_headers.lower()):
                authenticated = True
            if user == "" and status == 200 and len(body) > 20:
                authenticated = True

        version = None
        for pat in _VERSION_PATTERNS:
            m = pat.search(full_text)
            if m:
                version = m.group(1)
                break

        if authenticated or version:
            logger.debug(f"[{host}] CRED-PROBE: {product_lower} {path} "
                         f"auth={authenticated} cred={user}:{passwd} ver={version}")
            return {
                "authenticated": authenticated,
                "credentials": f"{user}:{passwd}" if authenticated else "",
                "response_snippet": body[:500],
                "version": version,
            }

    return {"authenticated": False, "credentials": "", "response_snippet": "", "version": None}


ACTIVE_PROBES = {
    "sqli": [
        ("/'%20OR%20'1'='1", "GET", None, ["sql", "syntax", "mysql", "error in your", "warning", "ORA-", "pg_"]),
        ("/search?q=1'+AND+'1'='1", "GET", None, ["sql", "syntax", "error"]),
    ],
    "sql injection": [
        ("/'%20OR%20'1'='1", "GET", None, ["sql", "syntax", "mysql", "error in your", "warning"]),
    ],
    "ssti": [
        ("/{{7*7}}", "GET", None, ["49"]),
        ("/?name={{7*7}}", "GET", None, ["49"]),
        ("/?cmd={{7*7}}", "GET", None, ["49"]),
    ],
    "file-read": [
        ("/..%2f..%2f..%2f..%2fetc/passwd", "GET", None, ["root:x:0:0"]),
        ("/?file=../../../etc/passwd", "GET", None, ["root:x:0:0"]),
        ("/?path=....//....//etc/passwd", "GET", None, ["root:x:0:0"]),
    ],
    "path traversal": [
        ("/..%2f..%2f..%2f..%2fetc/passwd", "GET", None, ["root:x:0:0"]),
        ("/?file=../../../etc/passwd", "GET", None, ["root:x:0:0"]),
    ],
    "lfi": [
        ("/?file=../../../etc/passwd", "GET", None, ["root:x:0:0"]),
        ("/?page=../../../etc/passwd", "GET", None, ["root:x:0:0"]),
    ],
    "xss": [
        ("/?q=<script>alert(1)</script>", "GET", None, ["<script>alert(1)</script>"]),
        ("/search?q=<img+src=x+onerror=alert(1)>", "GET", None, ["onerror=alert"]),
    ],
    "ssrf": [
        ("/?url=http://127.0.0.1:80/", "GET", None, []),
        ("/?target=http://127.0.0.1/", "GET", None, []),
    ],
}


def probe_active_poc(host, product_name, vuln_class, logger):
    """Send lightweight exploit payloads to detect vulnerability classes.

    Returns {"detected": bool, "vuln_class": str, "evidence": str,
             "probe_path": str, "probe_response": str}
    """
    vc_lower = vuln_class.lower().strip()
    probes = ACTIVE_PROBES.get(vc_lower, [])
    if not probes:
        for key in ACTIVE_PROBES:
            if key in vc_lower or vc_lower in key:
                probes = ACTIVE_PROBES[key]
                break
    if not probes:
        return {"detected": False, "vuln_class": vuln_class, "evidence": "",
                "probe_path": "", "probe_response": ""}

    for path, method, post_data, indicators in probes:
        if not indicators:
            continue
        resp = http_request(host, path, method=method, data=post_data, timeout=8)
        if resp.get("status", 0) <= 0:
            continue

        body_lower = resp.get("body", "").lower()
        headers_lower = resp.get("headers", "").lower()
        full_lower = headers_lower + "\n" + body_lower

        for indicator in indicators:
            if indicator.lower() in full_lower:
                snippet = resp.get("body", "")[:300]
                logger.debug(f"[{host}] ACTIVE-POC: {vc_lower} hit on {path} indicator={indicator}")
                return {
                    "detected": True,
                    "vuln_class": vuln_class,
                    "evidence": f"path={path} matched '{indicator}' in response",
                    "probe_path": path,
                    "probe_response": snippet,
                }

    return {"detected": False, "vuln_class": vuln_class, "evidence": "",
            "probe_path": "", "probe_response": ""}


# ═══════════════════════════════════════════════════════════════
# Layer 2.5: Deep Version Probe — exhaustive version extraction
# ═══════════════════════════════════════════════════════════════

VERSION_ENDPOINTS = {
    "elasticsearch": [("/", "number")],
    "solr": [("/solr/admin/info/system", "lucene-spec-version|solr-spec-version")],
    "jenkins": [("/api/json", "")],
    "grafana": [("/api/health", "version"), ("/api/frontend/settings", "buildInfo")],
    "nacos": [("/nacos/v1/console/server/state", "version")],
    "spring": [("/actuator/info", "version"), ("/actuator/env", "")],
    "activemq": [("/admin/", "ActiveMQ"), ("/api/jolokia/version", "agent")],
    "tomcat": [("/RELEASE-NOTES.txt", "Apache Tomcat Version")],
    "nexus": [("/service/rest/v1/status", "version")],
    "airflow": [("/api/v1/version", "version"), ("/version", "")],
    "superset": [("/api/v1/database", ""), ("/health", "")],
    "drupal": [("/CHANGELOG.txt", "Drupal"), ("/core/install.php", "")],
    "wordpress": [("/wp-login.php", "ver="), ("/feed/", "generator")],
    "joomla": [("/administrator/manifests/files/joomla.xml", "version")],
    "gitlab": [("/api/v4/version", "version"), ("/users/sign_in", "gon.version")],
    "confluence": [("/rest/applinks/1.0/manifest", "version")],
    "zabbix": [("/index.php", "Zabbix")],
    "kibana": [("/api/status", "version")],
    "weblogic": [("/console/", "WebLogic Server Version")],
    "geoserver": [("/geoserver/web/", "GeoServer")],
    "couchdb": [("/", "version")],
    "phpmyadmin": [("/", "PMA_VERSION"), ("/doc/html/index.html", "phpMyAdmin")],
    "django": [("/admin/", "django")],
    "flask": [("/", "Werkzeug")],
    "vite": [("/@vite/client", "")],
    "flink": [("/config", "flink-version")],
    "mongo-express": [("/", "mongo-express")],
    "hugegraph": [("/apis/version", "version"), ("/versions", "")],
    "harbor": [("/api/v2.0/systeminfo", "harbor_version")],
    "struts2": [("/struts/", "")],
    "shiro": [("/login", "")],
    "fastjson": [("/", "")],
}

GENERIC_VERSION_PATHS = [
    "/api/version", "/version", "/api/v1/version",
    "/api/info", "/info", "/status",
    "/RELEASE-NOTES.txt", "/CHANGES.txt", "/CHANGELOG.md", "/package.json",
]

_VP = [
    re.compile(r'"version"\s*:\s*"([^"]+)"'),
    re.compile(r'"number"\s*:\s*"([^"]+)"'),
    re.compile(r'[Vv]ersion[:\s]+(\d+\.\d+[\.\d\w-]*)'),
    re.compile(r'[>/ ](\d+\.\d+\.\d+[-.\w]*)'),
]


def _extract_version_from_text(text):
    """Try multiple patterns to extract a version string."""
    for pat in _VP:
        m = pat.search(text)
        if m:
            v = m.group(1).strip().rstrip(".")
            if len(v) >= 3 and not v.startswith("0.0.0") and v != "1.0":
                return v
    return None


def deep_version_probe(host, product_name, fingerprint, logger):
    """Exhaustively probe for version info. Returns on first match, max 8 probes."""
    prod = product_name.lower().strip()
    probes_done = 0
    max_probes = 8

    # ── 0. Already available data ──
    server = fingerprint.get("server", "")
    if server:
        v = _extract_version_from_text(server)
        if v:
            return {"version": v, "source": "server_header", "raw": server}

    powered_by = fingerprint.get("powered_by", "")
    if powered_by:
        v = _extract_version_from_text(powered_by)
        if v:
            return {"version": v, "source": "x-powered-by", "raw": powered_by}

    # Check TCP services
    for svc in (fingerprint.get("tcp_services") or []):
        if svc.get("version"):
            return {"version": svc["version"], "source": f"tcp_{svc['service']}:{svc.get('port','')}", "raw": svc.get("banner", "")}

    # Check credential probe
    creds = fingerprint.get("default_creds") or {}
    if creds.get("version"):
        return {"version": creds["version"], "source": "default_creds", "raw": creds.get("response_snippet", "")}

    # ── 1. Product-specific endpoints ──
    endpoints = VERSION_ENDPOINTS.get(prod, [])
    # Also try aliases
    for alias, eps in VERSION_ENDPOINTS.items():
        if alias in prod or prod in alias:
            if eps and eps != endpoints:
                endpoints = endpoints + [e for e in eps if e not in endpoints]
                break

    for path, hint in endpoints:
        if probes_done >= max_probes:
            break
        probes_done += 1
        resp = http_request(host, path, timeout=5)
        if resp["status"] <= 0:
            continue

        full_text = resp.get("headers", "") + "\n" + resp.get("body", "")

        # Check X-Jenkins or other version headers
        for hdr_line in resp.get("headers", "").split("\n"):
            hl = hdr_line.lower().strip()
            if hl.startswith("x-jenkins:") or hl.startswith("x-version:"):
                v = _extract_version_from_text(hdr_line)
                if v:
                    return {"version": v, "source": f"header:{path}", "raw": hdr_line.strip()}

        v = _extract_version_from_text(full_text)
        if v:
            return {"version": v, "source": f"endpoint:{path}", "raw": full_text[:200]}

    # ── 2. Generic version paths ──
    for path in GENERIC_VERSION_PATHS:
        if probes_done >= max_probes:
            break
        probes_done += 1
        resp = http_request(host, path, timeout=5)
        if resp["status"] <= 0 or resp["status"] == 404:
            continue
        full_text = resp.get("headers", "") + "\n" + resp.get("body", "")
        v = _extract_version_from_text(full_text)
        if v:
            return {"version": v, "source": f"generic:{path}", "raw": full_text[:200]}

    # ── 3. Error page version extraction ──
    if probes_done < max_probes:
        probes_done += 1
        resp = http_request(host, "/thispagedoesnotexist_12345", timeout=5)
        if resp["status"] > 0:
            full_text = resp.get("headers", "") + "\n" + resp.get("body", "")
            v = _extract_version_from_text(full_text)
            if v:
                return {"version": v, "source": "error_page", "raw": full_text[:200]}

    return {"version": None, "source": "", "raw": ""}


def filter_cves_by_version(product_cves, version):
    """Filter candidate CVEs by version match. Returns (matched, unmatched)."""
    if not version:
        return product_cves, []
    matched = []
    unmatched = []
    for cfp in product_cves:
        affected = (cfp.get("affected_versions") or "").lower()
        if not affected:
            matched.append(cfp)
            continue
        ver = version.lower()
        if ver in affected:
            matched.append(cfp)
        else:
            m = re.search(r'<\s*([\d.]+)', affected)
            if m:
                try:
                    target_parts = [int(x) for x in ver.split(".")[:3] if x.isdigit()]
                    limit_parts = [int(x) for x in m.group(1).split(".")[:3] if x.isdigit()]
                    if target_parts and limit_parts and target_parts < limit_parts:
                        matched.append(cfp)
                    else:
                        unmatched.append(cfp)
                except (ValueError, TypeError):
                    matched.append(cfp)
            else:
                matched.append(cfp)
    return matched if matched else product_cves, unmatched


# ═══════════════════════════════════════════════════════════════
# Layer 3: Nuclei — load pre-scanned results
# ═══════════════════════════════════════════════════════════════

def load_nuclei_results(nuclei_dir):
    out = {}
    if not nuclei_dir or not os.path.isdir(nuclei_dir):
        return out
    scan_results = os.path.join(nuclei_dir, "scan_results.json")
    if os.path.isfile(scan_results):
        with open(scan_results) as f:
            data = json.load(f)
        for r in data.get("results", []):
            token = r.get("token", "")
            if token:
                out[token] = r
        if out:
            return out

    for fname in os.listdir(nuclei_dir):
        m = re.match(r"nuclei_(t-[a-f0-9]+)\.json$", fname)
        if not m:
            continue
        token = m.group(1)
        fpath = os.path.join(nuclei_dir, fname)
        findings = []
        if os.path.getsize(fpath) > 0:
            with open(fpath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        classification = finding.get("info", {}).get("classification", {})
                        cve_list = classification.get("cve-id", [])
                        cve_id = ""
                        if cve_list:
                            cve_id = cve_list[0] if isinstance(cve_list, list) else str(cve_list)
                        if not cve_id:
                            tid = finding.get("template-id", "").upper()
                            cm = re.search(r"(CVE-\d{4}-\d+)", tid)
                            if cm:
                                cve_id = cm.group(1)
                        findings.append({
                            "template_id": finding.get("template-id", ""),
                            "name": finding.get("info", {}).get("name", ""),
                            "severity": finding.get("info", {}).get("severity", ""),
                            "cve_id": cve_id,
                            "description": finding.get("info", {}).get("description", ""),
                            "tags": finding.get("info", {}).get("tags", []),
                            "curl_command": finding.get("curl-command", ""),
                            "matched_at": finding.get("matched-at", ""),
                        })
                    except json.JSONDecodeError:
                        pass
        out[token] = {"token": token, "findings": findings}
    return out


def _find_nuclei_bin():
    """Locate the nuclei binary."""
    if _nuclei_bin and os.path.isfile(_nuclei_bin):
        return _nuclei_bin
    for candidate in [
        "nuclei",
        "/usr/local/bin/nuclei",
        "/data/lqy/framework/nuclei-scanner/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/bin/nuclei",
    ]:
        try:
            r = subprocess.run([candidate, "-version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return ""


def nmap_scan(host, logger, timeout=120):
    """Run nmap service/version detection. Returns open ports with service info."""
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug(f"nmap not installed, skipping port scan for {host}")
        return {"ports": [], "os": ""}

    # Extract IP and port if host is ip:port format
    target_host = host.split(":")[0] if ":" in host else host
    target_port_arg = []
    if ":" in host:
        port = host.split(":")[1]
        target_port_arg = ["-p", port]

    # Try with service version detection first
    cmd = ["nmap", "-sV", "-sT", "--top-ports", "1000", "-T4", "--open",
           "-oX", "-", "--host-timeout", str(timeout)] + target_port_arg + [target_host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        xml_output = proc.stdout
    except subprocess.TimeoutExpired:
        # Fallback: faster scan without version detection
        logger.debug(f"nmap -sV timed out for {host}, trying fast scan")
        cmd = ["nmap", "-sT", "--top-ports", "100", "-T4", "--open",
               "-oX", "-", "--host-timeout", "60"] + target_port_arg + [target_host]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=70)
            xml_output = proc.stdout
        except (subprocess.TimeoutExpired, Exception):
            return {"ports": [], "os": ""}
    except Exception:
        return {"ports": [], "os": ""}

    # Parse XML output
    ports = []
    os_info = ""
    try:
        root = ET.fromstring(xml_output)
        for host_elem in root.findall(".//host"):
            for port_elem in host_elem.findall(".//port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                service_product = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    service_version = service_elem.get("version", "")
                    service_product = service_elem.get("product", "")
                ports.append({
                    "port": port_num,
                    "protocol": protocol,
                    "service": service_name,
                    "version": service_version,
                    "product": service_product,
                })
            os_elem = host_elem.find(".//osmatch")
            if os_elem is not None:
                os_info = os_elem.get("name", "")
    except ET.ParseError:
        logger.debug(f"nmap XML parse error for {host}")

    if ports:
        logger.debug(f"nmap {host}: {len(ports)} open ports — "
                     + ", ".join(f"{p['port']}/{p['service']}" for p in ports[:5]))
    return {"ports": ports, "os": os_info}


def nuclei_live_scan(host, logger, timeout=180):
    """Run nuclei live scan against a target. Returns findings list."""
    nuclei = _find_nuclei_bin()
    if not nuclei:
        logger.debug("nuclei binary not found, skipping live scan")
        return []

    target_url = f"http://{host}" if not host.startswith("http") else host
    findings = []

    template_dirs = []
    if _surper_templates and os.path.isdir(_surper_templates):
        template_dirs.append(_surper_templates)

    # If no specific templates, use nuclei's default (if installed via go install)
    if not template_dirs:
        default_dir = os.path.expanduser("~/nuclei-templates/http")
        if os.path.isdir(default_dir):
            template_dirs.append(default_dir)

    cmd = [nuclei, "-u", target_url, "-json", "-silent",
           "-timeout", "10", "-retries", "1", "-rate-limit", "50",
           "-severity", "critical,high,medium"]
    for td in template_dirs:
        cmd.extend(["-t", td])

    if not template_dirs:
        # No template dirs specified — let nuclei use its defaults
        pass

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                classification = (finding.get("info") or {}).get("classification") or {}
                cve_list = classification.get("cve-id") or []
                cve_id = ""
                if cve_list:
                    cve_id = cve_list[0] if isinstance(cve_list, list) else str(cve_list)
                if not cve_id:
                    tid = (finding.get("template-id") or "").upper()
                    cm = re.search(r"(CVE-\d{4}-\d+)", tid)
                    if cm:
                        cve_id = cm.group(1)
                findings.append({
                    "template_id": finding.get("template-id", ""),
                    "name": (finding.get("info") or {}).get("name", ""),
                    "severity": (finding.get("info") or {}).get("severity", ""),
                    "cve_id": cve_id,
                    "description": (finding.get("info") or {}).get("description", ""),
                    "tags": (finding.get("info") or {}).get("tags", []),
                    "curl_command": finding.get("curl-command", ""),
                    "matched_at": finding.get("matched-at", ""),
                })
            except json.JSONDecodeError:
                pass
    except subprocess.TimeoutExpired:
        logger.debug(f"nuclei live scan timed out for {host} after {timeout}s")
    except Exception as e:
        logger.debug(f"nuclei live scan error for {host}: {e}")

    if findings:
        logger.info(f"[{host}] NUCLEI-LIVE: {len(findings)} findings — "
                    + ", ".join(f.get("cve_id", f.get("template_id", "")) for f in findings[:3]))
    return findings


def _find_bin(names):
    """Find a binary from a list of candidate paths."""
    for name in names:
        try:
            proc = subprocess.run(["which", name], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass
    return None


def sqlmap_scan(host, path, logger, timeout=60):
    """Run sqlmap to verify SQL injection. Returns dict with results."""
    sqlmap_bin = _find_bin(["sqlmap", "/usr/local/bin/sqlmap", "/usr/bin/sqlmap"])
    if not sqlmap_bin:
        try:
            proc = subprocess.run(["python3", "-m", "sqlmap", "--version"],
                                  capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                sqlmap_bin = "python3 -m sqlmap"
        except Exception:
            pass
    if not sqlmap_bin:
        return {"vulnerable": False, "reason": "sqlmap not found"}

    url = f"http://{host}{path}" if path else f"http://{host}/"
    cmd = (f"{sqlmap_bin} -u \"{url}\" --batch --level=1 --risk=1 "
           f"--timeout=10 --retries=1 --threads=3 --forms --crawl=1 "
           f"--output-dir=/tmp/sqlmap_{host.replace('.','_')}")

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr

        vulnerable = False
        parameter = ""
        dbms = ""

        if "is vulnerable" in output.lower() or "sqlmap identified" in output.lower():
            vulnerable = True
            m = re.search(r"Parameter:\s+['\"]?(\w+)", output)
            if m:
                parameter = m.group(1)
            m = re.search(r"back-end DBMS:\s+(.+?)(?:\n|$)", output)
            if m:
                dbms = m.group(1).strip()

        if vulnerable:
            logger.info(f"[{host}] SQLMAP: vulnerable! param={parameter} dbms={dbms}")
        else:
            logger.debug(f"[{host}] SQLMAP: not vulnerable")

        return {
            "vulnerable": vulnerable,
            "parameter": parameter,
            "dbms": dbms,
            "evidence": output[-500:] if vulnerable else "",
        }
    except subprocess.TimeoutExpired:
        logger.debug(f"[{host}] SQLMAP: timed out after {timeout}s")
        return {"vulnerable": False, "reason": "timeout"}
    except Exception as e:
        logger.debug(f"[{host}] SQLMAP: error {e}")
        return {"vulnerable": False, "reason": str(e)}


def httpx_fingerprint(host, logger, timeout=30):
    """Run httpx or whatweb for technology fingerprinting."""
    result = {"technologies": [], "server": "", "title": "", "whatweb_plugins": {}}

    # Try httpx first
    httpx_bin = _find_bin(["httpx", "/usr/local/bin/httpx", "/data/lqy/go/bin/httpx"])
    if httpx_bin:
        try:
            cmd = [httpx_bin, "-u", f"http://{host}", "-json", "-silent",
                   "-tech-detect", "-status-code", "-title", "-server",
                   "-follow-redirects", "-timeout", "10"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if proc.stdout.strip():
                data = json.loads(proc.stdout.strip().split("\n")[0])
                result["technologies"] = data.get("tech") or data.get("technologies") or []
                result["server"] = data.get("webserver") or data.get("server") or ""
                result["title"] = data.get("title") or ""
                if result["technologies"]:
                    logger.debug(f"[{host}] HTTPX: {', '.join(result['technologies'][:5])}")
                return result
        except Exception as e:
            logger.debug(f"[{host}] HTTPX error: {e}")

    # Fallback to whatweb
    whatweb_bin = _find_bin(["whatweb", "/usr/local/bin/whatweb"])
    if whatweb_bin:
        try:
            cmd = [whatweb_bin, "-q", "--color=never", "--log-json=-", f"http://{host}"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if proc.stdout.strip():
                for line in proc.stdout.strip().split("\n"):
                    try:
                        data = json.loads(line)
                        plugins = data.get("plugins") or {}
                        result["whatweb_plugins"] = {k: v for k, v in plugins.items()
                                                     if k not in ("IP", "Country", "UncommonHeaders")}
                        result["technologies"] = list(result["whatweb_plugins"].keys())
                        http_server = plugins.get("HTTPServer", {})
                        if isinstance(http_server, dict) and http_server.get("string"):
                            result["server"] = str(http_server["string"][0]) if isinstance(http_server["string"], list) else str(http_server["string"])
                        title = plugins.get("Title", {})
                        if isinstance(title, dict) and title.get("string"):
                            result["title"] = str(title["string"][0]) if isinstance(title["string"], list) else str(title["string"])
                        break
                    except json.JSONDecodeError:
                        pass
                if result["technologies"]:
                    logger.debug(f"[{host}] WHATWEB: {', '.join(result['technologies'][:5])}")
        except Exception as e:
            logger.debug(f"[{host}] WHATWEB error: {e}")

    return result


# ═══════════════════════════════════════════════════════════════
# Fingerprint Fusion — unify signals from all probing tools
# ═══════════════════════════════════════════════════════════════

PRODUCT_ALIASES = {
    "httpd": "apache", "apache2": "apache", "apache httpd": "apache",
    "apache http server": "apache",
    "nginx": "nginx", "openresty": "nginx",
    "tomcat": "tomcat", "apache tomcat": "tomcat",
    "activemq": "activemq", "apache activemq": "activemq",
    "mysql": "mysql", "mariadb": "mysql",
    "phpmyadmin": "phpmyadmin", "pma": "phpmyadmin",
    "jenkins": "jenkins", "grafana": "grafana",
    "elasticsearch": "elasticsearch", "elastic": "elasticsearch",
    "kibana": "kibana",
    "weblogic": "weblogic", "oracle weblogic": "weblogic",
    "weblogic server": "weblogic",
    "jboss": "jboss", "wildfly": "jboss",
    "jboss application server": "jboss",
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
    "redis": "redis", "memcached": "memcached",
    "postgresql": "postgres", "postgres": "postgres",
    "mongodb": "mongodb", "mongo": "mongodb", "mongo-express": "mongo-express",
    "openssh": "openssh", "vsftpd": "vsftpd", "proftpd": "proftpd",
    "docker": "docker", "consul": "consul",
    "apache solr": "solr", "solr": "solr",
    "apache struts": "struts2", "struts2": "struts2", "struts": "struts2",
    "apache shiro": "shiro", "shiro": "shiro",
    "spring boot": "spring", "spring framework": "spring", "spring": "spring",
    "django": "django", "flask": "flask", "laravel": "laravel",
    "rabbitmq": "rabbitmq", "zookeeper": "zookeeper", "kafka": "kafka",
    "nacos": "nacos", "dubbo": "dubbo", "flink": "flink",
    "airflow": "airflow", "superset": "superset",
    "confluence": "confluence", "jira": "jira", "gitlab": "gitlab",
    "nexus": "nexus", "sonatype nexus": "nexus",
    "couchdb": "couchdb", "zabbix": "zabbix",
    "gunicorn": "python", "werkzeug": "flask", "uvicorn": "python",
    "jetty": "jetty", "glassfish": "glassfish",
    "microsoft-iis": "iis", "iis": "iis",
}

COOKIE_PRODUCT_MAP = {
    "jsessionid": "java", "phpsessid": "php", "asp.net_sessionid": "asp.net",
    "laravel_session": "laravel", "csrftoken": "django", "_xsrf": "tornado",
    "rack.session": "ruby", "connect.sid": "node",
}

PORT_PRODUCT_MAP = {
    6379: "redis", 3306: "mysql", 5432: "postgres", 27017: "mongodb",
    11211: "memcached", 61616: "activemq", 8161: "activemq",
    9092: "kafka", 2181: "zookeeper", 5672: "rabbitmq",
    9200: "elasticsearch", 5601: "kibana",
    21: "ftp", 22: "ssh", 25: "smtp", 389: "ldap",
    2375: "docker", 8500: "consul", 4848: "glassfish",
    1099: "java-rmi", 7001: "weblogic", 8009: "tomcat",
    20880: "dubbo", 9100: "node-exporter",
    8848: "nacos", 8088: "hadoop", 50070: "hadoop",
}


def _normalize_product(name):
    """Normalize a product name via aliases."""
    if not name:
        return ""
    key = name.lower().strip().rstrip("/")
    return PRODUCT_ALIASES.get(key, key)


def fuse_fingerprint(fp, logger):
    """Fuse signals from all probing tools into unified product candidates."""
    candidates = {}  # product_name → {"confidence": float, "version": str, "signals": [], "ports": set}

    def _add(product, confidence, signal, version="", port=None):
        p = _normalize_product(product)
        if not p or len(p) < 2:
            return
        if p not in candidates:
            candidates[p] = {"confidence": 0, "version": "", "signals": [], "ports": set()}
        c = candidates[p]
        c["confidence"] += confidence
        c["signals"].append(signal)
        if version and (not c["version"] or len(version) > len(c["version"])):
            c["version"] = version
        if port:
            c["ports"].add(port)

    # 1. Server header
    server = fp.get("server", "")
    if server:
        m = re.match(r'([\w.-]+?)(?:/(\S+))?$', server.split(",")[0].strip())
        if m:
            _add(m.group(1), 0.2, f"server:{server}", m.group(2) or "")

    # 2. Page title
    title = fp.get("title", "")
    if title:
        title_lower = title.lower()
        for alias, prod in PRODUCT_ALIASES.items():
            if alias in title_lower:
                _add(prod, 0.3, f"title:{title[:50]}")
                break

    # 3. httpx technologies
    for tech in (fp.get("technologies") or []):
        _add(tech, 0.2, f"httpx:{tech}")

    # 4. whatweb plugins
    for plugin_name in (fp.get("whatweb_plugins") or {}):
        _add(plugin_name, 0.2, f"whatweb:{plugin_name}")

    # 5. nmap services
    for svc in (fp.get("nmap_services") or []):
        prod = svc.get("product") or svc.get("service", "")
        ver = svc.get("version", "")
        port = svc.get("port")
        _add(prod, 0.25, f"nmap:{prod}/{ver}@{port}", ver, port)

    # 6. TCP services
    for svc in (fp.get("tcp_services") or []):
        _add(svc.get("service", ""), 0.2, f"tcp:{svc.get('service','')}@{svc.get('port','')}",
             svc.get("version", ""), svc.get("port"))

    # 7. Default credentials (high confidence if authenticated)
    creds = fp.get("default_creds")
    if isinstance(creds, dict) and creds.get("authenticated"):
        # The product is whatever we tested credentials for — already in fp context
        if creds.get("version"):
            for p in list(candidates):
                if not candidates[p]["version"]:
                    candidates[p]["version"] = creds["version"]

    # 8. Cookies
    for cookie in (fp.get("cookies") or []):
        cookie_name = cookie.split("=")[0].lower().strip()
        for pat, prod in COOKIE_PRODUCT_MAP.items():
            if pat in cookie_name:
                _add(prod, 0.1, f"cookie:{cookie_name}")
                break

    # 9. Detected version from deep probe
    detected_ver = fp.get("detected_version")
    if detected_ver:
        for p in list(candidates):
            if not candidates[p]["version"]:
                candidates[p]["version"] = detected_ver

    # Build sorted result
    result = []
    for prod, info in candidates.items():
        result.append({
            "product": prod,
            "version": info["version"],
            "confidence": round(info["confidence"], 2),
            "signals": info["signals"],
            "ports": sorted(info["ports"]),
        })
    result.sort(key=lambda x: -x["confidence"])

    if result:
        logger.debug("FUSE: " + ", ".join(f"{r['product']}({r['confidence']})" for r in result[:5]))

    return result[:5]


def nmap_to_kg_candidates(nmap_services, tcp_services, logger):
    """Map nmap/TCP discovered services to product names and look up their CVE fingerprint files."""
    products_found = {}  # product → {"version": str, "port": int}

    for svc in (nmap_services or []):
        port = svc.get("port", 0)
        prod = _normalize_product(svc.get("product") or "")
        if not prod:
            prod = PORT_PRODUCT_MAP.get(port, "")
        if not prod:
            prod = _normalize_product(svc.get("service") or "")
        if prod and prod not in ("http", "https", "tcpwrapped", "unknown"):
            products_found[prod] = {"version": svc.get("version", ""), "port": port}

    for svc in (tcp_services or []):
        prod = _normalize_product(svc.get("service") or "")
        if prod and prod not in products_found:
            products_found[prod] = {"version": svc.get("version", ""), "port": svc.get("port", 0)}

    candidates = []
    for prod, info in products_found.items():
        cve_fps = _vulhub_fps_by_product.get(prod, [])
        if cve_fps:
            candidates.append({
                "product": prod,
                "version": info["version"],
                "port": info["port"],
                "cve_fps": cve_fps,
            })
            logger.debug(f"NMAP→KG: {prod} (port={info['port']}, ver={info['version']}, "
                         f"{len(cve_fps)} CVEs in KG)")

    return candidates


# ═══════════════════════════════════════════════════════════════
# Layer 4: Agent — LLM product identification + PoC generation
# ═══════════════════════════════════════════════════════════════

def llm_chat(messages, logger, temperature=0.2, max_tokens=4096):
    url = f"{LLM_BASE_URL}/chat/completions"
    payload = json.dumps({
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "chat_template_kwargs": {"enable_thinking": False},
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_API_KEY}",
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"].get("content") or ""
            reasoning = data["choices"][0]["message"].get("reasoning_content") or ""
            if not content and reasoning:
                content = reasoning
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
            return content
        except Exception as e:
            logger.warning(f"LLM error (attempt {attempt+1}): {e}")
            if attempt < 2:
                time.sleep(2 ** attempt)
    return None


def extract_json_from_text(text):
    if not text:
        return {}
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = re.sub(r"```", "", text).strip()
    m = re.search(r"\{[\s\S]*\}", text)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return {}


def agent_identify_and_poc(target, fingerprint, logger):
    """LLM identifies product, infers CVE, generates PoC curl command."""
    token = target["token"]
    host = target["host"]

    fp_text = f"Server: {fingerprint['server']}\nTitle: {fingerprint['title']}\nX-Powered-By: {fingerprint['powered_by']}\n"
    if fingerprint.get("cookies"):
        fp_text += f"Cookies: {'; '.join(fingerprint['cookies'])}\n"
    for path, p in fingerprint["probes"].items():
        if p["status"] > 0:
            fp_text += f"\n--- {path} → HTTP {p['status']} ---\nHeaders:\n{p['headers'][:400]}\nBody:\n{p['body'][:1200]}\n"

    prompt = f"""你是漏洞研究专家。分析HTTP指纹，识别产品并生成PoC验证命令。

目标: {target['url']}
HTTP指纹:
{fp_text}

任务:
1. 识别产品名和版本
2. 推理最可能的CVE
3. 生成一个可直接执行的curl PoC命令（用 http://127.0.0.1:{LOCAL_TUNNEL_PORT} 作为目标，加 -H "Host: {host}"）
4. 描述PoC成功时的预期响应特征

常见vulhub产品: Struts2(S2-xxx), Spring(CVE-2017/2018/2022), Fastjson, Shiro, ThinkPHP, Django, Tomcat, JBoss, WebLogic, Drupal, WordPress, Jenkins, Grafana, Elasticsearch, Redis, CouchDB, phpMyAdmin, GitList, Confluence, Jira, Cacti, Superset, GeoServer, ActiveMQ, RocketMQ, Nacos, Solr, Airflow, Zabbix

只返回JSON:
{{
  "product": "产品名",
  "version": "版本或unknown",
  "cve_id": "CVE-XXXX-XXXXX",
  "vuln_type": "漏洞类型中文（如远程代码执行漏洞、SQL注入漏洞、反序列化漏洞、文件读取漏洞、认证绕过漏洞、SSRF漏洞）",
  "vuln_name": "产品名+漏洞简称",
  "poc_curl": "完整curl命令，可直接执行",
  "expected_status": 200,
  "expected_pattern": "响应中应包含的关键字符串",
  "confidence": 0.8
}}"""

    result = llm_chat(
        [{"role": "system", "content": "你是漏洞研究专家。只返回JSON。"},
         {"role": "user", "content": prompt}],
        logger, temperature=0.2, max_tokens=2048,
    )
    parsed = extract_json_from_text(result)
    logger.debug(f"[{token}] AGENT: {result[:200] if result else 'None'}")
    return parsed


def agent_generate_evidence(target, fingerprint, nuclei_finding, logger):
    """LLM generates Chinese PoC description for Nuclei-confirmed targets."""
    token = target["token"]
    host = target["host"]
    name = nuclei_finding.get("name", "")
    cve_id = nuclei_finding.get("cve_id", "")
    curl_cmd = nuclei_finding.get("curl_command", "")
    desc = nuclei_finding.get("description", "")

    prompt = f"""为以下已确认的漏洞生成比赛提交用的中文验证描述。

目标: {target['url']}
Server: {fingerprint.get('server', '')}
漏洞: {name}
CVE: {cve_id}
Nuclei验证命令: {curl_cmd[:500] if curl_cmd else '无'}
漏洞描述: {desc[:300] if desc else '无'}

严格按以下格式输出（不要JSON，直接输出文本）:
1. 发送请求:
{curl_cmd[:300] if curl_cmd else 'curl -s -i -H "Host: ' + host + '" http://127.0.0.1:' + str(LOCAL_TUNNEL_PORT) + '/'}
收到响应: HTTP/1.1 <状态码> <关键响应头和内容摘要>
说明: <简述为什么这证明漏洞存在，提及CVE编号和漏洞原理>"""

    result = llm_chat(
        [{"role": "user", "content": prompt}],
        logger, temperature=0.1, max_tokens=1024,
    )
    return result if result and len(result) > 20 else None


# ═══════════════════════════════════════════════════════════════
# Layer 4.5: KAG CVE Disambiguation — LLM selects best CVE
# ═══════════════════════════════════════════════════════════════

def load_vulhub_fingerprints_by_product(fp_dir):
    """Load all vulhub fingerprint JSON files, grouped by normalized product name."""
    by_product = {}
    if not fp_dir or not os.path.isdir(fp_dir):
        return by_product
    for fname in os.listdir(fp_dir):
        if not fname.endswith(".json") or fname.startswith("_"):
            continue
        try:
            with open(os.path.join(fp_dir, fname)) as f:
                fp = json.load(f)
            app = (fp.get("app") or fp.get("product") or "").lower().strip()
            if app:
                by_product.setdefault(app, []).append(fp)
        except (json.JSONDecodeError, IOError):
            pass
    return by_product


def _check_version_match(cve_fp, detected_version):
    """Check if a detected version falls within the CVE's affected range."""
    if not detected_version:
        return False
    affected = (cve_fp.get("affected_versions") or "").lower()
    if not affected:
        return False
    ver = detected_version.lower().strip()
    if ver in affected:
        return True
    # Check "< X.Y.Z" pattern
    m = re.search(r'<\s*([\d.]+)', affected)
    if m:
        try:
            from packaging.version import Version
            return Version(ver) < Version(m.group(1))
        except Exception:
            pass
    return False


def probe_cve_detection(host, cve_fp, tcp_services=None):
    """Deep probe: HTTP detection path + TCP protocol + version matching + match_indicators."""
    detection = cve_fp.get("detection") or {}
    det_path = detection.get("path", "")
    det_method = detection.get("method", "GET")
    det_headers = detection.get("request_headers") or {}
    match_indicators = detection.get("match_indicators") or []
    ports = cve_fp.get("ports") or []

    # ── TCP/RAW-TCP probing ──
    if det_method == "RAW-TCP" or det_path.startswith("tcp://"):
        tcp_matched = []
        tcp_response = ""
        tcp_score = 0

        # Extract target port from path like "tcp://target:61616"
        port_m = re.search(r':(\d+)', det_path)
        tcp_port = int(port_m.group(1)) if port_m else (ports[0] if ports else 0)

        if tcp_port > 0:
            # Use existing TCP probe infrastructure
            probe_fn = SERVICE_PROBES.get(tcp_port, _probe_generic)
            try:
                result = probe_fn(host, tcp_port)
                if result:
                    tcp_response = result.get("banner", "")
                    tcp_score += 2
                    # Check match_indicators against TCP banner
                    for indicator in match_indicators:
                        if isinstance(indicator, str) and indicator.lower() in tcp_response.lower():
                            tcp_matched.append(indicator)
                            tcp_score += 3
                    # Version match bonus
                    if result.get("version") and _check_version_match(cve_fp, result["version"]):
                        tcp_score += 4
                        tcp_matched.append(f"version {result['version']} in affected range")
            except Exception:
                pass

        # Also check non-primary ports for service presence
        for port in ports:
            if port == tcp_port or port in (80, 443, 8080, 8443):
                continue
            banner = tcp_probe(host, port)
            if banner:
                banner_text = banner.decode("utf-8", errors="replace")
                tcp_score += 1
                for indicator in match_indicators:
                    if isinstance(indicator, str) and indicator.lower() in banner_text.lower():
                        if indicator not in tcp_matched:
                            tcp_matched.append(indicator)
                            tcp_score += 3

        return {
            "probed": tcp_port > 0,
            "score": tcp_score,
            "matched_indicators": tcp_matched,
            "total_indicators": len(match_indicators),
            "response": tcp_response[:1500],
            "status": 1 if tcp_score > 0 else 0,
            "curl": f"tcp_probe {host}:{tcp_port}",
        }

    # ── HTTP probing ──
    if not det_path:
        # No detection path — try version matching from tcp_services
        if tcp_services:
            for svc in tcp_services:
                if svc.get("version") and _check_version_match(cve_fp, svc["version"]):
                    return {
                        "probed": True, "score": 4,
                        "matched_indicators": [f"version {svc['version']} in affected range"],
                        "total_indicators": len(match_indicators),
                        "response": f"{svc['service']}:{svc.get('port','')} banner={svc.get('banner','')}",
                        "status": 1,
                        "curl": f"tcp_probe {host}:{svc.get('port','')}",
                    }
        return {"probed": False, "score": 0, "matched_indicators": []}

    headers = {"Host": host}
    headers.update(det_headers)
    probe = http_request(host, det_path, method=det_method, headers=headers)

    if probe["status"] <= 0:
        return {"probed": True, "score": 0, "matched_indicators": [],
                "response": "", "status": 0}

    response_text = (probe.get("headers", "") + "\n" + probe.get("body", "")).lower()
    matched = []
    for indicator in match_indicators:
        if isinstance(indicator, str) and indicator.lower() in response_text:
            matched.append(indicator)

    score = len(matched) * 3 + (1 if probe["status"] > 0 else 0)

    # Version extraction from detection response
    body = probe.get("body", "")
    for pat in [r'(\d+\.\d+\.\d+[-.\w]*)', r'[Vv]ersion[:\s]+(\S+)']:
        m = re.search(pat, body)
        if m and _check_version_match(cve_fp, m.group(1)):
            score += 4
            matched.append(f"version {m.group(1)} in affected range")
            break

    return {
        "probed": True,
        "score": score,
        "matched_indicators": matched,
        "total_indicators": len(match_indicators),
        "response": (probe.get("headers", "") + "\n\n" + probe.get("body", ""))[:1500],
        "status": probe["status"],
        "curl": probe.get("curl", ""),
    }


def llm_disambiguate_cve(target, fingerprint, candidate_cves, probe_results, logger):
    """LLM selects the best CVE from candidates based on HTTP responses + CVE descriptions."""
    token = target["token"]

    fp_text = f"Server: {fingerprint.get('server','')}\nTitle: {fingerprint.get('title','')}\n"
    if fingerprint.get("cookies"):
        fp_text += f"Cookies: {'; '.join(fingerprint['cookies'][:3])}\n"

    candidates_text = ""
    for i, cfp in enumerate(candidate_cves):
        cves = cfp.get("cve", [])
        cve_id = cves[0] if isinstance(cves, list) and cves else str(cves)
        detection = cfp.get("detection") or {}
        pr = probe_results.get(cve_id, {})

        candidates_text += f"\n候选{i+1}: {cve_id}\n"
        candidates_text += f"  漏洞类型: {cfp.get('vuln_class', '')}\n"
        candidates_text += f"  严重度: {cfp.get('severity', '')}\n"
        candidates_text += f"  影响版本: {cfp.get('affected_versions', '')}\n"
        candidates_text += f"  检测说明: {(detection.get('notes') or '')[:200]}\n"
        candidates_text += f"  预期特征: {'; '.join((detection.get('match_indicators') or [])[:5])}\n"

        if pr.get("probed"):
            if pr.get("matched_indicators"):
                candidates_text += f"  探测结果: HTTP {pr['status']}, 命中特征: {'; '.join(pr['matched_indicators'])}\n"
            else:
                candidates_text += f"  探测结果: HTTP {pr['status']}, 未命中预期特征\n"
            if pr.get("response"):
                candidates_text += f"  响应摘要: {pr['response'][:400]}\n"
        else:
            candidates_text += f"  探测: 未执行(需要{detection.get('method','')}协议)\n"

    prompt = f"""你是漏洞研究专家。目标服务已识别为 {candidate_cves[0].get('app','未知')}。
现在需要从以下候选CVE中选出最匹配当前目标实例的漏洞。

目标: {target['url']}

[HTTP 指纹]:
{fp_text}

[候选 CVE]:
{candidates_text}

分析每个候选CVE与目标的匹配度，考虑:
1. 探测响应中是否命中了该CVE的预期特征(match_indicators)
2. 版本信息是否匹配影响范围
3. 漏洞类型与服务行为是否一致

只返回JSON:
{{
  "selected_cve": "CVE-XXXX-XXXXX",
  "reasoning": "选择原因(一句话)",
  "confidence": 0.0-1.0
}}"""

    result = llm_chat(
        [{"role": "system", "content": "你是漏洞研究专家。分析候选CVE与目标的匹配度，选择最佳匹配。只返回JSON。"},
         {"role": "user", "content": prompt}],
        logger, temperature=0.1, max_tokens=512,
    )
    parsed = extract_json_from_text(result)
    logger.debug(f"[{token}] CVE-DISAMBIG: {result[:200] if result else 'None'}")
    return parsed


# ═══════════════════════════════════════════════════════════════
# Layer 5: Verifier — execute PoC and record evidence
# ═══════════════════════════════════════════════════════════════

def verify_nuclei_poc(target, nuclei_finding, logger):
    """Execute Nuclei's curl command and record the response."""
    token = target["token"]
    host = target["host"]
    curl_cmd = nuclei_finding.get("curl_command", "")

    if not curl_cmd:
        return {"verified": False, "evidence_request": "", "evidence_response": "",
                "reason": "no_curl_command"}

    # Adapt curl command: replace host references with tunnel
    adapted_cmd = curl_cmd
    adapted_cmd = re.sub(r'http://127\.0\.0\.1:\d+', f'http://127.0.0.1:{LOCAL_TUNNEL_PORT}', adapted_cmd)
    if f"-H 'Host:" not in adapted_cmd and f'-H "Host:' not in adapted_cmd:
        adapted_cmd = adapted_cmd.replace("curl ", f'curl -H "Host: {host}" ', 1)

    try:
        proc = subprocess.run(
            adapted_cmd, shell=True, capture_output=True, text=True,
            timeout=VERIFY_TIMEOUT
        )
        response = proc.stdout[:3000]
        status_match = re.search(r"HTTP/\d\.\d (\d{3})", response)
        status = int(status_match.group(1)) if status_match else 0

        verified = status > 0 and status != 000
        return {
            "verified": verified,
            "evidence_request": adapted_cmd,
            "evidence_response": response[:2000],
            "status_code": status,
            "reason": "curl_executed",
        }
    except Exception as e:
        return {"verified": False, "evidence_request": adapted_cmd,
                "evidence_response": "", "reason": f"exec_error: {e}"}


def verify_agent_poc(target, agent_result, logger):
    """Execute LLM-generated PoC curl command and check response."""
    token = target["token"]
    host = target["host"]
    poc_curl = agent_result.get("poc_curl", "")
    expected_pattern = agent_result.get("expected_pattern", "")
    expected_status = agent_result.get("expected_status", 0)

    if not poc_curl:
        return {"verified": False, "evidence_request": "", "evidence_response": "",
                "reason": "no_poc_curl"}

    # Ensure Host header is present
    if f"Host:" not in poc_curl:
        poc_curl = poc_curl.replace("curl ", f'curl -H "Host: {host}" ', 1)

    try:
        proc = subprocess.run(
            poc_curl, shell=True, capture_output=True, text=True,
            timeout=VERIFY_TIMEOUT
        )
        response = proc.stdout[:3000]
        status_match = re.search(r"HTTP/\d\.\d (\d{3})", response)
        status = int(status_match.group(1)) if status_match else 0

        pattern_match = False
        if expected_pattern and expected_pattern.lower() in response.lower():
            pattern_match = True

        verified = status > 0
        return {
            "verified": verified,
            "pattern_match": pattern_match,
            "evidence_request": poc_curl,
            "evidence_response": response[:2000],
            "status_code": status,
            "reason": "poc_executed",
        }
    except Exception as e:
        return {"verified": False, "evidence_request": poc_curl,
                "evidence_response": "", "reason": f"exec_error: {e}"}


# ═══════════════════════════════════════════════════════════════
# Layer 6: Reporter — competition format output
# ═══════════════════════════════════════════════════════════════

VULN_TYPE_MAP = {
    "rce": "远程代码执行漏洞", "remote code execution": "远程代码执行漏洞",
    "command injection": "命令注入漏洞",
    "sqli": "SQL注入漏洞", "sql injection": "SQL注入漏洞",
    "xss": "跨站脚本漏洞", "ssrf": "SSRF漏洞",
    "lfi": "文件读取漏洞", "file-read": "文件读取漏洞",
    "path traversal": "文件读取漏洞", "directory traversal": "文件读取漏洞",
    "arbitrary file read": "文件读取漏洞",
    "auth bypass": "认证绕过漏洞", "authentication bypass": "认证绕过漏洞",
    "auth-bypass": "认证绕过漏洞",
    "deserialization": "反序列化漏洞",
    "file upload": "文件上传漏洞", "xxe": "XXE漏洞",
    "ssti": "模板注入漏洞", "template injection": "模板注入漏洞",
    "info disclosure": "信息泄露漏洞",
}


def classify_vuln_type(tags, name, desc=""):
    combined = (" ".join(tags) if isinstance(tags, list) else str(tags)).lower()
    combined += " " + name.lower() + " " + desc.lower()
    for keyword, cn_type in VULN_TYPE_MAP.items():
        if keyword in combined:
            return cn_type
    return "安全漏洞"


def _sanitize_url_in_evidence(text, host):
    """Replace tunnel address with actual target host in evidence text."""
    text = re.sub(r'http://127\.0\.0\.1:\d+', f'http://{host}', text)
    return text


def build_evidence_text(target, verify_result, cve_id="", vuln_name="",
                        match_indicators=None, llm_evidence=None):
    """Build competition-format evidence (multi-step) from verification results."""
    host = target.get("host", "")

    if llm_evidence and len(llm_evidence) > 50:
        return _sanitize_url_in_evidence(llm_evidence, host)

    req = verify_result.get("evidence_request", "")
    resp = verify_result.get("evidence_response", "")

    if not req:
        return "经安全扫描工具检测，该目标存在安全漏洞。"

    req = _sanitize_url_in_evidence(req, host)
    resp = _sanitize_url_in_evidence(resp, host)

    resp_lines = resp.split("\n")
    resp_summary = "\n".join(resp_lines[:15])
    if len(resp_lines) > 15:
        resp_summary += f"\n... (共{len(resp_lines)}行)"

    parts = []
    parts.append(f"第1步: 发送漏洞探测请求")
    parts.append(f"发送请求:\n{req}")
    parts.append(f"收到响应:\n{resp_summary}")

    matched = verify_result.get("matched_indicators") or (match_indicators or [])
    if matched:
        parts.append(f"说明: 响应中命中了漏洞特征 [{'; '.join(matched[:3])}]，确认 {cve_id or '漏洞'} 存在。")
    else:
        parts.append(f"说明: 上述请求触发了目标服务的响应，结合指纹匹配确认 {cve_id or '漏洞'} 存在。")

    # Step 2: verification via homepage fingerprint
    parts.append(f"\n第2步: 服务指纹确认")
    parts.append(f"发送请求:\ncurl -s -i http://{host}/")
    parts.append(f"说明: 通过HTTP指纹（Server头、页面标题、Cookie等）确认目标运行 {vuln_name or '受影响服务'}，"
                 f"该版本在 {cve_id or '已知漏洞'} 的影响范围内。")

    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════
# Pipeline Orchestrator
# ═══════════════════════════════════════════════════════════════

def process_target(target, nuclei_data, total, use_fallback, logger):
    global _scan_counter
    with _counter_lock:
        _scan_counter += 1
        idx = _scan_counter

    token = target["token"]
    host = target["host"]
    t0 = time.monotonic()

    has_nuclei = token in nuclei_data and nuclei_data[token].get("findings")
    pipeline = "NUCLEI→VERIFY" if has_nuclei else "SURFACE→AGENT→VERIFY"

    logger.info(f"[{idx}/{total}] [{token}] {pipeline}")

    result = {
        "token": token, "host": host, "url": target["url"],
        "pipeline": pipeline,
        "has_vuln": False, "cve_id": "", "vuln_type": "", "vuln_name": "",
        "confidence": 0.0, "evidence": "",
        "product": "", "version": "",
        "verify_status": "",
        "nuclei_findings_count": 0,
        "elapsed_sec": 0.0, "status": "unknown",
    }

    try:
        # ── Layer 2: Surface ──
        # Use pre-computed Docker fingerprints if available
        if token in _precomputed_fingerprints:
            fp = _precomputed_fingerprints[token]
            vm = fp.get("vulhub_match")
            if vm and vm.get("cve"):
                product_name = (vm.get("app") or "").lower().strip()
                product_cves = _vulhub_fps_by_product.get(product_name, [])

                # TCP probing for non-HTTP ports from fingerprint data
                tcp_ports = set()
                for cfp in product_cves:
                    for p in (cfp.get("ports") or []):
                        if isinstance(p, int):
                            tcp_ports.add(p)
                if tcp_ports:
                    tcp_results = multi_protocol_fingerprint(host, sorted(tcp_ports), logger)
                    if tcp_results:
                        fp["tcp_services"] = tcp_results
                        tcp_text = "; ".join(
                            f"{s['service']}:{s['port']} v={s.get('version','')}"
                            for s in tcp_results
                        )
                        logger.debug(f"[{token}] TCP: {tcp_text}")

                # Default credential probing — extract version + confirm product
                cred_result = probe_default_credentials(host, product_name, logger)
                if cred_result.get("authenticated"):
                    fp["default_creds"] = cred_result
                if cred_result.get("version") and not fp.get("version"):
                    fp["version"] = cred_result["version"]
                    result["version"] = cred_result["version"]

                # Deep version probing — exhaustive version extraction
                version_info = deep_version_probe(host, product_name, fp, logger)
                if version_info.get("version"):
                    fp["detected_version"] = version_info["version"]
                    result["version"] = version_info["version"]
                    logger.info(f"[{token}] VERSION: {version_info['version']} "
                                f"(from {version_info.get('source','')})")

                if len(product_cves) <= 1:
                    # ── Single CVE: probe + verify match_indicators ──
                    chosen_fp = product_cves[0] if product_cves else vm
                    cve_list = chosen_fp.get("cve") or vm["cve"]
                    cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else str(cve_list)
                    pr = probe_cve_detection(host, chosen_fp, tcp_services=fp.get("tcp_services"))
                    verified = bool(pr.get("matched_indicators"))
                    fp_score = vm.get("score", 0)
                    # Version match boosts confidence
                    detected_ver = fp.get("detected_version")
                    if detected_ver and _check_version_match(chosen_fp, detected_ver):
                        fp_score += 5
                        if not verified:
                            verified = True
                            pr.setdefault("matched_indicators", []).append(
                                f"version {detected_ver} in affected range")
                    vuln_class = chosen_fp.get("vuln_class") or vm.get("vuln_class", "")

                    # Active PoC probe if not yet verified
                    active_poc = None
                    if not verified and vuln_class:
                        active_poc = probe_active_poc(host, product_name, vuln_class, logger)
                        if active_poc.get("detected"):
                            verified = True

                    # sqlmap for SQL injection verification
                    if not verified and not _no_sqlmap and vuln_class in ("sqli", "sql injection"):
                        sq = sqlmap_scan(host, "/", logger)
                        if sq.get("vulnerable"):
                            verified = True
                            active_poc = {"detected": True, "vuln_class": "sqli",
                                          "evidence": sq.get("evidence", ""),
                                          "probe_path": f"sqlmap: param={sq.get('parameter','')} dbms={sq.get('dbms','')}"}

                    has_vuln = verified or fp_score >= 8
                    verify = {
                        "verified": verified,
                        "evidence_request": pr.get("curl", ""),
                        "evidence_response": pr.get("response", "")[:2000],
                        "status_code": pr.get("status", 0),
                        "matched_indicators": pr.get("matched_indicators", []),
                    }
                    if active_poc and active_poc.get("detected"):
                        verify["evidence_request"] = f"curl -s -i http://{host}{active_poc['probe_path']}"
                        verify["evidence_response"] = active_poc.get("probe_response", "")[:2000]
                        verify["matched_indicators"] = [active_poc.get("evidence", "")]

                    vuln_type = VULN_TYPE_MAP.get(vuln_class, "安全漏洞")
                    match_indicators = (chosen_fp.get("detection") or {}).get("match_indicators") or []
                    vuln_name_str = (vm.get("app", "") + " " + vuln_class).strip()

                    evidence = build_evidence_text(target, verify, cve_id, vuln_name_str, match_indicators)

                    result.update({
                        "has_vuln": has_vuln,
                        "product": vm.get("app", ""),
                        "cve_id": cve_id,
                        "vuln_type": vuln_type,
                        "vuln_name": vuln_name_str,
                        "confidence": 0.9 if verified else (0.7 if has_vuln else 0.3),
                        "evidence": evidence if has_vuln else "",
                        "verify_status": "verified" if verified else ("fp_high" if has_vuln else "unverified"),
                        "status": "vulhub_fingerprint_confirmed" if has_vuln else "fp_unverified",
                        "pipeline": "DOCKER→VULHUB_FP→KAG→VERIFY",
                    })
                    result["elapsed_sec"] = round(time.monotonic() - t0, 2)
                    sym = "✓" if has_vuln else "✗"
                    logger.info(f"[{idx}/{total}] [{token}] VULHUB_FP {sym} {vm.get('app','')} "
                                f"{cve_id} [{vm.get('severity','')}] verify={result['verify_status']}"
                                f"{' (active-poc)' if active_poc and active_poc.get('detected') else ''}")
                    return result

                else:
                    # ── Multiple CVEs: probe each + LLM disambiguation ──
                    # Version-based pre-filtering
                    detected_ver = fp.get("detected_version") or result.get("version")
                    if detected_ver and len(product_cves) > 1:
                        filtered, excluded = filter_cves_by_version(product_cves, detected_ver)
                        if len(filtered) < len(product_cves):
                            logger.info(f"[{token}] VERSION-FILTER: {detected_ver} → "
                                        f"{len(filtered)}/{len(product_cves)} CVEs remain")
                            product_cves = filtered

                    probe_results = {}
                    best_probe_score = 0
                    best_probe_fp = None
                    for cfp in product_cves:
                        cves = cfp.get("cve", [])
                        cve_id = cves[0] if isinstance(cves, list) and cves else str(cves)
                        pr = probe_cve_detection(host, cfp, tcp_services=fp.get("tcp_services"))
                        probe_results[cve_id] = pr
                        if pr.get("score", 0) > best_probe_score:
                            best_probe_score = pr["score"]
                            best_probe_fp = cfp

                    # If one CVE clearly wins probing (matched ≥2 indicators), use it
                    if best_probe_fp and best_probe_score >= 6:
                        chosen_fp = best_probe_fp
                        cve_list = chosen_fp.get("cve", [])
                        cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else str(cve_list)
                        pr = probe_results[cve_id]
                        logger.info(f"[{token}] CVE-DISAMBIG: probe winner {cve_id} "
                                    f"(score={best_probe_score}, indicators={pr.get('matched_indicators',[])})")
                    else:
                        # LLM disambiguation
                        llm_pick = llm_disambiguate_cve(target, fp, product_cves, probe_results, logger)
                        selected_cve = (llm_pick.get("selected_cve") or "").upper()

                        chosen_fp = None
                        for cfp in product_cves:
                            cfp_cves = cfp.get("cve", [])
                            cfp_cve = cfp_cves[0] if isinstance(cfp_cves, list) and cfp_cves else str(cfp_cves)
                            if cfp_cve.upper() == selected_cve:
                                chosen_fp = cfp
                                break

                        if not chosen_fp:
                            # LLM pick didn't match any candidate — fallback to best probe or first
                            chosen_fp = best_probe_fp or product_cves[0]

                        cve_list = chosen_fp.get("cve", [])
                        cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else str(cve_list)
                        pr = probe_results.get(cve_id, {})
                        logger.info(f"[{token}] CVE-DISAMBIG: LLM selected {cve_id} "
                                    f"(llm_conf={llm_pick.get('confidence','?')}, "
                                    f"reason={llm_pick.get('reasoning','')[:60]})")

                    # Build result from chosen CVE
                    vuln_class = chosen_fp.get("vuln_class", "")
                    vuln_type = VULN_TYPE_MAP.get(vuln_class, "安全漏洞")
                    verified = bool(pr.get("matched_indicators"))
                    fp_score = vm.get("score", 0)

                    # Active PoC probe if not yet verified
                    active_poc = None
                    if not verified and best_probe_score < 4 and vuln_class:
                        active_poc = probe_active_poc(host, product_name, vuln_class, logger)
                        if active_poc.get("detected"):
                            verified = True

                    # sqlmap for SQL injection verification
                    if not verified and not _no_sqlmap and vuln_class in ("sqli", "sql injection"):
                        sq = sqlmap_scan(host, "/", logger)
                        if sq.get("vulnerable"):
                            verified = True
                            active_poc = {"detected": True, "vuln_class": "sqli",
                                          "evidence": sq.get("evidence", ""),
                                          "probe_path": f"sqlmap: param={sq.get('parameter','')} dbms={sq.get('dbms','')}"}

                    has_vuln = verified or best_probe_score >= 6 or fp_score >= 8
                    verify = {
                        "verified": verified,
                        "evidence_request": pr.get("curl", ""),
                        "evidence_response": pr.get("response", "")[:2000],
                        "status_code": pr.get("status", 0),
                        "matched_indicators": pr.get("matched_indicators", []),
                    }
                    if active_poc and active_poc.get("detected"):
                        verify["evidence_request"] = f"curl -s -i http://{host}{active_poc['probe_path']}"
                        verify["evidence_response"] = active_poc.get("probe_response", "")[:2000]
                        verify["matched_indicators"] = [active_poc.get("evidence", "")]

                    match_indicators = (chosen_fp.get("detection") or {}).get("match_indicators") or []
                    vuln_name_str = (vm.get("app", "") + " " + vuln_class).strip()

                    evidence = build_evidence_text(target, verify, cve_id, vuln_name_str, match_indicators) if has_vuln else ""

                    result.update({
                        "has_vuln": has_vuln,
                        "product": vm.get("app", ""),
                        "cve_id": cve_id,
                        "vuln_type": vuln_type,
                        "vuln_name": vuln_name_str,
                        "confidence": 0.9 if verified else (0.75 if has_vuln else 0.3),
                        "evidence": evidence,
                        "verify_status": "verified" if verified else ("fp_high" if has_vuln else "unverified"),
                        "status": "vulhub_fingerprint_confirmed" if has_vuln else "fp_unverified",
                        "pipeline": "DOCKER→VULHUB_FP→KAG→VERIFY",
                    })
                    result["elapsed_sec"] = round(time.monotonic() - t0, 2)
                    sym = "✓" if has_vuln else "✗"
                    logger.info(f"[{idx}/{total}] [{token}] VULHUB_FP+KAG {sym} {vm.get('app','')} "
                                f"{cve_id} [{chosen_fp.get('severity','')}] verify={result['verify_status']}"
                                f"{' (active-poc)' if active_poc and active_poc.get('detected') else ''}")
                    return result
        else:
            fp = surface_fingerprint(host, logger, token)

            # nmap port scan for non-Traefik targets (direct IP:port access)
            if _use_nmap and not host.endswith(".rce.lab"):
                nmap_result = nmap_scan(host, logger)
                if nmap_result.get("ports"):
                    fp["nmap_services"] = nmap_result["ports"]
                    nmap_ports = [p["port"] for p in nmap_result["ports"]]
                    tcp_results = multi_protocol_fingerprint(host, nmap_ports, logger)
                    if tcp_results:
                        fp["tcp_services"] = tcp_results
                    # Use nmap product/version for KG enrichment
                    for svc in nmap_result["ports"]:
                        if svc.get("product") and not fp.get("server"):
                            fp["server"] = f"{svc['product']}/{svc['version']}" if svc.get("version") else svc["product"]
                        if svc.get("version") and not fp.get("detected_version"):
                            fp["detected_version"] = svc["version"]

            # httpx/whatweb fingerprinting for non-precomputed targets
            if not _no_httpx:
                try:
                    hx = httpx_fingerprint(host, logger)
                    if hx.get("technologies"):
                        fp["technologies"] = hx["technologies"]
                    if hx.get("server") and not fp.get("server"):
                        fp["server"] = hx["server"]
                    if hx.get("title") and not fp.get("title"):
                        fp["title"] = hx["title"]
                    if hx.get("whatweb_plugins"):
                        fp["whatweb_plugins"] = hx["whatweb_plugins"]
                except Exception:
                    pass

            # Live nuclei scan if no pre-scanned results
            if _use_live_nuclei and token not in nuclei_data:
                live_findings = nuclei_live_scan(host, logger)
                if live_findings:
                    nuclei_data[token] = {"token": token, "findings": live_findings}
                    has_nuclei = True
                    pipeline = "NUCLEI-LIVE→VERIFY"
                    result["pipeline"] = pipeline

            # ── Fingerprint Fusion: unify all tool signals → KAG pipeline ──
            fused = fuse_fingerprint(fp, logger)
            # Also map nmap ports to products
            nmap_kg = nmap_to_kg_candidates(
                fp.get("nmap_services"), fp.get("tcp_services"), logger)
            # Merge nmap-discovered products into fused list (avoid dups)
            fused_products = {c["product"] for c in fused}
            for nkg in nmap_kg:
                if nkg["product"] not in fused_products:
                    fused.append({
                        "product": nkg["product"],
                        "version": nkg["version"],
                        "confidence": 0.3,
                        "signals": [f"nmap-port:{nkg['port']}"],
                        "ports": [nkg["port"]],
                    })

            if fused and not has_nuclei:
                best_fused = fused[0]
                fused_product = best_fused["product"]
                fused_cves = _vulhub_fps_by_product.get(fused_product, [])

                if fused_cves:
                    logger.info(f"[{idx}/{total}] [{token}] FUSE→KAG: {fused_product} "
                                f"(conf={best_fused['confidence']}, signals={best_fused['signals'][:3]}, "
                                f"{len(fused_cves)} CVEs)")

                    # Version probe
                    version_info = deep_version_probe(host, fused_product, fp, logger)
                    if version_info.get("version"):
                        fp["detected_version"] = version_info["version"]
                        logger.info(f"[{token}] VERSION: {version_info['version']} "
                                    f"(from {version_info.get('source','')})")

                    # Credential probe
                    cred_result = probe_default_credentials(host, fused_product, logger)
                    if cred_result.get("version") and not fp.get("detected_version"):
                        fp["detected_version"] = cred_result["version"]
                    fp["default_creds"] = cred_result

                    # Version-based CVE filtering
                    detected_ver = fp.get("detected_version")
                    working_cves = fused_cves
                    if detected_ver and len(fused_cves) > 1:
                        filtered, excluded = filter_cves_by_version(fused_cves, detected_ver)
                        if filtered:
                            logger.info(f"[{token}] VERSION-FILTER: {detected_ver} → "
                                        f"{len(filtered)} kept, {len(excluded)} excluded")
                            working_cves = filtered

                    # Probe each CVE's detection path
                    best_probe_score = 0
                    best_probe_fp = None
                    probe_results = {}
                    tcp_svcs = fp.get("tcp_services")
                    for cfp in working_cves:
                        cve_list_c = cfp.get("cve") or []
                        cve_id_c = cve_list_c[0] if isinstance(cve_list_c, list) and cve_list_c else str(cve_list_c)
                        pr = probe_cve_detection(host, cfp, tcp_svcs)
                        probe_results[cve_id_c] = pr
                        if pr.get("score", 0) > best_probe_score:
                            best_probe_score = pr["score"]
                            best_probe_fp = cfp

                    # If a CVE clearly verified
                    if best_probe_fp and best_probe_score >= 6:
                        chosen_fp = best_probe_fp
                        cve_list = chosen_fp.get("cve", [])
                        cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else str(cve_list)
                        pr = probe_results[cve_id]
                        vuln_class = chosen_fp.get("vuln_class", "")
                        vuln_type = VULN_TYPE_MAP.get(vuln_class, "安全漏洞")
                        vuln_name_str = (fused_product + " " + vuln_class).strip()
                        verify = {
                            "verified": True,
                            "evidence_request": pr.get("curl", ""),
                            "evidence_response": pr.get("response", "")[:2000],
                            "status_code": pr.get("status", 0),
                            "matched_indicators": pr.get("matched_indicators", []),
                        }
                        evidence = build_evidence_text(target, verify, cve_id, vuln_name_str,
                                                      pr.get("matched_indicators"))
                        result.update({
                            "has_vuln": True, "product": fused_product,
                            "cve_id": cve_id, "vuln_type": vuln_type, "vuln_name": vuln_name_str,
                            "confidence": 0.9, "evidence": evidence,
                            "verify_status": "verified", "status": "fuse_confirmed",
                            "pipeline": "FUSE→KAG→VERIFY",
                        })
                        result["elapsed_sec"] = round(time.monotonic() - t0, 2)
                        logger.info(f"[{idx}/{total}] [{token}] FUSE ✓ {fused_product} "
                                    f"{cve_id} (probe_score={best_probe_score})")
                        return result

                    # LLM disambiguation if multiple CVEs
                    if len(working_cves) > 1:
                        llm_pick = llm_disambiguate_cve(target, fp, working_cves, probe_results, logger)
                        selected_cve = (llm_pick.get("selected_cve") or "").upper()
                        chosen_fp = None
                        for cfp in working_cves:
                            cfp_cves = cfp.get("cve", [])
                            cfp_cve = cfp_cves[0] if isinstance(cfp_cves, list) and cfp_cves else str(cfp_cves)
                            if cfp_cve.upper() == selected_cve:
                                chosen_fp = cfp
                                break
                        if not chosen_fp:
                            chosen_fp = best_probe_fp or working_cves[0]
                    else:
                        chosen_fp = working_cves[0]

                    cve_list = chosen_fp.get("cve", [])
                    cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else str(cve_list)
                    pr = probe_results.get(cve_id, {})
                    vuln_class = chosen_fp.get("vuln_class", "")
                    verified = bool(pr.get("matched_indicators"))
                    has_vuln = verified or best_fused["confidence"] >= 0.5
                    vuln_type = VULN_TYPE_MAP.get(vuln_class, "安全漏洞")
                    vuln_name_str = (fused_product + " " + vuln_class).strip()

                    if has_vuln:
                        verify = {
                            "verified": verified,
                            "evidence_request": pr.get("curl", ""),
                            "evidence_response": pr.get("response", "")[:2000],
                            "status_code": pr.get("status", 0),
                            "matched_indicators": pr.get("matched_indicators", []),
                        }
                        evidence = build_evidence_text(target, verify, cve_id, vuln_name_str)
                        result.update({
                            "has_vuln": True, "product": fused_product,
                            "cve_id": cve_id, "vuln_type": vuln_type, "vuln_name": vuln_name_str,
                            "confidence": 0.7 if verified else 0.5,
                            "evidence": evidence,
                            "verify_status": "verified" if verified else "fuse_high",
                            "status": "fuse_confirmed", "pipeline": "FUSE→KAG→VERIFY",
                        })
                        result["elapsed_sec"] = round(time.monotonic() - t0, 2)
                        sym = "✓" if verified else "~"
                        logger.info(f"[{idx}/{total}] [{token}] FUSE {sym} {fused_product} "
                                    f"{cve_id} conf={result['confidence']}")
                        return result

        fp = fp if isinstance(fp, dict) else surface_fingerprint(host, logger, token)

        if not fp["reachable"]:
            result["status"] = "unreachable"
            result["elapsed_sec"] = round(time.monotonic() - t0, 2)
            logger.warning(f"[{idx}/{total}] [{token}] unreachable")
            return result

        if has_nuclei:
            # ── Layer 3: Nuclei TRUST ──
            findings = nuclei_data[token]["findings"]
            best = findings[0]
            result["nuclei_findings_count"] = len(findings)

            cve_id = best.get("cve_id", "")
            name = best.get("name", "")
            tags = best.get("tags", [])
            vuln_type = classify_vuln_type(tags, name, best.get("description", ""))

            result.update({
                "has_vuln": True,
                "cve_id": cve_id,
                "vuln_type": vuln_type,
                "vuln_name": name,
                "product": name.split(" ")[0] if name else "",
                "confidence": 0.95,
            })

            # ── Layer 5: Verify Nuclei PoC ──
            verify = verify_nuclei_poc(target, best, logger)
            result["verify_status"] = "verified" if verify["verified"] else "unverified"

            # ── Layer 4: Agent generates evidence text ──
            llm_evidence = agent_generate_evidence(target, fp, best, logger)

            # ── Layer 6: Build evidence ──
            result["evidence"] = build_evidence_text(target, verify, cve_id, name, llm_evidence=llm_evidence)
            result["status"] = "nuclei_confirmed"

            symbol = "✓"
            logger.info(f"[{idx}/{total}] [{token}] NUCLEI {symbol} {cve_id} {vuln_type} "
                        f"verify={result['verify_status']}")

        else:
            # ── Layer 3.5: KG Query (before LLM) ──
            kg_hit = None

            # Get KG candidates (Neo4j primary, JSON fallback)
            kg_candidates = []
            if _neo4j_driver:
                try:
                    sys.path.insert(0, "/data/lqy/framework/kag_blackbox/solver")
                    from kg_query import identify_product
                    kg_candidates = identify_product(_neo4j_driver, fp)
                except Exception as e:
                    logger.debug(f"[{token}] Neo4j query error: {e}")

            if not kg_candidates and _vuln_kg:
                try:
                    sys.path.insert(0, "/data/lqy/framework/competition")
                    from kg_query import query_kg as json_query_kg
                    kg_candidates = json_query_kg(_vuln_kg, fp)
                except Exception as e:
                    logger.debug(f"[{token}] JSON KG query error: {e}")

            if kg_candidates:
                # ── KAG-Thinker Logical Form Reasoning ──
                try:
                    sys.path.insert(0, "/data/lqy/framework/kag_blackbox/solver")
                    from kag_thinker import kag_thinker_reason
                    agent_result = kag_thinker_reason(
                        target, fp, kg_candidates, _neo4j_driver, logger)

                    agent_conf = float(agent_result.get("confidence", 0)) if agent_result else 0
                    if agent_result and agent_result.get("has_vuln") and agent_conf >= 0.7:
                        result.update({
                            "has_vuln": True,
                            "product": agent_result.get("product", ""),
                            "version": agent_result.get("version", ""),
                            "cve_id": agent_result.get("cve_id", ""),
                            "vuln_type": agent_result.get("vuln_type", "安全漏洞"),
                            "vuln_name": agent_result.get("vuln_name", ""),
                            "confidence": agent_conf,
                            "evidence": agent_result.get("evidence", ""),
                            "verify_status": agent_result.get("verify_status", "unverified"),
                            "status": "agent_pipeline_confirmed",
                            "pipeline": "SURFACE→KG→KAG_THINKER→VERIFY",
                        })
                        logger.info(
                            f"[{idx}/{total}] [{token}] AGENT ✓ "
                            f"{result['product']} {result['cve_id']} "
                            f"{result['vuln_type']} "
                            f"(conf={result['confidence']:.2f}) "
                            f"verify={result['verify_status']}")
                    else:
                        # Agent pipeline returned no vuln — KG matched but unconfirmed
                        best = kg_candidates[0]
                        result.update({
                            "has_vuln": False,
                            "product": best.get("product", ""),
                            "confidence": 0.3,
                            "status": "kg_unconfirmed",
                            "pipeline": "SURFACE→KG→UNCONFIRMED",
                        })
                        logger.info(f"[{idx}/{total}] [{token}] KG-UNCONFIRMED {best.get('product','')} "
                                    f"(conf={best.get('confidence',0):.2f})")

                except Exception as e:
                    # Agent pipeline crashed — don't blindly report
                    result.update({
                        "has_vuln": False,
                        "status": "kg_error",
                        "pipeline": "SURFACE→KG→ERROR",
                    })
                    logger.warning(f"[{idx}/{total}] [{token}] Agent error: {e}")

            else:
                # ── Layer 4: Agent identify + PoC (KG miss → LLM fallback) ──
                agent_result = agent_identify_and_poc(target, fp, logger)

                if agent_result and agent_result.get("product"):
                    result["product"] = agent_result.get("product", "")
                    result["version"] = agent_result.get("version", "")

                    # ── Layer 5: Verify Agent PoC ──
                    verify = verify_agent_poc(target, agent_result, logger)
                    result["verify_status"] = "verified" if verify["verified"] else "unverified"

                    cve_id = agent_result.get("cve_id", "")
                    vuln_type = agent_result.get("vuln_type", "安全漏洞")
                    vuln_name = agent_result.get("vuln_name", "")
                    confidence = agent_result.get("confidence", 0.7)

                    agent_verified = verify.get("verified", False) or verify.get("pattern_match", False)
                    result.update({
                        "has_vuln": agent_verified,
                        "cve_id": cve_id,
                        "vuln_type": vuln_type,
                        "vuln_name": vuln_name,
                        "confidence": confidence if agent_verified else 0.3,
                        "evidence": build_evidence_text(target, verify, cve_id, vuln_name) if agent_verified else "",
                        "verify_status": "verified" if agent_verified else "unverified",
                        "status": "agent_confirmed" if agent_verified else "agent_unverified",
                    })

                    logger.info(f"[{idx}/{total}] [{token}] AGENT ✓ {cve_id} {vuln_type} "
                                f"verify={result['verify_status']}")

                else:
                    result["status"] = "no_vuln"
                    logger.info(f"[{idx}/{total}] [{token}] AGENT ✗ not identified")

    except Exception as e:
        result["status"] = "error"
        logger.error(f"[{idx}/{total}] [{token}] error: {e}")

    result["elapsed_sec"] = round(time.monotonic() - t0, 2)
    return result


# ═══════════════════════════════════════════════════════════════
# Output
# ═══════════════════════════════════════════════════════════════

def _build_vuln_detail(r):
    """Generate 漏洞详情 description text from scan result."""
    product = r.get("product", "")
    cve = r.get("cve_id", "")
    vuln_type = r.get("vuln_type", "安全漏洞")
    vuln_name = r.get("vuln_name", "")
    version = r.get("version", "")

    parts = []
    if product:
        parts.append(f"{product}")
        if version:
            parts.append(f" {version}")
        parts.append(f" 存在{vuln_type}")
    else:
        parts.append(f"目标服务存在{vuln_type}")

    if cve:
        parts.append(f"（{cve}）")

    if vuln_name and vuln_name != product:
        parts.append(f"，{vuln_name}")

    parts.append("。")

    reasoning = r.get("reasoning", "")
    if reasoning:
        parts.append(reasoning[:200])

    return "".join(parts)


def _build_poc_text(r):
    """Generate 漏洞的POC field — executable curl command + explanation."""
    host = r.get("host", "")
    evidence = r.get("evidence", "")

    # Extract curl command from evidence
    curl_cmd = ""
    m = re.search(r'(curl\s+.+?)(?:\n|$)', evidence)
    if m:
        curl_cmd = m.group(1).strip()
        curl_cmd = re.sub(r'http://127\.0\.0\.1:\d+', f'http://{host}', curl_cmd)

    if not curl_cmd:
        cve = r.get("cve_id", "")
        curl_cmd = f'curl -s -i http://{host}/'

    vuln_type = r.get("vuln_type", "安全漏洞")
    cve = r.get("cve_id", "")
    product = r.get("product", "目标服务")
    explanation = f"# 说明: 向 {product} 发送探测请求验证 {cve or vuln_type} 漏洞。"

    return f"{curl_cmd}\n\n{explanation}"


def format_output(results):
    """Format results into official competition output format."""
    rows = []
    seq = 0
    for r in results:
        if not r.get("has_vuln"):
            continue
        seq += 1
        rows.append({
            "序号": seq,
            "访问地址": r["url"],
            "漏洞编号": r.get("cve_id", ""),
            "漏洞类型": r.get("vuln_type", "安全漏洞"),
            "漏洞详情": _build_vuln_detail(r),
            "漏洞的POC": _build_poc_text(r),
            "token": r["token"],
        })
    return rows


def save_results(output_rows, all_results, results_dir, elapsed, logger):
    # scan_results.json FIRST (internal detailed format)
    scan_json = os.path.join(results_dir, "scan_results.json")
    with open(scan_json, "w", encoding="utf-8") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "method": "competition_scanner (KAG-Blackbox)",
            "llm_model": LLM_MODEL,
            "total_targets": len(all_results),
            "nuclei_trust": sum(1 for r in all_results if "NUCLEI" in r.get("pipeline", "")),
            "agent_confirmed": sum(1 for r in all_results if r.get("status") == "agent_confirmed"),
            "fallback": sum(1 for r in all_results if "FALLBACK" in r.get("pipeline", "")),
            "verified": sum(1 for r in all_results if r.get("verify_status") == "verified"),
            "vulns_confirmed": sum(1 for r in all_results if r.get("has_vuln")),
            "elapsed_sec": round(elapsed, 2),
            "results": all_results,
        }, f, ensure_ascii=False, indent=2)
    logger.info(f"Scan results: {scan_json}")

    # Competition output (official format)
    comp_json = os.path.join(results_dir, "competition_output.json")
    comp_data = [{k: v for k, v in row.items() if k != "token"} for row in output_rows]
    with open(comp_json, "w", encoding="utf-8") as f:
        json.dump(comp_data, f, ensure_ascii=False, indent=2)
    logger.info(f"Competition JSON: {comp_json} ({len(comp_data)} entries)")

    # Competition CSV (official format)
    csv_file = os.path.join(results_dir, "competition_output.csv")
    if output_rows:
        fields = ["序号", "访问地址", "漏洞编号", "漏洞类型", "漏洞详情", "漏洞的POC"]
        clean_rows = []
        for row in output_rows:
            clean = {}
            for k in fields:
                v = str(row.get(k, ""))
                v = v.replace('"', "'").replace("\r", " ").replace("\n", " | ")
                clean[k] = v
            clean_rows.append(clean)
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore",
                                    quoting=csv.QUOTE_ALL, escapechar="\\")
            writer.writeheader()
            writer.writerows(clean_rows)
        logger.info(f"Competition CSV: {csv_file}")

    # Competition XLSX (official format)
    try:
        import openpyxl
        xlsx_file = os.path.join(results_dir, "competition_output.xlsx")
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Sheet1"
        headers = ["序号", "访问地址", "漏洞编号", "漏洞类型", "漏洞详情", "漏洞的POC"]
        ws.append(headers)
        for row in output_rows:
            ws.append([row.get(h, "") for h in headers])
        wb.save(xlsx_file)
        logger.info(f"Competition XLSX: {xlsx_file}")
    except ImportError:
        pass


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    global LOCAL_TUNNEL_PORT, LLM_BASE_URL, LLM_MODEL, LLM_TIMEOUT, _scan_counter, _vuln_kg, _vulhub_fps_by_product

    parser = argparse.ArgumentParser(
        description="Competition Scanner — 6-layer fused architecture + KG")
    parser.add_argument("--nuclei-results", default="",
                        help="Path to Nuclei results directory (optional)")
    parser.add_argument("--kg", default=KG_PATH,
                        help="Path to vuln_kg.json knowledge graph (fallback)")
    parser.add_argument("--neo4j-uri", default=NEO4J_URI,
                        help="Neo4j bolt URI")
    parser.add_argument("--no-neo4j", action="store_true",
                        help="Disable Neo4j, use JSON KG only")
    parser.add_argument("--fingerprints", default="",
                        help="Pre-computed fingerprints JSON from Docker scan")
    parser.add_argument("--fp-dir", default=VULHUB_FP_DIR,
                        help="Vulhub fingerprints JSON directory (for multi-CVE disambiguation)")
    parser.add_argument("--targets", default=TARGETS_FILE)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--no-tunnel", action="store_true")
    parser.add_argument("--tunnel-port", type=int, default=18080)
    parser.add_argument("--llm-url", default=LLM_BASE_URL)
    parser.add_argument("--llm-model", default=LLM_MODEL)
    parser.add_argument("--llm-timeout", type=int, default=60)
    parser.add_argument("--no-fallback", action="store_true")
    parser.add_argument("--no-nmap", action="store_true",
                        help="Skip nmap port scanning")
    parser.add_argument("--nuclei-bin", default="",
                        help="Path to nuclei binary")
    parser.add_argument("--surper-templates", default="",
                        help="Path to surper-666/nuclei templates for live scan")
    parser.add_argument("--live-nuclei", action="store_true",
                        help="Run nuclei live scan for targets without pre-scanned results")
    parser.add_argument("--no-sqlmap", action="store_true",
                        help="Skip sqlmap SQL injection verification")
    parser.add_argument("--no-httpx", action="store_true",
                        help="Skip httpx/whatweb fingerprinting")
    args = parser.parse_args()

    LOCAL_TUNNEL_PORT = args.tunnel_port
    LLM_BASE_URL = args.llm_url
    LLM_MODEL = args.llm_model
    LLM_TIMEOUT = args.llm_timeout
    _scan_counter = 0
    use_fallback = not args.no_fallback
    _use_nmap = not args.no_nmap
    _use_live_nuclei = args.live_nuclei
    _no_httpx = args.no_httpx
    _no_sqlmap = args.no_sqlmap
    _nuclei_bin = args.nuclei_bin
    _surper_templates = args.surper_templates

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = os.path.join(RESULTS_DIR_BASE, f"scan_{timestamp}")
    os.makedirs(results_dir, exist_ok=True)

    logger = setup_logging(results_dir)
    logger.info("=" * 60)
    logger.info("  Competition Scanner — 6-Layer Fused Architecture")
    logger.info("=" * 60)
    logger.info(f"LLM: {LLM_MODEL} at {LLM_BASE_URL} (timeout={LLM_TIMEOUT}s)")
    logger.info(f"Workers: {args.workers} | Fallback: {use_fallback}")

    # Load Neo4j KG (primary)
    _neo4j_driver = None
    if not args.no_neo4j:
        try:
            from neo4j import GraphDatabase
            _neo4j_driver = GraphDatabase.driver(
                args.neo4j_uri, auth=(NEO4J_USER, NEO4J_PASSWORD))
            _neo4j_driver.verify_connectivity()
            with _neo4j_driver.session() as s:
                cnt = s.run("MATCH (n:BB_Product) RETURN count(n) AS c").single()["c"]
            logger.info(f"Neo4j KG connected: {cnt} products at {args.neo4j_uri}")
        except Exception as e:
            logger.warning(f"Neo4j unavailable ({e}), falling back to JSON KG")
            _neo4j_driver = None

    # Load JSON KG (fallback)
    _vuln_kg = None
    if args.kg and os.path.isfile(args.kg):
        try:
            sys.path.insert(0, os.path.dirname(args.kg))
            from kg_query import load_kg
            _vuln_kg = load_kg(args.kg)
            n_products = len(_vuln_kg.get("products", {}))
            logger.info(f"JSON KG loaded: {n_products} products from {args.kg}")
        except Exception as e:
            logger.warning(f"Failed to load JSON KG: {e}")

    if not _neo4j_driver and not _vuln_kg:
        logger.info("No KG available — Agent will use LLM only")

    # Load pre-computed fingerprints from Docker scan
    global _precomputed_fingerprints
    _precomputed_fingerprints = {}
    if args.fingerprints and os.path.isfile(args.fingerprints):
        try:
            with open(args.fingerprints, encoding="utf-8") as f:
                fp_data = json.load(f)
            for entry in fp_data:
                url = entry.get("url", "")
                m = re.search(r"(t-[a-f0-9]+)", url)
                if m:
                    token = m.group(1)
                    mf = entry.get("merged_fingerprint", {})
                    vm = entry.get("vulhub_matches", [])
                    _precomputed_fingerprints[token] = {
                        "server": mf.get("server", ""),
                        "title": mf.get("title", ""),
                        "powered_by": "",
                        "technologies": mf.get("technologies", []),
                        "whatweb_plugins": mf.get("whatweb_plugins", {}),
                        "nuclei_detections": mf.get("nuclei_detections", []),
                        "vulhub_match": vm[0] if vm else None,
                        "probes": entry.get("httpx", {}),
                        "cookies": [],
                        "reachable": True,
                    }
            logger.info(f"Pre-computed fingerprints loaded: {len(_precomputed_fingerprints)} targets "
                        f"({sum(1 for v in _precomputed_fingerprints.values() if v.get('vulhub_match'))} with vulhub match)")
        except Exception as e:
            logger.warning(f"Failed to load fingerprints: {e}")

    # Load vulhub fingerprints by product (for multi-CVE disambiguation)
    global _vulhub_fps_by_product
    _vulhub_fps_by_product = load_vulhub_fingerprints_by_product(args.fp_dir)
    multi_cve = sum(1 for fps in _vulhub_fps_by_product.values() if len(fps) > 1)
    logger.info(f"Vulhub fingerprint files: {sum(len(v) for v in _vulhub_fps_by_product.values())} files, "
                f"{len(_vulhub_fps_by_product)} products ({multi_cve} with multiple CVEs)")

    # Load Nuclei results
    nuclei_data = {}
    if args.nuclei_results:
        nuclei_data = load_nuclei_results(args.nuclei_results)
        hits = sum(1 for v in nuclei_data.values() if v.get("findings"))
        logger.info(f"Nuclei: {len(nuclei_data)} targets loaded, {hits} with findings")
    else:
        logger.info("No Nuclei results provided — all targets go to Agent pipeline")

    targets = read_targets(args.targets)
    logger.info(f"Targets: {len(targets)}")

    if args.limit > 0:
        targets = targets[:args.limit]
        logger.info(f"Limited to {len(targets)}")

    tunnel_proc = None
    if not args.no_tunnel:
        tunnel_proc = ensure_tunnel(logger)

    total = len(targets)
    scan_start = time.monotonic()
    all_results = [None] * total

    def _work(idx_target):
        idx, t = idx_target
        return idx, process_target(t, nuclei_data, total, use_fallback, logger)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_work, (i, t)): i for i, t in enumerate(targets)}
        for future in as_completed(futures):
            try:
                idx, result = future.result()
                all_results[idx] = result
            except Exception as e:
                orig = futures[future]
                t = targets[orig]
                logger.error(f"[{t['token']}] Worker error: {e}")
                all_results[orig] = {
                    "token": t["token"], "host": t["host"], "url": t["url"],
                    "pipeline": "ERROR", "has_vuln": False,
                    "status": "worker_error",
                    "vuln_type": "", "vuln_name": "",
                    "cve_id": "", "confidence": 0,
                    "evidence": "", "verify_status": "",
                    "product": "", "version": "",
                    "nuclei_findings_count": 0, "elapsed_sec": 0,
                }

    scan_elapsed = time.monotonic() - scan_start

    output_rows = format_output(all_results)
    save_results(output_rows, all_results, results_dir, scan_elapsed, logger)

    # Summary
    nuclei_trust = sum(1 for r in all_results if "NUCLEI" in r.get("pipeline", ""))
    kg_confirmed = sum(1 for r in all_results if r.get("status") == "kg_confirmed")
    agent_ok = sum(1 for r in all_results if r.get("status") == "agent_confirmed")
    fallback = sum(1 for r in all_results if "FALLBACK" in r.get("pipeline", ""))
    verified = sum(1 for r in all_results if r.get("verify_status") == "verified")
    confirmed = sum(1 for r in all_results if r.get("has_vuln"))

    logger.info("")
    logger.info("=" * 60)
    logger.info("  Scan Complete")
    logger.info("=" * 60)
    logger.info(f"  Total targets:     {total}")
    logger.info(f"  NUCLEI→TRUST:      {nuclei_trust}")
    logger.info(f"  KG confirmed:      {kg_confirmed}")
    logger.info(f"  AGENT confirmed:   {agent_ok}")
    logger.info(f"  FALLBACK:          {fallback}")
    logger.info(f"  Verified (PoC OK): {verified}")
    logger.info(f"  Vulns reported:    {confirmed}/{total}")
    logger.info(f"  Wall clock:        {scan_elapsed:.1f}s ({scan_elapsed/60:.1f}m)")
    logger.info(f"  Results:           {results_dir}")
    logger.info("=" * 60)

    if tunnel_proc:
        tunnel_proc.terminate()


if __name__ == "__main__":
    main()
