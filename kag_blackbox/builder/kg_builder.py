"""
KAG-Blackbox KG Builder.

Ingests Nuclei templates and vulhub data into Neo4j as BB_-prefixed nodes.
"""
import csv
import json
import os
import re
import sys
import time
import logging

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from config import NUCLEI_BATCH_SIZE, VULN_TYPE_CN
from schema import infer_cwe

log = logging.getLogger("kag_blackbox.builder")

# Severity ordering for picking the "best" CVE
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}

# Tags that are not product names
_SKIP_TAGS = {
    "cve", "rce", "lfi", "sqli", "xss", "ssrf", "xxe", "ssti", "idor",
    "deserialization", "injection", "auth-bypass", "fileupload", "misconfig",
    "default-login", "exposure", "panel", "detect", "tech", "config",
    "intrusive", "authenticated", "unauth", "oast", "network", "cloud",
    "high", "medium", "low", "critical", "info",
}


def _extract_product(tags, metadata):
    """Guess a product name from template tags and metadata."""
    if isinstance(metadata, dict):
        for key in ("product", "vendor"):
            val = metadata.get(key)
            if val and isinstance(val, str):
                return val.lower().strip().replace(" ", "-")

    if not tags:
        return ""
    year_re = re.compile(r"^cve\d{4}$|^\d{4}$")
    for tag in tags:
        t = tag.lower().strip()
        if t in _SKIP_TAGS or year_re.match(t) or len(t) < 2:
            continue
        if t.startswith("cve-"):
            continue
        return t
    return ""


def _extract_cve(data):
    """Extract CVE ID from a Nuclei template dict."""
    classification = data.get("info") or {}
    classification = classification.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    cve_raw = classification.get("cve-id", "")
    if isinstance(cve_raw, list):
        return cve_raw[0].upper() if cve_raw else ""
    if isinstance(cve_raw, str) and cve_raw.upper().startswith("CVE-"):
        return cve_raw.upper()
    tid = (data.get("id") or "").upper()
    m = re.search(r"(CVE-\d{4}-\d+)", tid)
    return m.group(1) if m else ""


def _extract_cwe(data):
    """Extract CWE from classification or infer from tags."""
    classification = (data.get("info") or {}).get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    cwe = classification.get("cwe-id", "")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    if cwe:
        return str(cwe).upper()
    tags = (data.get("info") or {}).get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return infer_cwe(" ".join(tags))


def _extract_poc(http_list):
    """Extract PoC request info from http section."""
    if not http_list or not isinstance(http_list, list):
        return {}
    h = http_list[0] if http_list else {}
    if not isinstance(h, dict):
        return {}

    method = (h.get("method") or "GET").upper()
    paths = h.get("path") or h.get("paths") or []
    if isinstance(paths, list) and paths:
        path = str(paths[0]).replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
    else:
        path = ""
    body = h.get("body") or ""
    headers = h.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    # Extract matchers
    matchers_raw = h.get("matchers") or []
    matcher_words = []
    matcher_status = []
    for m in matchers_raw:
        if not isinstance(m, dict):
            continue
        matcher_words.extend(m.get("words") or [])
        matcher_status.extend(m.get("status") or [])

    return {
        "method": method,
        "path": path[:500],
        "headers": json.dumps(headers, ensure_ascii=False)[:500],
        "body": str(body)[:1000],
        "matcher_words": json.dumps(matcher_words[:10], ensure_ascii=False),
        "matcher_status": json.dumps(matcher_status[:5]),
    }


def _extract_fingerprints(http_list, metadata):
    """Extract fingerprint patterns from matchers and metadata."""
    fps = []

    if isinstance(metadata, dict):
        for key in ("shodan-query", "fofa-query", "google-query"):
            val = metadata.get(key)
            if val and isinstance(val, str):
                fps.append({"type": "search_query", "pattern": val[:200]})

    if not http_list or not isinstance(http_list, list):
        return fps

    for h in http_list:
        if not isinstance(h, dict):
            continue
        for matcher in (h.get("matchers") or []):
            if not isinstance(matcher, dict):
                continue
            part = (matcher.get("part") or "").lower()
            words = matcher.get("words") or []
            for w in words:
                if not isinstance(w, str) or len(w) < 3:
                    continue
                if part == "header" or part == "":
                    fps.append({"type": "header_pattern", "pattern": w[:200]})
                elif part == "body":
                    fps.append({"type": "body_pattern", "pattern": w[:200]})
                elif part == "status":
                    pass
    return fps[:20]


def parse_nuclei_templates(nuclei_dir):
    """Parse all Nuclei YAML templates under a directory tree."""
    templates = []
    count = 0
    errors = 0

    for root, _, files in os.walk(nuclei_dir):
        for fname in files:
            if not fname.endswith(".yaml") and not fname.endswith(".yml"):
                continue
            fpath = os.path.join(root, fname)
            count += 1
            if count % 2000 == 0:
                log.info(f"  Parsed {count} templates ({errors} errors)...")

            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    data = yaml.safe_load(f)
            except Exception:
                errors += 1
                continue

            if not data or not isinstance(data, dict):
                errors += 1
                continue

            info = data.get("info") or {}
            if not isinstance(info, dict):
                continue
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            metadata = info.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}

            product = _extract_product(tags, metadata)
            if not product:
                continue

            cve_id = _extract_cve(data)
            cwe_id = _extract_cwe(data)
            http_list = data.get("http") or []
            poc = _extract_poc(http_list)
            fingerprints = _extract_fingerprints(http_list, metadata)

            severity = (info.get("severity") or "info").lower()
            vuln_type = ""
            tags_lower = [t.lower() for t in tags]
            for kw in ["rce", "sqli", "xss", "ssrf", "lfi", "xxe", "ssti",
                        "deserialization", "auth-bypass", "fileupload"]:
                if kw in tags_lower:
                    vuln_type = kw
                    break

            templates.append({
                "template_id": data.get("id", fname.replace(".yaml", "")),
                "product": product,
                "name": (info.get("name") or "")[:300],
                "description": (info.get("description") or "")[:500],
                "severity": severity,
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "vuln_type": vuln_type,
                "type_cn": VULN_TYPE_CN.get(vuln_type, "安全漏洞"),
                "vendor": metadata.get("vendor", ""),
                "tags": tags,
                "poc": poc,
                "fingerprints": fingerprints,
            })

    log.info(f"  Total: {count} files, {len(templates)} with product, {errors} errors")
    return templates


def build_from_nuclei(driver, nuclei_dir):
    """Parse Nuclei templates and write to Neo4j."""
    log.info(f"Parsing Nuclei templates from {nuclei_dir} ...")
    t0 = time.time()
    templates = parse_nuclei_templates(nuclei_dir)
    log.info(f"Parsed {len(templates)} templates in {time.time()-t0:.1f}s")

    # Group by product
    by_product = {}
    for t in templates:
        by_product.setdefault(t["product"], []).append(t)

    log.info(f"Writing {len(by_product)} products to Neo4j ...")
    t0 = time.time()

    with driver.session() as session:
        # Batch create products
        products_batch = [
            {"name": pname, "vendor": tmps[0].get("vendor", ""),
             "template_count": len(tmps)}
            for pname, tmps in by_product.items()
        ]
        for i in range(0, len(products_batch), NUCLEI_BATCH_SIZE):
            batch = products_batch[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS p
                   MERGE (prod:BB_Product {name: p.name})
                   SET prod.vendor = p.vendor,
                       prod.template_count = p.template_count""",
                batch=batch,
            )

        # Batch create CVEs + relationships
        cve_batch = []
        for t in templates:
            if not t["cve_id"]:
                continue
            cve_batch.append({
                "product": t["product"],
                "cve_id": t["cve_id"],
                "name": t["name"],
                "severity": t["severity"],
                "description": t["description"],
                "vuln_type": t["vuln_type"],
                "type_cn": t["type_cn"],
                "cwe_id": t["cwe_id"],
            })

        for i in range(0, len(cve_batch), NUCLEI_BATCH_SIZE):
            batch = cve_batch[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS c
                   MERGE (cve:BB_CVE {cve_id: c.cve_id})
                   SET cve.name = c.name,
                       cve.severity = c.severity,
                       cve.description = c.description,
                       cve.type = c.vuln_type,
                       cve.type_cn = c.type_cn,
                       cve.cwe_id = c.cwe_id
                   WITH cve, c
                   MATCH (p:BB_Product {name: c.product})
                   MERGE (p)-[:BB_HAS_CVE]->(cve)""",
                batch=batch,
            )

        # Link CVEs to CWE
        session.run(
            """MATCH (cve:BB_CVE)
               WHERE cve.cwe_id IS NOT NULL AND cve.cwe_id <> ''
               MATCH (cwe:BB_CWE {cwe_id: cve.cwe_id})
               MERGE (cve)-[:BB_BELONGS_TO]->(cwe)""",
        )

        # Batch create PoCs
        poc_batch = []
        for t in templates:
            poc = t.get("poc")
            if not poc or not poc.get("path"):
                continue
            poc_batch.append({
                "cve_id": t["cve_id"] or t["template_id"],
                "product": t["product"],
                "method": poc.get("method", "GET"),
                "path": poc.get("path", ""),
                "headers": poc.get("headers", "{}"),
                "body": poc.get("body", ""),
                "matcher_words": poc.get("matcher_words", "[]"),
                "matcher_status": poc.get("matcher_status", "[]"),
                "source": "nuclei",
                "template_id": t["template_id"],
            })

        for i in range(0, len(poc_batch), NUCLEI_BATCH_SIZE):
            batch = poc_batch[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS pc
                   CREATE (poc:BB_PoC {
                       method: pc.method, path: pc.path,
                       headers: pc.headers, body: pc.body,
                       matcher_words: pc.matcher_words,
                       matcher_status: pc.matcher_status,
                       source: pc.source, template_id: pc.template_id
                   })
                   WITH poc, pc
                   OPTIONAL MATCH (cve:BB_CVE {cve_id: pc.cve_id})
                   FOREACH (_ IN CASE WHEN cve IS NOT NULL THEN [1] ELSE [] END |
                       MERGE (cve)-[:BB_HAS_POC]->(poc)
                   )
                   WITH poc, pc
                   MATCH (p:BB_Product {name: pc.product})
                   MERGE (poc)-[:BB_TARGETS]->(p)""",
                batch=batch,
            )

        # Batch create fingerprints
        fp_batch = []
        for t in templates:
            for fp in t.get("fingerprints", []):
                fp_batch.append({
                    "product": t["product"],
                    "type": fp["type"],
                    "pattern": fp["pattern"],
                })

        # Deduplicate
        seen = set()
        deduped = []
        for fp in fp_batch:
            key = (fp["product"], fp["type"], fp["pattern"])
            if key not in seen:
                seen.add(key)
                deduped.append(fp)

        for i in range(0, len(deduped), NUCLEI_BATCH_SIZE):
            batch = deduped[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS f
                   MERGE (fp:BB_Fingerprint {type: f.type, pattern: f.pattern})
                   WITH fp, f
                   MATCH (p:BB_Product {name: f.product})
                   MERGE (p)-[:BB_IDENTIFIED_BY]->(fp)""",
                batch=batch,
            )

    elapsed = time.time() - t0
    log.info(f"Neo4j write complete in {elapsed:.1f}s")
    return len(by_product), len(cve_batch), len(poc_batch), len(deduped)


def build_from_vulhub(driver, mapping_csv, readmes_dir=None):
    """Import vulhub mapping + README PoCs into Neo4j."""
    if not os.path.isfile(mapping_csv):
        log.warning(f"Mapping CSV not found: {mapping_csv}")
        return 0

    rows = []
    with open(mapping_csv, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            product = (row.get("product") or "").lower().strip()
            cve = (row.get("cve") or "").strip()
            vuln_class = (row.get("vuln_class") or "").strip()
            real_env = (row.get("real_env") or "").strip()
            vuln_desc = (row.get("vuln (README)") or "").strip()

            if not product:
                continue

            readme_poc = ""
            if readmes_dir:
                readme_name = real_env.replace("/", "_") + ".md"
                readme_path = os.path.join(readmes_dir, readme_name)
                if os.path.isfile(readme_path):
                    readme_poc = _parse_readme_poc(readme_path)

            rows.append({
                "product": product,
                "cve_id": cve.upper() if cve.upper().startswith("CVE-") else cve,
                "vuln_class": vuln_class,
                "type_cn": VULN_TYPE_CN.get(vuln_class, "安全漏洞"),
                "real_env": real_env,
                "description": vuln_desc,
                "readme_poc": readme_poc[:3000],
                "cwe_id": infer_cwe(vuln_class),
            })

    with driver.session() as session:
        for i in range(0, len(rows), NUCLEI_BATCH_SIZE):
            batch = rows[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS v
                   MERGE (p:BB_Product {name: v.product})
                   MERGE (cve:BB_CVE {cve_id: v.cve_id})
                   SET cve.name = v.description,
                       cve.severity = 'high',
                       cve.type = v.vuln_class,
                       cve.type_cn = v.type_cn,
                       cve.cwe_id = v.cwe_id,
                       cve.vulhub_env = v.real_env
                   MERGE (p)-[:BB_HAS_CVE]->(cve)""",
                batch=batch,
            )

            # Create PoC nodes from README
            poc_rows = [r for r in batch if r["readme_poc"]]
            if poc_rows:
                session.run(
                    """UNWIND $batch AS v
                       MATCH (cve:BB_CVE {cve_id: v.cve_id})
                       CREATE (poc:BB_PoC {
                           source: 'vulhub_readme',
                           readme_poc: v.readme_poc,
                           method: '', path: '', headers: '', body: '',
                           matcher_words: '[]', matcher_status: '[]',
                           template_id: v.real_env
                       })
                       MERGE (cve)-[:BB_HAS_POC]->(poc)
                       WITH poc, v
                       MATCH (p:BB_Product {name: v.product})
                       MERGE (poc)-[:BB_TARGETS]->(p)""",
                    batch=poc_rows,
                )

    log.info(f"  Imported {len(rows)} vulhub entries ({sum(1 for r in rows if r['readme_poc'])} with README PoC)")
    return len(rows)


def _parse_readme_poc(readme_path):
    """Extract PoC code blocks from a vulhub README."""
    try:
        with open(readme_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return ""

    blocks = []
    in_code = False
    buf = []
    for line in content.split("\n"):
        if line.strip().startswith("```"):
            if in_code:
                block = "\n".join(buf)
                if any(kw in block.lower() for kw in
                       ["curl ", "get /", "post /", "http/1.", "host:", "content-type"]):
                    blocks.append(block)
                buf = []
                in_code = False
            else:
                in_code = True
                buf = []
        elif in_code:
            buf.append(line)

    return "\n\n".join(blocks[:3])


def build_from_vulhub_fingerprints(driver, fingerprints_dir):
    """Import vulhub_fingerprints JSON dataset into Neo4j.

    Each JSON file contains precise identification rules (title, body_keywords,
    cookies, unique_paths, version_regex) and detection PoC for one vulhub scenario.
    """
    if not os.path.isdir(fingerprints_dir):
        log.warning(f"Fingerprints dir not found: {fingerprints_dir}")
        return 0

    entries = []
    for fname in os.listdir(fingerprints_dir):
        if not fname.endswith(".json") or fname.startswith("_"):
            continue
        fpath = os.path.join(fingerprints_dir, fname)
        try:
            with open(fpath, encoding="utf-8") as f:
                fp = json.load(f)
        except (json.JSONDecodeError, IOError):
            continue

        product = (fp.get("app") or "").lower().strip()
        if not product:
            continue

        ident = fp.get("identification") or {}
        detection = fp.get("detection") or {}
        cves = fp.get("cve") or []
        cve_id = cves[0] if cves else ""

        # Collect all fingerprint patterns from identification
        fingerprints = []
        for title in (ident.get("http_title") or []):
            if title:
                fingerprints.append({"type": "title", "pattern": title, "confidence": 0.95})
        for kw in (ident.get("body_keywords") or []):
            if kw and len(kw) > 3:
                fingerprints.append({"type": "body_keyword", "pattern": kw, "confidence": 0.80})
        for cookie in (ident.get("cookies") or []):
            if cookie:
                fingerprints.append({"type": "cookie", "pattern": cookie, "confidence": 0.90})
        for path in (ident.get("unique_paths") or []):
            if path:
                fingerprints.append({"type": "unique_path", "pattern": path, "confidence": 0.85})
        for header in (ident.get("server_header") or []):
            if header:
                fingerprints.append({"type": "server_header", "pattern": header, "confidence": 0.70})
        for regex in (ident.get("version_regex") or []):
            if regex:
                fingerprints.append({"type": "version_regex", "pattern": regex, "confidence": 0.90})

        # Build PoC from detection
        poc_method = detection.get("method", "")
        poc_path = detection.get("path", "")
        poc_headers = json.dumps(detection.get("request_headers") or {})
        poc_payload = detection.get("payload", "")
        match_indicators = detection.get("match_indicators") or []

        entries.append({
            "product": product,
            "cve_id": cve_id,
            "cwe": fp.get("cwe", ""),
            "vuln_class": fp.get("vuln_class", ""),
            "type_cn": VULN_TYPE_CN.get(fp.get("vuln_class", ""), "安全漏洞"),
            "severity": fp.get("severity", "high"),
            "affected_versions": fp.get("affected_versions", ""),
            "description": fp.get("product", ""),
            "vulhub_id": fp.get("id", ""),
            "fingerprints": fingerprints,
            "poc_method": poc_method,
            "poc_path": poc_path,
            "poc_headers": poc_headers,
            "poc_payload": poc_payload,
            "match_indicators": json.dumps(match_indicators),
        })

    if not entries:
        return 0

    with driver.session() as session:
        for entry in entries:
            # Merge product + CVE
            session.run(
                """MERGE (p:BB_Product {name: $product})
                   MERGE (cve:BB_CVE {cve_id: $cve_id})
                   SET cve.severity = $severity,
                       cve.type = $vuln_class,
                       cve.type_cn = $type_cn,
                       cve.cwe_id = $cwe,
                       cve.affected_versions = $affected_versions,
                       cve.description = $description,
                       cve.vulhub_env = $vulhub_id
                   MERGE (p)-[:BB_HAS_CVE]->(cve)""",
                **{k: entry[k] for k in [
                    "product", "cve_id", "severity", "vuln_class",
                    "type_cn", "cwe", "affected_versions", "description", "vulhub_id"
                ]}
            )

            # Create high-quality fingerprint nodes
            for fp in entry["fingerprints"]:
                session.run(
                    """MATCH (p:BB_Product {name: $product})
                       MERGE (f:BB_Fingerprint {type: $type, pattern: $pattern})
                       SET f.confidence = $confidence,
                           f.source = 'vulhub_fingerprints'
                       MERGE (p)-[:BB_IDENTIFIED_BY]->(f)""",
                    product=entry["product"],
                    type=fp["type"],
                    pattern=fp["pattern"],
                    confidence=fp["confidence"],
                )

            # Create PoC with structured fields
            if entry["poc_path"]:
                session.run(
                    """MATCH (cve:BB_CVE {cve_id: $cve_id})
                       CREATE (poc:BB_PoC {
                           source: 'vulhub_fingerprints',
                           method: $method, path: $path,
                           headers: $headers, body: $payload,
                           matcher_words: $match_indicators,
                           matcher_status: '[]',
                           template_id: $vulhub_id
                       })
                       MERGE (cve)-[:BB_HAS_POC]->(poc)
                       WITH poc
                       MATCH (p:BB_Product {name: $product})
                       MERGE (poc)-[:BB_TARGETS]->(p)""",
                    cve_id=entry["cve_id"],
                    method=entry["poc_method"],
                    path=entry["poc_path"],
                    headers=entry["poc_headers"],
                    payload=entry["poc_payload"],
                    match_indicators=entry["match_indicators"],
                    vulhub_id=entry["vulhub_id"],
                    product=entry["product"],
                )

    log.info(f"  Imported {len(entries)} vulhub fingerprint entries "
             f"({sum(len(e['fingerprints']) for e in entries)} fingerprint patterns, "
             f"{sum(1 for e in entries if e['poc_path'])} with structured PoC)")
    return len(entries)


def build_from_other_vul(driver, zip_path):
    """Import other_vul.zip (mixed Nuclei + xray PoC templates) into Neo4j at lowest priority.

    These templates supplement the KG with additional CVE/product coverage but
    are marked source='other_vul', priority=0 so KAG-Thinker treats them as
    lower-confidence candidates compared to vulhub_fingerprints (priority=2)
    and official Nuclei templates (priority=1).
    """
    import zipfile

    if not os.path.isfile(zip_path):
        log.warning(f"other_vul.zip not found: {zip_path}")
        return 0, 0

    zf = zipfile.ZipFile(zip_path)
    templates = []
    count = 0
    errors = 0
    skipped_dir = 0

    # Directories irrelevant to HTTP blackbox testing
    _SKIP_PREFIXES = (
        'cloud/', 'file/', 'dns/', 'network/', 'ssl/', 'ftp/',
        'helpers/', 'profiles/', 'workflows/', 'passive/',
        'javascript/', 'java/', 'python/', 'ruby/', 'perl/',
        'ssh/', 'smtp/', 'ldap/', 'redis/', 'mongodb/', 'postgres/',
        'samba/', 'kafka/', 'rabbitmq/', 'mysql/', 'sql/',
        'other/', 'headless/',
    )
    # Subdirectories to skip even under http/
    _SKIP_HTTP_SUBS = (
        'http/exposed-panels/', 'http/technologies/', 'http/osint/',
        'http/honeypot/', 'http/fuzzing/', 'http/takeovers/',
        'http/token-spray/', 'http/exposures/tokens/',
        'http/miscellaneous/', 'http/iot/',
    )

    for info in zf.infolist():
        if not info.filename.endswith(('.yaml', '.yml')) or info.is_dir():
            continue
        if info.file_size > 500000:
            continue

        # Filter out non-HTTP directories
        fname_lower = info.filename.lower()
        if any(fname_lower.startswith(p) for p in _SKIP_PREFIXES):
            skipped_dir += 1
            continue
        if any(fname_lower.startswith(p) for p in _SKIP_HTTP_SUBS):
            skipped_dir += 1
            continue

        count += 1
        if count % 5000 == 0:
            log.info(f"  Parsed {count} other_vul templates ({errors} errors, {skipped_dir} skipped)...")

        try:
            raw = zf.read(info.filename)
            data = yaml.safe_load(raw)
        except Exception:
            errors += 1
            continue

        if not data or not isinstance(data, dict):
            continue

        # ── Nuclei format ──
        if 'id' in data and 'info' in data:
            info_d = data.get('info') or {}
            if not isinstance(info_d, dict):
                continue
            tags = info_d.get('tags') or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',')]
            metadata = info_d.get('metadata') or {}
            if not isinstance(metadata, dict):
                metadata = {}

            product = _extract_product(tags, metadata)
            if not product:
                continue

            cve_id = _extract_cve(data)
            if not cve_id:
                continue

            severity = (info_d.get('severity') or 'info').lower()
            vuln_type = ''
            tags_lower = [t.lower() for t in tags]
            for kw in ['rce', 'sqli', 'xss', 'ssrf', 'lfi', 'xxe', 'ssti',
                        'deserialization', 'auth-bypass', 'fileupload']:
                if kw in tags_lower:
                    vuln_type = kw
                    break

            http_list = data.get('http') or []
            poc = _extract_poc(http_list)
            fingerprints = _extract_fingerprints(http_list, metadata)

            templates.append({
                'product': product,
                'cve_id': cve_id,
                'name': (info_d.get('name') or '')[:300],
                'description': (info_d.get('description') or '')[:500],
                'severity': severity,
                'vuln_type': vuln_type,
                'type_cn': VULN_TYPE_CN.get(vuln_type, '安全漏洞'),
                'cwe_id': _extract_cwe(data),
                'poc': poc,
                'fingerprints': fingerprints,
                'template_id': data.get('id', ''),
            })

        # ── xray PoC format ──
        elif 'name' in data and ('rules' in data or 'transport' in data):
            # Only accept HTTP transport
            transport = (data.get('transport') or 'http').lower()
            if transport not in ('http', 'https', ''):
                continue

            name = data.get('name', '')
            m = re.search(r'(CVE-\d{4}-\d+)', name, re.I)
            if not m:
                continue
            cve_id = m.group(1).upper()

            # Normalize product name from xray naming convention
            # e.g. "poc-yaml-apache-druid-cve-2021-36749" → "apache-druid"
            clean_name = name.replace('poc-yaml-', '').replace('poc_yaml_', '')
            product_m = re.match(r'([\w][\w-]*?)[-_](?:cve|CVE)', clean_name)
            product = product_m.group(1).lower().rstrip('-_') if product_m else ''
            if not product or len(product) < 2:
                continue
            # Normalize common product aliases
            _PRODUCT_ALIASES = {
                'apache-httpd': 'apache', 'httpd': 'apache',
                'apache-tomcat': 'tomcat', 'apache-struts': 'struts2',
                'apache-struts2': 'struts2', 'apache-solr': 'solr',
                'apache-druid': 'apache-druid', 'apache-ofbiz': 'ofbiz',
                'oracle-weblogic': 'weblogic', 'weblogic-server': 'weblogic',
            }
            product = _PRODUCT_ALIASES.get(product, product)

            # Extract PoC from xray rules
            xray_poc = {}
            rules = data.get('rules') or {}
            if isinstance(rules, dict):
                for rule_name, rule in rules.items():
                    if not isinstance(rule, dict):
                        continue
                    req = rule.get('request') or {}
                    if req.get('path'):
                        xray_poc = {
                            'method': (req.get('method') or 'GET').upper(),
                            'path': str(req['path'])[:500],
                            'headers': json.dumps(req.get('headers') or {})[:500],
                            'body': str(req.get('body') or '')[:1000],
                            'matcher_words': '[]',
                            'matcher_status': '[]',
                        }
                        break

            templates.append({
                'product': product,
                'cve_id': cve_id,
                'name': name[:300],
                'description': '',
                'severity': 'medium',
                'vuln_type': '',
                'type_cn': '安全漏洞',
                'cwe_id': '',
                'poc': xray_poc,
                'fingerprints': [],
                'template_id': name,
            })

    zf.close()
    log.info(f"  Parsed {count} files, {len(templates)} with CVE, "
             f"{errors} errors, {skipped_dir} skipped (non-HTTP)")

    if not templates:
        return 0, 0

    # Filter: prefer templates that have a PoC path (more useful for verification)
    with_poc = [t for t in templates if t.get('poc') and t['poc'].get('path')]
    without_poc = [t for t in templates if not (t.get('poc') and t['poc'].get('path'))]
    log.info(f"  With PoC path: {len(with_poc)}, without: {len(without_poc)}")

    # Deduplicate by CVE ID — prefer templates with PoC
    seen_cves = set()
    deduped = []
    for t in with_poc + without_poc:
        if t['cve_id'] not in seen_cves:
            seen_cves.add(t['cve_id'])
            deduped.append(t)
    templates = deduped
    log.info(f"  After dedup: {len(templates)} unique CVEs")

    # Group by product
    by_product = {}
    for t in templates:
        by_product.setdefault(t['product'], []).append(t)

    with driver.session() as session:
        # Batch create products (MERGE — don't overwrite existing)
        products_batch = [{'name': pname} for pname in by_product]
        for i in range(0, len(products_batch), NUCLEI_BATCH_SIZE):
            batch = products_batch[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS p
                   MERGE (:BB_Product {name: p.name})""",
                batch=batch,
            )

        # Batch create CVEs with source + priority
        cve_batch = []
        for t in templates:
            cve_batch.append({
                'product': t['product'],
                'cve_id': t['cve_id'],
                'name': t['name'],
                'severity': t['severity'],
                'description': t['description'],
                'vuln_type': t['vuln_type'],
                'type_cn': t['type_cn'],
                'cwe_id': t['cwe_id'],
            })

        for i in range(0, len(cve_batch), NUCLEI_BATCH_SIZE):
            batch = cve_batch[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS c
                   MERGE (cve:BB_CVE {cve_id: c.cve_id})
                   ON CREATE SET cve.name = c.name,
                       cve.severity = c.severity,
                       cve.description = c.description,
                       cve.type = c.vuln_type,
                       cve.type_cn = c.type_cn,
                       cve.cwe_id = c.cwe_id,
                       cve.source = 'other_vul',
                       cve.priority = 0
                   WITH cve, c
                   MATCH (p:BB_Product {name: c.product})
                   MERGE (p)-[:BB_HAS_CVE]->(cve)""",
                batch=batch,
            )

        # Batch create PoCs
        poc_batch = []
        for t in templates:
            poc = t.get('poc')
            if not poc or not poc.get('path'):
                continue
            poc_batch.append({
                'cve_id': t['cve_id'],
                'product': t['product'],
                'method': poc.get('method', 'GET'),
                'path': poc.get('path', ''),
                'headers': poc.get('headers', '{}'),
                'body': poc.get('body', ''),
                'matcher_words': poc.get('matcher_words', '[]'),
                'matcher_status': poc.get('matcher_status', '[]'),
                'source': 'other_vul',
                'template_id': t['template_id'],
            })

        for i in range(0, len(poc_batch), NUCLEI_BATCH_SIZE):
            batch = poc_batch[i:i + NUCLEI_BATCH_SIZE]
            session.run(
                """UNWIND $batch AS pc
                   CREATE (poc:BB_PoC {
                       method: pc.method, path: pc.path,
                       headers: pc.headers, body: pc.body,
                       matcher_words: pc.matcher_words,
                       matcher_status: pc.matcher_status,
                       source: pc.source, template_id: pc.template_id
                   })
                   WITH poc, pc
                   OPTIONAL MATCH (cve:BB_CVE {cve_id: pc.cve_id})
                   FOREACH (_ IN CASE WHEN cve IS NOT NULL THEN [1] ELSE [] END |
                       MERGE (cve)-[:BB_HAS_POC]->(poc)
                   )
                   WITH poc, pc
                   MATCH (p:BB_Product {name: pc.product})
                   MERGE (poc)-[:BB_TARGETS]->(p)""",
                batch=batch,
            )

    log.info(f"  Imported {len(templates)} other_vul CVEs "
             f"({len(by_product)} products, {len(poc_batch)} PoCs)")
    return len(templates), len(poc_batch)


def set_source_priority(driver):
    """Set source and priority on existing CVE nodes that don't have them yet."""
    with driver.session() as session:
        # vulhub_fingerprints → priority 2 (highest)
        session.run(
            """MATCH (cve:BB_CVE)
               WHERE cve.vulhub_env IS NOT NULL AND cve.vulhub_env STARTS WITH 'activemq/'
                  OR EXISTS { MATCH (cve)<-[:BB_HAS_POC]-(poc:BB_PoC {source: 'vulhub_fingerprints'}) }
               SET cve.source = COALESCE(cve.source, 'vulhub_fingerprints'),
                   cve.priority = 2""")
        # nuclei → priority 1
        session.run(
            """MATCH (cve:BB_CVE)
               WHERE cve.priority IS NULL
                 AND cve.source IS NULL
               SET cve.source = 'nuclei',
                   cve.priority = 1""")


def build_fingerprint_index(driver):
    """Ensure fulltext index is created (idempotent)."""
    with driver.session() as session:
        try:
            session.run(
                """CREATE FULLTEXT INDEX bb_fingerprint_text IF NOT EXISTS
                   FOR (n:BB_Fingerprint) ON EACH [n.pattern]""")
        except Exception:
            pass


def get_stats(driver):
    """Return node/relationship counts."""
    stats = {}
    with driver.session() as session:
        for label in ["BB_Product", "BB_CVE", "BB_PoC", "BB_Fingerprint", "BB_CWE"]:
            r = session.run(f"MATCH (n:{label}) RETURN count(n) AS cnt")
            stats[label] = r.single()["cnt"]
        r = session.run("MATCH ()-[r]->() WHERE type(r) STARTS WITH 'BB_' RETURN count(r) AS cnt")
        stats["relationships"] = r.single()["cnt"]
    return stats
