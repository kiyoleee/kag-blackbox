"""
KAG-Blackbox Neo4j query module.

Multi-hop reasoning: Fingerprint → Product → CVE → PoC
"""
import os
import sys
import re
import json
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from config import FINGERPRINT_CONFIDENCE_THRESHOLD, TOP_K_PRODUCTS


def identify_product(driver, fingerprint):
    """
    Match HTTP fingerprint against BB_Fingerprint nodes.

    fingerprint: {
        "server": "Apache/2.4.54",
        "title": "Cacti Login",
        "powered_by": "PHP/7.4.33",
        "cookies": ["Cacti=abc"],
        "probes": {"/": {"status": 200, "headers": "...", "body": "..."}, ...}
    }

    Returns: [{"product": "cacti", "confidence": 0.92, "match_reasons": [...],
               "cves": [...], "poc": {...}}, ...]
    """
    candidates = defaultdict(lambda: {"score": 0.0, "reasons": [], "signal_count": 0})

    with driver.session() as session:
        # 1. Title match via fulltext (highest confidence)
        title = (fingerprint.get("title") or "").strip()
        if title and len(title) >= 2:
            _match_fulltext(session, title, candidates, "title", 0.88)

        # 2. Server header match
        server = (fingerprint.get("server") or "").strip()
        if server:
            _match_fulltext(session, server, candidates, "server", 0.65)

        # 3. Body content match — search within probe responses
        for path, probe in (fingerprint.get("probes") or {}).items():
            if not isinstance(probe, dict):
                continue
            body = (probe.get("body") or "")[:500]
            if body and len(body) > 20:
                _match_body_patterns(session, body, candidates)

        # 4. Cookie match
        for cookie in (fingerprint.get("cookies") or []):
            if cookie:
                _match_fulltext(session, cookie.split("=")[0], candidates, "cookie", 0.75)

        # 5. Direct product name search in title/server
        _match_product_name(session, title, server, candidates)

    # Score and rank
    results = []
    for product, info in candidates.items():
        score = min(info["score"], 0.99)
        if info["signal_count"] > 1:
            score = min(score + 0.03 * (info["signal_count"] - 1), 0.99)
        if score < FINGERPRINT_CONFIDENCE_THRESHOLD:
            continue
        results.append({
            "product": product,
            "confidence": round(score, 3),
            "match_reasons": info["reasons"],
            "signal_count": info["signal_count"],
        })

    results.sort(key=lambda x: -x["confidence"])
    results = results[:TOP_K_PRODUCTS]

    # Enrich with CVEs and PoCs
    if results:
        with driver.session() as session:
            for r in results:
                r["cves"] = get_product_cves(driver, r["product"])
                if r["cves"]:
                    r["best_cve"] = r["cves"][0]
                    r["best_poc"] = get_poc_for_cve(driver, r["cves"][0]["cve_id"])
                else:
                    r["best_cve"] = {}
                    r["best_poc"] = {}

    return results


def _match_fulltext(session, query, candidates, source, base_confidence):
    """Search BB_Fingerprint fulltext index and update candidates."""
    safe_query = re.sub(r'[^\w\s\-./]', ' ', query).strip()
    if not safe_query or len(safe_query) < 2:
        return

    try:
        result = session.run(
            """CALL db.index.fulltext.queryNodes('bb_fingerprint_text', $q)
               YIELD node, score
               WHERE score > 0.5
               WITH node, score LIMIT 10
               MATCH (p:BB_Product)-[:BB_IDENTIFIED_BY]->(node)
               RETURN p.name AS product, score, node.pattern AS pattern""",
            q=safe_query,
        )
        for record in result:
            product = record["product"]
            ft_score = record["score"]
            conf = base_confidence * min(ft_score / 2.0, 1.0)
            candidates[product]["score"] = max(candidates[product]["score"], conf)
            candidates[product]["reasons"].append(f"{source}:{record['pattern'][:50]}")
            candidates[product]["signal_count"] += 1
    except Exception:
        pass


def _match_body_patterns(session, body_text, candidates):
    """Check if any BB_Fingerprint body_pattern appears in probe body text."""
    try:
        result = session.run(
            """MATCH (p:BB_Product)-[:BB_IDENTIFIED_BY]->(f:BB_Fingerprint)
               WHERE f.type = 'body_pattern'
                 AND size(f.pattern) > 3
                 AND $body CONTAINS f.pattern
               RETURN p.name AS product, f.pattern AS pattern
               LIMIT 5""",
            body=body_text,
        )
        for record in result:
            product = record["product"]
            candidates[product]["score"] = max(candidates[product]["score"], 0.72)
            candidates[product]["reasons"].append(f"body:{record['pattern'][:40]}")
            candidates[product]["signal_count"] += 1
    except Exception:
        pass


def _match_product_name(session, title, server, candidates):
    """Direct substring match: if a product name appears in title or server."""
    combined = (title + " " + server).lower()
    if len(combined.strip()) < 3:
        return
    try:
        result = session.run(
            """MATCH (p:BB_Product)
               WHERE toLower($text) CONTAINS p.name
                 AND size(p.name) > 2
               RETURN p.name AS product
               LIMIT 10""",
            text=combined,
        )
        for record in result:
            product = record["product"]
            conf = 0.85 if product in title.lower() else 0.60
            candidates[product]["score"] = max(candidates[product]["score"], conf)
            candidates[product]["reasons"].append(f"name_in_text:{product}")
            candidates[product]["signal_count"] += 1
    except Exception:
        pass


def get_product_cves(driver, product_name):
    """Get all CVEs for a product, ordered by severity."""
    sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    with driver.session() as session:
        result = session.run(
            """MATCH (p:BB_Product {name: $name})-[:BB_HAS_CVE]->(cve:BB_CVE)
               RETURN cve.cve_id AS cve_id, cve.name AS name,
                      cve.severity AS severity, cve.type AS type,
                      cve.type_cn AS type_cn, cve.description AS description,
                      cve.cwe_id AS cwe_id, cve.vulhub_env AS vulhub_env
               ORDER BY CASE cve.severity
                   WHEN 'critical' THEN 4
                   WHEN 'high' THEN 3
                   WHEN 'medium' THEN 2
                   WHEN 'low' THEN 1
                   ELSE 0
               END DESC""",
            name=product_name,
        )
        return [dict(r) for r in result]


def get_poc_for_cve(driver, cve_id):
    """Get PoC details for a specific CVE."""
    with driver.session() as session:
        result = session.run(
            """MATCH (cve:BB_CVE {cve_id: $cve_id})-[:BB_HAS_POC]->(poc:BB_PoC)
               RETURN poc.method AS method, poc.path AS path,
                      poc.headers AS headers, poc.body AS body,
                      poc.matcher_words AS matcher_words,
                      poc.matcher_status AS matcher_status,
                      poc.source AS source, poc.template_id AS template_id,
                      poc.readme_poc AS readme_poc
               LIMIT 3""",
            cve_id=cve_id,
        )
        pocs = [dict(r) for r in result]
        return pocs[0] if pocs else {}


def multi_hop_query(driver, fingerprint):
    """
    Full reasoning chain: fingerprint → Product → CVE → PoC.
    Returns the best match with complete attack information.
    """
    products = identify_product(driver, fingerprint)
    if not products:
        return None

    best = products[0]
    return {
        "product": best["product"],
        "confidence": best["confidence"],
        "match_reasons": best["match_reasons"],
        "cve": best.get("best_cve", {}),
        "poc": best.get("best_poc", {}),
        "all_candidates": [
            {"product": p["product"], "confidence": p["confidence"]}
            for p in products
        ],
    }
