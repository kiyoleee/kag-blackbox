#!/usr/bin/env python3
"""
Multi-tool fingerprint scanner v2 — active probing with vulhub_fingerprints.

Key changes from v1:
  1. Active probing: for each fingerprint file, probe its unique_paths (not just homepage)
  2. Version extraction: use version_regex from fingerprint to extract exact version
  3. Multi-CVE disambiguation: when product matches, test each CVE's detection.path
  4. All via Traefik port 80 (confirmed all services route through Host header)

Usage:
  python3 fingerprint_scan_v2.py --targets targets.txt --output fingerprints.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


TUNNEL_PORT = 18080  # SSH tunnel to Traefik
FP_DIR = "/opt/vulhub_fingerprints"
REQUEST_TIMEOUT = 10


def curl_probe(host, path="/", port=None, headers=None):
    """HTTP probe via Traefik tunnel with Host header."""
    p = port or TUNNEL_PORT
    url = f"http://127.0.0.1:{p}{path}"
    cmd = ["curl", "-s", "-i", "-H", f"Host: {host}",
           "--connect-timeout", "5", "--max-time", str(REQUEST_TIMEOUT), url]
    if headers:
        for k, v in headers.items():
            if k.lower() != "host":
                cmd.extend(["-H", f"{k}: {v}"])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=REQUEST_TIMEOUT + 3)
        raw = proc.stdout
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) != 2:
            parts = raw.split("\n\n", 1)
        resp_headers = parts[0] if parts else raw
        resp_body = parts[1] if len(parts) > 1 else ""
        status = 0
        m = re.search(r"(\d{3})", resp_headers.split("\n")[0] if resp_headers else "")
        if m:
            status = int(m.group(1))
        return {"status": status, "headers": resp_headers, "body": resp_body, "curl": " ".join(cmd)}
    except Exception:
        return {"status": 0, "headers": "", "body": "", "curl": " ".join(cmd)}


def load_fingerprints(fp_dir):
    """Load all vulhub fingerprint JSON files, grouped by product."""
    by_product = {}
    all_fps = []
    for fname in os.listdir(fp_dir):
        if not fname.endswith(".json") or fname.startswith("_"):
            continue
        try:
            with open(os.path.join(fp_dir, fname)) as f:
                fp = json.load(f)
            app = (fp.get("app") or "").lower()
            if app:
                by_product.setdefault(app, []).append(fp)
                all_fps.append(fp)
        except (json.JSONDecodeError, IOError):
            pass
    return all_fps, by_product


def match_target(host, all_fps, by_product):
    """
    Active fingerprint matching for a single target.

    Strategy:
      Phase 1: Quick homepage probe → extract server/title/body
      Phase 2: Match against all fingerprint files using title/body_keywords/cookies
      Phase 3: For matched products, probe unique_paths to confirm
      Phase 4: Extract version using version_regex
      Phase 5: If multiple CVEs for same product, test detection.path to disambiguate
    """
    result = {
        "host": host,
        "server": "",
        "title": "",
        "cookies": [],
        "homepage_status": 0,
        "matched_product": None,
        "matched_cve": None,
        "all_matches": [],
        "version": None,
        "detection_verified": False,
    }

    # ── Phase 1: Homepage probe ──
    home = curl_probe(host, "/")
    result["homepage_status"] = home["status"]

    for line in home["headers"].split("\n"):
        ll = line.lower().strip()
        if ll.startswith("server:"):
            result["server"] = line.split(":", 1)[1].strip()
        elif ll.startswith("set-cookie:"):
            result["cookies"].append(line.split(":", 1)[1].strip().split(";")[0])

    m = re.search(r"<title>(.*?)</title>", home["body"], re.I | re.S)
    if m:
        result["title"] = m.group(1).strip()[:200]

    full_response = (home["headers"] + "\n" + home["body"]).lower()

    # ── Phase 2: Score all fingerprint files ──
    candidates = []
    for fp in all_fps:
        ident = fp.get("identification") or {}
        score = 0
        reasons = []

        # Title match (highest signal)
        for title_pat in (ident.get("http_title") or []):
            if title_pat.lower() in full_response:
                score += 5
                reasons.append(f"title:{title_pat}")

        # Body keywords
        for kw in (ident.get("body_keywords") or []):
            if kw.lower() in full_response:
                score += 2
                reasons.append(f"body:{kw}")

        # Cookies
        for cookie_pat in (ident.get("cookies") or []):
            for actual_cookie in result["cookies"]:
                if cookie_pat.lower() in actual_cookie.lower():
                    score += 4
                    reasons.append(f"cookie:{cookie_pat}")

        # Server header
        for srv_pat in (ident.get("server_header") or []):
            if srv_pat.lower() in result["server"].lower():
                score += 2
                reasons.append(f"server:{srv_pat}")

        if score >= 3:
            candidates.append({
                "fp": fp,
                "score": score,
                "reasons": reasons,
            })

    candidates.sort(key=lambda x: -x["score"])

    # ── Phase 3: Active path probing for top candidates ──
    confirmed_candidates = []
    tested_products = set()

    for cand in candidates[:10]:
        fp = cand["fp"]
        app = (fp.get("app") or "").lower()
        if app in tested_products:
            continue
        tested_products.add(app)

        ident = fp.get("identification") or {}
        unique_paths = ident.get("unique_paths") or []
        path_hits = 0

        for upath in unique_paths[:5]:
            probe = curl_probe(host, upath)
            if probe["status"] > 0 and probe["status"] < 404:
                path_hits += 1
                cand["score"] += 3
                cand["reasons"].append(f"path_hit:{upath}→{probe['status']}")

                # Also check body for more keywords
                probe_body = probe["body"].lower()
                for kw in (ident.get("body_keywords") or []):
                    if kw.lower() in probe_body and f"body:{kw}" not in cand["reasons"]:
                        cand["score"] += 1
                        cand["reasons"].append(f"path_body:{kw}")

        if path_hits > 0 or cand["score"] >= 5:
            confirmed_candidates.append(cand)

    # If no confirmed candidates, fall back to homepage-only matches
    if not confirmed_candidates and candidates:
        confirmed_candidates = candidates[:3]

    if not confirmed_candidates:
        return result

    # ── Phase 4: Version extraction ──
    best = confirmed_candidates[0]
    best_fp = best["fp"]
    app = (best_fp.get("app") or "").lower()
    ident = best_fp.get("identification") or {}

    # Try version_regex on all responses
    version = None
    version_regexes = ident.get("version_regex") or []
    # Collect all response bodies
    all_bodies = home["body"]
    for upath in (ident.get("unique_paths") or [])[:3]:
        p = curl_probe(host, upath)
        if p["body"]:
            all_bodies += "\n" + p["body"]

    for vr in version_regexes:
        try:
            vm = re.search(vr, all_bodies, re.I)
            if vm:
                version = vm.group(1) if vm.lastindex else vm.group(0)
                break
        except re.error:
            pass
    result["version"] = version

    # ── Phase 5: CVE disambiguation ──
    # Get all fingerprint files for this product
    product_fps = by_product.get(app, [best_fp])
    best_cve_fp = best_fp
    best_detection_score = 0

    if len(product_fps) > 1:
        # Test each CVE's detection path
        for pfp in product_fps:
            detection = pfp.get("detection") or {}
            det_path = detection.get("path", "")
            det_method = detection.get("method", "GET")
            det_headers = detection.get("request_headers") or {}
            match_indicators = detection.get("match_indicators") or []

            if det_path:
                probe = curl_probe(host, det_path, headers=det_headers)
                det_score = 0

                if probe["status"] > 0:
                    det_score += 1
                    # Check match indicators
                    probe_text = (probe["headers"] + "\n" + probe["body"]).lower()
                    for indicator in match_indicators:
                        if isinstance(indicator, str) and indicator.lower() in probe_text:
                            det_score += 3

                if det_score > best_detection_score:
                    best_detection_score = det_score
                    best_cve_fp = pfp
                    result["detection_verified"] = det_score >= 2

        # If version available, try to match affected_versions
        if version and best_detection_score == 0:
            for pfp in product_fps:
                av = pfp.get("affected_versions", "")
                if av and version in av:
                    best_cve_fp = pfp
                    break

    # ── Build result ──
    cves = best_cve_fp.get("cve") or []
    result["matched_product"] = app
    result["matched_cve"] = {
        "id": best_cve_fp.get("id", ""),
        "app": best_cve_fp.get("app", ""),
        "cve": cves,
        "cwe": best_cve_fp.get("cwe", ""),
        "vuln_class": best_cve_fp.get("vuln_class", ""),
        "severity": best_cve_fp.get("severity", ""),
        "affected_versions": best_cve_fp.get("affected_versions", ""),
        "detection": best_cve_fp.get("detection", {}),
        "score": best["score"],
        "reasons": best["reasons"],
    }
    result["all_matches"] = [
        {"app": c["fp"].get("app",""), "score": c["score"],
         "cve": (c["fp"].get("cve") or [None])[0]}
        for c in confirmed_candidates[:5]
    ]

    return result


def scan_target(url, all_fps, by_product):
    """Scan a single target URL."""
    m = re.match(r"http://(t-[a-f0-9]+\.rce\.lab)(?::(\d+))?(/.*)?", url)
    if not m:
        return {"url": url, "error": "invalid URL format"}

    host = m.group(1)
    token = host.split(".")[0]

    t0 = time.time()
    result = match_target(host, all_fps, by_product)
    result["url"] = url
    result["token"] = token
    result["scan_time_sec"] = round(time.time() - t0, 1)

    # Convert to format expected by competition_scanner
    vm = result.get("matched_cve")
    if vm:
        result["vulhub_matches"] = [vm]
    else:
        result["vulhub_matches"] = []

    result["merged_fingerprint"] = {
        "server": result.get("server", ""),
        "title": result.get("title", ""),
        "technologies": [],
        "whatweb_plugins": {},
        "nuclei_detections": [],
        "webtech": [],
        "vulhub_top_match": vm,
    }

    return result


def main():
    parser = argparse.ArgumentParser(description="Fingerprint scanner v2 (active probing)")
    parser.add_argument("--url", help="Single target URL")
    parser.add_argument("--targets", help="File with target URLs")
    parser.add_argument("--output", default="/workspace/fingerprints.json")
    parser.add_argument("--fp-dir", default=FP_DIR, help="Vulhub fingerprints directory")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--tunnel-port", type=int, default=18080)
    args = parser.parse_args()

    global TUNNEL_PORT
    TUNNEL_PORT = args.tunnel_port

    urls = []
    if args.url:
        urls = [args.url]
    elif args.targets:
        with open(args.targets) as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        parser.error("Provide --url or --targets")

    print(f"Loading fingerprints from {args.fp_dir}...")
    all_fps, by_product = load_fingerprints(args.fp_dir)
    print(f"  {len(all_fps)} fingerprint files, {len(by_product)} products")

    print(f"Scanning {len(urls)} targets with {args.workers} workers...")
    results = []

    def _scan(url):
        return scan_target(url, all_fps, by_product)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_scan, url): url for url in urls}
        for i, future in enumerate(as_completed(futures)):
            url = futures[future]
            try:
                r = future.result()
                results.append(r)
                prod = r.get("matched_product", "?")
                cve = r.get("matched_cve", {})
                cve_id = (cve.get("cve") or [""])[0] if cve else ""
                verified = "✓" if r.get("detection_verified") else ""
                print(f"[{i+1}/{len(urls)}] {r.get('token','?')} → {prod} {cve_id} "
                      f"(score={cve.get('score',0) if cve else 0}) {verified} "
                      f"ver={r.get('version','?')} ({r.get('scan_time_sec',0)}s)")
            except Exception as e:
                print(f"[{i+1}/{len(urls)}] {url} → ERROR: {e}")
                results.append({"url": url, "error": str(e)})

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    matched = sum(1 for r in results if r.get("matched_product"))
    verified = sum(1 for r in results if r.get("detection_verified"))
    print(f"\nResults: {len(results)} scanned, {matched} matched, {verified} verified")
    print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
