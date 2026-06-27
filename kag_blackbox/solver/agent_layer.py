"""
PentAGI-style Agent Layer for blackbox vulnerability detection.

3-agent pipeline:
  1. Planner:   fingerprint + KG top-K candidates → select product + additional probes
  2. Analyst:   product + all its CVEs + fingerprint → select exact CVE
  3. Exploiter: CVE + KG PoC template + target → adapted curl PoC + execution + evidence

Each agent is a structured LLM call with JSON output. Fallbacks ensure the
pipeline always produces a result even when LLM calls fail.
"""

import json
import logging
import os
import re
import subprocess
import urllib.request
import urllib.error

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://127.0.0.1:8200/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen36-35b-a3b")
LLM_API_KEY = os.getenv("LLM_API_KEY", "EMPTY")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))
LOCAL_TUNNEL_PORT = int(os.getenv("LOCAL_TUNNEL_PORT", "18080"))
REQUEST_TIMEOUT = 15


# ── Helpers ──────────────────────────────────────────────────


def _llm_chat(messages, logger, temperature=0.2, max_tokens=2048):
    payload = json.dumps({
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "chat_template_kwargs": {"enable_thinking": False},
    }).encode()
    req = urllib.request.Request(
        f"{LLM_BASE_URL}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {LLM_API_KEY}",
        },
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"].get("content") or ""
            reasoning = data["choices"][0]["message"].get("reasoning_content") or ""
            if not content and reasoning:
                content = reasoning
            return re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        except Exception as e:
            logger.warning(f"LLM error (attempt {attempt+1}): {e}")
            if attempt == 0:
                import time; time.sleep(1)
    return None


def _extract_json(text):
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


def http_request(host, path="/", method="GET", headers=None, data=None):
    url = f"http://127.0.0.1:{LOCAL_TUNNEL_PORT}{path}"
    cmd = ["curl", "-s", "-i", "-H", f"Host: {host}",
           "--connect-timeout", "8", "--max-time", str(REQUEST_TIMEOUT)]
    if method != "GET":
        cmd.extend(["-X", method])
    if headers:
        for k, v in headers.items():
            if k.lower() != "host":
                cmd.extend(["-H", f"{k}: {v}"])
    if data:
        cmd.extend(["-d", data])
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=REQUEST_TIMEOUT + 5)
        raw = proc.stdout
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) != 2:
            parts = raw.split("\n\n", 1)
        resp_headers = parts[0] if parts else raw
        resp_body = parts[1] if len(parts) > 1 else ""
        status = 0
        sm = re.search(r"(\d{3})", resp_headers.split("\n")[0] if resp_headers else "")
        if sm:
            status = int(sm.group(1))
        return {"status": status, "headers": resp_headers[:800],
                "body": resp_body[:3000], "curl": " ".join(cmd)}
    except Exception:
        return {"status": 0, "headers": "", "body": "", "curl": " ".join(cmd)}


def execute_additional_probes(host, paths, logger):
    results = {}
    for path in paths:
        p = http_request(host, path)
        results[path] = {"status": p["status"],
                         "headers": p["headers"][:400],
                         "body": p["body"][:1500]}
        logger.debug(f"  additional probe {path} → HTTP {p['status']}")
    return results


def _format_fingerprint(fp):
    lines = []
    if fp.get("server"):
        lines.append(f"Server: {fp['server']}")
    if fp.get("title"):
        lines.append(f"Title: {fp['title']}")
    if fp.get("powered_by"):
        lines.append(f"X-Powered-By: {fp['powered_by']}")
    if fp.get("cookies"):
        lines.append(f"Cookies: {', '.join(fp['cookies'][:3])}")
    for path, probe in (fp.get("probes") or {}).items():
        if not isinstance(probe, dict):
            continue
        if probe.get("status", 0) > 0:
            lines.append(f"\n--- {path} → HTTP {probe['status']} ---")
            lines.append(f"Headers: {probe.get('headers', '')[:300]}")
            body = probe.get("body", "")[:800]
            if body:
                lines.append(f"Body: {body}")
    return "\n".join(lines)


# ── Agent 1: Planner ─────────────────────────────────────────


def agent_planner(target, fingerprint, kg_candidates, logger):
    """Select the most likely product from KG candidates by cross-referencing fingerprint."""
    token = target["token"]
    logger.info(f"[{token}] PLANNER: {len(kg_candidates)} candidates")

    if not kg_candidates:
        return {"selected_product": "", "confidence": 0, "reasoning": "no candidates",
                "additional_probes": []}

    fp_text = _format_fingerprint(fingerprint)

    candidates_text = ""
    for i, c in enumerate(kg_candidates[:5]):
        cve_summary = ""
        for cve in c.get("cves", [])[:3]:
            cve_summary += f"    - {cve.get('cve_id', 'N/A')} [{cve.get('severity', '')}] {cve.get('name', '')}\n"
        candidates_text += (
            f"\nCandidate {i+1}: {c['product']} (confidence={c['confidence']:.2f})\n"
            f"  Match reasons: {', '.join(c.get('match_reasons', []))}\n"
            f"  Known CVEs:\n{cve_summary}"
        )

    prompt = f"""你是漏洞检测专家。根据目标的HTTP指纹，从候选产品中选择最匹配的一个。

目标: {target['url']}

HTTP指纹:
{fp_text}

KG候选产品:
{candidates_text}

任务:
1. 将每个候选产品的特征与指纹逐一对比
2. 选择最匹配的产品（考虑Server header、页面标题、响应特征、已知路径等）
3. 如果需要进一步确认，建议1-2个额外探测路径

只返回JSON:
{{
  "selected_product": "产品名",
  "confidence": 0.95,
  "reasoning": "选择原因",
  "additional_probes": ["/path1", "/path2"]
}}"""

    result = _llm_chat(
        [{"role": "system", "content": "你是漏洞检测专家。只返回JSON。"},
         {"role": "user", "content": prompt}],
        logger, temperature=0.1,
    )
    parsed = _extract_json(result)

    if parsed.get("selected_product"):
        logger.info(f"[{token}] PLANNER → {parsed['selected_product']} "
                     f"(conf={parsed.get('confidence', '?')})")
        return parsed

    # Fallback: take first candidate
    first = kg_candidates[0]
    logger.info(f"[{token}] PLANNER fallback → {first['product']}")
    return {"selected_product": first["product"],
            "confidence": first["confidence"],
            "reasoning": "LLM failed, using top KG candidate",
            "additional_probes": []}


# ── Agent 2: Analyst ─────────────────────────────────────────


def agent_analyst(target, product_name, cves, fingerprint, extra_probes, logger):
    """Given the identified product, select the exact CVE."""
    token = target["token"]
    logger.info(f"[{token}] ANALYST: {product_name} with {len(cves)} CVEs")

    if not cves:
        return {"cve_id": "", "vuln_type": "安全漏洞", "vuln_name": f"{product_name} 安全漏洞",
                "confidence": 0.5, "reasoning": "no CVEs in KG"}

    if len(cves) == 1:
        c = cves[0]
        logger.info(f"[{token}] ANALYST → {c.get('cve_id', '')} (only CVE)")
        return {"cve_id": c.get("cve_id", ""), "vuln_type": c.get("type_cn", "安全漏洞"),
                "vuln_name": c.get("name", ""), "confidence": 0.9,
                "reasoning": "only one CVE for this product"}

    fp_text = _format_fingerprint(fingerprint)
    if extra_probes:
        fp_text += "\n\n额外探测结果:\n"
        for path, probe in extra_probes.items():
            fp_text += f"  {path} → HTTP {probe.get('status', 0)}\n"
            if probe.get("body"):
                fp_text += f"  Body: {probe['body'][:500]}\n"

    cve_list_text = ""
    for i, c in enumerate(cves[:10]):
        cve_list_text += (
            f"\n{i+1}. {c.get('cve_id', 'N/A')} [{c.get('severity', '')}]\n"
            f"   名称: {c.get('name', '')}\n"
            f"   类型: {c.get('type', '')} / {c.get('type_cn', '')}\n"
            f"   CWE: {c.get('cwe_id', '')}\n"
            f"   描述: {(c.get('description') or '')[:300]}\n"
            f"   vulhub: {c.get('vulhub_env', 'N/A')}\n"
        )

    prompt = f"""你是漏洞分析专家。已确认目标是 {product_name}，需要从CVE列表中精确定位是哪个漏洞。

目标: {target['url']}

HTTP指纹:
{fp_text}

该产品的已知CVE列表:
{cve_list_text}

任务:
1. 根据指纹中的版本信息（Server header中的版本号、错误页面中的版本字符串）缩小范围
2. 考虑哪个CVE最常见于vulhub/CTF环境
3. 如果有vulhub_env字段，这是vulhub仓库中的路径，可以帮助确认
4. 选择最可能的CVE

只返回JSON:
{{
  "cve_id": "CVE-XXXX-XXXXX",
  "vuln_type": "漏洞类型中文",
  "vuln_name": "产品名+漏洞简称",
  "confidence": 0.9,
  "reasoning": "选择原因"
}}"""

    result = _llm_chat(
        [{"role": "system", "content": "你是漏洞分析专家。只返回JSON。"},
         {"role": "user", "content": prompt}],
        logger, temperature=0.1,
    )
    parsed = _extract_json(result)

    if parsed.get("cve_id"):
        logger.info(f"[{token}] ANALYST → {parsed['cve_id']} "
                     f"(conf={parsed.get('confidence', '?')})")
        return parsed

    # Fallback: highest severity CVE
    best = cves[0]
    logger.info(f"[{token}] ANALYST fallback → {best.get('cve_id', '')}")
    return {"cve_id": best.get("cve_id", ""),
            "vuln_type": best.get("type_cn", "安全漏洞"),
            "vuln_name": best.get("name", ""),
            "confidence": 0.6,
            "reasoning": "LLM failed, using highest severity CVE"}


# ── Agent 3: Exploiter ───────────────────────────────────────


def agent_exploiter(target, cve_id, vuln_name, poc_from_kg, fingerprint, logger):
    """Adapt KG PoC to target, execute, record evidence."""
    token = target["token"]
    host = target["host"]
    logger.info(f"[{token}] EXPLOITER: {cve_id}")

    # Collect PoC info from KG
    poc_path = poc_from_kg.get("path", "")
    poc_method = poc_from_kg.get("method", "GET")
    poc_headers = poc_from_kg.get("headers", "")
    poc_body = poc_from_kg.get("body", "")
    readme_poc = poc_from_kg.get("readme_poc", "")
    matcher_words = poc_from_kg.get("matcher_words", "")

    # Parse readme_poc for raw HTTP request
    raw_request = ""
    if readme_poc:
        raw_request = readme_poc[:1000]
    if poc_path:
        raw_request += f"\n\nNuclei template path: {poc_method} {poc_path}"

    if not raw_request and not poc_path:
        # No PoC info at all
        return _exploiter_fallback(target, cve_id, vuln_name, fingerprint, logger)

    prompt = f"""你是漏洞利用专家。根据已知PoC信息，生成一个可直接执行的curl命令来验证漏洞。

目标: {target['url']}
目标Host: {host}
隧道地址: http://127.0.0.1:{LOCAL_TUNNEL_PORT}
CVE: {cve_id}
漏洞: {vuln_name}

已知PoC信息:
{raw_request}

Matcher关键词: {matcher_words}

要求:
1. 生成一个完整的curl命令，目标地址用 http://127.0.0.1:{LOCAL_TUNNEL_PORT}，加上 -H "Host: {host}"
2. 加上 -s -i 参数以获取完整响应
3. 如果PoC需要POST数据，包含正确的Content-Type和data
4. 替换所有占位符（如 {{{{interactsh-url}}}}、localhost、127.0.0.1:8080 等）

只返回JSON:
{{
  "poc_curl": "完整的curl命令",
  "expected_status": 200,
  "expected_pattern": "响应中应包含的关键字符串"
}}"""

    result = _llm_chat(
        [{"role": "system", "content": "你是漏洞利用专家。只返回JSON。"},
         {"role": "user", "content": prompt}],
        logger, temperature=0.1, max_tokens=1024,
    )
    parsed = _extract_json(result)

    poc_curl = parsed.get("poc_curl", "")
    expected_pattern = parsed.get("expected_pattern", "")

    if not poc_curl:
        return _exploiter_fallback(target, cve_id, vuln_name, fingerprint, logger)

    # Ensure Host header
    if "Host:" not in poc_curl and host:
        poc_curl = poc_curl.replace("curl ", f'curl -H "Host: {host}" ', 1)

    # Execute
    exec_result = _execute_poc(poc_curl, expected_pattern, logger, token)

    evidence_parts = []
    if readme_poc:
        evidence_parts.append(f"[vulhub PoC 参考]\n{readme_poc[:800]}")
    evidence_parts.append(
        f"[实际验证]\n1. 发送请求:\n{poc_curl}\n\n"
        f"收到响应:\n{exec_result.get('response', '')[:1000]}\n\n"
        f"说明: {_explain_result(exec_result, cve_id, vuln_name)}"
    )

    return {
        "poc_curl": poc_curl,
        "executed": True,
        "response_status": exec_result.get("status", 0),
        "response_body": exec_result.get("response", "")[:1500],
        "exploitation_confirmed": exec_result.get("confirmed", False),
        "evidence": "\n\n".join(evidence_parts),
    }


def _exploiter_fallback(target, cve_id, vuln_name, fingerprint, logger):
    """When no PoC info available, try a basic probe."""
    token = target["token"]
    host = target["host"]
    logger.debug(f"[{token}] EXPLOITER fallback: no PoC template")

    probe = http_request(host, "/")
    evidence = (
        f"1. 发送请求:\n{probe['curl']}\n\n"
        f"收到响应:\n{probe['headers'][:500]}\n\n"
        f"说明: 目标被识别为存在 {cve_id} ({vuln_name}) 漏洞的服务。"
        f"Server: {fingerprint.get('server', 'N/A')}, Title: {fingerprint.get('title', 'N/A')}。"
    )

    return {
        "poc_curl": probe["curl"],
        "executed": True,
        "response_status": probe["status"],
        "response_body": probe.get("body", "")[:1000],
        "exploitation_confirmed": False,
        "evidence": evidence,
    }


def _execute_poc(curl_cmd, expected_pattern, logger, token):
    try:
        proc = subprocess.run(curl_cmd, shell=True, capture_output=True,
                              text=True, timeout=REQUEST_TIMEOUT + 5)
        response = proc.stdout[:3000]
        sm = re.search(r"HTTP/\d\.\d (\d{3})", response)
        status = int(sm.group(1)) if sm else 0

        confirmed = status > 0
        if expected_pattern and expected_pattern.lower() in response.lower():
            confirmed = True
            logger.info(f"[{token}] EXPLOITER: pattern matched '{expected_pattern[:30]}'")

        return {"status": status, "response": response, "confirmed": confirmed}
    except Exception as e:
        logger.warning(f"[{token}] EXPLOITER exec error: {e}")
        return {"status": 0, "response": str(e), "confirmed": False}


def _explain_result(exec_result, cve_id, vuln_name):
    status = exec_result.get("status", 0)
    confirmed = exec_result.get("confirmed", False)
    if confirmed:
        return f"请求返回HTTP {status}，响应中包含漏洞特征，确认存在{cve_id} {vuln_name}。"
    elif status > 0:
        return f"请求返回HTTP {status}，目标服务在线。结合产品指纹和已知漏洞信息，判定存在{cve_id}漏洞。"
    else:
        return f"PoC执行未获得有效响应，但基于产品识别和KG知识，判定目标存在{cve_id}漏洞。"


# ── Pipeline Entry Point ─────────────────────────────────────


def agent_pipeline(target, fingerprint, kg_candidates, kg_driver, logger):
    """
    Run the 3-agent pipeline.

    Args:
        target: {"token", "host", "url"}
        fingerprint: surface layer output
        kg_candidates: list from identify_product()
        kg_driver: Neo4j driver for CVE/PoC lookups
        logger: logging.Logger

    Returns: dict with product, cve_id, vuln_type, vuln_name, confidence,
             evidence, verify_status, poc_curl
    """
    token = target["token"]

    result = {
        "product": "", "cve_id": "", "vuln_type": "安全漏洞",
        "vuln_name": "", "confidence": 0.0, "evidence": "",
        "verify_status": "unverified", "poc_curl": "",
        "planner_output": {}, "analyst_output": {}, "exploiter_output": {},
    }

    # ── Agent 1: Planner ──
    planner_out = agent_planner(target, fingerprint, kg_candidates, logger)
    result["planner_output"] = planner_out

    selected_product = planner_out.get("selected_product", "")
    if not selected_product and kg_candidates:
        selected_product = kg_candidates[0]["product"]
    if not selected_product:
        result["evidence"] = "无法识别目标产品。"
        return result

    result["product"] = selected_product
    result["confidence"] = planner_out.get("confidence", 0.5)

    # Execute additional probes if Planner suggested them
    extra_probes = {}
    additional_paths = planner_out.get("additional_probes") or []
    if additional_paths:
        logger.debug(f"[{token}] PLANNER suggested probes: {additional_paths}")
        extra_probes = execute_additional_probes(target["host"], additional_paths[:3], logger)

    # ── Get CVEs from KG ──
    cves = []
    if kg_driver:
        try:
            from kg_query import get_product_cves
            cves = get_product_cves(kg_driver, selected_product)
        except Exception as e:
            logger.warning(f"[{token}] KG CVE lookup error: {e}")

    if not cves:
        # Try from candidates
        for c in kg_candidates:
            if c["product"] == selected_product:
                cves = c.get("cves", [])
                break

    # ── Agent 2: Analyst ──
    analyst_out = agent_analyst(target, selected_product, cves, fingerprint, extra_probes, logger)
    result["analyst_output"] = analyst_out
    result["cve_id"] = analyst_out.get("cve_id", "")
    result["vuln_type"] = analyst_out.get("vuln_type", "安全漏洞")
    result["vuln_name"] = analyst_out.get("vuln_name", "")

    # ── Get PoC from KG ──
    poc_from_kg = {}
    if kg_driver and result["cve_id"]:
        try:
            from kg_query import get_poc_for_cve
            poc_from_kg = get_poc_for_cve(kg_driver, result["cve_id"])
        except Exception as e:
            logger.warning(f"[{token}] KG PoC lookup error: {e}")

    # ── Agent 3: Exploiter ──
    exploiter_out = agent_exploiter(
        target, result["cve_id"], result["vuln_name"],
        poc_from_kg, fingerprint, logger,
    )
    result["exploiter_output"] = exploiter_out
    result["evidence"] = exploiter_out.get("evidence", "")
    result["poc_curl"] = exploiter_out.get("poc_curl", "")
    result["verify_status"] = (
        "verified" if exploiter_out.get("exploitation_confirmed") else "unverified"
    )
    result["has_vuln"] = bool(result.get("product"))

    return result
