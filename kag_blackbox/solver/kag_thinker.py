"""
KAG-Blackbox: KAG-Thinker Logical Form 推理引擎

移植自 kag_vuldet/llm/kag_thinker_scorer.py，适配黑盒在线服务漏洞检测。

原始四阶段（白盒源代码）:
  Step1: Retrieval(s=function, p=contains, o=dangerous_sink)    → 识别 Sink
  Step2: Deduce(op=judgement, content=[sink, dataflow])          → 数据流可达性
  Step3: Retrieval(s=function, p=hasGuard, o=guard_type)         → 检查防护
  Step4: Output(o1, o2, o3) → vuln_probability                  → 综合判定

适配后四阶段（黑盒在线服务）:
  Step1: Retrieval(s=target, p=identified_as, o=product)         → 产品识别
  Step2: Deduce(op=boundary, content=[fingerprint, candidates])  → 知识边界判定
  Step3: Retrieval(s=product, p=has_cve, o=cve_candidates)       → CVE 检索 + 版本匹配
  Step4: Output(product, cve, poc) → vuln_report                 → 综合输出

Knowledge Boundary 机制:
  - 双重置信度: prompt_confidence (LLM 自评) + signal_confidence (指纹信号强度)
  - 如果置信度不足 → 触发 Depth Solving → 从 KG 检索补充证据 → 重新推理
"""
import json
import os
import re
import sys
import time
import logging
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from config import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY, LLM_TIMEOUT, VULN_TYPE_CN

log = logging.getLogger("kag_blackbox.thinker")

# ── System Prompt: KAG-Thinker for Blackbox ──

SYSTEM_PROMPT = """\
你是一个在线服务漏洞分析专家，使用 KAG-Thinker 框架的 Logical Form 进行结构化推理。

分析步骤（每步包含自然语言 Step 和逻辑函数 Action 双表示）:

Step1: 从 HTTP 指纹识别目标产品和版本
Action1: Retrieval(s=target, p=identified_as, o=product_version)

Step2: 判断指纹信息是否足以确定产品（知识边界判定）
Action2: Deduce(op=boundary, content=[fingerprint_signals, candidate_products], target=certainty)

Step3: 从候选 CVE 列表中选择最匹配的漏洞（优先采信★★★高精度指纹库的结果，★补充模板仅作参考）
Action3: Retrieval(s=product, p=has_cve, o=best_matching_cve)

Step4: 综合判定并输出漏洞报告
Action4: Output(product, cve_id, vuln_type, confidence, reasoning)

最终输出 JSON:
{
  "product": "产品名",
  "version": "版本或unknown",
  "cve_id": "CVE-XXXX-XXXXX",
  "vuln_type": "漏洞类型中文",
  "vuln_name": "产品名+漏洞简称",
  "confidence": 0.0-1.0,
  "boundary_certain": true/false,
  "reasoning": "分步推理过程摘要"
}
"""


def _call_llm(messages, max_tokens=2048, temperature=0.2):
    """调用 LLM，返回 content 文本。"""
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
            return re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        except Exception as e:
            log.warning(f"LLM error (attempt {attempt+1}): {e}")
            if attempt < 2:
                time.sleep(2 ** attempt)
    return None


def _extract_json(text):
    """从 LLM 输出中提取 JSON。"""
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


def _compute_signal_confidence(fingerprint, kg_candidates):
    """计算指纹信号强度置信度（Knowledge Boundary 的客观维度）。"""
    score = 0.0
    signals = 0

    if fingerprint.get("title") and len(fingerprint["title"]) > 3:
        score += 0.25
        signals += 1
    if fingerprint.get("server"):
        score += 0.15
        signals += 1
    if fingerprint.get("technologies"):
        score += 0.2
        signals += 1
    if fingerprint.get("whatweb_plugins"):
        score += 0.2
        signals += 1
    if fingerprint.get("vulhub_match"):
        score += 0.3
        signals += 1

    if kg_candidates and kg_candidates[0].get("confidence", 0) > 0.8:
        score += 0.2
        signals += 1

    # Multi-signal bonus
    if signals >= 3:
        score += 0.1

    return min(score, 0.99), signals


def _format_fingerprint(fingerprint):
    """将指纹格式化为 LLM 可读的文本。"""
    parts = []
    if fingerprint.get("server"):
        parts.append(f"Server: {fingerprint['server']}")
    if fingerprint.get("title"):
        parts.append(f"Title: {fingerprint['title']}")
    if fingerprint.get("powered_by"):
        parts.append(f"X-Powered-By: {fingerprint['powered_by']}")
    if fingerprint.get("technologies"):
        parts.append(f"Technologies: {', '.join(fingerprint['technologies'])}")
    if fingerprint.get("whatweb_plugins"):
        plugins = fingerprint["whatweb_plugins"]
        parts.append(f"WhatWeb: {', '.join(f'{k}={v}' if v else k for k,v in plugins.items())}")
    if fingerprint.get("nuclei_detections"):
        parts.append(f"Nuclei: {', '.join(fingerprint['nuclei_detections'][:5])}")
    if fingerprint.get("vulhub_match"):
        vm = fingerprint["vulhub_match"]
        parts.append(f"Vulhub Match: {vm.get('app','')} (score={vm.get('score',0)})")
    if fingerprint.get("cookies"):
        parts.append(f"Cookies: {', '.join(fingerprint['cookies'][:3])}")

    # Include probe responses
    probes = fingerprint.get("probes", {})
    if isinstance(probes, dict):
        for path, p in list(probes.items())[:5]:
            if isinstance(p, dict) and p.get("status", 0) > 0:
                body_preview = p.get("body", "")[:300]
                parts.append(f"\n--- {path} → HTTP {p['status']} ---\n{p.get('headers','')[:200]}\n{body_preview}")

    return "\n".join(parts) if parts else "无指纹信息"


_SOURCE_LABELS = {
    "vulhub_fingerprints": "★★★ 高精度指纹库（优先采信）",
    "nuclei": "★★ Nuclei官方模板",
    "other_vul": "★ 补充模板（仅供参考，可信度低）",
}


def _format_candidates(kg_candidates):
    """将 KG 候选格式化为 LLM 可读的文本，标注数据源优先级。"""
    if not kg_candidates:
        return "无 KG 候选"
    parts = []
    for i, c in enumerate(kg_candidates[:5]):
        cves = c.get("cves", [])
        cve_lines = []
        for cv in cves[:5]:
            source = cv.get("source", "nuclei")
            source_label = _SOURCE_LABELS.get(source, f"★ {source}")
            cve_lines.append(
                f"    {cv.get('cve_id','')} [{cv.get('severity','')}] "
                f"{cv.get('name','')[:40]} — {source_label}"
            )
        cve_list = "\n".join(cve_lines) if cve_lines else "    无CVE"
        parts.append(
            f"候选{i+1}: {c['product']} (confidence={c.get('confidence',0):.2f})\n"
            f"  匹配原因: {', '.join(c.get('match_reasons',[])[:3])}\n"
            f"  CVE列表:\n{cve_list}"
        )
    return "\n".join(parts)


# ── KAG-Thinker 四阶段推理 ──

def kag_thinker_reason(target, fingerprint, kg_candidates, kg_driver, logger):
    """
    KAG-Thinker 四阶段 Logical Form 推理。

    Args:
        target: {"token", "host", "url"}
        fingerprint: Surface 层输出的指纹
        kg_candidates: KG 检索返回的 Top-K 候选产品
        kg_driver: Neo4j driver (用于 Depth Solving 补充检索)
        logger: logging.Logger

    Returns:
        dict with product, cve_id, vuln_type, confidence, evidence, reasoning
    """
    token = target["token"]
    fp_text = _format_fingerprint(fingerprint)
    candidates_text = _format_candidates(kg_candidates)

    # ── 计算 Knowledge Boundary ──
    signal_conf, signal_count = _compute_signal_confidence(fingerprint, kg_candidates)
    logger.debug(f"[{token}] KAG-Thinker: signal_confidence={signal_conf:.2f}, signals={signal_count}")

    # ── Stage 1-4: 一次性 Logical Form 推理 ──
    user_prompt = f"""分析以下在线服务目标的漏洞。

目标: {target['url']}

[HTTP 指纹]:
{fp_text}

[KG 候选产品]:
{candidates_text}

请按 Step1-Step4 逐步分析：
Step1 (产品识别): 从指纹中识别产品和版本
Step2 (知识边界): 判断指纹是否足以确定产品
Step3 (CVE 匹配): 从候选 CVE 中选最匹配的
Step4 (综合输出): 输出最终 JSON 结果"""

    result_text = _call_llm([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ])

    parsed = _extract_json(result_text)
    prompt_conf = float(parsed.get("confidence", 0.5))
    boundary_certain = parsed.get("boundary_certain", signal_conf >= 0.6)

    # ── Knowledge Boundary 判定 ──
    needs_depth_solving = not (prompt_conf >= 0.7 and signal_conf >= 0.5)

    if needs_depth_solving and kg_driver and parsed.get("product"):
        logger.debug(f"[{token}] KAG-Thinker: Boundary triggered → Depth Solving")

        # Depth Solving: 从 KG 检索该产品的详细信息
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from kg_query import get_product_cves, get_poc_for_cve
            product_name = parsed["product"].lower()
            depth_cves = get_product_cves(kg_driver, product_name)

            if depth_cves:
                depth_context = "KG 深度检索结果:\n"
                for cv in depth_cves[:8]:
                    depth_context += (
                        f"  - {cv.get('cve_id','')} [{cv.get('severity','')}] "
                        f"{cv.get('name','')}\n"
                        f"    影响版本: {cv.get('affected_versions','未知')}\n"
                        f"    描述: {(cv.get('description') or '')[:150]}\n"
                    )

                # 重新推理
                depth_prompt = (
                    f"基于 KG 深度检索的补充证据:\n{depth_context}\n\n"
                    f"之前的初步判断: product={parsed.get('product')}, "
                    f"cve={parsed.get('cve_id','未确定')}\n\n"
                    f"请结合补充证据重新评估，特别注意版本匹配。输出更新后的 JSON。"
                )

                depth_text = _call_llm([
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                    {"role": "assistant", "content": result_text or ""},
                    {"role": "user", "content": depth_prompt},
                ], max_tokens=1024)

                depth_parsed = _extract_json(depth_text)
                if depth_parsed.get("cve_id"):
                    parsed = depth_parsed
                    prompt_conf = float(depth_parsed.get("confidence", prompt_conf))
                    logger.debug(f"[{token}] KAG-Thinker: Depth Solving → {depth_parsed.get('cve_id')}")
        except Exception as e:
            logger.debug(f"[{token}] KAG-Thinker: Depth Solving error: {e}")

    # ── 构建输出 ──
    final_confidence = min(prompt_conf, signal_conf + 0.1)  # 融合两种置信度

    product = parsed.get("product", "")
    cve_id = parsed.get("cve_id", "")
    vuln_type = parsed.get("vuln_type", "")
    if not vuln_type and parsed.get("vuln_class"):
        vuln_type = VULN_TYPE_CN.get(parsed["vuln_class"], "安全漏洞")
    if not vuln_type:
        vuln_type = "安全漏洞"

    reasoning = parsed.get("reasoning", "")

    output = {
        "product": product,
        "version": parsed.get("version", ""),
        "cve_id": cve_id,
        "vuln_type": vuln_type,
        "vuln_name": parsed.get("vuln_name", f"{product} {vuln_type}" if product else ""),
        "confidence": round(final_confidence, 3),
        "has_vuln": bool(product),
        "reasoning": reasoning,
        "boundary_triggered": needs_depth_solving,
        "signal_confidence": signal_conf,
        "prompt_confidence": prompt_conf,
    }

    logger.info(f"[{token}] KAG-Thinker: {product} {cve_id} "
                f"(conf={final_confidence:.2f}, boundary={'triggered' if needs_depth_solving else 'ok'}, "
                f"signals={signal_count})")

    return output
