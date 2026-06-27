#!/usr/bin/env python3
"""
Evaluation script for vulnerability scanning frameworks.
Reads framework output + ground-truth-292.csv, computes precision, recall, F1.
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime


GROUND_TRUTH_FILE = "/data/lqy/testinfo/vulhub-300/ground-truth-292.csv"


def load_ground_truth(gt_file: str) -> dict:
    gt = {}
    with open(gt_file, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt[row["token"]] = {
                "token": row["token"],
                "blind_url": row["blind_url"],
                "product": row.get("product", ""),
                "expected_cve": row.get("expected_cve", ""),
                "expected_class": row.get("expected_class", ""),
                "expected_cwe": row.get("expected_cwe", ""),
                "accept_synonyms": row.get("accept_synonyms", ""),
                "scoring_note": row.get("scoring_note", ""),
                "official_vuln_desc": row.get("official_vuln_desc", ""),
            }
    return gt


def _extract_token(url_or_text: str) -> str:
    m = re.search(r"(t-[a-f0-9]+)", url_or_text)
    return m.group(1) if m else ""


def _load_json_data(path: str) -> dict:
    """Load a JSON file and return parsed results dict keyed by token.

    Handles three formats:
      1. {"results": [...]}  -- internal scan_results.json from either framework
      2. [{"序号":..., "目标资产":..., ...}, ...]  -- competition output JSON array
      3. {"scan_time":..., "results":[...]}  -- variant of (1)
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    results = {}

    if isinstance(data, list):
        # Competition output format (JSON array)
        for row in data:
            url = row.get("目标资产", "")
            token = _extract_token(url)
            if not token:
                continue
            results[token] = {
                "has_vuln": row.get("是否存在漏洞", "") == "是",
                "claimed_cve": (row.get("漏洞编号", "") or "").upper(),
                "claimed_class": row.get("漏洞类型", ""),
                "claimed_type": "",
            }
        return results

    # Dict format -- look for "results" key
    items = data.get("results", [])
    for r in items:
        token = r.get("token", "")
        if not token:
            # Try extracting from URL fields
            for url_key in ("url", "host", "目标资产"):
                if url_key in r:
                    token = _extract_token(str(r[url_key]))
                    if token:
                        break
        if not token:
            continue

        has_vuln = False
        claimed_cve = ""
        claimed_class = ""
        claimed_type = ""

        # LLM agent format
        if "has_vuln" in r:
            has_vuln = r["has_vuln"]
            claimed_cve = r.get("cve_id", "")
            claimed_class = r.get("vuln_type", "")
            claimed_type = r.get("vuln_name", "")

        # Nuclei format
        elif "findings" in r:
            findings = r.get("findings", [])
            if findings:
                has_vuln = True
                best = findings[0]
                claimed_cve = best.get("cve_id", "")
                claimed_class = best.get("name", "")
                claimed_type = ""
                for t in best.get("tags", []):
                    if t.strip().upper().startswith("CVE-"):
                        claimed_cve = t.strip().upper()
                        break

        # Competition-style keys inside results list
        elif "是否存在漏洞" in r:
            has_vuln = r.get("是否存在漏洞", "") == "是"
            claimed_cve = (r.get("漏洞编号", "") or "").upper()
            claimed_class = r.get("漏洞类型", "")

        results[token] = {
            "has_vuln": has_vuln,
            "claimed_cve": claimed_cve.upper() if claimed_cve else "",
            "claimed_class": claimed_class,
            "claimed_type": claimed_type,
        }

    return results


def load_framework_results(results_path: str) -> dict:
    """Load framework results from a file or directory, return dict keyed by token."""

    # If it's a file, load it directly
    if os.path.isfile(results_path):
        if results_path.endswith(".json"):
            return _load_json_data(results_path)
        if results_path.endswith(".csv"):
            return _load_csv_data(results_path)
        # Try JSON first, then CSV
        try:
            return _load_json_data(results_path)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _load_csv_data(results_path)

    # It's a directory -- try known filenames in order
    results = {}
    for candidate in ("scan_results.json", "competition_output.json"):
        json_file = os.path.join(results_path, candidate)
        if os.path.isfile(json_file):
            results = _load_json_data(json_file)
            if results:
                return results

    csv_file = os.path.join(results_path, "competition_output.csv")
    if os.path.isfile(csv_file) and not results:
        results = _load_csv_data(csv_file)

    return results


def _load_csv_data(csv_path: str) -> dict:
    results = {}
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("目标资产", "")
            token = _extract_token(url)
            if token:
                results[token] = {
                    "has_vuln": row.get("是否存在漏洞", "") == "是",
                    "claimed_cve": (row.get("漏洞编号", "") or "").upper(),
                    "claimed_class": row.get("漏洞类型", ""),
                    "claimed_type": "",
                }
    return results


def normalize_cve(cve: str) -> str:
    if not cve:
        return ""
    cve = cve.strip().upper()
    m = re.match(r"(CVE-\d{4}-\d+)", cve)
    return m.group(1) if m else cve


def match_class(claimed_class: str, expected_class: str, accept_synonyms: str) -> bool:
    if not expected_class:
        return True

    claimed_lower = claimed_class.lower()
    expected_lower = expected_class.lower()

    if expected_lower in claimed_lower or claimed_lower in expected_lower:
        return True

    if accept_synonyms:
        synonyms = [s.strip().lower() for s in accept_synonyms.split(";")]
        for syn in synonyms:
            if syn in claimed_lower:
                return True

    type_map = {
        "命令注入": ["rce", "command injection", "remote code execution"],
        "sql注入": ["sqli", "sql injection"],
        "跨站脚本": ["xss", "cross-site scripting"],
        "ssrf": ["ssrf", "server-side request forgery"],
        "文件读取": ["file-read", "file read", "path traversal", "lfi", "directory traversal"],
        "认证绕过": ["auth-bypass", "authentication bypass", "auth bypass"],
        "反序列化": ["deserialization"],
        "文件上传": ["file upload", "upload"],
        "xxe": ["xxe", "xml external entity"],
        "模板注入": ["ssti", "template injection"],
        "安全漏洞": [],
    }

    for cn_type, en_types in type_map.items():
        if cn_type in claimed_lower:
            for en_type in en_types:
                if en_type in expected_lower:
                    return True

    return False


def evaluate(gt: dict, results: dict) -> dict:
    tp = 0
    tp_partial = 0
    fp = 0
    fn = 0

    per_class = defaultdict(lambda: {"tp": 0, "tp_partial": 0, "fp": 0, "fn": 0, "total": 0})
    details = []
    confusion_pairs = []

    for token, truth in gt.items():
        expected_cve = normalize_cve(truth["expected_cve"])
        expected_class = truth["expected_class"]
        accept_synonyms = truth.get("accept_synonyms", "")

        per_class[expected_class]["total"] += 1

        if token not in results:
            fn += 1
            per_class[expected_class]["fn"] += 1
            details.append({
                "token": token,
                "expected_cve": expected_cve,
                "expected_class": expected_class,
                "result": "FN",
                "reason": "not_scanned",
            })
            continue

        r = results[token]
        if not r["has_vuln"]:
            fn += 1
            per_class[expected_class]["fn"] += 1
            details.append({
                "token": token,
                "expected_cve": expected_cve,
                "expected_class": expected_class,
                "claimed_cve": "",
                "result": "FN",
                "reason": "reported_no_vuln",
            })
            continue

        claimed_cve = normalize_cve(r["claimed_cve"])
        claimed_class = r["claimed_class"]

        if claimed_cve and claimed_cve == expected_cve:
            tp += 1
            per_class[expected_class]["tp"] += 1
            details.append({
                "token": token,
                "expected_cve": expected_cve,
                "expected_class": expected_class,
                "claimed_cve": claimed_cve,
                "claimed_class": claimed_class,
                "result": "TP",
                "reason": "exact_cve_match",
            })
        elif match_class(claimed_class + " " + r.get("claimed_type", ""),
                        expected_class, accept_synonyms):
            if claimed_cve and claimed_cve != expected_cve:
                tp_partial += 1
                per_class[expected_class]["tp_partial"] += 1
                details.append({
                    "token": token,
                    "expected_cve": expected_cve,
                    "expected_class": expected_class,
                    "claimed_cve": claimed_cve,
                    "claimed_class": claimed_class,
                    "result": "TP_partial",
                    "reason": "class_match_cve_mismatch",
                })
            else:
                tp += 1
                per_class[expected_class]["tp"] += 1
                details.append({
                    "token": token,
                    "expected_cve": expected_cve,
                    "expected_class": expected_class,
                    "claimed_cve": claimed_cve,
                    "claimed_class": claimed_class,
                    "result": "TP",
                    "reason": "class_match",
                })
        else:
            fp += 1
            per_class[expected_class]["fp"] += 1
            confusion_pairs.append((expected_class, claimed_class))
            details.append({
                "token": token,
                "expected_cve": expected_cve,
                "expected_class": expected_class,
                "claimed_cve": claimed_cve,
                "claimed_class": claimed_class,
                "result": "FP",
                "reason": "wrong_class",
            })

    total_gt = len(gt)
    total_scanned = len(results)
    total_reported = sum(1 for r in results.values() if r["has_vuln"])

    tp_effective = tp + tp_partial
    miss_rate = fn / total_gt if total_gt > 0 else 1.0
    recall = 1 - miss_rate
    precision = tp_effective / (tp_effective + fp) if (tp_effective + fp) > 0 else 0.0
    f1 = 2 * recall * precision / (recall + precision) * 100 if (recall + precision) > 0 else 0.0

    strict_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    strict_recall = tp / total_gt if total_gt > 0 else 0.0
    strict_f1 = 2 * strict_recall * strict_precision / (strict_recall + strict_precision) * 100 if (strict_recall + strict_precision) > 0 else 0.0

    metrics = {
        "total_ground_truth": total_gt,
        "total_scanned": total_scanned,
        "total_reported_vuln": total_reported,
        "tp": tp,
        "tp_partial": tp_partial,
        "tp_effective": tp_effective,
        "fp": fp,
        "fn": fn,
        "miss_rate": round(miss_rate, 4),
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 2),
        "strict_precision": round(strict_precision, 4),
        "strict_recall": round(strict_recall, 4),
        "strict_f1_score": round(strict_f1, 2),
    }

    class_breakdown = {}
    for cls, counts in sorted(per_class.items()):
        cls_tp = counts["tp"] + counts["tp_partial"]
        cls_precision = cls_tp / (cls_tp + counts["fp"]) if (cls_tp + counts["fp"]) > 0 else 0.0
        cls_recall = cls_tp / counts["total"] if counts["total"] > 0 else 0.0
        cls_f1 = 2 * cls_recall * cls_precision / (cls_recall + cls_precision) * 100 if (cls_recall + cls_precision) > 0 else 0.0
        class_breakdown[cls] = {
            "total": counts["total"],
            "tp": counts["tp"],
            "tp_partial": counts["tp_partial"],
            "fp": counts["fp"],
            "fn": counts["fn"],
            "precision": round(cls_precision, 4),
            "recall": round(cls_recall, 4),
            "f1": round(cls_f1, 2),
        }

    # Build confusion matrix from misclassified pairs
    confusion = defaultdict(int)
    for expected, claimed in confusion_pairs:
        confusion[(expected, claimed)] += 1
    confusion_list = [
        {"expected": e, "claimed": c, "count": n}
        for (e, c), n in sorted(confusion.items(), key=lambda x: -x[1])
    ]

    return {
        "metrics": metrics,
        "per_class": class_breakdown,
        "confusion": confusion_list,
        "details": details,
    }


def _display_width(s: str) -> int:
    """Approximate display width accounting for wide CJK characters."""
    w = 0
    for ch in s:
        if '一' <= ch <= '鿿' or '　' <= ch <= '〿' or '＀' <= ch <= '￯':
            w += 2
        else:
            w += 1
    return w


def _pad(s: str, width: int) -> str:
    """Left-align string padded to *display* width."""
    return s + " " * max(0, width - _display_width(s))


def print_summary(eval_result: dict, framework_name: str):
    m = eval_result["metrics"]

    print(f"\n{'=' * 72}")
    print(f"  Evaluation Results: {framework_name}")
    print(f"{'=' * 72}")
    print(f"  Ground truth targets:     {m['total_ground_truth']}")
    print(f"  Targets scanned:          {m['total_scanned']}")
    print(f"  Vulnerabilities reported: {m['total_reported_vuln']}")
    print()
    print(f"  --- Metrics (lenient: class match counts) ---")
    print(f"  TP (exact CVE):           {m['tp']}")
    print(f"  TP (class match):         {m['tp_partial']}")
    print(f"  TP (effective):           {m['tp_effective']}")
    print(f"  FP:                       {m['fp']}")
    print(f"  FN:                       {m['fn']}")
    print(f"  Precision:                {m['precision']:.4f}")
    print(f"  Recall (1-miss_rate):     {m['recall']:.4f}")
    print(f"  F1 Score:                 {m['f1_score']:.2f}")
    print()
    print(f"  --- Metrics (strict: exact CVE only) ---")
    print(f"  Strict Precision:         {m['strict_precision']:.4f}")
    print(f"  Strict Recall:            {m['strict_recall']:.4f}")
    print(f"  Strict F1 Score:          {m['strict_f1_score']:.2f}")

    # Per-class breakdown with CJK-aware column widths
    COL_CLS = 30
    print(f"\n  --- Per-Class Breakdown ---")
    hdr = (_pad("Class", COL_CLS)
           + f"{'Total':>6} {'TP':>5} {'TP~':>5} {'FP':>5} {'FN':>5}"
           + f" {'Prec':>7} {'Recall':>7} {'F1':>7}")
    print(f"  {hdr}")
    print(f"  {'-' * len(hdr)}")

    for cls, info in sorted(eval_result["per_class"].items(), key=lambda x: -x[1]["total"]):
        label = _pad(cls if cls else "(empty)", COL_CLS)
        print(f"  {label}"
              f"{info['total']:>6} {info['tp']:>5} {info['tp_partial']:>5} "
              f"{info['fp']:>5} {info['fn']:>5}"
              f" {info['precision']:>7.4f} {info['recall']:>7.4f} {info['f1']:>7.2f}")

    # Confusion matrix (misclassifications)
    confusion = eval_result.get("confusion", [])
    if confusion:
        print(f"\n  --- Confusion Matrix (top misclassifications) ---")
        print(f"  {_pad('Expected', COL_CLS)} {_pad('Claimed', COL_CLS)} {'Count':>6}")
        print(f"  {'-' * COL_CLS} {'-' * COL_CLS} {'-' * 6}")
        for entry in confusion[:15]:
            exp = _pad(entry["expected"] or "(empty)", COL_CLS)
            clm = _pad(entry["claimed"] or "(empty)", COL_CLS)
            print(f"  {exp} {clm} {entry['count']:>6}")

    print(f"{'=' * 72}\n")


def main():
    parser = argparse.ArgumentParser(description="Evaluate vulnerability scanner results")
    parser.add_argument("results_path", nargs="?", default=None,
                        help="Path to results directory or JSON/CSV file")
    parser.add_argument("--results-file", default=None,
                        help="Path to a results JSON or CSV file (alternative to positional arg)")
    parser.add_argument("--ground-truth", default=GROUND_TRUTH_FILE,
                        help="Path to ground truth CSV")
    parser.add_argument("--name", default="framework",
                        help="Framework name for display")
    parser.add_argument("--output", default=None,
                        help="Save detailed results JSON to this path")
    args = parser.parse_args()

    # Determine input path
    input_path = args.results_file or args.results_path
    if not input_path:
        parser.error("Provide a results path as positional arg or via --results-file")

    # Load data
    gt = load_ground_truth(args.ground_truth)
    print(f"Loaded {len(gt)} ground truth entries")

    results = load_framework_results(input_path)
    print(f"Loaded {len(results)} framework results from {input_path}")

    if not results:
        print("ERROR: No results found. Check the path.")
        print("  Supported formats:")
        print("    - Directory containing scan_results.json or competition_output.json/csv")
        print("    - JSON file: {\"results\":[...]} or [{\"序号\":..., \"目标资产\":...}, ...]")
        print("    - CSV file with columns: 目标资产, 是否存在漏洞, 漏洞类型, 漏洞编号")
        sys.exit(1)

    # Evaluate
    eval_result = evaluate(gt, results)

    # Print summary
    print_summary(eval_result, args.name)

    # Save detailed results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        output_path = args.output
    elif os.path.isdir(input_path):
        output_path = os.path.join(input_path, f"eval_results_{timestamp}.json")
    else:
        output_path = f"eval_results_{timestamp}.json"

    output_data = {
        "eval_timestamp": datetime.now().isoformat(),
        "framework_name": args.name,
        "ground_truth_file": args.ground_truth,
        "results_source": input_path,
        **eval_result,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    print(f"Detailed evaluation saved to: {output_path}")


if __name__ == "__main__":
    main()
