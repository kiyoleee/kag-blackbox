# KAG-Blackbox: Knowledge Augmented Generation for Online Service Vulnerability Detection

CNCERT 2026 AI赋能漏洞挖掘竞赛 - 在线服务类漏洞检测框架

## 概述

KAG-Blackbox 是一个基于知识增强生成 (KAG) 的黑盒在线服务漏洞检测系统。系统通过 Neo4j 知识图谱存储漏洞知识，结合 HTTP 指纹探测和 LLM 推理，实现对在线服务的自动化漏洞检测、CVE 识别和 PoC 验证。

### 核心特点

- **KAG 架构**: Knowledge Graph + LLM Augmented Generation，而非纯规则匹配
- **多层流水线**: 指纹探测 → KG检索 → LLM推理 → PoC验证，层层递进
- **PoC 守门**: 只有验证通过才报告漏洞，避免误报
- **CVE 消歧**: LLM 基于 HTTP 响应 + 版本信息 + KG 候选，精确选择 CVE
- **三级数据源优先级**: vulhub_fingerprints(最高) > Nuclei模板(中) > 补充模板(低)

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                    KAG-Blackbox Pipeline                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: Controller (并发调度, 时间预算)                      │
│      ↓                                                      │
│  Layer 2: Surface (HTTP 指纹探测, 18路径扫描)                  │
│      ↓                                                      │
│  Layer 3: Nuclei (模板匹配, CVE识别)                          │
│      ↓                                                      │
│  Layer 4: KAG-Thinker (LLM 四阶段 Logical Form 推理)         │
│      │   Step1: Retrieval(target → product)                 │
│      │   Step2: Deduce(boundary → certainty)                │
│      │   Step3: Retrieval(product → CVE candidates)         │
│      │   Step4: Output(product, cve, poc)                   │
│      ↓                                                      │
│  Layer 5: Verifier (PoC执行, match_indicators检查)           │
│      ↓                                                      │
│  Layer 6: Reporter (比赛格式输出)                             │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Knowledge Graph (Neo4j)                                    │
│  ┌──────────┐  BB_HAS_CVE  ┌──────────┐  BB_HAS_POC       │
│  │BB_Product├─────────────→│ BB_CVE   ├───────────→BB_PoC  │
│  └────┬─────┘              └──────────┘                     │
│       │ BB_IDENTIFIED_BY                                    │
│       ↓                                                     │
│  ┌──────────────┐                                           │
│  │BB_Fingerprint│                                           │
│  └──────────────┘                                           │
│  4853 Products | 4273 CVEs | 6068 PoCs | 18285 Fingerprints│
└─────────────────────────────────────────────────────────────┘
```

## 目录结构

```
kag-blackbox/
├── kag_blackbox/                 # 核心模块
│   ├── builder/                  # KG 构建器
│   │   ├── build_kg.py           # 入口: 构建知识图谱
│   │   ├── kg_builder.py         # 数据解析与导入
│   │   └── schema.py             # Neo4j Schema定义
│   ├── solver/                   # 推理引擎
│   │   ├── kag_thinker.py        # KAG-Thinker 四阶段推理
│   │   ├── kg_query.py           # Neo4j 多跳查询
│   │   └── agent_layer.py        # LLM Agent Pipeline
│   └── common/
│       └── config.py             # 配置(Neo4j, LLM, 路径)
├── scanner/                      # 扫描器
│   ├── competition_scanner.py    # 主扫描器(6层流水线)
│   └── fingerprint_scan_v2.py    # 指纹扫描器(活跃探测)
├── fingerprints/                 # 数据
│   └── vulhub_fingerprints.zip   # 330个高精度指纹文件
├── tools/
│   └── evaluate.py               # 评测脚本
├── requirements.txt
└── README.md
```

## 快速开始

### 1. 环境准备

```bash
# 依赖安装
pip install -r requirements.txt

# 需要的外部服务:
# - Neo4j 数据库 (bolt://127.0.0.1:7687)
# - vLLM 推理服务 (http://127.0.0.1:8200/v1)
# - Nuclei 扫描器 (可选)
```

### 2. 构建知识图谱

```bash
# 解压指纹数据
cd fingerprints && unzip vulhub_fingerprints.zip && cd ..

# 构建 KG (需要 Neo4j 运行中)
python3 kag_blackbox/builder/build_kg.py \
    --nuclei-dir /path/to/nuclei-templates \
    --fingerprints fingerprints/vulhub_fingerprints \
    --no-vulhub-mapping \
    --clear
```

KG 构建完成后包含:
- **BB_Product**: 4853 个产品节点
- **BB_CVE**: 4273 个 CVE 节点
- **BB_PoC**: 6068 个 PoC 节点
- **BB_Fingerprint**: 18285 个指纹模式

### 3. 运行指纹扫描

```bash
# 生成目标指纹 (需要网络连通目标)
python3 scanner/fingerprint_scan_v2.py \
    --targets targets.txt \
    --output fingerprints.json \
    --fp-dir fingerprints/vulhub_fingerprints \
    --workers 5
```

### 4. 运行主扫描器

```bash
python3 scanner/competition_scanner.py \
    --neo4j-uri bolt://127.0.0.1:7687 \
    --fingerprints fingerprints.json \
    --fp-dir fingerprints/vulhub_fingerprints \
    --llm-url http://127.0.0.1:8200/v1 \
    --llm-model qwen36-35b-a3b \
    --workers 5 \
    --no-fallback
```

### 5. 评测

```bash
python3 tools/evaluate.py \
    results/scan_XXXXXXXX_XXXXXX/scan_results.json \
    --ground-truth ground-truth.csv \
    --name "KAG-Blackbox v1.0"
```

## 配置说明

### Neo4j

在 `kag_blackbox/common/config.py` 中配置:

```python
NEO4J_URI = "bolt://127.0.0.1:7687"   # Neo4j Bolt 地址
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "neo4j@openspg"
```

### LLM

扫描器支持通过命令行参数配置 LLM:

```bash
--llm-url http://127.0.0.1:8200/v1   # vLLM 服务地址
--llm-model qwen36-35b-a3b            # 模型名称
--llm-timeout 60                       # 超时(秒)
```

推荐使用 Qwen3.6-35B-A3B (no-think 模式)，单次推理 5-15秒。

### 扫描器参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--neo4j-uri` | `bolt://127.0.0.1:17687` | Neo4j 地址 |
| `--fingerprints` | | 预计算指纹 JSON |
| `--fp-dir` | | vulhub_fingerprints 目录 |
| `--nuclei-results` | | Nuclei 扫描结果目录 |
| `--workers` | 5 | 并发数 |
| `--no-fallback` | False | 禁用 FALLBACK (推荐) |
| `--no-tunnel` | False | 禁用 SSH 隧道 |

## 输出格式

符合 CNCERT 比赛要求:

| 字段 | 说明 | 示例 |
|------|------|------|
| 序号 | 自然数 | 1 |
| 目标资产 | URL + CVE + 漏洞名 | `http://x.x.x.x 存在CVE-2024-36401 GeoServer ssti` |
| 是否存在漏洞 | 是/否 | 是 |
| 漏洞类型 | 漏洞分类 | 模板注入漏洞 |
| 漏洞编号 | CVE编号 | CVE-2024-36401 |
| 漏洞验证描述 | 多步骤PoC验证 | 第1步: 发送探测请求... 第2步: 指纹确认... |

输出文件:
- `scan_results.json` — 详细扫描结果
- `competition_output.json` — 比赛格式 JSON
- `competition_output.csv` — 比赛格式 CSV

## 数据源与优先级

| 优先级 | 数据源 | 来源 | 数量 |
|--------|--------|------|------|
| ★★★ | vulhub_fingerprints | 手工标注, 精确检测规则 | 328 CVE |
| ★★ | Nuclei 官方模板 | 社区维护 | 4143 CVE |
| ★ | 补充模板 (other_vul) | 混合来源 | 17127 CVE |

KAG-Thinker 在推理时会标注候选 CVE 的数据源，优先采信高优先级来源。

## 性能指标

在 vulhub-300 测试集 (292个目标) 上的评测结果:

| 版本 | Lenient F1 | Strict F1 | Precision | Recall | TP(exact CVE) |
|------|-----------|-----------|-----------|--------|---------------|
| v1.0 | **61.20** | **33.97** | **0.53** | 0.72 | **80** |

## 依赖

- Python 3.8+
- Neo4j 5.x
- vLLM (或兼容 OpenAI API 的推理服务)
- curl (系统命令)
- Nuclei (可选, 用于模板扫描)

## 硬件要求

| 组件 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 8核 | 16核+ |
| RAM | 16GB | 64GB+ |
| GPU/NPU | - | Ascend 910B / NVIDIA A100 |
| 存储 | 10GB | 50GB+ |

LLM 推理需要 GPU/NPU 加速卡，推荐使用 Ascend 910B 或同等算力。

## License

MIT
