"""KAG-Blackbox configuration."""
import os

# Neo4j (shared instance with kag_vuldet, different node labels)
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:17687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4j@openspg")

# LLM — local Qwen3.6-35B-A3B (no-think mode)
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://127.0.0.1:8200/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen36-35b-a3b")
LLM_API_KEY = os.getenv("LLM_API_KEY", "EMPTY")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))

# Data sources
NUCLEI_TEMPLATES_DIR = os.getenv(
    "NUCLEI_TEMPLATES_DIR",
    "/data/lqy/framework/nuclei-scanner/nuclei-templates/http")
VULHUB_MAPPING_CSV = os.getenv(
    "VULHUB_MAPPING_CSV",
    "/data/lqy/testinfo/vulhub-300/mapping.csv")
VULHUB_READMES_DIR = os.getenv(
    "VULHUB_READMES_DIR",
    "/data/lqy/testinfo/vulhub-300/readmes")

# Builder
NUCLEI_BATCH_SIZE = 200
MAX_RETRIES = 3

# Solver
FINGERPRINT_CONFIDENCE_THRESHOLD = 0.55
TOP_K_PRODUCTS = 5

# Vuln type mapping (English class -> Chinese)
VULN_TYPE_CN = {
    "rce": "远程代码执行漏洞",
    "command injection": "命令注入漏洞",
    "sqli": "SQL注入漏洞",
    "sql injection": "SQL注入漏洞",
    "xss": "跨站脚本漏洞",
    "ssrf": "SSRF漏洞",
    "file-read/traversal": "文件读取漏洞",
    "file-read": "文件读取漏洞",
    "path traversal": "文件读取漏洞",
    "auth-bypass": "认证绕过漏洞",
    "authentication bypass": "认证绕过漏洞",
    "deserialization": "反序列化漏洞",
    "file-upload": "文件上传漏洞",
    "xxe": "XXE漏洞",
    "ssti": "模板注入漏洞",
    "info-disclosure": "信息泄露漏洞",
    "misconfig": "配置错误漏洞",
    "open-redirect": "URL重定向漏洞",
    "crlf-injection": "CRLF注入漏洞",
}
