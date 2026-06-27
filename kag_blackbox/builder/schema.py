"""
KAG-Blackbox Neo4j Schema.

Node types use a BB_ prefix to coexist with kag_vuldet in the same Neo4j instance.

Graph structure:
  (BB_Product)-[:BB_HAS_CVE]->(BB_CVE)-[:BB_HAS_POC]->(BB_PoC)
  (BB_Product)-[:BB_IDENTIFIED_BY]->(BB_Fingerprint)
  (BB_CVE)-[:BB_BELONGS_TO]->(BB_CWE)
  (BB_Product)-[:BB_HAS_VERSION]->(BB_Version)-[:BB_AFFECTED_BY]->(BB_CVE)
  (BB_PoC)-[:BB_TARGETS]->(BB_Product)
"""
from neo4j import GraphDatabase


SCHEMA_QUERIES = [
    # Constraints
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:BB_Product) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:BB_CVE) REQUIRE n.cve_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:BB_CWE) REQUIRE n.cwe_id IS UNIQUE",
    # Indexes
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_Product) ON (n.vendor)",
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_CVE) ON (n.severity)",
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_CVE) ON (n.type)",
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_Fingerprint) ON (n.type)",
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_Fingerprint) ON (n.pattern)",
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_PoC) ON (n.source)",
    "CREATE INDEX IF NOT EXISTS FOR (n:BB_Version) ON (n.product_name)",
]

# Fulltext index for fuzzy fingerprint search
FULLTEXT_QUERIES = [
    """CREATE FULLTEXT INDEX bb_fingerprint_text IF NOT EXISTS
       FOR (n:BB_Fingerprint) ON EACH [n.pattern]""",
    """CREATE FULLTEXT INDEX bb_product_text IF NOT EXISTS
       FOR (n:BB_Product) ON EACH [n.name, n.description]""",
]

CWE_SEEDS = [
    {"cwe_id": "CWE-78", "name": "OS Command Injection", "family": "injection",
     "description": "用户输入混入系统命令，导致任意命令执行"},
    {"cwe_id": "CWE-79", "name": "Cross-site Scripting (XSS)", "family": "injection",
     "description": "用户输入被嵌入HTML页面，导致客户端脚本执行"},
    {"cwe_id": "CWE-89", "name": "SQL Injection", "family": "injection",
     "description": "用户输入混入SQL查询，导致数据泄露或篡改"},
    {"cwe_id": "CWE-22", "name": "Path Traversal", "family": "injection",
     "description": "用户控制的路径字符串未过滤，可读写任意文件"},
    {"cwe_id": "CWE-94", "name": "Code Injection", "family": "injection",
     "description": "用户输入被作为代码执行（eval/OGNL/SpEL/SSTI等）"},
    {"cwe_id": "CWE-502", "name": "Insecure Deserialization", "family": "data_integrity",
     "description": "反序列化不可信数据导致任意代码执行"},
    {"cwe_id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "family": "injection",
     "description": "服务端发起用户控制的HTTP请求，访问内部资源"},
    {"cwe_id": "CWE-287", "name": "Improper Authentication", "family": "auth",
     "description": "认证机制缺陷导致未授权访问"},
    {"cwe_id": "CWE-611", "name": "XML External Entity (XXE)", "family": "injection",
     "description": "XML解析器处理外部实体导致文件读取或SSRF"},
    {"cwe_id": "CWE-434", "name": "Unrestricted File Upload", "family": "data_integrity",
     "description": "未限制上传文件类型，可上传恶意文件执行"},
    {"cwe_id": "CWE-200", "name": "Information Exposure", "family": "information",
     "description": "敏感信息泄露给未授权用户"},
    {"cwe_id": "CWE-74", "name": "Injection (Generic)", "family": "injection",
     "description": "通用注入类漏洞（OGNL/EL/模板注入等）"},
]

# Map CWE to vuln type keywords for linking
CWE_TYPE_MAP = {
    "CWE-78": ["rce", "command injection", "os command"],
    "CWE-79": ["xss", "cross-site scripting"],
    "CWE-89": ["sqli", "sql injection"],
    "CWE-22": ["lfi", "path traversal", "directory traversal", "file-read", "file read"],
    "CWE-94": ["rce", "code injection", "ssti", "template injection", "ognl", "spel"],
    "CWE-502": ["deserialization", "unserialize", "pickle"],
    "CWE-918": ["ssrf", "server-side request forgery"],
    "CWE-287": ["auth bypass", "authentication bypass", "auth-bypass"],
    "CWE-611": ["xxe", "xml external entity"],
    "CWE-434": ["file upload", "unrestricted upload"],
    "CWE-200": ["info disclosure", "information exposure", "phpinfo"],
    "CWE-74": ["injection", "ognl injection", "el injection"],
}


def init_schema(driver):
    """Create constraints, indexes, and fulltext indexes."""
    with driver.session() as session:
        for q in SCHEMA_QUERIES:
            try:
                session.run(q)
            except Exception:
                pass
        for q in FULLTEXT_QUERIES:
            try:
                session.run(q)
            except Exception:
                pass


def inject_cwe_seeds(driver):
    """Create CWE concept nodes."""
    with driver.session() as session:
        session.run(
            """UNWIND $seeds AS s
               MERGE (c:BB_CWE {cwe_id: s.cwe_id})
               SET c.name = s.name,
                   c.family = s.family,
                   c.description = s.description""",
            seeds=CWE_SEEDS,
        )


def clear_all(driver):
    """Remove all BB_ nodes and relationships. Use with caution."""
    with driver.session() as session:
        for label in ["BB_PoC", "BB_Fingerprint", "BB_Version", "BB_CVE", "BB_Product", "BB_CWE"]:
            session.run(f"MATCH (n:{label}) DETACH DELETE n")


def infer_cwe(vuln_type_str):
    """Infer CWE ID from a vulnerability type string."""
    if not vuln_type_str:
        return ""
    lower = vuln_type_str.lower()
    for cwe_id, keywords in CWE_TYPE_MAP.items():
        for kw in keywords:
            if kw in lower:
                return cwe_id
    return ""
