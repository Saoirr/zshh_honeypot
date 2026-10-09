"""请求分类：AI 爬虫 UA、数据库探测路径、假端口首包特征。

分类只用来给记录打标签，宁可多标不可漏标。
"""
import re

# (子串, 展示名)：UA 命中即认为是 AI 系爬虫
AI_UA_PATTERNS = [
    ("gptbot", "OpenAI GPTBot"),
    ("chatgpt-user", "OpenAI ChatGPT-User"),
    ("oai-searchbot", "OpenAI OAI-SearchBot"),
    ("claudebot", "Anthropic ClaudeBot"),
    ("claude-web", "Anthropic Claude-Web"),
    ("anthropic-ai", "Anthropic anthropic-ai"),
    ("ccbot", "Common Crawl CCBot"),
    ("perplexitybot", "PerplexityBot"),
    ("perplexity-user", "Perplexity-User"),
    ("bytespider", "ByteDance Bytespider"),
    ("amazonbot", "Amazonbot"),
    ("applebot-extended", "Apple Applebot-Extended"),
    ("meta-externalagent", "Meta meta-externalagent"),
    ("facebookbot", "Meta FacebookBot"),
    ("diffbot", "Diffbot"),
    ("imagesiftbot", "ImagesiftBot"),
    ("timpibot", "Timpibot"),
    ("youbot", "You.com YouBot"),
    ("cohere-training-data-crawler", "Cohere training crawler"),
    ("cohere-ai", "Cohere cohere-ai"),
    ("kagibot", "Kagi Kagibot"),
]

# 通用自动化/扫描器 UA
AUTOMATION_UA_PATTERNS = [
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("httpx", "httpx"),
    ("aiohttp", "aiohttp"),
    ("curl/", "curl"),
    ("wget/", "wget"),
    ("go-http-client", "go-http-client"),
    ("okhttp", "okhttp"),
    ("java/", "java"),
    ("libwww-perl", "libwww-perl"),
    ("scrapy", "scrapy"),
    ("zgrab", "zgrab"),
    ("nmap", "nmap"),
    ("masscan", "masscan"),
    ("nuclei", "nuclei"),
    ("gobuster", "gobuster"),
    ("dirbuster", "dirbuster"),
    ("feroxbuster", "feroxbuster"),
    ("ffuf", "ffuf"),
    ("sqlmap", "sqlmap"),
    ("hydra", "hydra"),
]

# (正则, 标签)：路径命中即视为“数据库/管理面”类探测
DB_PROBE_PATTERNS = [
    (r"(?i)(phpmyadmin|pma/|adminer|dbadmin|mysqladmin)", "admin-console"),
    (r"(?i)/\.env", "config-leak"),
    (r"(?i)(wp-config|config\.(php|ya?ml|json)|database\.ya?ml|appsettings|settings\.py)", "config-leak"),
    (r"(?i)/\.git/", "config-leak"),
    (r"(?i)(actuator|jolokia|heapdump)", "spring-actuator"),
    (r"(?i)(elasticsearch|_cat/|_cluster|_nodes)", "elasticsearch"),
    (r"(?i)redis", "redis"),
    (r"(?i)mongo", "mongodb"),
    (r"(?i)(mysql|mariadb)", "mysql"),
    (r"(?i)(solr|druid|geoserver|/console)", "admin-console"),
    (r"(?i)/manager/html|host-manager", "tomcat"),
    (r"(?i)\.(sql|dump|bak|old|save|swp|tar\.gz|zip)$", "backup-hunting"),
]


def _first_substring(haystack: str, patterns):
    for needle, label in patterns:
        if needle in haystack:
            return label
    return None


def _first_regex(path: str, patterns):
    for pattern, label in patterns:
        if re.search(pattern, path):
            return label
    return None


def classify_http(ua: str, path: str) -> dict:
    """HTTP 请求分类，返回 {"category", "ai_crawler", "matched", "db_probe", "tags"}。"""
    ua = ua or ""
    lowered = ua.lower()
    ai = _first_substring(lowered, AI_UA_PATTERNS)
    automation = _first_substring(lowered, AUTOMATION_UA_PATTERNS)
    db_tag = _first_regex(path or "", DB_PROBE_PATTERNS)

    tags = []
    if ai:
        tags.append(f"ai:{ai}")
    if automation:
        tags.append(f"auto:{automation}")
    if db_tag:
        tags.append(f"db:{db_tag}")

    if ai:
        category = "ai_crawler"
    elif db_tag:
        category = "db_probe"
    else:
        category = "http_probe"

    return {
        "category": category,
        "ai_crawler": bool(ai),
        "matched": ai,
        "db_probe": bool(db_tag),
        "tags": tags,
    }


def classify_tcp(port: int, service: str, payload: bytes) -> dict:
    """假数据库端口首包分类。"""
    tags = [f"service:{service}"]
    if not payload:
        return {
            "category": "port_scan",
            "ai_crawler": False,
            "matched": None,
            "db_probe": True,
            "tags": tags + ["connect-only"],
        }

    text = payload[:1024].decode("latin-1", "replace").lower()
    if service == "redis":
        for cmd in ("ping", "info", "config", "keys", "get", "set", "module", "replicaof"):
            if cmd in text:
                tags.append(f"redis:{cmd}")
    elif service == "elasticsearch":
        for item in ("_cat", "_cluster", "_search", "_nodes", "_all"):
            if item in text:
                tags.append(f"es:{item.strip('_')}")
    elif service == "mysql":
        tags.append("mysql:handshake")
    elif service == "mongodb":
        tags.append("mongo:handshake")

    return {
        "category": "db_probe",
        "ai_crawler": False,
        "matched": None,
        "db_probe": True,
        "tags": tags,
    }
