"""蜜罐主进程：HTTP 诱饵 + 假数据库端口 + JSON 查询接口。

原则：只接受连接、只记录，不转发任何流量，不主动外连。
"""
import hmac
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import classifier, config, store, tcpdecoys

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("honeypot")

API_PATH = f"/{config.API_PREFIX}/answer"

# ---------------------------------------------------------------- 诱饵内容（全部虚构）

FAKE_ENV = """APP_NAME=portal-internal
APP_ENV=production
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=10.24.3.11
DB_PORT=3306
DB_DATABASE=portal_prod
DB_USERNAME=portal_rw
DB_PASSWORD=Pl4tP0rt!2026
REDIS_HOST=10.24.3.12
REDIS_PORT=6379
REDIS_PASSWORD=rd1s_Pl4t!2026
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = git@10.24.3.20:infra/portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""

FAKE_ACTUATOR = json.dumps({
    "activeProfiles": ["prod"],
    "propertySources": [{
        "name": "applicationConfig: [classpath:/application-prod.yml]",
        "properties": {
            "spring.datasource.url": {"value": "jdbc:mysql://10.24.3.11:3306/portal_prod?useSSL=false"},
            "spring.datasource.username": {"value": "portal_rw"},
            "spring.datasource.password": {"value": "Pl4tP0rt!2026"},
            "spring.redis.host": {"value": "10.24.3.12"},
            "spring.redis.password": {"value": "rd1s_Pl4t!2026"},
        },
    }],
}, indent=2)

FAKE_ES_ROOT = json.dumps({
    "name": "prod-es-01",
    "cluster_name": "prod-logs",
    "cluster_uuid": "kq8Xk3nTQw2mVn8sJx7H2A",
    "version": {"number": "7.17.23", "build_flavor": "default", "lucene_version": "8.11.1"},
    "tagline": "You Know, for Search",
}, indent=2)

FAKE_ES_INDICES = """green  open users-2026.10    3 1   1024   12     2.1mb     1.1mb
green  open orders-2026.09   3 1   8842  120      44mb      20mb
yellow open logs-app-2026.10 1 1  95231 4096     890mb     445mb
"""

FAKE_ADMIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Database Admin</title></head>
<body>
<h2>Database Administration Console</h2>
<p>Please log in to continue.</p>
<form method="post" action="">
  <input name="username" placeholder="username" autocomplete="off"><br>
  <input name="password" type="password" placeholder="password"><br>
  <input type="hidden" name="server" value="1">
  <button type="submit">Log in</button>
</form>
<p style="color:#a00">Login failed.</p>
</body></html>
"""

FAKE_SERVER_STATUS = """Apache Server Status for 10.24.3.10 (via 127.0.0.1)

Server Version: Apache/2.4.52 (Ubuntu)
Server Built: 2024-07-17T22:59:55
Current Time: October 2026
Restart Time: 3 days ago
Total Accesses: 1283743 - Total Traffic: 18.9 GB
CPU Usage: u251.2 s22.1 cu0 cs0 - .0105% CPU load
3.1 requests/sec - 48.9 kB/second - 15.8 kB/request
"""

NGINX_404 = """<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0 (Ubuntu)</center>
</body>
</html>
"""

# (路径正则, 响应体, content-type, 状态码, 额外响应头)
DECOY_RULES = [
    (r"(?i)^/\.env", FAKE_ENV, "text/plain; charset=utf-8", 200, None),
    (r"(?i)^/(wp-config\.php[^/]*|config\.php\.(bak|old|save|txt)|database\.ya?ml|application\.ya?ml)$",
     FAKE_ENV, "text/plain; charset=utf-8", 200, None),
    (r"(?i)^/\.git/(config|HEAD)$", FAKE_GIT_CONFIG, "text/plain; charset=utf-8", 200, None),
    (r"(?i)^/(phpmyadmin|pma|dbadmin|mysqladmin|adminer)(/|$|\.php)",
     FAKE_ADMIN_HTML, "text/html; charset=utf-8", 200, None),
    (r"(?i)^/actuator(/|$)", FAKE_ACTUATOR, "application/json; charset=utf-8", 200, None),
    (r"(?i)^/_cat/indices", FAKE_ES_INDICES, "text/plain; charset=utf-8", 200, None),
    (r"(?i)^/(_cluster/health|_nodes|elasticsearch$)",
     FAKE_ES_ROOT, "application/json; charset=utf-8", 200, None),
    (r"(?i)^/(druid|geoserver|solr|console)(/|$)",
     FAKE_ADMIN_HTML, "text/html; charset=utf-8", 200, None),
    (r"(?i)^/manager/html$", "Unauthorized", "text/plain; charset=utf-8", 401,
     {"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'}),
    (r"(?i)^/server-status", FAKE_SERVER_STATUS, "text/plain; charset=utf-8", 200, None),
]

# ---------------------------------------------------------------- 工具函数


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


def _parse_ts(value):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _iso(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _limit(value) -> int:
    try:
        return max(1, min(int(value), config.MAX_EVENTS_PER_QUERY))
    except (TypeError, ValueError):
        return config.DEFAULT_EVENTS_PER_QUERY


async def _read_body_limited(request: Request) -> bytes:
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) >= config.MAX_BODY_BYTES:
            break
    return body[: config.MAX_BODY_BYTES]


def _authorized(request: Request) -> bool:
    if not config.TOKEN:
        return True
    supplied = (request.query_params.get("token") or "").strip()
    if not supplied:
        supplied = request.headers.get("x-honeypot-token", "").strip()
    auth = request.headers.get("authorization", "")
    if not supplied and auth.lower().startswith("bearer "):
        supplied = auth[7:].strip()
    return bool(supplied) and hmac.compare_digest(supplied, config.TOKEN)


def _verdict(payload: dict) -> dict:
    """兼容用法：调用方送来一条数据（UA/请求头/路径），回一个判定。"""
    ua = str(payload.get("ua") or payload.get("user_agent") or "")
    headers = payload.get("headers")
    if not ua and isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "user-agent":
                ua = str(value)
                break
    path = str(payload.get("path") or payload.get("url") or "")
    result = classifier.classify_http(ua, path)
    return {
        "is_ai_crawler": result["ai_crawler"],
        "matched": result["matched"],
        "category": result["category"],
        "path_is_db_probe": result["db_probe"],
        "tags": result["tags"],
    }


# ---------------------------------------------------------------- 应用

@asynccontextmanager
async def lifespan(_: FastAPI):
    store.init()
    servers = await tcpdecoys.serve_all()
    log.info("honeypot up: api=%s token=%s tcp_decoys=%s",
             API_PATH, "on" if config.TOKEN else "OFF",
             sorted(config.TCP_PORTS) or "none")
    try:
        yield
    finally:
        await tcpdecoys.shutdown(servers)


app = FastAPI(title="zshh-honeypot", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def _server_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Server"] = "nginx/1.24.0 (Ubuntu)"
    return response


@app.get("/healthz")
async def healthz():
    return {"ok": True, "time": int(time.time())}


@app.api_route(API_PATH, methods=["GET", "POST"])
async def answer(request: Request):
    """查询接口：GET 查记录；POST 既可以传过滤条件，也可以送一条数据求判定。"""
    if not _authorized(request):
        ua = request.headers.get("user-agent", "")
        result = classifier.classify_http(ua, request.url.path)
        store.add_event(kind="http", src_ip=_client_ip(request), method=request.method,
                        path=request.url.path, ua=ua, category="http_probe",
                        ai_crawler=result["ai_crawler"],
                        tags=result["tags"] + ["api-auth-fail"],
                        detail={"query": str(request.url.query)[:512]})
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=403)

    filters = {
        "since": _parse_ts(request.query_params.get("since")),
        "until": _parse_ts(request.query_params.get("until")),
        "category": request.query_params.get("category") or None,
        "limit": _limit(request.query_params.get("limit")),
    }

    if request.method == "POST":
        raw = await _read_body_limited(request)
        payload = None
        if raw.strip():
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
        if isinstance(payload, dict):
            if any(key in payload for key in ("ua", "user_agent", "headers", "path", "ip", "source_ip")):
                return JSONResponse({"ok": True, "verdict": _verdict(payload)})
            if "since" in payload:
                filters["since"] = _parse_ts(payload.get("since")) or filters["since"]
            if "until" in payload:
                filters["until"] = _parse_ts(payload.get("until")) or filters["until"]
            if payload.get("category"):
                filters["category"] = payload["category"]
            if "limit" in payload:
                filters["limit"] = _limit(payload.get("limit"))

    events = store.query(since=filters["since"], until=filters["until"],
                         category=filters["category"], limit=filters["limit"])
    return JSONResponse({
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window": {"since": _iso(filters["since"]), "until": _iso(filters["until"])},
        "query": {"category": filters["category"], "limit": filters["limit"]},
        "summary": store.summary(since=filters["since"], until=filters["until"]),
        "count": len(events),
        "events": events,
    })


@app.api_route("/{full_path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def decoy(full_path: str, request: Request):
    """兜底路由：任何其他访问都记一笔，然后给一个像普通 web 服务器的响应。"""
    path = "/" + full_path
    body = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await _read_body_limited(request)

    headers = {key.lower(): value for key, value in request.headers.items()}
    ua = headers.get("user-agent", "")
    result = classifier.classify_http(ua, path)

    detail = {"headers": headers, "query": str(request.url.query)[:512]}
    if body:
        detail["body"] = body.decode("utf-8", "replace")

    store.add_event(kind="http", src_ip=_client_ip(request), method=request.method,
                    path=path, ua=ua, category=result["category"],
                    ai_crawler=result["ai_crawler"], tags=result["tags"], detail=detail)

    for pattern, text, content_type, status, extra in DECOY_RULES:
        if re.search(pattern, path):
            return Response(text, status_code=status,
                            media_type=content_type, headers=extra or None)

    return HTMLResponse(NGINX_404, status_code=404)
