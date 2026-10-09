# zshh_honeypot

被动记录型蜜罐：放几个诱饵（假数据库端口 + 假管理后台/配置泄漏路径），把所有访问者记录下来，
通过一个 JSON 接口对外提供查询。**只接受连接、只记录，不转发、不主动外连。**

> 使用前提：只部署在你拥有或被授权使用的服务器上；这台机器上不要放任何真实数据、真实密码。

## 组成

```
app/
  main.py       HTTP 诱饵路由 + 查询接口
  classifier.py AI 爬虫 UA / 数据库探测路径 / 端口首包 分类
  tcpdecoys.py  假数据库端口监听（mysql/redis/elasticsearch/mongodb）
  store.py      SQLite + JSONL 落库
  config.py     环境变量配置
Dockerfile / docker-compose.yml / .env.example
data/           运行后生成 honeypot.db、events.jsonl
```

## 快速开始（Linux + Docker + 公网 IP）

```bash
# 一把梭：自动装 Docker、生成随机 token、启动、自测（推荐）
bash deploy.sh

# 或者手动
cp .env.example .env        # 改掉 HONEYPOT_TOKEN
docker compose up -d --build
```

云安全组放行端口：`80`（HTTP_PORT）、`3306`、`6379`、`9200`、`27017`。

自测（换成你的 IP 和 token）：

```bash
# 造一条 AI 爬虫记录
curl -A "GPTBot/1.0 (+https://openai.com/gptbot)" http://<你的IP>/.env
# 查记录
curl "http://<你的IP>/2026_10_questions/answer?token=<你的TOKEN>"
```

## 查询接口

`GET|POST /2026_10_questions/answer`

鉴权（`HONEYPOT_TOKEN` 为空则不用带）：`?token=xxx`、`X-Honeypot-Token: xxx`
或 `Authorization: Bearer xxx`。

查询参数（都可选）：`since` / `until`（unix 秒或 ISO 时间）、`category`、`limit`（默认 500，上限 5000）。

```json
{
  "ok": true,
  "generated_at": "2026-10-09T07:00:00+00:00",
  "window": { "since": null, "until": null },
  "summary": {
    "total": 1327,
    "ai_crawler_total": 89,
    "by_category": { "db_probe": 401, "http_probe": 812, "ai_crawler": 89, "port_scan": 25 },
    "unique_sources": 233,
    "top_sources": [{ "src_ip": "1.2.3.4", "count": 57 }],
    "top_uas": [{ "ua": "GPTBot/1.0", "count": 12 }]
  },
  "count": 500,
  "events": [
    {
      "id": 1327, "ts": 1791521892.5, "time": "2026-10-09T06:58:12+00:00",
      "kind": "http", "src_ip": "1.2.3.4", "src_port": 51022, "port": null,
      "method": "GET", "path": "/.env", "ua": "GPTBot/1.0",
      "category": "ai_crawler", "ai_crawler": true,
      "tags": ["ai:OpenAI GPTBot", "db:config-leak"],
      "detail": { "headers": {}, "query": "" }
    }
  ]
}
```

`POST` 同一路径有两种用法：

```bash
# 1) 等同于 GET，body 里写过滤条件
curl -X POST -H 'content-type: application/json' -d '{"category":"ai_crawler","limit":100}' \
  "http://<你的IP>/2026_10_questions/answer?token=<TOKEN>"

# 2) 送一条数据求判定（兼容"发数据回判定"的用法）
curl -X POST -H 'content-type: application/json' -d '{"ua":"ClaudeBot/1.0","path":"/.env"}' \
  "http://<你的IP>/2026_10_questions/answer?token=<TOKEN>"
# -> {"ok":true,"verdict":{"is_ai_crawler":true,"matched":"Anthropic ClaudeBot",...}}
```

事件字段：

| 字段 | 说明 |
|---|---|
| `kind` | `http` / `tcp` |
| `category` | `ai_crawler` / `db_probe` / `port_scan` / `http_probe` |
| `ai_crawler` | 是否命中 AI 爬虫 UA 名单 |
| `tags` | `ai:*`、`auto:*`（curl/扫描器等）、`db:*`（admin-console/config-leak/…）、`service:*` |
| `detail` | HTTP：全部请求头 + 截断的 body；TCP：首包 hex 预览 |

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `HONEYPOT_TOKEN` | 空（不鉴权） | 查询接口 token |
| `HONEYPOT_API_PREFIX` | `2026_10_questions` | 接口前缀，路径为 `/{前缀}/answer`；按月轮换改这里 |
| `HTTP_PORT` | `80` | 宿主机 HTTP 端口（compose 用） |
| `DECOY_TCP_PORTS` | `3306:mysql,6379:redis,9200:elasticsearch,27017:mongodb` | 假端口 → 服务；置空则不起 |
| `HONEYPOT_DATA_DIR` | `/data` | 数据目录（容器内） |
| `HONEYPOT_MAX_BODY` | `2048` | 每个请求最多记录的 body 字节数 |

## 数据

- `data/honeypot.db` — SQLite，接口查询用
- `data/events.jsonl` — 一行一条，`scp` 走随便分析

## 部署注意

- **隔离**：单独一台 VPS，不和任何真实业务同机同网；假配置里全是虚构的内网地址和凭据。
- **防火墙**：Docker 发布端口会绕过 ufw，要用云厂商安全组 / iptables `DOCKER-USER` 链控制。
- **出站**：建议在云安全组把出站只放行 DNS/NTP 等必需项——蜜罐不需要外连，防止被当跳板。
- **HTTPS**：默认直接 HTTP。要 TLS 在前面加 Caddy/nginx 反代，注意把真实来源 IP 透传。
- **日志轮转**：compose 里已把 docker 日志限制为 10m × 3。

## 本地开发

```bash
py -3 -m venv .venv
.venv/Scripts/pip install -r requirements.txt            # Windows
HONEYPOT_DATA_DIR=./data_local HONEYPOT_TOKEN=devtoken \
  .venv/Scripts/python -m uvicorn app.main:app --port 8000 --no-server-header
```
