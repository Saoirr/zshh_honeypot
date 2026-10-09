"""事件落库：SQLite（查询用）+ JSONL（直接拷走用）。"""
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config

log = logging.getLogger("honeypot.store")

_lock = threading.Lock()
_db_path = None  # type: Path | None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    kind       TEXT    NOT NULL,
    src_ip     TEXT,
    src_port   INTEGER,
    port       INTEGER,
    method     TEXT,
    path       TEXT,
    ua         TEXT,
    category   TEXT,
    ai_crawler INTEGER DEFAULT 0,
    tags       TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip);
"""


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(_db_path, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def init() -> None:
    global _db_path
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    _db_path = config.DATA_DIR / "honeypot.db"
    with _lock:
        con = _connect()
        try:
            con.executescript(_SCHEMA)
            con.commit()
        finally:
            con.close()


def _iso(ts) -> str:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def add_event(*, kind, src_ip, category="other", ai_crawler=False,
              src_port=None, port=None, method=None, path=None, ua=None,
              tags=None, detail=None) -> None:
    """记录一条事件；任何异常都吞掉（蜜罐不能因为落库失败给访问者 500）。"""
    try:
        if _db_path is None:
            init()
        ts = time.time()
        with _lock:
            con = _connect()
            try:
                cur = con.execute(
                    "INSERT INTO events (ts, kind, src_ip, src_port, port, method, path,"
                    " ua, category, ai_crawler, tags, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ts, kind, src_ip, src_port, port, method, path, ua, category,
                     1 if ai_crawler else 0,
                     json.dumps(tags or [], ensure_ascii=False),
                     json.dumps(detail or {}, ensure_ascii=False)),
                )
                con.commit()
                event_id = cur.lastrowid
            finally:
                con.close()

            event = {
                "id": event_id, "ts": ts, "time": _iso(ts), "kind": kind,
                "src_ip": src_ip, "src_port": src_port, "port": port,
                "method": method, "path": path, "ua": ua, "category": category,
                "ai_crawler": bool(ai_crawler), "tags": tags or [], "detail": detail or {},
            }
            with open(config.DATA_DIR / "events.jsonl", "a", encoding="utf-8") as fp:
                fp.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        log.exception("failed to persist event")


def _where(since=None, until=None, extra=None):
    conditions, params = [], []
    if since is not None:
        conditions.append("ts >= ?")
        params.append(since)
    if until is not None:
        conditions.append("ts <= ?")
        params.append(until)
    if extra:
        conditions.append(extra)
    clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    return clause, params


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"], "ts": row["ts"], "time": _iso(row["ts"]),
        "kind": row["kind"], "src_ip": row["src_ip"], "src_port": row["src_port"],
        "port": row["port"], "method": row["method"], "path": row["path"],
        "ua": row["ua"], "category": row["category"],
        "ai_crawler": bool(row["ai_crawler"]),
        "tags": json.loads(row["tags"] or "[]"),
        "detail": json.loads(row["detail"] or "{}"),
    }


def query(since=None, until=None, category=None, limit=500) -> list:
    if _db_path is None:
        init()
    clause, params = _where(since, until, "category = ?" if category else None)
    if category:
        params.append(category)
    params.append(int(limit))
    sql = "SELECT * FROM events" + clause + " ORDER BY ts DESC LIMIT ?"
    with _lock:
        con = _connect()
        try:
            rows = con.execute(sql, params).fetchall()
        finally:
            con.close()
    return [_row_to_dict(row) for row in rows]


def summary(since=None, until=None) -> dict:
    if _db_path is None:
        init()
    clause, params = _where(since, until)
    ai_clause, ai_params = _where(since, until, "ai_crawler = 1")
    with _lock:
        con = _connect()
        try:
            total = con.execute("SELECT COUNT(*) FROM events" + clause, params).fetchone()[0]
            ai_total = con.execute("SELECT COUNT(*) FROM events" + ai_clause, ai_params).fetchone()[0]
            by_category = {row[0] or "other": row[1] for row in con.execute(
                "SELECT category, COUNT(*) FROM events" + clause + " GROUP BY category", params)}
            unique_sources = con.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM events" + clause, params).fetchone()[0]
            top_sources = [{"src_ip": row[0], "count": row[1]} for row in con.execute(
                "SELECT src_ip, COUNT(*) AS c FROM events" + clause
                + " GROUP BY src_ip ORDER BY c DESC LIMIT 10", params)]
            top_uas = [{"ua": row[0], "count": row[1]} for row in con.execute(
                "SELECT ua, COUNT(*) AS c FROM events" + clause
                + " GROUP BY ua ORDER BY c DESC LIMIT 10", params)]
        finally:
            con.close()
    return {
        "total": total,
        "ai_crawler_total": ai_total,
        "by_category": by_category,
        "unique_sources": unique_sources,
        "top_sources": top_sources,
        "top_uas": top_uas,
    }
