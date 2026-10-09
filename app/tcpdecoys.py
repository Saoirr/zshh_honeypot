"""假数据库端口：接受连接、记录首包、给一点回应，然后断开。不转发、不代理。"""
import asyncio
import functools
import logging
import os
import struct

from . import classifier, config, store

log = logging.getLogger("honeypot.tcp")

_READ_TIMEOUT = 6.0
_FOLLOWUP_TIMEOUT = 3.0


def _mysql_greeting(connection_id: int) -> bytes:
    """造一个格式大致正确的 MySQL 服务端握手包，钓鱼用。"""
    salt1 = os.urandom(8)
    salt2 = os.urandom(12)
    payload = b"\x0a"  # protocol version 10
    payload += b"5.7.44-log\x00"
    payload += struct.pack("<I", connection_id)
    payload += salt1 + b"\x00"
    payload += struct.pack("<H", 0xFFFF)  # capability flags (lower)
    payload += b"\x21"                    # utf8_general_ci
    payload += struct.pack("<H", 0x0002)  # status flags
    payload += struct.pack("<H", 0xFFFF)  # capability flags (upper)
    payload += b"\x15"                    # auth plugin data length
    payload += b"\x00" * 10               # reserved
    payload += salt2 + b"\x00"
    payload += b"mysql_native_password\x00"
    header = struct.pack("<I", len(payload))[:3] + b"\x00"  # 3 字节长度 + 序号 0
    return header + payload


_ES_BODY = (
    b'{"name":"prod-es-01","cluster_name":"prod-logs",'
    b'"cluster_uuid":"kq8Xk3nTQw2mVn8sJx7H2A",'
    b'"version":{"number":"7.17.23","build_flavor":"default","lucene_version":"8.11.1"},'
    b'"tagline":"You Know, for Search"}'
)


def _http_body() -> bytes:
    head = ("HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n"
            f"Content-Length: {len(_ES_BODY)}\r\n"
            "Connection: close\r\n\r\n")
    return head.encode() + _ES_BODY


async def _read(reader, timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except Exception:
        return b""


async def _handle(reader, writer, port, service, connection_id):
    peer = writer.get_extra_info("peername") or ("-", 0)
    src_ip, src_port = (peer[0], peer[1]) if len(peer) >= 2 else (str(peer), 0)
    payload = b""
    try:
        if service == "mysql":
            writer.write(_mysql_greeting(connection_id))
            await writer.drain()

        payload += await _read(reader, _READ_TIMEOUT)

        if payload:
            if service == "redis":
                reply = b"+PONG\r\n" if b"ping" in payload.lower() else b"-ERR unknown command\r\n"
                writer.write(reply)
                await writer.drain()
                payload += await _read(reader, _FOLLOWUP_TIMEOUT)
            elif service == "elasticsearch":
                writer.write(_http_body())
                await writer.drain()
    except Exception:
        log.exception("decoy tcp handler error on port %s", port)
    finally:
        result = classifier.classify_tcp(port, service, payload)
        store.add_event(
            kind="tcp", src_ip=src_ip, src_port=src_port, port=port,
            category=result["category"], tags=result["tags"],
            detail={"service": service, "bytes": len(payload),
                    "preview": payload[:512].decode("latin-1", "replace")},
        )
        try:
            writer.close()
        except Exception:
            pass


async def serve_all():
    """按配置启动假端口监听，返回 (server, task) 列表；某个端口起不来不影响其他端口。"""
    servers = []
    connection_id = 0
    for port, service in sorted(config.TCP_PORTS.items()):
        connection_id += 1
        handler = functools.partial(_handle, port=port, service=service,
                                    connection_id=connection_id)
        try:
            server = await asyncio.start_server(handler, host="0.0.0.0", port=port)
        except OSError as exc:
            log.warning("cannot bind decoy port %s (%s): %s", port, service, exc)
            continue
        task = asyncio.create_task(server.serve_forever(), name=f"decoy-tcp-{port}")
        log.info("decoy tcp listening on %s (%s)", port, service)
        servers.append((server, task))
    return servers


async def shutdown(servers):
    for server, task in servers:
        server.close()
        task.cancel()
