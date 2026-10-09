"""运行配置：全部通过环境变量覆盖，默认值面向 Docker 部署。"""
import os
from pathlib import Path

# 数据落地目录（容器内挂卷到宿主机 ./data）
DATA_DIR = Path(os.environ.get("HONEYPOT_DATA_DIR", "/data"))

# 查询接口前缀，最终路径为 /{API_PREFIX}/answer
API_PREFIX = os.environ.get("HONEYPOT_API_PREFIX", "2026_10_questions").strip("/")

# 调用查询接口时要带的 token；留空 = 不鉴权
TOKEN = os.environ.get("HONEYPOT_TOKEN", "").strip()

# 每个请求最多记录的 body 字节数
MAX_BODY_BYTES = int(os.environ.get("HONEYPOT_MAX_BODY", "2048"))

# 单次查询返回的事件数上限 / 默认值
MAX_EVENTS_PER_QUERY = 5000
DEFAULT_EVENTS_PER_QUERY = 500

_DEFAULT_TCP = "3306:mysql,6379:redis,9200:elasticsearch,27017:mongodb"


def _parse_ports(raw: str) -> dict:
    """把 "3306:mysql,6379:redis" 解析成 {3306: "mysql", 6379: "redis"}，置空则不起监听。"""
    ports = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        port, _, service = item.partition(":")
        try:
            ports[int(port)] = service.strip() or "generic"
        except ValueError:
            continue
    return ports


# 假数据库端口 -> 服务类型
TCP_PORTS = _parse_ports(os.environ.get("DECOY_TCP_PORTS", _DEFAULT_TCP))
