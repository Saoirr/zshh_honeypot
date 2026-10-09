#!/usr/bin/env bash
# 服务器端一键部署：装 Docker、生成 .env（随机 token）、启动蜜罐、自测。
# 用法：把整个项目目录传到服务器后，在目录里执行  bash deploy.sh
set -euo pipefail

cd "$(dirname "$0")"
log()  { printf '\033[1;32m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*"; }

# 0) 权限
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  echo "请用 root 运行，或先装 sudo"; exit 1
fi

# 1) Docker
if ! command -v docker >/dev/null 2>&1; then
  log "未检测到 Docker，开始安装（首次可能要一两分钟）..."
  if curl -fsSL --max-time 90 https://get.docker.com -o /tmp/get-docker.sh; then
    $SUDO sh /tmp/get-docker.sh \
      || { warn "官方源失败，改用阿里云镜像重试"; $SUDO sh /tmp/get-docker.sh --mirror Aliyun; }
  else
    warn "连不上 get.docker.com。如果是国内机器，可手动装："
    warn "  sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2"
    exit 1
  fi
fi

$SUDO systemctl enable --now docker >/dev/null 2>&1 || true
$SUDO docker info >/dev/null 2>&1 || { warn "Docker 守护进程没起来，检查: systemctl status docker"; exit 1; }

if ! $SUDO docker compose version >/dev/null 2>&1; then
  warn "缺少 docker compose 插件，尝试安装 ..."
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq docker-compose-v2 2>/dev/null \
      || $SUDO apt-get install -y -qq docker-compose-plugin 2>/dev/null \
      || true
  fi
fi
$SUDO docker compose version >/dev/null 2>&1 \
  || { warn "docker compose 不可用，请手动安装 compose 插件后重跑本脚本"; exit 1; }

# 2) .env（不存在才生成，token 随机）
if [ ! -f .env ]; then
  TOKEN="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
  sed "s|^HONEYPOT_TOKEN=.*|HONEYPOT_TOKEN=${TOKEN}|" .env.example > .env
  log "已生成 .env，token = ${TOKEN}"
else
  log ".env 已存在，不覆盖"
fi
TOKEN="$(grep -E '^HONEYPOT_TOKEN=' .env | cut -d= -f2- || true)"
HTTP_PORT="$(grep -E '^HTTP_PORT=' .env | cut -d= -f2- || true)"; HTTP_PORT="${HTTP_PORT:-80}"
API_PREFIX="$(grep -E '^HONEYPOT_API_PREFIX=' .env | cut -d= -f2- || true)"; API_PREFIX="${API_PREFIX:-2026_10_questions}"

# 3) 启动
log "docker compose up -d --build（第一次要拉基础镜像，稍等）..."
$SUDO docker compose up -d --build

# 4) 等就绪 + 自测
for _ in $(seq 1 60); do
  curl -fsS --max-time 2 "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null 2>&1 && break
  sleep 1
done
log "自测 1：伪造一条 GPTBot 访问 /.env（应返回假配置）"
curl -fsS --max-time 5 -A "GPTBot/1.0" "http://127.0.0.1:${HTTP_PORT}/.env" | head -n 4 || warn "自测 1 失败"
log "自测 2：查询接口（应返回 JSON 记录）"
curl -fsS --max-time 5 "http://127.0.0.1:${HTTP_PORT}/${API_PREFIX}/answer?token=${TOKEN}&limit=2" || warn "自测 2 失败"

# 5) 打印外网地址
PUBIP="$(curl -fsS --max-time 5 https://api.ip.sb/ip 2>/dev/null | tr -d '[:space:]' || true)"
[ -z "$PUBIP" ] && PUBIP="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)"
[ -z "$PUBIP" ] && PUBIP="<服务器公网IP>"
if [ "$HTTP_PORT" = "80" ]; then URL="http://${PUBIP}"; else URL="http://${PUBIP}:${HTTP_PORT}"; fi
echo
log "部署完成。调用地址："
echo "    ${URL}/${API_PREFIX}/answer?token=${TOKEN}"
echo "    假数据库诱饵端口：3306 / 6379 / 9200 / 27017"
warn "记得在云控制台安全组放行：${HTTP_PORT}、3306、6379、9200、27017"
