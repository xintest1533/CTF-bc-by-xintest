#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[*]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[x]${NC} $1"
    exit 1
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../" && pwd)

cd "$PROJECT_ROOT"

log "====================================="
log "    CTF系统自动更新"
log "====================================="

log "检查是否有新版本..."
git fetch origin master

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/master)

if [ "$LOCAL" = "$REMOTE" ]; then
    log "当前已是最新版本"
    exit 0
fi

log "发现新版本，开始更新..."

log "备份当前配置..."
cp -r judge/config/ /tmp/ctf_config_backup_$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
cp -r target_client/config/ /tmp/ctf_client_config_backup_$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true

log "拉取最新代码..."
git pull origin master

log "更新依赖..."
pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt 2>/dev/null || warn "依赖更新失败"

log "恢复配置文件..."
if [ -d "/tmp/ctf_config_backup_*" ]; then
    cp -r /tmp/ctf_config_backup_*/. judge/config/ 2>/dev/null || true
    cp -r /tmp/ctf_client_config_backup_*/. target_client/config/ 2>/dev/null || true
    log "配置文件已恢复"
fi

log "重启服务..."
pkill -f "tcp_heartbeat/heartbeat_server.py" 2>/dev/null || true
pkill -f "http_submit/submit_server.py" 2>/dev/null || true
pkill -f "web_dashboard/dashboard.py" 2>/dev/null || true

sleep 2

nohup python3 judge/tcp_heartbeat/heartbeat_server.py > judge/logs/heartbeat.log 2>&1 &
nohup python3 judge/http_submit/submit_server.py > judge/logs/submit.log 2>&1 &
nohup python3 judge/web_dashboard/dashboard.py > judge/logs/dashboard.log 2>&1 &

sleep 3

log "验证服务状态..."
ps aux | grep python3 | grep -E 'heartbeat|submit|dashboard' | grep -v grep

log "====================================="
log "    更新完成！"
log "====================================="