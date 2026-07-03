#!/bin/bash
set -e

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

log "====================================="
log "    CTF裁判服务器一键部署脚本"
log "====================================="

if [ "$(id -u)" != "0" ]; then
    warn "建议使用 sudo 运行，以便配置防火墙和开机自启"
    sleep 2
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../" && pwd)
BASE_DIR="/opt/ctf-attack-defense-system"

log "1/6 准备项目目录..."
if [ -d "$BASE_DIR" ]; then
    warn "目录已存在，使用当前目录: $BASE_DIR"
else
    ln -s "$PROJECT_ROOT" "$BASE_DIR"
    log "创建符号链接: $PROJECT_ROOT -> $BASE_DIR"
fi

log "2/6 安装 Python 依赖..."
cd "$PROJECT_ROOT"
pip3 install -r requirements.txt 2>/dev/null || {
    warn "pip3 安装失败，尝试使用 pip..."
    pip install -r requirements.txt || {
        error "Python 依赖安装失败"
    }
}

log "3/6 配置防火墙..."
if command -v firewall-cmd &> /dev/null; then
    log "使用 firewalld..."
    firewall-cmd --permanent --add-port=9999/tcp
    firewall-cmd --permanent --add-port=8080/tcp
    firewall-cmd --permanent --add-port=8000/tcp
    firewall-cmd --reload
    log "防火墙端口已开放"
elif command -v ufw &> /dev/null; then
    log "使用 ufw..."
    ufw allow 9999/tcp
    ufw allow 8080/tcp
    ufw allow 8000/tcp
    log "防火墙端口已开放"
elif command -v iptables &> /dev/null; then
    log "使用 iptables..."
    iptables -A INPUT -p tcp --dport 9999 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
    log "防火墙端口已开放（临时生效，重启后需重新配置）"
else
    warn "未检测到防火墙工具，请手动开放端口 9999/8080/8000"
fi

log "4/6 创建 systemd 服务..."
cat > /etc/systemd/system/ctf-heartbeat.service << 'EOF'
[Unit]
Description=CTF Heartbeat Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ctf-attack-defense-system
ExecStart=/usr/bin/python3 judge/tcp_heartbeat/heartbeat_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ctf-submit.service << 'EOF'
[Unit]
Description=CTF Submit Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ctf-attack-defense-system
ExecStart=/usr/bin/python3 judge/http_submit/submit_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ctf-dashboard.service << 'EOF'
[Unit]
Description=CTF Dashboard Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ctf-attack-defense-system
ExecStart=/usr/bin/python3 judge/web_dashboard/dashboard.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log "systemd 服务已创建"

log "5/6 启动服务..."
systemctl enable --now ctf-heartbeat
systemctl enable --now ctf-submit
systemctl enable --now ctf-dashboard

sleep 3

log "6/6 验证服务状态..."
echo ""
echo "---------- 服务状态 ----------"
systemctl status ctf-heartbeat --no-pager | grep -E "(Active|Loaded)"
systemctl status ctf-submit --no-pager | grep -E "(Active|Loaded)"
systemctl status ctf-dashboard --no-pager | grep -E "(Active|Loaded)"

echo ""
echo "---------- 端口监听 ----------"
ss -tlnp | grep -E '9999|8080|8000' || netstat -tlnp | grep -E '9999|8080|8000' || echo "端口状态检查失败"

echo ""
log "====================================="
log "    部署完成！"
log "====================================="
echo ""
echo "服务信息："
echo "  TCP心跳服务：0.0.0.0:9999"
echo "  HTTP提交服务：0.0.0.0:8080"
echo "  Web可视化看板：http://<IP>:8000"
echo ""
echo "修改配置："
echo "  编辑 $BASE_DIR/judge/config/judge_config.py"
echo "  修改后执行: sudo systemctl restart ctf-heartbeat ctf-submit ctf-dashboard"
echo ""
echo "查看日志："
echo "  tail -f $BASE_DIR/judge/logs/heartbeat.log"
echo "  tail -f $BASE_DIR/judge/logs/submit.log"
echo "  tail -f $BASE_DIR/judge/logs/dashboard.log"
echo ""
echo "停止服务："
echo "  sudo systemctl stop ctf-heartbeat ctf-submit ctf-dashboard"