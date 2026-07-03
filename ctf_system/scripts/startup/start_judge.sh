#!/bin/bash
set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../" && pwd)

echo "================================================"
echo "CTF赛事 - 启动裁判服务"
echo "================================================"
echo "项目目录: $PROJECT_ROOT"
echo ""

echo "检查更新..."
cd "$PROJECT_ROOT"
if git fetch origin master 2>/dev/null && [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/master)" ]; then
    echo "发现新版本，自动更新中..."
    bash "$SCRIPT_DIR/update.sh"
else
    echo "当前已是最新版本"
fi

mkdir -p "$PROJECT_ROOT/judge/logs"

echo "正在启动TCP心跳服务..."
cd "$PROJECT_ROOT"
nohup python3 judge/tcp_heartbeat/heartbeat_server.py > judge/logs/heartbeat.log 2>&1 &
HEARTBEAT_PID=$!
echo "TCP心跳服务已启动 (PID: $HEARTBEAT_PID)"

echo ""
echo "正在启动HTTP提交服务..."
nohup python3 judge/http_submit/submit_server.py > judge/logs/submit.log 2>&1 &
SUBMIT_PID=$!
echo "HTTP提交服务已启动 (PID: $SUBMIT_PID)"

echo ""
echo "正在启动Web看板..."
nohup python3 judge/web_dashboard/dashboard.py > judge/logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "Web看板已启动 (PID: $DASHBOARD_PID)"

echo ""
echo "================================================"
echo "所有裁判服务已启动！"
echo "TCP心跳服务: 0.0.0.0:9999"
echo "HTTP提交服务: 0.0.0.0:8080"
echo "Web看板: 0.0.0.0:8000"
echo "================================================"

echo "$HEARTBEAT_PID $SUBMIT_PID $DASHBOARD_PID" > /tmp/ctf_judge_pids.txt

echo ""
echo "验证服务状态..."
sleep 2

echo "---------- 进程状态 ----------"
ps aux | grep python3 | grep -E 'heartbeat|submit|dashboard' | grep -v grep

echo ""
echo "---------- 端口监听 ----------"
ss -tlnp 2>/dev/null | grep -E '9999|8080|8000' || netstat -tlnp 2>/dev/null | grep -E '9999|8080|8000' || echo "端口状态检查失败"