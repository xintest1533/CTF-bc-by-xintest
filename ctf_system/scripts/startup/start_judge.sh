#!/bin/bash
echo "================================================"
echo "CTF赛事 - 启动裁判服务"
echo "================================================"

mkdir -p judge/logs

echo "正在启动TCP心跳服务..."
python3 judge/tcp_heartbeat/heartbeat_server.py &
HEARTBEAT_PID=$!
echo "TCP心跳服务已启动 (PID: $HEARTBEAT_PID)"

echo ""
echo "正在启动HTTP提交服务..."
python3 judge/http_submit/submit_server.py &
SUBMIT_PID=$!
echo "HTTP提交服务已启动 (PID: $SUBMIT_PID)"

echo ""
echo "正在启动Web看板..."
python3 judge/web_dashboard/dashboard.py &
DASHBOARD_PID=$!
echo "Web看板已启动 (PID: $DASHBOARD_PID)"

echo ""
echo "================================================"
echo "所有裁判服务已启动！"
echo "TCP心跳服务: 9999端口"
echo "HTTP提交服务: 8080端口"
echo "Web看板: 8000端口"
echo "================================================"

echo "$HEARTBEAT_PID $SUBMIT_PID $DASHBOARD_PID" > /tmp/ctf_judge_pids.txt

trap "echo '正在停止裁判服务...'; kill $HEARTBEAT_PID $SUBMIT_PID $DASHBOARD_PID 2>/dev/null; rm /tmp/ctf_judge_pids.txt; exit" SIGINT SIGTERM

wait
