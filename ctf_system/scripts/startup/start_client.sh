#!/bin/bash
set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../../" && pwd)

echo "================================================"
echo "CTF赛事 - 启动选手客户端"
echo "================================================"
echo "项目目录: $PROJECT_ROOT"
echo ""

mkdir -p "$PROJECT_ROOT/target_client/logs"

echo "正在启动靶机服务..."
cd "$PROJECT_ROOT"
nohup python3 target_client/target_server.py > target_client/logs/target.log 2>&1 &
TARGET_PID=$!
echo "靶机服务已启动 (PID: $TARGET_PID, 端口: 8000)"

echo ""
echo "================================================"
echo "客户端启动完成！"
echo "靶机服务: http://localhost:8000"
echo "心跳连接: 裁判服务器 9999端口"
echo "================================================"

echo "$TARGET_PID" > /tmp/ctf_client_pid.txt

echo ""
echo "验证服务状态..."
sleep 2

echo "---------- 进程状态 ----------"
ps aux | grep python3 | grep target_server | grep -v grep

echo ""
echo "---------- 端口监听 ----------"
ss -tlnp 2>/dev/null | grep 8000 || netstat -tlnp 2>/dev/null | grep 8000 || echo "端口状态检查失败"