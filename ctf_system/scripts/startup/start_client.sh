#!/bin/bash
echo "================================================"
echo "CTF赛事 - 启动选手客户端"
echo "================================================"

echo "正在检查IP配置文件..."
if [ ! -f "ip_config.ini" ]; then
    echo "错误：未找到 ip_config.ini 文件"
    echo "请先配置 ip_config.ini 文件后再启动"
    exit 1
fi

echo "正在启动靶机服务..."
python3 target_client/target_server.py &
TARGET_PID=$!
echo "靶机服务已启动 (PID: $TARGET_PID)"

echo ""
echo "================================================"
echo "选手客户端已启动！"
echo "靶机服务: 8000端口"
echo "请配置 ip_config.ini 中的 primary_ip 字段"
echo "================================================"

echo "$TARGET_PID" > /tmp/ctf_client_pid.txt

trap "echo '正在停止客户端...'; kill $TARGET_PID 2>/dev/null; rm /tmp/ctf_client_pid.txt; exit" SIGINT SIGTERM

wait
