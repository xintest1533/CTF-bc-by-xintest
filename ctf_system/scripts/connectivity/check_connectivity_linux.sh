#!/bin/bash
echo "================================================"
echo "CTF赛事 - Linux连通性检测脚本"
echo "================================================"

JUDGE_TCP_IP="127.0.0.1"
JUDGE_TCP_PORT="9999"
JUDGE_HTTP_IP="127.0.0.1"
JUDGE_HTTP_PORT="8080"

echo "正在检测网络连通性..."

echo "1. 检测裁判TCP心跳服务 ($JUDGE_TCP_IP:$JUDGE_TCP_PORT)"
if timeout 5 bash -c "echo > /dev/tcp/$JUDGE_TCP_IP/$JUDGE_TCP_PORT"; then
    echo "TCP服务可达"
else
    echo "TCP服务不可达"
fi

echo ""
echo "2. 检测裁判HTTP提交服务 ($JUDGE_HTTP_IP:$JUDGE_HTTP_PORT)"
if curl -s --connect-timeout 5 "http://$JUDGE_HTTP_IP:$JUDGE_HTTP_PORT/status" > /dev/null; then
    echo "HTTP服务可达"
    curl -s "http://$JUDGE_HTTP_IP:$JUDGE_HTTP_PORT/status"
else
    echo "HTTP服务不可达"
fi

echo ""
echo "3. 检测本机IP配置..."
ip addr show | grep inet | grep -v 127.0.0.1 | grep -v ::1

echo ""
echo "================================================"
echo "连通性检测完成！"
echo "================================================"
