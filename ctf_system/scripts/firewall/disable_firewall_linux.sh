#!/bin/bash
echo "================================================"
echo "CTF赛事 - Linux防火墙关闭脚本"
echo "================================================"

echo "正在检测Linux发行版..."

if command -v systemctl &> /dev/null; then
    echo "正在关闭ufw防火墙..."
    sudo ufw disable 2>/dev/null || echo "ufw未安装或已关闭"
    
    echo "正在关闭firewalld防火墙..."
    sudo systemctl stop firewalld 2>/dev/null || echo "firewalld未安装"
    sudo systemctl disable firewalld 2>/dev/null || echo "firewalld未安装"
fi

echo "正在清空iptables规则..."
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

echo "正在检查防火墙状态..."
if command -v ufw &> /dev/null; then
    sudo ufw status
fi

echo "================================================"
echo "防火墙关闭完成！"
echo "================================================"
