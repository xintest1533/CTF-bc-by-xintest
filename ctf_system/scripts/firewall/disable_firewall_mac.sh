#!/bin/bash
echo "================================================"
echo "CTF赛事 - Mac防火墙关闭脚本"
echo "================================================"

echo "正在关闭系统防火墙..."
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off

echo "正在禁用防火墙服务..."
sudo launchctl unload /System/Library/LaunchDaemons/com.apple.alf.plist 2>/dev/null || echo "防火墙服务已禁用"

echo "正在检查防火墙状态..."
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

echo "================================================"
echo "防火墙关闭完成！"
echo "================================================"
