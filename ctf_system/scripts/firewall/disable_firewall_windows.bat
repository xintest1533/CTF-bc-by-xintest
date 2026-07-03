@echo off
echo ================================================
echo CTF赛事 - Windows防火墙关闭脚本
echo ================================================

echo 正在关闭Windows Defender防火墙...
netsh advfirewall set allprofiles state off

echo 正在禁用防火墙服务...
sc config mpssvc start= disabled
sc stop mpssvc

echo 正在检查防火墙状态...
netsh advfirewall show allprofiles | findstr /i "State"

echo ================================================
echo 防火墙关闭完成！
echo ================================================
pause
