@echo off
echo ================================================
echo CTF赛事 - Windows连通性检测脚本
echo ================================================

set JUDGE_TCP_IP=127.0.0.1
set JUDGE_TCP_PORT=9999
set JUDGE_HTTP_IP=127.0.0.1
set JUDGE_HTTP_PORT=8080

echo 正在检测网络连通性...

echo 1. 检测裁判TCP心跳服务 (%JUDGE_TCP_IP%:%JUDGE_TCP_PORT%)
powershell -Command "Test-NetConnection %JUDGE_TCP_IP% -Port %JUDGE_TCP_PORT%"

echo.
echo 2. 检测裁判HTTP提交服务 (%JUDGE_HTTP_IP%:%JUDGE_HTTP_PORT%)
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://%JUDGE_HTTP_IP%:%JUDGE_HTTP_PORT%/status' -UseBasicParsing; Write-Host 'HTTP服务可达'; Write-Host '响应:' $response.Content } catch { Write-Host 'HTTP服务不可达: ' $_.Exception.Message }"

echo.
echo 3. 检测本机IP配置...
ipconfig | findstr /i "IPv4 Address"

echo.
echo ================================================
echo 连通性检测完成！
echo ================================================
pause
