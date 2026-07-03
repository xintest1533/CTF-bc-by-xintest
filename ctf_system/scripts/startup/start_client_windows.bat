@echo off
echo ================================================
echo CTF赛事 - 启动选手客户端
echo ================================================

echo 正在检查IP配置文件...
if not exist ip_config.ini (
    echo 错误：未找到 ip_config.ini 文件
    echo 请先配置 ip_config.ini 文件后再启动
    pause
    exit /b 1
)

echo 正在启动靶机服务...
start python target_client/target_server.py

echo.
echo ================================================
echo 选手客户端已启动！
echo 靶机服务: 8000端口
echo 请配置 ip_config.ini 中的 primary_ip 字段
echo ================================================
pause
