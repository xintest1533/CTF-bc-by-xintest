Write-Host "================================================" -ForegroundColor Green
Write-Host "CTF赛事 - 启动选手客户端" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

$ErrorActionPreference = "Stop"

try {
    Write-Host "正在检查Python环境..." -ForegroundColor Yellow
    $python = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python -ErrorAction SilentlyContinue
    }
    
    if (-not $python) {
        throw "未找到Python，请安装Python 3.7+"
    }
    
    Write-Host "Python版本: $($python.Source)" -ForegroundColor Cyan
    
    Write-Host "`n正在启动靶机服务..." -ForegroundColor Yellow
    Start-Process -FilePath $python.Source -ArgumentList "target_client/target_server.py" -NoNewWindow -PassThru
    Write-Host "靶机服务已启动 (端口: 8000)" -ForegroundColor Green
    
    Write-Host "`n正在启动心跳客户端..." -ForegroundColor Yellow
    Start-Process -FilePath $python.Source -ArgumentList "target_client/utils/heartbeat_client.py" -NoNewWindow -PassThru
    Write-Host "心跳客户端已启动" -ForegroundColor Green
    
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host "客户端启动完成！" -ForegroundColor Green
    Write-Host "靶机服务: http://localhost:8000" -ForegroundColor Cyan
    Write-Host "心跳连接: 裁判服务器 9999端口" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Green
    
    Write-Host "`n按 Ctrl+C 停止服务" -ForegroundColor Yellow
}
catch {
    Write-Host "启动失败: $_" -ForegroundColor Red
    exit 1
}