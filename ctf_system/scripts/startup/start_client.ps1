$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent (Split-Path -Parent $SCRIPT_DIR)

Write-Host "================================================" -ForegroundColor Green
Write-Host "CTF赛事 - 启动选手客户端" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host "项目目录: $PROJECT_ROOT" -ForegroundColor Cyan
Write-Host ""

New-Item -ItemType Directory -Path "$PROJECT_ROOT\target_client\logs" -Force | Out-Null

Write-Host "正在启动靶机服务..." -ForegroundColor Yellow
$python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
}

if (-not $python) {
    Write-Host "错误：未找到Python，请安装Python 3.7+" -ForegroundColor Red
    exit 1
}

Write-Host "Python路径: $($python.Source)" -ForegroundColor Cyan

$process = Start-Process -FilePath $python.Source -ArgumentList "$PROJECT_ROOT\target_client\target_server.py" -NoNewWindow -PassThru -RedirectStandardOutput "$PROJECT_ROOT\target_client\logs\target.log" -RedirectStandardError "$PROJECT_ROOT\target_client\logs\target_error.log"
Write-Host "靶机服务已启动 (PID: $($process.Id), 端口: 8000)" -ForegroundColor Green

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "客户端启动完成！" -ForegroundColor Green
Write-Host "靶机服务: http://localhost:8000" -ForegroundColor Cyan
Write-Host "心跳连接: 裁判服务器 9999端口" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Green

Write-Host ""
Write-Host "验证服务状态..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

Write-Host "---------- 进程状态 ----------" -ForegroundColor Yellow
Get-Process -Name python* -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "target_server" } | Select-Object Id, ProcessName

Write-Host ""
Write-Host "---------- 端口监听 ----------" -ForegroundColor Yellow
try {
    Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State
} catch {
    Write-Host "端口状态检查失败" -ForegroundColor Red
}