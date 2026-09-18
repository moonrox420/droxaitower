<#
.SYNOPSIS
    Installs Drox Command Tower as an automatic background Windows Service using NSSM.

.DESCRIPTION
    Configures NSSM to manage the FastAPI server with automatic boot startup,
    automatic crash recovery, and rotating stdout/stderr logs. Self-elevates to
    Administrator if required.
#>

param(
    [switch]$StartAfterInstall = $true
)

# 1. Self-elevation to Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator privileges to register Windows Service..." -ForegroundColor Cyan
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$BaseDir = "C:\Users\droxa\droxaitower"
$NssmExe = "$BaseDir\nssm-2.24\win64\nssm.exe"
$PythonExe = "$BaseDir\.venv\Scripts\python.exe"
$ServerScript = "$BaseDir\server.py"
$LogsDir = "$BaseDir\logs"
$ServiceName = "DroxCommandTower"

# 2. Validation
if (-not (Test-Path $NssmExe)) {
    Write-Error "[!] NSSM binary not found at: $NssmExe"
    exit 1
}
if (-not (Test-Path $PythonExe)) {
    Write-Error "[!] Virtual environment Python not found at: $PythonExe. Run 'uv sync' first."
    exit 1
}

# 3. Create Logs Directory
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   DROX COMMAND TOWER - WINDOWS SERVICE INSTALLATION       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 4. Remove existing service if present
& $NssmExe status $ServiceName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Existing $ServiceName service detected. Stopping and removing..." -ForegroundColor Yellow
    & $NssmExe stop $ServiceName 2>$null | Out-Null
    & $NssmExe remove $ServiceName confirm 2>$null | Out-Null
    Start-Sleep -Seconds 1
}

# 5. Register Service via NSSM
Write-Host "[+] Registering Service: $ServiceName" -ForegroundColor Green
& $NssmExe install $ServiceName "$PythonExe" "server.py"

# 6. Configure Service Parameters
Write-Host "[+] Configuring working directory, metadata, and auto-start..." -ForegroundColor Green
& $NssmExe set $ServiceName AppDirectory "$BaseDir"
& $NssmExe set $ServiceName DisplayName "Drox Command Tower (Licensing & Kill-Switch Hub)"
& $NssmExe set $ServiceName Description "Centralized Sovereign Licensing, Entitlements & Customer Kill-Switch Hub for TradePost and DroxAI ecosystem applications."
& $NssmExe set $ServiceName Start SERVICE_AUTO_START
& $NssmExe set $ServiceName AppEnvironmentExtra "PYTHONUNBUFFERED=1"

# 7. Configure Logging & Log Rotation
Write-Host "[+] Configuring stdout/stderr logs and automatic rotation..." -ForegroundColor Green
& $NssmExe set $ServiceName AppStdout "$LogsDir\service_stdout.log"
& $NssmExe set $ServiceName AppStderr "$LogsDir\service_stderr.log"
& $NssmExe set $ServiceName AppRotateFiles 1
& $NssmExe set $ServiceName AppRotateOnline 1
& $NssmExe set $ServiceName AppRotateBytes 10485760 # 10MB rotation

# 8. Configure Crash Recovery
Write-Host "[+] Configuring automatic crash restart throttle (3s)..." -ForegroundColor Green
& $NssmExe set $ServiceName AppThrottle 3000

# 9. Start Service
if ($StartAfterInstall) {
    Write-Host "[*] Starting $ServiceName..." -ForegroundColor Cyan
    & $NssmExe start $ServiceName
    Start-Sleep -Seconds 2
    $status = & $NssmExe status $ServiceName
    Write-Host "[+] Service Status: $status" -ForegroundColor Green
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Service successfully installed!" -ForegroundColor Green
Write-Host "Cockpit HUD:     http://127.0.0.1:8088/" -ForegroundColor White
Write-Host "API Docs:        http://127.0.0.1:8088/docs" -ForegroundColor White
Write-Host "Stdout Log:      $LogsDir\service_stdout.log" -ForegroundColor Gray
Write-Host "Stderr Log:      $LogsDir\service_stderr.log" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

Start-Sleep -Seconds 3

