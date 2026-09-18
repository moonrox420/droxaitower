<#
.SYNOPSIS
    Controls and inspects the Drox Command Tower Windows Service.

.EXAMPLE
    .\service_control.ps1 -Action status
    .\service_control.ps1 -Action restart
    .\service_control.ps1 -Action logs
#>

param(
    [ValidateSet("status", "start", "stop", "restart", "logs")]
    [string]$Action = "status"
)

$BaseDir = "C:\Users\droxa\droxaitower"
$NssmExe = "$BaseDir\nssm-2.24\win64\nssm.exe"
$ServiceName = "DroxCommandTower"
$LogsDir = "$BaseDir\logs"
$EnvFile = Join-Path $BaseDir ".env"

if (-not (Test-Path $EnvFile)) {
    Write-Error ".env not found at $EnvFile"
    exit 1
}

Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()

    if ($line -and -not $line.StartsWith("#")) {
        $parts = $line -split "=", 2

        if ($parts.Count -eq 2) {
            $name = $parts[0].Trim()
            $value = $parts[1].Trim()

            Set-Item -Path "Env:$name" -Value $value
        }
    }
}

if (-not $env:DROX_MASTER_KEY) {
    Write-Error "DROX_MASTER_KEY is missing from .env"
    exit 1
}

switch ($Action) {
    "status" {
        Write-Host "Checking service status for $ServiceName..." -ForegroundColor Cyan
        & $NssmExe status $ServiceName
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8088/api/v1/admin/stats" -Headers @{"X-Master-Key"=$env:DROX_MASTER_KEY} -TimeoutSec 2 -ErrorAction Stop
            Write-Host "[+] Command Tower API is healthy and reachable at http://127.0.0.1:8088/" -ForegroundColor Green
            Write-Host "    Active Customers: $($resp.active_customers)" -ForegroundColor White
            Write-Host "    Total MRR:        `$$($resp.total_mrr_usd)" -ForegroundColor White
            Write-Host "    Active Keys:      $($resp.active_credentials)" -ForegroundColor White
            Write-Host "    Kill Switches:    $($resp.tripped_kill_switches)" -ForegroundColor White
        } catch {
            Write-Host "[-] API not responding on http://127.0.0.1:8088/" -ForegroundColor Red
        }
    }
    "start" {
        & $NssmExe start $ServiceName
    }
    "stop" {
        & $NssmExe stop $ServiceName
    }
    "restart" {
        & $NssmExe restart $ServiceName
    }
    "logs" {
        Write-Host "=== Latest stdout log (Tail 25) ===" -ForegroundColor Cyan
        if (Test-Path "$LogsDir\service_stdout.log") {
            Get-Content "$LogsDir\service_stdout.log" -Tail 25
        } else {
            Write-Host "No stdout log found yet." -ForegroundColor Gray
        }
        Write-Host "`n=== Latest stderr log (Tail 25) ===" -ForegroundColor Yellow
        if (Test-Path "$LogsDir\service_stderr.log") {
            Get-Content "$LogsDir\service_stderr.log" -Tail 25
        } else {
            Write-Host "No stderr log found yet." -ForegroundColor Gray
        }
    }
}

