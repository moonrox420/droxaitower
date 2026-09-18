<#
.SYNOPSIS
    Uninstalls the Drox Command Tower Windows Service.
#>

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator privileges to uninstall Windows Service..." -ForegroundColor Cyan
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$BaseDir = "C:\Users\droxa\droxaitower"
$NssmExe = "$BaseDir\nssm-2.24\win64\nssm.exe"
$ServiceName = "DroxCommandTower"

Write-Host "[*] Stopping $ServiceName..." -ForegroundColor Yellow
& $NssmExe stop $ServiceName 2>$null | Out-Null

Write-Host "[*] Removing $ServiceName..." -ForegroundColor Yellow
& $NssmExe remove $ServiceName confirm

Write-Host "[+] $ServiceName successfully removed from Windows Services." -ForegroundColor Green
Start-Sleep -Seconds 2
