@echo off
where pwsh.exe >nul 2>nul
if errorlevel 1 (
    echo SyncExtend requires PowerShell 7.
    pause
    exit /b 1
)
pwsh.exe -NoLogo -NoProfile -STA -File "%~dp0launch-client.ps1" %*
if errorlevel 1 pause
