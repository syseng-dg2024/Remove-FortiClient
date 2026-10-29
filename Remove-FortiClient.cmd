@echo off

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b %ERRORLEVEL%
)

set "WORKDIR=%~dp0Remove-FortiClient"
if not exist "%WORKDIR%" mkdir "%WORKDIR%"
cd /d "%WORKDIR%"

set "PS1=%WORKDIR%\Remove-FortiClient.ps1"
set "URL=https://raw.githubusercontent.com/syseng-dg2024/Remove-FortiClient/main/Remove-FortiClient.ps1"

echo Downloading Remove-FortiClient.ps1 from GitHub...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -OutFile '%PS1%'"
if not exist "%PS1%" (
    echo ERROR: Download failed. Check internet access to github.com.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
exit /b %ERRORLEVEL%