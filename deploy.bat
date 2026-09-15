@echo off
setlocal
cd /d "%~dp0"

chcp 65001 >nul
set "PS_BIN=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_BIN%" set "PS_BIN=powershell.exe"

"%PS_BIN%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy.ps1" %*

if "%~1"=="" pause
endlocal
