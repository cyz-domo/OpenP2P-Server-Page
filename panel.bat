@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title OpenP2P Panel

rem ============================================================
rem  OpenP2P 面板服务管理（Windows）
rem  - 启动 / 停止 / 重启 / 状态 / 停止所有 8377 端口服务
rem  - 输入数字回车执行，循环菜单
rem ============================================================

rem Python 路径：默认取 PATH 里的 python，可在下面直接指定绝对路径
set "PYTHON=python"
set "PORT=8377"
set "DIR=%~dp0"

:menu
cls
echo.
echo  ================================================
echo   OpenP2P Panel  (port %PORT%)
echo  ================================================
echo.
echo    [1] 启动面板
echo    [2] 停止面板
echo    [3] 重启面板
echo    [4] 查看运行状态
echo    [5] 停止所有占用 %PORT% 端口的服务
echo    [6] 查看实时日志 (Ctrl+C 返回)
echo.
echo    [0] 退出
echo.
set /p choice=  请输入数字后回车: 

if "%choice%"=="1" goto start
if "%choice%"=="2" goto stop
if "%choice%"=="3" goto restart
if "%choice%"=="4" goto status
if "%choice%"=="5" goto killport
if "%choice%"=="6" goto logs
if "%choice%"=="0" exit /b 0
goto menu

:start
call :check_running
if !RUNNING! == 1 (
    echo.
    echo  [!] 面板已在运行 (PID !RUNPID!)，无需重复启动
) else (
    echo.
    echo  [*] 启动面板...
    cd /d "%DIR%"
    start "OpenP2P-Panel" /min cmd /c "%PYTHON% server.py --port %PORT% > server.log 2>&1"
    timeout /t 3 /nobreak >nul
    call :check_running
    if !RUNNING! == 1 (
        echo  [✓] 已启动, PID !RUNPID!   http://127.0.0.1:!PORT!
    ) else (
        echo  [x] 启动失败，最近日志:
        tail -5 server.log 2>nul || type server.log 2>nul | more +0
    )
)
echo.
pause
goto menu

:stop
call :check_running
if !RUNNING! == 0 (
    echo.
    echo  [!] 面板未在运行
) else (
    echo.
    echo  [*] 停止面板 (PID !RUNPID!)...
    taskkill /F /PID !RUNPID! >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo  [✓] 已停止
)
echo.
pause
goto menu

:restart
call :check_running
if !RUNNING! == 1 (
    echo.
    echo  [*] 重启: 先停止 PID !RUNPID!...
    taskkill /F /PID !RUNPID! >nul 2>&1
    timeout /t 1 /nobreak >nul
)
echo  [*] 启动面板...
cd /d "%DIR%"
start "OpenP2P-Panel" /min cmd /c "%PYTHON% server.py --port %PORT% > server.log 2>&1"
timeout /t 3 /nobreak >nul
call :check_running
if !RUNNING! == 1 (
    echo  [✓] 重启完成, PID !RUNPID!   http://127.0.0.1:!PORT!
) else (
    echo  [x] 启动失败，请查看 server.log
)
echo.
pause
goto menu

:status
call :check_running
echo.
if !RUNNING! == 1 (
    echo  面板状态: 运行中  PID=!RUNPID!  地址=http://127.0.0.1:%PORT%
) else (
    echo  面板状态: 未运行
)
echo.
pause
goto menu

:killport
echo.
echo  [*] 查找所有占用 %PORT% 端口的进程...
set FOUND=0
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    set FOUND=1
    echo      - PID %%P
    taskkill /F /PID %%P >nul 2>&1
)
if !FOUND! == 0 (
    echo  [!] 端口 %PORT% 当前无进程占用
) else (
    timeout /t 1 /nobreak >nul
    echo  [✓] 已全部停止
)
echo.
pause
goto menu

:logs
echo.
echo  ===== server.log (实时，Ctrl+C 结束返回) =====
if exist "%DIR%server.log" (
    powershell -NoProfile -Command "Get-Content '%DIR%server.log' -Wait -Tail 30"
) else (
    echo  [!] 尚无日志文件
)
goto menu

rem ---------- 子过程: 检测面板是否在运行 ----------
:check_running
set RUNNING=0
set RUNPID=
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING" 2^>nul') do (
    set RUNNING=1
    set RUNPID=%%P
)
exit /b 0
