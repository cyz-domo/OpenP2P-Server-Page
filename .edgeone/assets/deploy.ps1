# ==============================================================================
# OpenP2P 管理面板 (openp2p-panel) — Windows 一键部署与管理脚本 (PowerShell)
# 支持系统：Windows 10 / 11 / Windows Server
# ==============================================================================

param(
    [string]$Action = "",
    [int]$Port = 8377,
    [string]$HostIP = "0.0.0.0",
    [string]$Auth = "",
    [string]$Upstream = ""
)

# 确保控制台输出使用 UTF-8 避免中文乱码
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ScriptDir ".server.pid"
$LogFile = Join-Path $ScriptDir "server.log"
$TaskName = "OpenP2P-Panel-AutoStart"

function Write-Banner {
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "       OpenP2P 管理面板 — Windows 一键部署与管理工具     " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Find-Python {
    $candidates = @("python.exe", "py.exe", "python3.exe")
    foreach ($cmd in $candidates) {
        $path = (Get-Command $cmd -ErrorAction SilentlyContinue)
        if ($path) {
            try {
                $verOutput = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                $parts = $verOutput.Trim().Split('.')
                if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 8) {
                    return $cmd
                }
            } catch {}
        }
    }
    return $null
}

function Get-LocalIPList {
    $ips = @()
    try {
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.IPAddress -ne "127.0.0.1" -and
            $_.IPAddress -notmatch "^169\.254\." -and
            $_.InterfaceAlias -notmatch "Loopback|vEthernet|VirtualBox|VMware"
        }
        foreach ($item in $adapters) {
            $ips += $item.IPAddress
        }
    } catch {}
    return $ips
}

function Test-IsRunning {
    # 1. 优先检查端口监听（最直接准确，即使未通过本脚本启动也能检测到）
    try {
        $conn = Get-NetTCPConnection -LocalPort $script:Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($conn -and $conn.OwningProcess) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                # 记录有效 PID 文件供后续使用
                $proc.Id | Out-File -FilePath $PidFile -Encoding ascii
                return $proc
            }
        }
    } catch {}

    # 2. 检查 PID 文件中的记录
    if (Test-Path $PidFile) {
        try {
            $p = (Get-Content $PidFile -ErrorAction SilentlyContinue).Trim()
            if ($p -match '^\d+$') {
                $proc = Get-Process -Id ([int]$p) -ErrorAction SilentlyContinue
                if ($proc -and ($proc.ProcessName -match "python")) {
                    return $proc
                }
            }
        } catch {}
    }

    # 3. 通过 WMI/CIM 查找正在运行 server.py 的 Python 进程
    try {
        $cim = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -match "^python" -or $_.Name -match "^py") -and ($_.CommandLine -match "server\.py")
        } | Select-Object -First 1
        if ($cim) {
            $proc = Get-Process -Id $cim.ProcessId -ErrorAction SilentlyContinue
            if ($proc) {
                $proc.Id | Out-File -FilePath $PidFile -Encoding ascii
                return $proc
            }
        }
    } catch {}

    return $null
}

function Start-ServerBackground {
    param([int]$pPort, [string]$pHost)
    $proc = Test-IsRunning
    if ($proc) {
        Write-Host "[!] 面板已在运行中 (PID: $($proc.Id))" -ForegroundColor Yellow
        Show-Status
        return
    }

    $py = Find-Python
    if (-not $py) {
        Write-Host "[X 错误] 未找到 Python 3.8 或更高版本！" -ForegroundColor Red
        Write-Host "请前往 https://www.python.org/downloads/ 安装 Python，并勾选 Add python.exe to PATH" -ForegroundColor Yellow
        return
    }

    Write-Host "[+] 正在后台启动 OpenP2P 管理面板..." -ForegroundColor Cyan
    $argsList = @("server.py", "--host", $pHost, "--port", $pPort)
    if ($Auth) { $argsList += @("--auth", $Auth) }
    if ($Upstream) { $argsList += @("--upstream", $Upstream) }

    # 优先使用 pythonw 免黑框静默运行
    $pyDir = Split-Path (Get-Command $py).Source
    $pywPath = Join-Path $pyDir "pythonw.exe"
    $execBin = if (Test-Path $pywPath) { $pywPath } else { $py }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $execBin
    $startInfo.Arguments = ($argsList -join " ")
    $startInfo.WorkingDirectory = $ScriptDir
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $p = [System.Diagnostics.Process]::Start($startInfo)
    $p.Id | Out-File -FilePath $PidFile -Encoding ascii

    Start-Sleep -Milliseconds 1200
    if (-not $p.HasExited) {
        Write-Host "[OK] OpenP2P 面板后台启动成功！(PID: $($p.Id))" -ForegroundColor Green
        Write-Host "访问地址：" -ForegroundColor White
        Write-Host "  - 本机访问:   http://localhost:$pPort" -ForegroundColor Cyan
        $lanIps = Get-LocalIPList
        foreach ($ip in $lanIps) {
            Write-Host "  - 局域网访问:  http://$($ip):$pPort" -ForegroundColor Cyan
        }
        Start-Process "http://localhost:$pPort"
    } else {
        Write-Host "[X] 启动失败，请检查配置或端口 $pPort 是否被占用。" -ForegroundColor Red
    }
}

function Start-ServerForeground {
    param([int]$pPort, [string]$pHost)
    $py = Find-Python
    if (-not $py) {
        Write-Host "[X 错误] 未找到 Python 3.8+！" -ForegroundColor Red
        return
    }
    Write-Host "[+] 正在前台启动 OpenP2P 管理面板 (按 Ctrl+C 退出)..." -ForegroundColor Cyan
    Set-Location $ScriptDir
    $argsList = @("server.py", "--host", $pHost, "--port", $pPort)
    if ($Auth) { $argsList += @("--auth", $Auth) }
    if ($Upstream) { $argsList += @("--upstream", $Upstream) }
    & $py $argsList
}

function Stop-Server {
    Write-Host "[+] 正在停止 OpenP2P 管理面板..." -ForegroundColor Cyan
    $killed = $false

    # 1. 优先关闭监听端口的进程
    try {
        $conn = Get-NetTCPConnection -LocalPort $script:Port -State Listen -ErrorAction SilentlyContinue
        foreach ($c in $conn) {
            if ($c.OwningProcess) {
                Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
                $killed = $true
            }
        }
    } catch {}

    # 2. 检查 PID 文件中的进程
    if (Test-Path $PidFile) {
        $p = (Get-Content $PidFile -ErrorAction SilentlyContinue).Trim()
        if ($p -match '^\d+$') {
            Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue
            $killed = $true
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }

    # 3. 检查所有匹配 server.py 的 Python 进程
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -match "^python" -or $_.Name -match "^py") -and ($_.CommandLine -match "server\.py")
        }
        foreach ($pr in $procs) {
            Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue
            $killed = $true
        }
    } catch {}

    if ($killed) {
        Write-Host "[OK] 面板服务已成功停止。" -ForegroundColor Green
    } else {
        Write-Host "[!] 未发现运行中的面板进程。" -ForegroundColor Yellow
    }
}

function Show-Status {
    $proc = Test-IsRunning
    if ($proc) {
        Write-Host "服务状态: [Active] 正在运行 (Running)" -ForegroundColor Green
        Write-Host "进程 PID: $($proc.Id)" -ForegroundColor Cyan
        Write-Host "本机访问: http://localhost:$Port" -ForegroundColor Cyan
        $lanIps = Get-LocalIPList
        foreach ($ip in $lanIps) {
            Write-Host "局域网:   http://$($ip):$Port" -ForegroundColor Cyan
        }
    } else {
        Write-Host "服务状态: [Stopped] 未运行 (Not Running)" -ForegroundColor Red
    }
}

function Register-AutoStartTask {
    $py = Find-Python
    if (-not $py) {
        Write-Host "[X 错误] 未找到 Python 环境！" -ForegroundColor Red
        return
    }
    $pyDir = Split-Path (Get-Command $py).Source
    $pywPath = Join-Path $pyDir "pythonw.exe"
    $execBin = if (Test-Path $pywPath) { $pywPath } else { $py }
    $execArgs = "server.py --host 0.0.0.0 --port $Port"
    if ($Upstream) { $execArgs += " --upstream $Upstream" }

    try {
        $action = New-ScheduledTaskAction -Execute $execBin -Argument $execArgs -WorkingDirectory $ScriptDir
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Description "OpenP2P Panel Background Service" -Force | Out-Null
        Write-Host "[OK] 已成功注册 Windows 开机自启任务 ($TaskName)！" -ForegroundColor Green
    } catch {
        Write-Host "[X] 注册开机自启任务失败: $_" -ForegroundColor Red
        Write-Host "请以管理员身份运行 PowerShell 再次尝试。" -ForegroundColor Yellow
    }
}

function Unregister-AutoStartTask {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[OK] 已移除开机自启任务。" -ForegroundColor Green
    } catch {
        Write-Host "[!] 移除任务时提示: $_" -ForegroundColor Yellow
    }
}

# 交互式菜单
function Show-Menu {
    Write-Banner
    $py = Find-Python
    if ($py) {
        Write-Host "当前 Python 环境: $py" -ForegroundColor Green
    } else {
        Write-Host "当前 Python 环境: [未检测到 Python 3.8+]" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "请选择操作："
    Write-Host "  [1] 后台静默运行 (推荐，免命令行窗口)"
    Write-Host "  [2] 前台控制台运行 (调试排错)"
    Write-Host "  [3] 停止面板服务"
    Write-Host "  [4] 重启面板"
    Write-Host "  [5] 查看服务状态与访问地址"
    Write-Host "  [6] 设置开机自动启动 (Windows 计划任务)"
    Write-Host "  [7] 取消开机自动启动"
    Write-Host "  [0] 退出"
    Write-Host ""
    $choice = Read-Host "请输入数字 [1-7, 0]"

    switch ($choice) {
        "1" {
            $p = Read-Host "请输入监听端口 (回车默认 8377)"
            if ($p) { $script:Port = [int]$p }
            Start-ServerBackground -pPort $script:Port -pHost $HostIP
        }
        "2" {
            $p = Read-Host "请输入监听端口 (回车默认 8377)"
            if ($p) { $script:Port = [int]$p }
            Start-ServerForeground -pPort $script:Port -pHost $HostIP
        }
        "3" { Stop-Server }
        "4" {
            Stop-Server
            Start-Sleep -Seconds 1
            Start-ServerBackground -pPort $Port -pHost $HostIP
        }
        "5" { Show-Status }
        "6" { Register-AutoStartTask }
        "7" { Unregister-AutoStartTask }
        "0" { exit }
        Default { Write-Host "无效选择！" -ForegroundColor Red }
    }
}

if ($Action -eq "start") {
    Start-ServerBackground -pPort $Port -pHost $HostIP
} elseif ($Action -eq "run") {
    Start-ServerForeground -pPort $Port -pHost $HostIP
} elseif ($Action -eq "stop") {
    Stop-Server
} elseif ($Action -eq "restart") {
    Stop-Server
    Start-Sleep -Seconds 1
    Start-ServerBackground -pPort $Port -pHost $HostIP
} elseif ($Action -eq "status") {
    Show-Status
} elseif ($Action -eq "service") {
    Register-AutoStartTask
} elseif ($Action -eq "unservice") {
    Unregister-AutoStartTask
} else {
    Show-Menu
}
