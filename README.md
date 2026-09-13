# OpenP2P 管理面板（openp2p-panel）

对 OpenP2P 官方控制台（console.openpxp.com / console.openp2p.cn）能力的重构、现代化设计与全方位增强：
**设备大盘统计与批量操作、隧道规则全量聚合（展示官方隐藏的「链路模式/中继节点」）、虚拟网络全表格直编、子网代理 (Resource) 原生下发、实时成员隧道状态透视、多架构客户端下载中心**。

纯 Python 标准库 + 原生现代 HTML5/CSS3/ES6，**零第三方依赖，无需构建，极速秒开**，任何能跑 Python 3.8+ 的 Linux、macOS 或 Windows 系统即可一键部署。

---

## 🌟 核心功能对照（相对官方控制台的增强）

| 能力 | 官方控制台 | 本面板 |
|---|---|---|
| **大盘指标** | 仅列表平铺 | **4维 KPI 统计卡片**（总设备、在线呼吸灯、离线、活跃隧道/规则） |
| **设备列表** | 单卡片逐台操作 | 表格总览 + 智能搜索/仅在线过滤 + **多选批量重启/升级/删除** |
| **操作系统识别** | 纯文字显示 | **专属系统图标微徽章**（🪟 Windows / 🐧 Linux / 🍎 macOS / 🤖 Android / 🐳 Docker 等） |
| **转发规则** | 进入单台设备逐条查看 | **全部设备规则聚合一张表**，支持跨设备模糊搜索 |
| **下一条 / 中继链路** | ❌ 不展示 | ✅ 实时透视上报数据，显示 `linkMode` / `relayNode` / `specRelayNode` |
| **子网代理（组网隧道）** | 与端口转发混淆在一起 | 独立「组网隧道」类型标识，一键分类过滤 |
| **子网代理网段 (resource)**| ❌ 入口极深且难修改 | ✅ 成员表格内直接编辑，随整网一键保存与下发生效 |
| **组网成员连接状态** | 逐台进入繁琐查看 | 成员列表直观显示活跃隧道数 + 明细透视表（`MsgPushReportMemApps`） |
| **虚拟网络成员管理** | 逐个节点增删 | **勾选式批量加入**（自动计算分配虚拟 IP）+ 表格直编 + 一键移除 |
| **官方控制台域名切换** | ❌ 锁定官方主站 | ✅ **可直接自定义官方代理域名**（预置官方主站与国内镜像，随时切换） |
| **下载安装中心** | 多标签反复切换 | 单页四大专属卡片（Win/Linux/Mac/Android）+ 一键复制内嵌 Token 安装命令 |
| **系统级服务化部署** | 需手动配置 | **全平台一键部署**：Linux systemd + 全局命令 `openp2p-panel`、Windows 双击运行 |

---

## 🎨 现代控制台 UI 设计亮点

- **双主题视觉体系**：
  - **深色模式 (Obsidian Slate)**：底色采用深邃科技黑（`#090d16`），微光边框高亮，极光翡翠绿（`#10b981`）与科技青（`#06b6d4`）点缀；
  - **浅色模式 (Crisp Zinc)**：高雅纯净的纸白底色（`#f8fafc`）与纯白卡片，自然柔和的微阴影；
  - 顶栏一键切换主题，配置自动保存在浏览器 `localStorage`。
- **毛玻璃与呼吸微动效**：
  - 顶栏高阶毛玻璃质感（`backdrop-filter: blur(14px)`）；
  - 在线状态与连接徽章带有实时脉冲呼吸律动（Pulse Beacon），网络状态一目了然。
- **触感微交互**：
  - 页面中所有的 IP 地址、端口、命令行均支持一键复制，并伴随按键状态即时变更反馈（`✓` 绿色高亮）与浮动通知。

---

## 🌐 官方代理访问域名配置（灵活适配官方换域）

面板通过反向代理与官方控制台 API 通信。考虑到官方控制台未来可能更换域名或需要在多镜像间切换，**面板提供了三层自由配置通道**：

### 1. Web 界面直接配置（最便捷）
- **登录页面设置**：
  登录卡片顶部设有「官方控制台地址 (Upstream)」输入框，可直接修改，或点击快捷预设按钮：
  - **官方默认**：`https://console.openpxp.com`
  - **国内镜像**：`https://console.openp2p.cn`
- **登录后随时切换**：
  在控制台顶部导航栏点击 **⚙️（设置按钮）**，呼出设置弹窗，即可直接修改或切换官方代理上游地址，**保存后即时生效并持久化**，无需重启服务，所有下载中心的安装命令与链接也会自动联动变更为新域名！

### 2. 命令行参数启动指定
```bash
# 启动时通过 --upstream 指定上游地址
python3 server.py --upstream https://console.openp2p.cn --port 8377
```

### 3. 直接编辑配置文件 (`config.json`)
面板在首次运行时会生成 `config.json`，直接修改其中的 `"upstream"` 字段即可：
```json
{
  "upstream": "https://console.openp2p.cn",
  "token": "...",
  "accounts": [...]
}
```

---

## 🚀 全平台一键部署 (Linux / macOS / Windows)

面板自带完善的跨平台部署管理脚本，无需配置复杂的运行环境：

### 1. Linux 一键部署与系统服务化

#### 方案 A：一键安装为 Linux systemd 系统服务 + 全局命令（推荐）
```bash
# 赋予执行权限并以 root/sudo 运行
chmod +x install-systemd.sh deploy.sh
sudo ./install-systemd.sh
```
执行后，脚本会自动：
1. 校验 Python 3.8+ 环境；
2. 自动生成并注册 `/etc/systemd/system/openp2p-panel.service`；
3. 设置服务开机自启并立即启动；
4. 自动创建系统全局管理命令 `/usr/local/bin/openp2p-panel`。

> 💡 **带参数安装示例**（自定义端口、访问口令或上游域名）：
> ```bash
> sudo ./install-systemd.sh --port 8377 --auth 你的访问口令 --upstream https://console.openp2p.cn
> ```

#### 方案 B：随时在终端任意目录下使用系统管理命令
安装完成后，您可以在**任何终端路径**下直接执行：
```bash
openp2p-panel           # 呼出交互式部署运维菜单
openp2p-panel status    # 查看面板服务运行状态与访问链接
openp2p-panel restart   # 重启面板服务
openp2p-panel stop      # 停止面板服务
openp2p-panel start     # 启动面板服务
openp2p-panel logs      # 实时追踪运行日志 (tail -f)
sudo openp2p-panel unservice  # 卸载 systemd 服务及全局管理命令
```

#### 方案 C：通用部署脚本与菜单 (`deploy.sh`)
```bash
./deploy.sh             # 交互式菜单
./deploy.sh start       # 后台运行
./deploy.sh stop        # 停止运行
./deploy.sh logs        # 查看日志
```

---

### 2. Windows 一键部署 (`deploy.bat` / `deploy.ps1`)

#### 方案 A：双击即用（小白模式）
- 直接鼠标**双击 `deploy.bat`** 批处理文件；
- 弹出选项菜单后输入 `1`（后台静默运行）；
- 脚本自动通过 `pythonw` 在后台启动面板，免黑框遮挡，并**自动在默认浏览器中打开面板网址**！

#### 方案 B：PowerShell 命令行
```powershell
# 启动后台服务并自动打开浏览器
.\deploy.ps1 -Action start

# 查看运行状态
.\deploy.ps1 -Action status

# 停止服务
.\deploy.ps1 -Action stop

# 注册为 Windows 开机自动启动计划任务
.\deploy.ps1 -Action service
```

---

### 3. macOS 一键运行
```bash
chmod +x deploy.sh
./deploy.sh start       # 后台启动服务
./deploy.sh status      # 查看运行状态及局域网访问地址
```

---

## 👥 多账户管理

顶栏「👤 账户名 ▾」下拉可管理多个 OpenP2P 账号：
- **添加账户**：走登录页（账号密码或 Token 均可），成功后自动加入账户池；
- **一键切换**：点选即切，设备、隧道规则、虚拟网络数据随之即时切换到该账户视图；
- **凭据管理**：非激活账户可在下拉菜单中直接点击 `✕` 移除本地凭据（不影响官方云端账号）；
- 账户凭据安全保存在 `config.json` 的 `accounts` 数组中。

---

## 🛡️ 安全机制与防爆破

1. **登录安全与防爆破**：
   - 内置无第三方依赖的 SVG 动态数字验证码（支持旋转与干扰线，点击即刷，5 分钟时效）；
   - 同一 IP 连续失败 **5 次**自动触发 **15 分钟 IP 锁定**，成功登录自动清零；
   - 验证码答案仅存储在服务端内存中，前端无法窥视。
2. **面板访问口令保护**：
   - 暴露于局域网或公网时，建议添加 `--auth` 口令：
     ```bash
     python3 server.py --host 0.0.0.0 --auth <你设置的访问口令>
     ```
   - 浏览器首次访问会提示输入口令，并以 `X-Panel-Key` 请求头安全校验。
3. **路径与代理安全**：
   - 静态资源服务采用 `Path.relative_to` 严密防御路径穿越攻击；
   - 反向代理严格白名单放行 `/api/` 官方控制台前缀，防止服务器被滥用为外部代理；
   - 限制请求体上限为 1MB，POSIX 系统下自动对 `config.json` 执行 `chmod 600` 权限收紧。

---

## 📂 项目结构

```
openp2p-panel/
├── deploy.sh              # Linux & macOS 部署与管理脚本
├── install-systemd.sh     # Linux systemd 系统服务与全局命令一键专用安装器
├── deploy.bat             # Windows 双击运行启动器
├── deploy.ps1             # Windows PowerShell 自动化部署与自启脚本
├── server.py              # 服务端核心（仅依赖 Python 3 标准库）
├── config.json            # 运行时配置（保存 upstream、账户凭据、token）
├── README.md              # 完整项目使用说明
└── public/                # 现代原生静态前端
    ├── index.html         # HTML 骨架与交互弹窗
    ├── app.css            # 现代 Obsidian/Zinc 设计系统与动效样式
    └── app.js             # 纯原生交互逻辑
```
