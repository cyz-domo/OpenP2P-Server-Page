# OpenP2P 管理面板 — Vercel 边缘版本 (Edge Functions)

纯 Serverless 边缘运行版本，基于 **Vercel Edge Functions**（标准 Web Crypto / Fetch API 构建）。无需服务器、无需数据库、无需 Python 环境，全球 CDN 节点低延迟秒级响应。

## 🌟 核心特性
- **0 服务器运维**：直接部署于 Vercel 全球边缘网络，冷启动时间 0ms。
- **AES-GCM-256 会话加密**：多账号 Token 与凭据使用 AES-GCM 强加密存储于 HttpOnly Cookie，杜绝客户端泄露风险。
- **SSRF 严格防御**：强制 HTTPS 并全量拦截针对私有内网和云元数据 IP 的非法代理请求。
- **2分钟防重放验证码**：密码学动态签名与高熵随机 Nonce，保障防爆破安全。
- **多账号与实时穿透**：支持多账号平滑无感切换、设备实时搜索、隧道管理与虚拟网络一键配置。

---

## 🚀 部署指南

### 方法一：GitHub 一键导入（推荐）
1. 打开 [Vercel 官网控制台](https://vercel.com/new)；
2. 导入您的 GitHub 仓库 `cyz-domo/OpenP2P-Server-Page`；
3. **关键设置**：
   - **Production Branch**（生产分支）：设置为 **`vercel`**；
   - **Framework Preset**：选择 **Other**；
   - **Root Directory**：保持默认 `./`；
4. 点击 **Deploy**，等待约 30 秒即可生成专属访问域名。

### 方法二：使用 Vercel CLI 命令行部署
```bash
# 全局安装 Vercel CLI
npm install -g vercel

# 登录 Vercel
vercel login

# 部署到生产环境
vercel --prod
```

---

## ⚙️ 可选环境变量配置

在 Vercel 项目设置中的 **Settings -> Environment Variables** 中可按需添加：

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `SESSION_SECRET` | 内部自动派生安全密钥 | 用于 AES-GCM 加密 Cookie 的私钥（建议填写 32 位以上随机字符串） |
| `UPSTREAM_URL` | `https://console.openpxp.com` | OpenP2P 官方默认控制台代理目标 |
| `PANEL_KEY` | *(空)* | 全站访问口令（配置后访问面板需先输入口令鉴权） |

---

## 🇨🇳 关于国内网络优化说明
- Vercel 赠送的 `*.vercel.app` 免费域名在国内部分地区可能会受到 DNS 干扰；
- **强烈建议绑定您的自有域名**（如 `p2p.yourdomain.com`）：
  - 在 Vercel 控制台 **Settings -> Domains** 中添加域名；
  - 在您的 DNS 解析商处添加一条 `CNAME` 记录指向 `cname.vercel-dns.com` 或 `A` 记录指向 `76.76.21.21`；
  - 绑定自定义域名后，国内各运营商均可高速直连访问！
