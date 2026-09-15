# OpenP2P 管理面板 — Cloudflare Workers / Pages 边缘分支

这是专为 **Cloudflare Workers / Cloudflare Pages** 适配的完全 Serverless 边缘运行版本。

无需云服务器，无需 Python 运行环境，直接运行在 Cloudflare 全球 300+ 边缘数据中心，免费额度充裕，自带全球 CDN 加速与 DDoS 基础防护。

---

## 🌟 特性

- **全球 300+ 边缘节点极速分发**：毫秒级响应，告别国内/海外线路延迟。
- **静态资源 + 边缘函数融合**：`./public` 前端静态资源直接通过 Cloudflare 静态资产托管；`/api/*` 与 `/pxp/*` 走 Worker 动态代理。
- **无状态分布式 Session**：基于 Web Crypto（HMAC-SHA256）加密签名 Cookie，跨全球节点无缝鉴权，无需额外数据库。
- **支持多账户无缝切换**：可保存多用户凭据并一键切换。
- **开箱即用**：标准 `wrangler dev` 本地调试与 `wrangler deploy` 一键部署。

---

## 🚀 快速开始与一键部署

### 1. 安装 Wrangler CLI
```bash
npm install -g wrangler
```

### 2. 登录 Cloudflare 账户
```bash
wrangler login
```

### 3. 本地开发与调试
```bash
wrangler dev
```
启动后可在终端打开提示的本地预览地址（如 `http://localhost:8787`）。

### 4. 一键部署上线
```bash
wrangler deploy
```
部署完成后终端会直接输出您的专属 `.workers.dev` 域名。

---

## ⚙️ 环境变量与密钥配置（可选）

您可以在 `wrangler.toml` 的 `[vars]` 段中或 Cloudflare 控制台 -> Workers -> Settings -> Variables 中配置：

| 变量名 | 说明 |
| :--- | :--- |
| `PANEL_KEY` | *(可选)* 面板访问安全口令（若设置，所有人访问面板必须输入口令） |
| `UPSTREAM_URL` | *(默认 `https://console.openpxp.com`)* OpenP2P 官方控制台地址 |
| `SESSION_SECRET` | *(可选)* Session 签名密钥（建议生产环境设置为随机复杂字符串） |

配置加密密钥示例：
```bash
wrangler secret put PANEL_KEY
wrangler secret put SESSION_SECRET
```
