# OpenP2P 管理面板 — 腾讯云 EdgeOne Makers 边缘分支

这是专为**腾讯云 EdgeOne Makers（边缘函数 / Pages）**适配的完全 Serverless 边缘运行版本。

无需云服务器，无需 Python 运行环境，直接运行在 EdgeOne 全球边缘网络，享受全球加速与自动 HTTPS。

---

## 🌟 特性

- **全球边缘低延迟**：由腾讯云 EdgeOne 全球边缘节点就近响应。
- **纯原生前端 + 边缘代理**：前端静态托管加速，`/api/*` 与 `/pxp/*` 边缘函数动态反向代理并注入鉴权。
- **无状态分布式 Session**：基于 Web Crypto（HMAC-SHA256）加密签名 Cookie，跨全球节点无缝鉴权，无需额外数据库。
- **多账户无缝切换**：支持保存多用户 Token/密码快速切换。
- **开箱即用**：支持 `edgeone makers dev` 本地调试与 `edgeone makers deploy` 一键部署。

---

## 🚀 快速开始与一键部署

### 1. 安装 EdgeOne CLI
```bash
npm install -g edgeone
```

### 2. 登录 EdgeOne 账户
```bash
edgeone login
```

### 3. 本地开发调试
```bash
edgeone makers dev
```
启动后可在浏览器打开 `http://localhost:8787` 查看效果。

### 4. 一键部署到全球边缘节点
```bash
edgeone makers deploy
```

---

## ⚙️ 环境变量配置（可选）

在 EdgeOne 控制台项目设置中的 **环境变量** 配置：

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PANEL_KEY` | *(留空表示不设口令)* | 面板访问安全口令（若设置，所有人访问必须输入口令） |
| `UPSTREAM_URL` | `https://console.openpxp.com` | OpenP2P 官方控制台地址（支持切换为自建或镜像地址） |
| `SESSION_SECRET` | *(内置密钥)* | Session 签名密钥（建议在生产环境自定义为随机字符串） |
