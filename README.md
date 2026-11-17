# OpenP2P 管理面板

支持两种运行方式：

- **Vercel 边缘版本（推荐）**：基于 Vercel Edge Functions（标准 Web Crypto / Fetch API），无需服务器、数据库或 Python 环境。
- **自托管 Python 版本**：`server.py`，仅依赖 Python 3 标准库，适合内网或自有服务器部署。

## 🌟 核心特性
- **0 服务器运维（Edge）**：部署于 Vercel 全球边缘网络，全球 CDN 节点低延迟响应。
- **AES-GCM-256 会话加密**：Edge 版多账号 Token 使用 AES-GCM 加密存储于 HttpOnly Cookie；配置 KV 后可切换为服务端可吊销 Session。
- **不保存账号密码**：登录成功后仅保留上游 token；token 过期后需重新登录，面板不会落盘密码。
- **WebAuthn 通行密钥（仅 Edge 版）**：服务端完整校验 challenge、origin、RP ID、签名与签名计数器，支持凭据吊销。
- **SSRF 严格防御**：强制 HTTPS，拦截私有内网与云元数据地址，并校验上游地址白名单。
- **6 位一次性验证码**：验证码密文下发、单次有效，并配合按 IP 的登录限速与失败锁定。
- **多账号与实时穿透**：支持多账号切换、设备实时搜索、隧道管理与虚拟网络配置。

---

## 🚀 Vercel 部署指南

### 方法一：GitHub 一键导入（推荐）
1. 打开 [Vercel 官网控制台](https://vercel.com/new)；
2. 导入您的 GitHub 仓库 `cyz-domo/OpenP2P-Server-Page`；
3. **关键设置**：
   - **Production Branch**（生产分支）：设置为 **`vercel`**；
   - **Framework Preset**：选择 **Other**；
   - **Root Directory**：保持默认 `./`；
4. 在 **Settings -> Environment Variables** 中**至少配置 `SESSION_SECRET`**（见下文）；
5. 点击 **Deploy**，等待约 30 秒即可生成专属访问域名。

### 方法二：使用 Vercel CLI 命令行部署
```bash
npm install -g vercel
vercel login
vercel --prod
```

---

## ⚙️ 环境变量

### 必填（Vercel / 生产环境）

| 变量名 | 说明 |
| :--- | :--- |
| `SESSION_SECRET` | **必填**，至少 32 字符的随机字符串。用于派生 AES-GCM 与 HMAC 密钥（会话、通行密钥、验证码、挑战令牌）。未配置时生产环境会拒绝启动。 |

生成示例：
```bash
openssl rand -base64 48
```

### 可选

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PANEL_KEY` | *(空)* | 全站访问口令。配置后访问面板需先输入口令，口令通过 HttpOnly Cookie 保存 12 小时。 |
| `APP_ORIGIN` | 自动推断 | 面板对外访问源（如 `https://p2p.yourdomain.com`），用于 WebAuthn origin 与 CSRF 校验。绑定自定义域名后建议显式配置。 |
| `RP_ID` | 由 `APP_ORIGIN` 推断 | WebAuthn RP ID，通常是域名本身（如 `p2p.yourdomain.com`）。配置错误会导致通行密钥无法识别。 |
| `PASSKEY_REQUIRE_UV` | `false` | 设为 `true` 时要求通行密钥登录必须完成用户验证（PIN/生物识别）。 |
| `ALLOW_CUSTOM_UPSTREAM` | `false` | 设为 `true` 才允许使用官方列表之外的上游控制台地址。 |
| `UPSTREAM_URL` | `https://console.openpxp.com` | 官方控制台代理目标。默认仅允许 `console.openpxp.com` / `console.openp2p.cn`，自定义需开启 `ALLOW_CUSTOM_UPSTREAM`。 |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` | *(空)* | 配置后启用服务端 Session 与通行密钥注册表（Vercel KV）。 |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | *(空)* | 同上，兼容 Upstash Redis REST。 |

> **建议配置 KV/Upstash**：未配置时 Session 以加密 Cookie 保存，无法在服务端主动吊销；配置后登出、轮换与通行密钥吊销会立即在服务端生效。

---

## 🔐 升级到本安全版本后的行为变化

- **旧会话全部失效**：Session 结构与密钥派生已变更，用户需要重新登录。
- **旧通行密钥需要重新绑定**：旧版本登记的凭据不再被接受（避免不安全的凭据结构继续生效）。
- **不再保存密码**：面板不会持久化账号密码，也不再静默自动重登；上游 token 过期后请重新输入密码。
- **登录必须具备一次性验证码**：验证码为 6 位数字，单次有效。
- **Cookie 仅在 HTTPS 下下发 `Secure` 标记**：请务必通过 HTTPS 访问面板。

---

## 🐍 自托管 Python 版本

```bash
python3 server.py --auth '你的访问口令' --upstream https://console.openpxp.com
```

说明：

- 默认只监听 `127.0.0.1`；对外提供服务时**必须**设置访问口令（推荐 `PANEL_KEY` 环境变量，避免出现在 `ps` 命令行中）并置于 HTTPS 反向代理之后。
- 访问口令通过 `/api/panel-auth` 换取 HttpOnly Cookie（12 小时），前端不再把口令写入 localStorage；API 客户端仍可使用 `X-Panel-Key` 请求头。
- 自托管版本**不提供通行密钥登录/绑定**（缺少 WebAuthn 验签依赖）；相关接口统一返回 `501`，请使用密码或 token 登录。
- 自托管版本同样**不保存密码**；`config.json` 中仅保留 Session 与上游 token。启动时会自动清除旧版本遗留的密码与通行密钥记录。
- 上游地址必须是 HTTPS 根地址，且不能指向私有内网、回环地址或云元数据地址。
- 若 `config.json` 曾由旧版本生成，首次启动后请确认其中的 `password`、`passkeys` 字段已被清除。

---

## 🇨🇳 国内网络优化说明
- Vercel 赠送的 `*.vercel.app` 免费域名在国内部分地区可能会受到 DNS 干扰；
- **强烈建议绑定您的自有域名**（如 `p2p.yourdomain.com`）：
  - 在 Vercel 控制台 **Settings -> Domains** 中添加域名；
  - 在 DNS 解析商处添加 `CNAME` 记录指向 `cname.vercel-dns.com`，或 `A` 记录指向 `76.76.21.21`；
  - 绑定自定义域名后，国内各运营商均可高速直连访问。

---

## 🧪 安全测试

```bash
node --test tests/security.test.mjs
```

覆盖 SSRF 过滤、上游白名单、CBOR/COSE 解析、ES256/RS256 签名校验、签名计数器防重放、challenge 一次性与绑定、KV Session 吊销、验证码一次性、`SESSION_SECRET` 强制校验与跨站请求拦截。
