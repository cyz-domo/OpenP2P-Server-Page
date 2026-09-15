/**
 * OpenP2P 管理面板 — Cloudflare Workers 边缘脚本
 * 纯 Serverless 边缘运行，支持 AES-GCM-256 会话加密、SSRF 严格防护、防重放验证码与全站安全响应头
 */

const DEFAULT_UPSTREAM = "https://console.openpxp.com";
const SESSION_COOKIE_NAME = "openp2p_session";
const SESSION_TTL = 30 * 24 * 3600; // 30天
const DEFAULT_SECRET = "openp2p-cloudflare-aes-secret-key-32bytes-v2";

/* ---------------- 基础工具与 Base64 ---------------- */
function base64UrlEncode(strOrBuffer) {
  let bytes = typeof strOrBuffer === "string" ? new TextEncoder().encode(strOrBuffer) : new Uint8Array(strOrBuffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecodeBytes(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  let binary = atob(base64);
  let bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlDecode(str) {
  return new TextDecoder().decode(base64UrlDecodeBytes(str));
}

/* ---------------- AES-GCM-256 加密存储与 HMAC 签名 ---------------- */
async function getDerivedAesKey(secret) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(secret || DEFAULT_SECRET), "PBKDF2", false, ["deriveKey"]);
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("openp2p-salt-2026"), iterations: 10000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(plainText, secret) {
  const key = await getDerivedAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plainText));
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);
  return base64UrlEncode(combined);
}

async function decryptData(cipherB64, secret) {
  try {
    const raw = base64UrlDecodeBytes(cipherB64);
    if (raw.byteLength <= 12) return null;
    const iv = raw.slice(0, 12);
    const data = raw.slice(12);
    const key = await getDerivedAesKey(secret);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch {
    return null;
  }
}

async function getHmacKey(secret) {
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret || DEFAULT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signData(dataStr, secret) {
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(dataStr));
  return `${base64UrlEncode(dataStr)}.${base64UrlEncode(signature)}`;
}

async function verifyData(signedStr, secret) {
  if (!signedStr || !signedStr.includes(".")) return null;
  const [b64Data, b64Sig] = signedStr.split(".");
  try {
    const rawData = base64UrlDecode(b64Data);
    const key = await getHmacKey(secret);
    const sigBytes = base64UrlDecodeBytes(b64Sig);
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(rawData));
    return valid ? rawData : null;
  } catch {
    return null;
  }
}

/* ---------------- SSRF 内网地址检测 ---------------- */
function isPrivateHost(hostname) {
  if (!hostname) return true;
  hostname = hostname.toLowerCase().trim();
  if (hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal")) return true;
  const parts = hostname.split(".");
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)) {
    const [a, b, c, d] = parts.map(Number);
    if (a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0 || a >= 224) {
      return true;
    }
  }
  if (hostname === "::1" || hostname.startsWith("fe80:") || hostname.startsWith("fc00:") || hostname.startsWith("fd00:")) return true;
  return false;
}

function validateUpstreamUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "https:") return { valid: false, reason: "上游地址必须使用 HTTPS 协议" };
    if (isPrivateHost(parsed.hostname)) return { valid: false, reason: "禁止使用私有内网或云平台元数据 IP 地址" };
    return { valid: true, url: parsed.origin };
  } catch {
    return { valid: false, reason: "上游地址格式不合法" };
  }
}

function parseJwt(token) {
  try {
    const part = token.split(".")[1];
    return JSON.parse(base64UrlDecode(part));
  } catch {
    return {};
  }
}

function jwtExp(token) {
  const p = parseJwt(token);
  return Number(p.exp || 0);
}

function jwtUser(token) {
  const p = parseJwt(token);
  return p.user || "";
}

/* ---------------- 验证码生成 ---------------- */
function generateCaptchaSvg(code, theme = "dark") {
  const isLight = theme === "light";
  const bg = isLight ? "#e2ebe6" : "#16241f";
  const noise = isLight ? "#b8c6bf" : "#3a4a44";
  const colors = isLight
    ? ["#0d9e73", "#b07d1a", "#3d7fb8", "#8a5cb8"]
    : ["#35d9a4", "#e8b64c", "#7db4e8", "#c98ce8"];

  let chars = "";
  for (let i = 0; i < code.length; i++) {
    const x = 21 + i * 26;
    const y = 31;
    const color = colors[i % colors.length];
    chars += `<text x="${x}" y="${y}" text-anchor="middle" font-family="Consolas,monospace" font-size="24" font-weight="bold" fill="${color}">${code[i]}</text>`;
  }

  const svgXml = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="44" viewBox="0 0 120 44">` +
    `<rect width="120" height="44" fill="${bg}" rx="6"/>` +
    `<line x1="10" y1="12" x2="110" y2="34" stroke="${noise}" stroke-width="1"/>` +
    `<line x1="10" y1="36" x2="110" y2="10" stroke="${noise}" stroke-width="1"/>` +
    `${chars}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svgXml);
}

/* ---------------- 会话管理 ---------------- */
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(";").forEach((part) => {
    const [k, v] = part.trim().split("=");
    if (k && v) cookies[k] = decodeURIComponent(v);
  });
  return cookies;
}

async function getSession(request, env) {
  const secret = (env && env.SESSION_SECRET) || DEFAULT_SECRET;
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const rawCookie = cookies[SESSION_COOKIE_NAME] || request.headers.get("X-Session-Id");
  if (!rawCookie) return { accounts: [], activeUser: "", upstream: (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM };

  let decryptedStr = await decryptData(rawCookie, secret);
  if (!decryptedStr) {
    decryptedStr = await verifyData(rawCookie, secret);
  }
  if (!decryptedStr) return { accounts: [], activeUser: "", upstream: (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM };

  try {
    const session = JSON.parse(decryptedStr);
    if (!session.upstream) session.upstream = (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM;
    return session;
  } catch {
    return { accounts: [], activeUser: "", upstream: (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM };
  }
}

async function createSessionCookie(sessionData, env) {
  const secret = (env && env.SESSION_SECRET) || DEFAULT_SECRET;
  const encrypted = await encryptData(JSON.stringify(sessionData), secret);
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(encrypted)}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; SameSite=Lax; Secure`;
}

function applySecurityHeaders(headers) {
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

function jsonRsp(data, status = 200, extraHeaders = {}) {
  const h = new Headers(extraHeaders);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store, no-cache, must-revalidate");
  applySecurityHeaders(h);
  return new Response(JSON.stringify(data), { status, headers: h });
}

/* ---------------- Cloudflare Worker 主入口 ---------------- */
export default {
  async fetch(request, env = {}, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    // 口令鉴权
    const panelKey = env.PANEL_KEY || "";
    if (panelKey && !["/", "/index.html", "/app.css", "/app.js", "/favicon.ico"].includes(pathname)) {
      const clientKey = request.headers.get("X-Panel-Key");
      if (clientKey !== panelKey) {
        return jsonRsp({ error: 401, detail: "本面板已启用访问口令，需要正确口令" }, 401);
      }
    }

    // ---------- API 路由 ----------
    if (pathname.startsWith("/api/")) {
      const session = await getSession(request, env);
      const upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

      // 1. 面板状态
      if (pathname === "/api/state" && (method === "GET" || method === "HEAD")) {
        const pool = session.accounts || [];
        const user = session.activeUser || "";
        const acc = pool.find((a) => a.user === user);
        const token = acc ? acc.token : "";
        return jsonRsp({
          upstream,
          user,
          hasToken: Boolean(token),
          tokenExp: token ? jwtExp(token) : 0,
          accounts: pool.map((a) => ({
            user: a.user,
            hasToken: Boolean(a.token),
            tokenExp: jwtExp(a.token || ""),
            hasPassword: Boolean(a.password),
            active: a.user === user,
          })),
        });
      }

      // 2. 验证码接口 (2分钟窗口 + 随机 Nonce)
      if (pathname === "/api/captcha" && (method === "GET" || method === "POST")) {
        const secret = env.SESSION_SECRET || DEFAULT_SECRET;
        const theme = url.searchParams.get("theme") || request.headers.get("X-Panel-Theme") || "dark";
        const code = Math.floor(1000 + Math.random() * 9000).toString();
        const nonce = Math.random().toString(36).slice(2, 8);
        const cid = await signData(JSON.stringify({ code, nonce, exp: Date.now() + 120000 }), secret);
        const svg = generateCaptchaSvg(code, theme);
        return jsonRsp({ captcha_id: cid, captchaId: cid, svg });
      }

      // 3. 登录 (支持密码与 Token 登录)
      if ((pathname === "/api/login" || pathname === "/api/login-token") && method === "POST") {
        const secret = env.SESSION_SECRET || DEFAULT_SECRET;
        let body;
        try {
          body = await request.json();
        } catch {
          return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
        }

        const cid = body.captchaId || body.captcha_id;
        const ccode = body.captcha || body.captcha_code;
        if (cid && ccode) {
          const verified = await verifyData(cid, secret);
          if (!verified) return jsonRsp({ error: -1, detail: "验证码已过期或无效" }, 400);
          try {
            const parsed = JSON.parse(verified);
            if (Date.now() > parsed.exp || parsed.code !== String(ccode).trim()) {
              return jsonRsp({ error: -1, detail: "验证码错误或已失效" }, 400);
            }
          } catch {
            return jsonRsp({ error: -1, detail: "验证码解析失败" }, 400);
          }
        }

        const token = (body.token || "").trim();
        const user = (body.user || "").trim();
        const password = body.password || "";
        const customUp = (body.upstream || "").trim().replace(/\/+$/, "");
        if (customUp) {
          const upCheck = validateUpstreamUrl(customUp);
          if (!upCheck.valid) return jsonRsp({ error: -1, detail: upCheck.reason }, 400);
          session.upstream = upCheck.url;
        }
        const activeUpstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

        if (token) {
          const profRsp = await fetch(`${activeUpstream}/api/v1/user/profile`, {
            method: "POST",
            headers: { Authorization: token, "Content-Type": "application/json" },
            body: "{}",
          });
          const profData = await profRsp.json().catch(() => ({ error: -1 }));
          if (profData.error !== 0) {
            return jsonRsp({ error: -1, detail: "Token 无效或已失效" }, 401);
          }
          const loginUser = profData.user || jwtUser(token);
          const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
          pool.push({ user: loginUser, token, password: "" });
          session.accounts = pool;
          session.activeUser = loginUser;

          const cookie = await createSessionCookie(session, env);
          return jsonRsp({ error: 0, user: loginUser, token }, 200, { "Set-Cookie": cookie });
        }

        if (user && password) {
          const loginRsp = await fetch(`${activeUpstream}/api/v1/user/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user, password }),
          });
          const loginData = await loginRsp.json().catch(() => ({ error: -1 }));
          if (loginData.error === 0 && loginData.token) {
            const loginUser = loginData.user || user;
            const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
            pool.push({ user: loginUser, token: loginData.token, password });
            session.accounts = pool;
            session.activeUser = loginUser;

            const cookie = await createSessionCookie(session, env);
            return jsonRsp({ error: 0, user: loginUser, token: loginData.token }, 200, { "Set-Cookie": cookie });
          }
          return jsonRsp({ error: loginData.error || -1, detail: loginData.detail || "用户名或密码错误" });
        }

        return jsonRsp({ error: -1, detail: "缺少凭据" }, 400);
      }

      // 4. 退出登录
      if (pathname === "/api/logout" && method === "POST") {
        const pool = (session.accounts || []).filter((a) => a.user !== session.activeUser);
        session.accounts = pool;
        session.activeUser = pool.length > 0 ? pool[0].user : "";
        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
      }

      // 5. 切换账户
      if (pathname === "/api/accounts/switch" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const targetUser = body.user;
        const acc = (session.accounts || []).find((a) => a.user === targetUser);
        if (!acc) return jsonRsp({ error: -1, detail: "未找到该账户" }, 404);
        session.activeUser = targetUser;
        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ error: 0, user: targetUser }, 200, { "Set-Cookie": cookie });
      }

      // 6. 移除账户
      if (pathname === "/api/accounts/remove" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const targetUser = body.user;
        session.accounts = (session.accounts || []).filter((a) => a.user !== targetUser);
        if (session.activeUser === targetUser) {
          session.activeUser = session.accounts.length > 0 ? session.accounts[0].user : "";
        }
        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ error: 0, ok: true }, 200, { "Set-Cookie": cookie });
      }

      // 7. 切换官方控制台地址 (严格 SSRF 防护)
      if (pathname === "/api/upstream" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const newUp = (body.upstream || "").trim().replace(/\/+$/, "");
        const upCheck = validateUpstreamUrl(newUp);
        if (!upCheck.valid) {
          return jsonRsp({ error: -1, detail: upCheck.reason }, 400);
        }
        session.upstream = upCheck.url;
        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ error: 0, upstream: upCheck.url }, 200, { "Set-Cookie": cookie });
      }

      return jsonRsp({ error: -1, detail: "未知接口" }, 404);
    }

    // ---------- 反向代理 /pxp/* ----------
    if (pathname.startsWith("/pxp/")) {
      const session = await getSession(request, env);
      let upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;
      
      try {
        const upUrl = new URL(upstream);
        if (upUrl.protocol !== "https:" || isPrivateHost(upUrl.hostname)) {
          upstream = DEFAULT_UPSTREAM;
        }
      } catch {
        upstream = DEFAULT_UPSTREAM;
      }

      const subPath = pathname.slice(4);
      const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
      let token = acc ? acc.token : "";

      // 自动刷新 Token
      if (acc && acc.password && (!token || jwtExp(token) < Date.now() / 1000 + 60)) {
        try {
          const r = await fetch(`${upstream}/api/v1/user/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user: acc.user, password: acc.password }),
          });
          const d = await r.json();
          if (d.error === 0 && d.token) {
            token = d.token;
            acc.token = token;
          }
        } catch {}
      }

      const targetUrl = `${upstream}${subPath}${url.search}`;
      const fwdHeaders = new Headers(request.headers);
      fwdHeaders.delete("host");
      fwdHeaders.delete("cookie");
      if (token) fwdHeaders.set("Authorization", token);

      try {
        const upstreamRsp = await fetch(targetUrl, {
          method,
          headers: fwdHeaders,
          body: ["GET", "HEAD"].includes(method) ? undefined : await request.arrayBuffer(),
          redirect: "follow",
        });

        const respHeaders = new Headers(upstreamRsp.headers);
        respHeaders.set("Cache-Control", "no-store");
        applySecurityHeaders(respHeaders);
        return new Response(upstreamRsp.body, {
          status: upstreamRsp.status,
          headers: respHeaders,
        });
      } catch (err) {
        return jsonRsp({ error: -2, detail: `Upstream error: ${err.message}` }, 502);
      }
    }

    // ---------- 静态资源响应 (注入安全头) ----------
    if (env.ASSETS) {
      const assetResp = await env.ASSETS.fetch(request);
      const headers = new Headers(assetResp.headers);
      applySecurityHeaders(headers);
      return new Response(assetResp.body, {
        status: assetResp.status,
        headers,
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
