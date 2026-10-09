/**
 * OpenP2P 管理面板 — Vercel Edge Function
 * 纯 Serverless 边缘运行，支持 AES-GCM-256 会话加密 (带单例 Key 缓存)、SSRF 防护、防重放验证码与全量流式反代
 */

export const config = {
  runtime: "edge",
};

const DEFAULT_UPSTREAM = "https://console.openpxp.com";
const SESSION_COOKIE_NAME = "openp2p_session";
const SESSION_TTL = 30 * 24 * 3600; // 30天

/* ---------------- 运行时密钥管理 ---------------- */
const DEFAULT_SECRET = "openp2p-vercel-aes-secret-key-32bytes-v2";
const LEGACY_FALLBACK_SECRETS = [
  "openp2p-vercel-aes-secret-key-32bytes-v2",
  "openp2p-cloudflare-aes-secret-key-32bytes-v2",
  "openp2p-edgeone-aes-secret-key-32bytes-v2",
  "openp2p-default-aes-secret-key-32bytes",
  "openp2p-default-aes-secret-key-32bytes-v2"
];

let _hasWarnedSecret = false;
function getSessionSecret(env) {
  const custom = env && typeof env.SESSION_SECRET === "string" ? env.SESSION_SECRET.trim() : "";
  if (custom) return custom;
  if (!_hasWarnedSecret) {
    _hasWarnedSecret = true;
    console.warn("[SECURITY NOTICE] 未配置 SESSION_SECRET 环境变量，当前使用平台默认会话密钥。建议在部署环境变量中配置固定 SESSION_SECRET。");
  }
  return DEFAULT_SECRET;
}

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

/* ---------------- AES-GCM-256 强加密 (带内存 Key Map 缓存与平滑回退) ---------------- */
const _cachedAesKeys = new Map();

async function getDerivedAesKey(secret) {
  const currentSecret = secret || getSessionSecret(getEnv());
  if (_cachedAesKeys.has(currentSecret)) {
    return _cachedAesKeys.get(currentSecret);
  }
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(currentSecret), "PBKDF2", false, ["deriveKey"]);
  const derived = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("openp2p-salt-2026"), iterations: 10000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  if (_cachedAesKeys.size > 20) _cachedAesKeys.clear();
  _cachedAesKeys.set(currentSecret, derived);
  return derived;
}

async function encryptData(plainText, secret) {
  const currentSecret = secret || getSessionSecret(getEnv());
  const key = await getDerivedAesKey(currentSecret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plainText));
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);
  return base64UrlEncode(combined);
}

async function decryptWithSecret(cipherB64, secret) {
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

async function decryptDataWithMeta(cipherB64, secret) {
  const currentSecret = secret || getSessionSecret(getEnv());
  const primary = await decryptWithSecret(cipherB64, currentSecret);
  if (primary !== null) return { text: primary, isLegacy: false };

  for (const legacy of LEGACY_FALLBACK_SECRETS) {
    if (legacy === currentSecret) continue;
    const fallback = await decryptWithSecret(cipherB64, legacy);
    if (fallback !== null) return { text: fallback, isLegacy: true };
  }
  return { text: null, isLegacy: false };
}

async function decryptData(cipherB64, secret) {
  const meta = await decryptDataWithMeta(cipherB64, secret);
  return meta.text;
}

/* ---------------- HMAC-SHA256 签名 (带内存 Key Map 缓存与平滑回退) ---------------- */
const _cachedHmacKeys = new Map();

async function getHmacKey(secret) {
  const currentSecret = secret || getSessionSecret(getEnv());
  if (_cachedHmacKeys.has(currentSecret)) {
    return _cachedHmacKeys.get(currentSecret);
  }
  const derived = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(currentSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  if (_cachedHmacKeys.size > 20) _cachedHmacKeys.clear();
  _cachedHmacKeys.set(currentSecret, derived);
  return derived;
}

async function signData(dataStr, secret) {
  const currentSecret = secret || getSessionSecret(getEnv());
  const key = await getHmacKey(currentSecret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(dataStr));
  return `${base64UrlEncode(dataStr)}.${base64UrlEncode(signature)}`;
}

async function verifyData(signedStr, secret) {
  if (!signedStr || !signedStr.includes(".")) return null;
  const currentSecret = secret || getSessionSecret(getEnv());
  const [b64Data, b64Sig] = signedStr.split(".");
  const tryVerify = async (sec) => {
    try {
      const rawData = base64UrlDecode(b64Data);
      const key = await getHmacKey(sec);
      const sigBytes = base64UrlDecodeBytes(b64Sig);
      const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(rawData));
      return valid ? rawData : null;
    } catch {
      return null;
    }
  };

  const primary = await tryVerify(currentSecret);
  if (primary !== null) return primary;

  for (const legacy of LEGACY_FALLBACK_SECRETS) {
    if (legacy === currentSecret) continue;
    const fallback = await tryVerify(legacy);
    if (fallback !== null) return fallback;
  }
  return null;
}

/* ---------------- SSRF 内网拦截 ---------------- */
function isPrivateHost(hostname) {
  if (!hostname) return true;
  hostname = hostname.replace(/^\[|\]$/g, "").toLowerCase().trim();
  if (
    hostname === "localhost" ||
    hostname === "ip6-localhost" ||
    hostname === "ip6-loopback" ||
    hostname === "instance-data" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return true;
  }
  // 处理 IPv4 映射的 IPv6 (::ffff:127.0.0.1 等)
  if (hostname.startsWith("::ffff:")) {
    hostname = hostname.slice(7);
  }
  const parts = hostname.split(".");
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)) {
    const [a, b, c, d] = parts.map(Number);
    if (
      a === 0 ||
      a === 10 ||
      (a === 100 && b >= 64 && b <= 127) ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224
    ) {
      return true;
    }
  }
  if (
    hostname === "::1" ||
    hostname.startsWith("fe80:") ||
    hostname.startsWith("fc00:") ||
    hostname.startsWith("fd00:")
  ) {
    return true;
  }
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

/* ---------------- 会话 Cookie ---------------- */
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(";").forEach((part) => {
    const [k, v] = part.trim().split("=");
    if (k && v) cookies[k] = decodeURIComponent(v);
  });
  return cookies;
}

function getEnv() {
  return typeof process !== "undefined" && process.env ? process.env : {};
}

async function getSession(request) {
  const env = getEnv();
  const secret = getSessionSecret(env);
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const rawCookie = cookies[SESSION_COOKIE_NAME] || request.headers.get("X-Session-Id");
  if (!rawCookie) return { accounts: [], activeUser: "", upstream: env.UPSTREAM_URL || DEFAULT_UPSTREAM };

  let decryptedStr = await decryptData(rawCookie, secret);
  if (!decryptedStr) {
    decryptedStr = await verifyData(rawCookie, secret);
  }
  if (!decryptedStr) return { accounts: [], activeUser: "", upstream: env.UPSTREAM_URL || DEFAULT_UPSTREAM };

  try {
    const session = JSON.parse(decryptedStr);
    if (!session.upstream) session.upstream = env.UPSTREAM_URL || DEFAULT_UPSTREAM;
    return session;
  } catch {
    return { accounts: [], activeUser: "", upstream: env.UPSTREAM_URL || DEFAULT_UPSTREAM };
  }
}

async function createSessionCookie(sessionData) {
  const env = getEnv();
  const secret = getSessionSecret(env);
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

/* ---------------- Vercel Edge 主入口 ---------------- */
export default async function handler(request) {
  const env = getEnv();
  const url = new URL(request.url);
  const rawPath = url.searchParams.get("_vercel_path") || request.headers.get("x-matched-path") || request.headers.get("x-forwarded-uri") || url.pathname;
  url.searchParams.delete("_vercel_path");
  
  const pathname = rawPath.split("?")[0];
  const method = request.method;

  // 口令鉴权
  const panelKey = env.PANEL_KEY || "";
  if (panelKey && !["/", "/index.html", "/app.css", "/app.js", "/favicon.ico"].includes(pathname)) {
    const clientKey = request.headers.get("X-Panel-Key");
    if (clientKey !== panelKey) {
      return jsonRsp({ error: 401, detail: "本面板已启用访问口令，需要正确口令" }, 401);
    }
  }

  // ---------- 反向代理 /pxp/* 路由（含 /api/pxp/* 与 rewrite 路由）----------
  if (pathname.startsWith("/api/pxp/") || pathname.startsWith("/pxp/")) {
    const session = await getSession(request);
    let upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;
    
    try {
      const upUrl = new URL(upstream);
      if (upUrl.protocol !== "https:" || isPrivateHost(upUrl.hostname)) {
        upstream = DEFAULT_UPSTREAM;
      }
    } catch {
      upstream = DEFAULT_UPSTREAM;
    }

    // 准确提取上游子路径（例如 /api/v1/sdwans/，保留末尾斜杠和查询参数）
    const subPath = pathname.replace(/^\/api\/pxp/, "").replace(/^\/pxp/, "");
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
    const fwdHeaders = new Headers();
    for (const [k, v] of request.headers.entries()) {
      const lk = k.toLowerCase();
      if (["host", "cookie", "connection", "accept-encoding", "content-length"].includes(lk)) continue;
      fwdHeaders.set(k, v);
    }
    fwdHeaders.set("Host", new URL(upstream).host);
    if (token) fwdHeaders.set("Authorization", token);

    try {
      const reqBody = ["GET", "HEAD"].includes(method) ? undefined : await request.arrayBuffer();
      const upstreamRsp = await fetch(targetUrl, {
        method,
        headers: fwdHeaders,
        body: reqBody,
        redirect: "manual",
      });

      // 严格检查 3xx 重定向，防止重定向逃逸至云元数据 (169.254.169.254) 或内部私网
      if (upstreamRsp.status >= 300 && upstreamRsp.status < 400) {
        const loc = upstreamRsp.headers.get("Location") || "";
        try {
          const locUrl = new URL(loc, targetUrl);
          if (isPrivateHost(locUrl.hostname)) {
            return jsonRsp({ error: 403, detail: "SSRF Blocked: 上游重定向至私有地址已被拦截" }, 403);
          }
        } catch {
          return jsonRsp({ error: 400, detail: "上游重定向目标不合法" }, 400);
        }
      }

      const respData = await upstreamRsp.arrayBuffer();
      const respHeaders = new Headers(upstreamRsp.headers);
      respHeaders.delete("content-encoding");
      respHeaders.delete("content-length");
      respHeaders.delete("transfer-encoding");
      respHeaders.delete("connection");
      respHeaders.delete("keep-alive");
      respHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate");
      applySecurityHeaders(respHeaders);

      return new Response(respData, {
        status: upstreamRsp.status,
        headers: respHeaders,
      });
    } catch (err) {
      return jsonRsp({ error: -2, detail: `Upstream error: ${err.message}` }, 502);
    }
  }

  // ---------- 管理 API 路由 /api/* ----------
  if (pathname.startsWith("/api/")) {
    const session = await getSession(request);
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
        hasCustomSecret: Boolean((env.SESSION_SECRET || "").trim()),
        insecureSsl: false,
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
      const secret = getSessionSecret(env);
      const theme = url.searchParams.get("theme") || request.headers.get("X-Panel-Theme") || "dark";
      const code = Math.floor(1000 + Math.random() * 9000).toString();
      const nonce = Math.random().toString(36).slice(2, 8);
      const cid = await signData(JSON.stringify({ code, nonce, exp: Date.now() + 120000 }), secret);
      const svg = generateCaptchaSvg(code, theme);
      return jsonRsp({ captcha_id: cid, captchaId: cid, svg });
    }

    // 2.1 通行密钥 (Passkey) - 获取 Challenge
    if (pathname === "/api/passkey/challenge" && (method === "GET" || method === "POST")) {
      const challengeBytes = new Uint8Array(32);
      crypto.getRandomValues(challengeBytes);
      return jsonRsp({ error: 0, challenge: base64UrlEncode(challengeBytes) });
    }

    // 2.2 通行密钥 (Passkey) - 绑定凭据 (需在登录态下执行)
    if (pathname === "/api/passkey/bind" && method === "POST") {
      const secret = getSessionSecret(env);
      if (!session.activeUser) {
        return jsonRsp({ error: 401, detail: "请先登录后再绑定通行密钥" }, 401);
      }
      const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
      if (!acc) return jsonRsp({ error: 401, detail: "未找到当前账户凭据" }, 401);

      let body;
      try { body = await request.json(); } catch { return jsonRsp({ error: -1, detail: "参数错误" }, 400); }

      const credentialId = (body.credentialId || "").trim();
      const deviceName = (body.deviceName || "当前设备").trim();
      if (!credentialId) return jsonRsp({ error: -1, detail: "缺少凭据标识" }, 400);

      const passkeyPayload = {
        credentialId,
        user: acc.user,
        token: acc.token,
        password: acc.password || "",
        upstream: session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM,
        deviceName,
        createdAt: Date.now()
      };

      const passkeyCipher = await encryptData(JSON.stringify(passkeyPayload), secret);
      return jsonRsp({
        error: 0,
        credentialId,
        passkeyCipher,
        user: acc.user,
        deviceName,
        createdAt: passkeyPayload.createdAt
      });
    }

    // 2.3 通行密钥 (Passkey) - 验证登录
    if (pathname === "/api/passkey/login" && method === "POST") {
      const secret = getSessionSecret(env);
      let body;
      try { body = await request.json(); } catch { return jsonRsp({ error: -1, detail: "参数错误" }, 400); }

      const credentialId = (body.credentialId || "").trim();
      const passkeyCipher = (body.passkeyCipher || "").trim();
      if (!credentialId || !passkeyCipher) {
        return jsonRsp({ error: -1, detail: "通行密钥凭据不完整" }, 400);
      }

      const meta = await decryptDataWithMeta(passkeyCipher, secret);
      if (!meta.text) {
        return jsonRsp({ error: 401, detail: "通行密钥凭据已失效或损坏，请重新绑定" }, 401);
      }

      let payload;
      try { payload = JSON.parse(meta.text); } catch { return jsonRsp({ error: -1, detail: "凭据解析失败" }, 400); }
      if (payload.credentialId !== credentialId) {
        return jsonRsp({ error: 401, detail: "凭据指纹不匹配" }, 401);
      }

      const loginUser = payload.user;
      let token = payload.token;
      const targetUpstream = payload.upstream || session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

      if (!token || jwtExp(token) < Date.now() / 1000 + 60) {
        if (payload.password) {
          const r = await fetch(`${targetUpstream}/api/v1/user/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user: loginUser, password: payload.password }),
          }).catch(() => null);
          if (r) {
            const d = await r.json().catch(() => null);
            if (d && d.error === 0 && d.token) token = d.token;
          }
        }
      }

      const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
      pool.push({ user: loginUser, token, password: payload.password || "" });
      session.accounts = pool;
      session.activeUser = loginUser;
      session.upstream = targetUpstream;

      // 若使用历史密钥解密成功，或 Token 发生了刷新，使用当前密钥重新加密生成新凭据下发给客户端无感升级
      let updatedCipher = passkeyCipher;
      if (meta.isLegacy || (token && token !== payload.token)) {
        try {
          payload.token = token || payload.token;
          payload.upstream = targetUpstream;
          updatedCipher = await encryptData(JSON.stringify(payload), secret);
        } catch {}
      }

      const cookie = await createSessionCookie(session);
      return jsonRsp({
        error: 0,
        user: loginUser,
        token,
        credentialId,
        passkeyCipher: updatedCipher,
        deviceName: payload.deviceName || "当前设备",
        createdAt: payload.createdAt || Date.now()
      }, 200, { "Set-Cookie": cookie });
    }

    // 3. 登录 (支持密码与 Token 登录)
    if ((pathname === "/api/login" || pathname === "/api/login-token") && method === "POST") {
      const secret = getSessionSecret(env);
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

        const cookie = await createSessionCookie(session);
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

          const cookie = await createSessionCookie(session);
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
      const cookie = await createSessionCookie(session);
      return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
    }

    // 5. 切换账户
    if (pathname === "/api/accounts/switch" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const targetUser = body.user;
      const acc = (session.accounts || []).find((a) => a.user === targetUser);
      if (!acc) return jsonRsp({ error: -1, detail: "未找到该账户" }, 404);
      session.activeUser = targetUser;
      const cookie = await createSessionCookie(session);
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
      const cookie = await createSessionCookie(session);
      return jsonRsp({ error: 0, ok: true }, 200, { "Set-Cookie": cookie });
    }

    // 7. 切换官方控制台地址
    if (pathname === "/api/upstream" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const newUp = (body.upstream || "").trim().replace(/\/+$/, "");
      const upCheck = validateUpstreamUrl(newUp);
      if (!upCheck.valid) {
        return jsonRsp({ error: -1, detail: upCheck.reason }, 400);
      }
      session.upstream = upCheck.url;
      const cookie = await createSessionCookie(session);
      return jsonRsp({ error: 0, upstream: upCheck.url }, 200, { "Set-Cookie": cookie });
    }

    return jsonRsp({ error: -1, detail: "未知接口" }, 404);
  }

  return new Response("Not Found", { status: 404 });
}
