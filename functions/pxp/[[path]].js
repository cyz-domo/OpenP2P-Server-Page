/**
 * OpenP2P 管理面板 — EdgeOne Makers 反向代理处理器
 * 匹配 /pxp/* 路由并代理转发至 OpenP2P 官方控制台
 * 集成 AES-GCM 会话解密、SSRF 拦截与安全响应头
 */

const DEFAULT_UPSTREAM = "https://console.openpxp.com";
const SESSION_COOKIE_NAME = "openp2p_session";
const DEFAULT_SECRET = "openp2p-edgeone-aes-secret-key-32bytes-v2";

/* ---------------- 基础工具与 Base64 ---------------- */
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

/* ---------------- AES-GCM-256 解密与 HMAC 校验 (带内存 Key 单例缓存) ---------------- */
let _cachedAesKey = null;
let _cachedAesSecret = null;

async function getDerivedAesKey(secret) {
  const currentSecret = secret || DEFAULT_SECRET;
  if (_cachedAesKey && _cachedAesSecret === currentSecret) {
    return _cachedAesKey;
  }
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(currentSecret), "PBKDF2", false, ["deriveKey"]);
  _cachedAesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("openp2p-salt-2026"), iterations: 10000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  _cachedAesSecret = currentSecret;
  return _cachedAesKey;
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

let _cachedHmacKey = null;
let _cachedHmacSecret = null;

async function verifyData(signedStr, secret) {
  if (!signedStr || !signedStr.includes(".")) return null;
  const [b64Data, b64Sig] = signedStr.split(".");
  try {
    const rawData = base64UrlDecode(b64Data);
    const currentSecret = secret || DEFAULT_SECRET;
    if (!_cachedHmacKey || _cachedHmacSecret !== currentSecret) {
      _cachedHmacKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(currentSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
      );
      _cachedHmacSecret = currentSecret;
    }
      new TextEncoder().encode(secret || DEFAULT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = base64UrlDecodeBytes(b64Sig);
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(rawData));
    return valid ? rawData : null;
  } catch {
    return null;
  }
}

/* ---------------- SSRF 校验 ---------------- */
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

function applySecurityHeaders(headers) {
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

function jsonRsp(data, status = 200) {
  const h = new Headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store, no-cache, must-revalidate");
  applySecurityHeaders(h);
  return new Response(JSON.stringify(data), { status, headers: h });
}

export async function onRequest(context) {
  const { request, env = {} } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  // 口令鉴权
  const panelKey = env.PANEL_KEY || "";
  if (panelKey) {
    const clientKey = request.headers.get("X-Panel-Key");
    if (clientKey !== panelKey) {
      return jsonRsp({ error: 401, detail: "本面板已启用访问口令，需要正确口令" }, 401);
    }
  }

  const session = await getSession(request, env);
  let upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;
  
  // SSRF 防护检查
  try {
    const upUrl = new URL(upstream);
    if (upUrl.protocol !== "https:" || isPrivateHost(upUrl.hostname)) {
      upstream = DEFAULT_UPSTREAM;
    }
  } catch {
    upstream = DEFAULT_UPSTREAM;
  }

  const subPath = pathname.slice(4); // 去除 /pxp 前缀
  const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
  let token = acc ? acc.token : "";

  // Token 过期自动刷新 (如果有密码)
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
