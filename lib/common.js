/**
 * OpenP2P 边缘运行公共核心库 (Vercel Edge Runtime)
 * 集成 WebCrypto AES-GCM-256 加解密、HMAC 签名、SSRF 内网拦截与全站安全响应头
 */

export const DEFAULT_UPSTREAM = "https://console.openpxp.com";
export const SESSION_COOKIE_NAME = "openp2p_session";
export const SESSION_TTL = 30 * 24 * 3600; // 30天
export const DEFAULT_SECRET = "openp2p-vercel-aes-secret-key-32bytes-v2";

/* ---------------- 基础 Base64URL 工具 ---------------- */
export function base64UrlEncode(strOrBuffer) {
  let bytes = typeof strOrBuffer === "string" ? new TextEncoder().encode(strOrBuffer) : new Uint8Array(strOrBuffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecodeBytes(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  let binary = atob(base64);
  let bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64UrlDecode(str) {
  return new TextDecoder().decode(base64UrlDecodeBytes(str));
}

/* ---------------- AES-GCM-256 强加密 ---------------- */
export async function getDerivedAesKey(secret) {
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

export async function encryptData(plainText, secret) {
  const key = await getDerivedAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plainText));
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);
  return base64UrlEncode(combined);
}

export async function decryptData(cipherB64, secret) {
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

/* ---------------- HMAC-SHA256 签名 ---------------- */
export async function getHmacKey(secret) {
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret || DEFAULT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

export async function signData(dataStr, secret) {
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(dataStr));
  return `${base64UrlEncode(dataStr)}.${base64UrlEncode(signature)}`;
}

export async function verifyData(signedStr, secret) {
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

/* ---------------- SSRF 内网拦截 ---------------- */
export function isPrivateHost(hostname) {
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

export function validateUpstreamUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "https:") return { valid: false, reason: "上游地址必须使用 HTTPS 协议" };
    if (isPrivateHost(parsed.hostname)) return { valid: false, reason: "禁止使用私有内网或云平台元数据 IP 地址" };
    return { valid: true, url: parsed.origin };
  } catch {
    return { valid: false, reason: "上游地址格式不合法" };
  }
}

export function parseJwt(token) {
  try {
    const part = token.split(".")[1];
    return JSON.parse(base64UrlDecode(part));
  } catch {
    return {};
  }
}

export function jwtExp(token) {
  const p = parseJwt(token);
  return Number(p.exp || 0);
}

export function jwtUser(token) {
  const p = parseJwt(token);
  return p.user || "";
}

/* ---------------- 验证码生成 ---------------- */
export function generateCaptchaSvg(code, theme = "dark") {
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
export function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(";").forEach((part) => {
    const [k, v] = part.trim().split("=");
    if (k && v) cookies[k] = decodeURIComponent(v);
  });
  return cookies;
}

export function getEnv() {
  return typeof process !== "undefined" && process.env ? process.env : {};
}

export async function getSession(request) {
  const env = getEnv();
  const secret = env.SESSION_SECRET || DEFAULT_SECRET;
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

export async function createSessionCookie(sessionData) {
  const env = getEnv();
  const secret = env.SESSION_SECRET || DEFAULT_SECRET;
  const encrypted = await encryptData(JSON.stringify(sessionData), secret);
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(encrypted)}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; SameSite=Lax; Secure`;
}

export function applySecurityHeaders(headers) {
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

export function jsonRsp(data, status = 200, extraHeaders = {}) {
  const h = new Headers(extraHeaders);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store, no-cache, must-revalidate");
  applySecurityHeaders(h);
  return new Response(JSON.stringify(data), { status, headers: h });
}
