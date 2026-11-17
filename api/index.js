/**
 * OpenP2P 管理面板 — Vercel Edge Function
 *
 * 安全基线：
 * - 会话 Cookie 使用 AES-GCM-256 加密；配置 KV/Upstash 后自动改为服务端会话（可撤销）
 * - 通行密钥执行完整 WebAuthn 校验（challenge / origin / RP ID / 签名 / signCount）
 * - 验证码强制、单次使用、IP 绑定；挑战令牌单次使用
 * - 反向代理仅允许登录会话 + 官方上游（自定义需显式开关），且不转发敏感性请求头
 */

export const config = {
  runtime: "edge",
};

const DEFAULT_UPSTREAM = "https://console.openpxp.com";
const OFFICIAL_UPSTREAMS = new Set([
  "https://console.openpxp.com",
  "https://console.openp2p.cn",
]);

const SESSION_COOKIE_NAME = "openp2p_session";
const PANEL_COOKIE_NAME = "openp2p_panel";
const SESSION_TTL = 7 * 24 * 3600; // 7 天
const PASSKEY_TTL = 30 * 24 * 3600; // 30 天
const CHALLENGE_TTL = 120; // 2 分钟
const CAPTCHA_TTL = 300; // 5 分钟
const PANEL_COOKIE_TTL = 12 * 3600; // 12 小时
const MAX_BODY_BYTES = 1024 * 1024;
const PBKDF2_ITERATIONS = 100000;
const DEFAULT_DEV_SECRET = "openp2p-local-dev-only-secret-please-change-32b";

/* ---------------- 环境与密钥 ---------------- */
function getEnv() {
  return typeof process !== "undefined" && process.env ? process.env : {};
}

function isHostedEnv(env) {
  return Boolean(env.VERCEL || env.VERCEL_ENV || env.NOW_REGION);
}

let _hasWarnedSecret = false;
function getSessionSecret(env = getEnv()) {
  const custom = typeof env.SESSION_SECRET === "string" ? env.SESSION_SECRET.trim() : "";
  if (custom) {
    if (custom.length < 32) throw new Error("SESSION_SECRET 至少需要 32 个字符");
    return custom;
  }
  if (isHostedEnv(env) || env.NODE_ENV === "production") {
    throw new Error("生产环境必须配置至少 32 字符的 SESSION_SECRET");
  }
  if (!_hasWarnedSecret) {
    _hasWarnedSecret = true;
    console.warn("[SECURITY NOTICE] 未配置 SESSION_SECRET，当前使用仅限本地开发的默认密钥。");
  }
  return DEFAULT_DEV_SECRET;
}

function isTruthy(v) {
  return ["1", "true", "yes", "on"].includes(String(v || "").toLowerCase());
}

/* ---------------- 基础工具与 Base64 ---------------- */
function base64UrlEncode(strOrBuffer) {
  const bytes = typeof strOrBuffer === "string" ? new TextEncoder().encode(strOrBuffer) : new Uint8Array(strOrBuffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecodeBytes(str) {
  let base64 = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlDecode(str) {
  return new TextDecoder().decode(base64UrlDecodeBytes(str));
}

function bytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i];
  return out === 0;
}

function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function cleanLabel(value, fallback = "当前设备") {
  const s = String(value || "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 80);
  return s || fallback;
}

/* ---------------- AES-GCM-256（按用途分离密钥） ---------------- */
const _cachedAesKeys = new Map();

async function getDerivedAesKey(secret, context = "session") {
  const keyId = `${context}\u0000${secret}`;
  if (_cachedAesKeys.has(keyId)) return _cachedAesKeys.get(keyId);
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  const derived = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode(`openp2p:${context}:aes-gcm:2026`), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  if (_cachedAesKeys.size > 30) _cachedAesKeys.clear();
  _cachedAesKeys.set(keyId, derived);
  return derived;
}

async function encryptData(plainText, secret, context = "session") {
  const key = await getDerivedAesKey(secret, context);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plainText));
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);
  return base64UrlEncode(combined);
}

async function decryptWithSecret(cipherB64, secret, context = "session") {
  try {
    const raw = base64UrlDecodeBytes(cipherB64);
    if (raw.byteLength <= 12) return null;
    const key = await getDerivedAesKey(secret, context);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, 12) },
      key,
      raw.slice(12)
    );
    return new TextDecoder().decode(decrypted);
  } catch {
    return null;
  }
}

/* ---------------- HMAC-SHA256（按用途分离密钥） ---------------- */
const _cachedHmacKeys = new Map();

async function getHmacKey(secret, context = "hmac") {
  const keyId = `${context}\u0000${secret}`;
  if (_cachedHmacKeys.has(keyId)) return _cachedHmacKeys.get(keyId);
  const derived = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  if (_cachedHmacKeys.size > 30) _cachedHmacKeys.clear();
  _cachedHmacKeys.set(keyId, derived);
  return derived;
}

async function signData(dataStr, secret, context = "hmac") {
  const key = await getHmacKey(secret, context);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(dataStr));
  return `${base64UrlEncode(dataStr)}.${base64UrlEncode(signature)}`;
}

async function verifyData(signedStr, secret, context = "hmac") {
  if (!signedStr || !signedStr.includes(".")) return null;
  const [b64Data, b64Sig] = signedStr.split(".");
  try {
    const rawData = base64UrlDecode(b64Data);
    const key = await getHmacKey(secret, context);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecodeBytes(b64Sig),
      new TextEncoder().encode(rawData)
    );
    return valid ? rawData : null;
  } catch {
    return null;
  }
}

/* ---------------- KV / Upstash REST（可选，用于可撤销会话与通行密钥注册表） ---------------- */
function getStoreConfig(env = getEnv()) {
  const url = String(env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL || "").replace(/\/+$/, "");
  const token = String(env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN || "");
  if (!url || !token) return null;
  return { url, token };
}

function hasRemoteStore(env = getEnv()) {
  return Boolean(getStoreConfig(env));
}

async function kvCommand(env, args) {
  const cfg = getStoreConfig(env);
  if (!cfg) throw new Error("KV 未配置");
  const rsp = await fetch(cfg.url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cfg.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(args),
  });
  if (!rsp.ok) throw new Error(`KV HTTP ${rsp.status}`);
  const data = await rsp.json();
  if (data && data.error) throw new Error(`KV error: ${data.error}`);
  return data ? data.result : null;
}

function storageUnavailable() {
  const err = new Error("会话/通行密钥存储暂时不可用，请稍后重试");
  err.status = 503;
  return err;
}

async function kvGet(env, key) {
  try {
    return await kvCommand(env, ["GET", key]);
  } catch (e) {
    console.error("[kv:get]", e.message);
    throw storageUnavailable();
  }
}

async function kvSet(env, key, value, ttl) {
  try {
    return await kvCommand(env, ["SET", key, value, "EX", String(ttl)]);
  } catch (e) {
    console.error("[kv:set]", e.message);
    throw storageUnavailable();
  }
}

async function kvDel(env, key) {
  try {
    return await kvCommand(env, ["DEL", key]);
  } catch (e) {
    console.error("[kv:del]", e.message);
    throw storageUnavailable();
  }
}

async function kvSAdd(env, key, member, ttl) {
  try {
    const result = await kvCommand(env, ["SADD", key, member]);
    if (ttl) await kvCommand(env, ["EXPIRE", key, String(ttl)]);
    return result;
  } catch (e) {
    console.error("[kv:sadd]", e.message);
    throw storageUnavailable();
  }
}

async function kvSRem(env, key, member) {
  try {
    return await kvCommand(env, ["SREM", key, member]);
  } catch (e) {
    console.error("[kv:srem]", e.message);
    throw storageUnavailable();
  }
}

async function kvSMembers(env, key) {
  try {
    const result = await kvCommand(env, ["SMEMBERS", key]);
    return Array.isArray(result) ? result : [];
  } catch (e) {
    console.error("[kv:smembers]", e.message);
    throw storageUnavailable();
  }
}

/* ---------------- 单次令牌与限流（KV 存在时跨实例生效） ---------------- */
const _once = new Map();
const _rate = new Map();

async function consumeOnce(env, key, ttlSec) {
  if (hasRemoteStore(env)) {
    try {
      const result = await kvCommand(env, ["SET", key, "1", "EX", String(ttlSec), "NX"]);
      return result === "OK";
    } catch (e) {
      console.error("[once:kv]", e.message);
      throw storageUnavailable();
    }
  }
  const now = Date.now();
  const exp = _once.get(key);
  if (exp && exp > now) return false;
  if (_once.size > 5000) {
    for (const [k, v] of _once) if (v <= now) _once.delete(k);
  }
  _once.set(key, now + ttlSec * 1000);
  return true;
}

function bumpLocalRate(key, windowSec) {
  const now = Date.now();
  const item = _rate.get(key);
  if (!item || item.exp <= now) {
    _rate.set(key, { count: 1, exp: now + windowSec * 1000 });
    if (_rate.size > 10000) {
      for (const [k, v] of _rate) if (v.exp <= now) _rate.delete(k);
    }
    return 1;
  }
  item.count += 1;
  return item.count;
}

async function bumpRate(env, key, windowSec) {
  if (hasRemoteStore(env)) {
    try {
      const n = Number(await kvCommand(env, ["INCR", `rl:${key}`]));
      if (n === 1) await kvCommand(env, ["EXPIRE", `rl:${key}`, String(windowSec)]);
      return n;
    } catch (e) {
      console.warn("[rate:kv fallback]", e.message);
    }
  }
  return bumpLocalRate(key, windowSec);
}

async function clearRate(env, key) {
  try {
    if (hasRemoteStore(env)) await kvCommand(env, ["DEL", `rl:${key}`]);
    else _rate.delete(key);
  } catch {}
}

/* ---------------- SSRF 与上游地址限制 ---------------- */
function isPrivateHost(hostname) {
  if (!hostname) return true;
  hostname = hostname.replace(/^\[|\]$/g, "").toLowerCase().trim().replace(/\.$/, "");
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "ip6-localhost" ||
    hostname === "ip6-loopback" ||
    hostname === "instance-data" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".home.arpa")
  ) {
    return true;
  }

  const mapped = hostname.match(/^::ffff:(.+)$/);
  if (mapped) {
    const rest = mapped[1];
    if (rest.includes(".")) return isPrivateHost(rest);
    const hex = rest.split(":").filter(Boolean);
    if (hex.length === 2 && hex.every((p) => /^[0-9a-f]{1,4}$/.test(p))) {
      const hi = parseInt(hex[0], 16);
      const lo = parseInt(hex[1], 16);
      return isPrivateHost(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
    }
    return true;
  }

  if (hostname.includes(":")) {
    const v6 = hostname.split("%")[0];
    if (v6.startsWith("2001:db8:")) return true;
    const first = v6.split(":")[0];
    if (!/^[23][0-9a-f]{0,3}$/.test(first)) return true;
    return false;
  }

  const parts = hostname.split(".");
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)) {
    const [a, b] = parts.map(Number);
    if (
      a === 0 ||
      a === 10 ||
      (a === 100 && b >= 64 && b <= 127) ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    ) {
      return true;
    }
  }
  return false;
}

function validateUpstreamUrl(urlStr, env = getEnv()) {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "https:") return { valid: false, reason: "上游地址必须使用 HTTPS 协议" };
    if (parsed.username || parsed.password) return { valid: false, reason: "上游地址不能包含用户名或密码" };
    if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
      return { valid: false, reason: "上游地址只能是站点根地址，不能包含路径、查询或片段" };
    }
    if (isPrivateHost(parsed.hostname)) return { valid: false, reason: "禁止使用私有内网或云平台元数据地址" };
    const allowCustom = isTruthy(env.ALLOW_CUSTOM_UPSTREAM);
    if (!allowCustom && !OFFICIAL_UPSTREAMS.has(parsed.origin)) {
      return { valid: false, reason: "默认仅允许官方控制台地址；如需自定义上游，请配置 ALLOW_CUSTOM_UPSTREAM=true" };
    }
    return { valid: true, url: parsed.origin };
  } catch {
    return { valid: false, reason: "上游地址格式不合法" };
  }
}

function getDefaultUpstream(env = getEnv()) {
  const configured = String(env.UPSTREAM_URL || "").trim();
  if (configured) {
    const check = validateUpstreamUrl(configured, env);
    if (check.valid) return check.url;
  }
  return DEFAULT_UPSTREAM;
}

/* ---------------- JWT 解析 ---------------- */
function parseJwt(token) {
  try {
    return JSON.parse(base64UrlDecode(String(token || "").split(".")[1]));
  } catch {
    return {};
  }
}

function jwtExp(token) {
  return Number(parseJwt(token).exp || 0);
}

function jwtUser(token) {
  return parseJwt(token).user || "";
}

/* ---------------- 验证码 ---------------- */
function generateCaptchaSvg(code, theme = "dark") {
  const isLight = theme === "light";
  const bg = isLight ? "#e2ebe6" : "#16241f";
  const noise = isLight ? "#b8c6bf" : "#3a4a44";
  const colors = isLight
    ? ["#0d9e73", "#b07d1a", "#3d7fb8", "#8a5cb8"]
    : ["#35d9a4", "#e8b64c", "#7db4e8", "#c98ce8"];
  const width = Math.max(120, 36 + code.length * 24);

  let chars = "";
  for (let i = 0; i < code.length; i++) {
    const x = 24 + i * 24;
    const color = colors[i % colors.length];
    chars += `<text x="${x}" y="31" text-anchor="middle" font-family="Consolas,monospace" font-size="24" font-weight="bold" fill="${color}">${code[i]}</text>`;
  }

  const svgXml = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="44" viewBox="0 0 ${width} 44">` +
    `<rect width="${width}" height="44" fill="${bg}" rx="6"/>` +
    `<line x1="10" y1="12" x2="${width - 10}" y2="34" stroke="${noise}" stroke-width="1"/>` +
    `<line x1="10" y1="36" x2="${width - 10}" y2="10" stroke="${noise}" stroke-width="1"/>` +
    `${chars}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svgXml);
}

function badRequest(message, status = 400) {
  const err = new Error(message);
  err.status = status;
  return err;
}

async function createCaptcha(env, request, theme) {
  const ip = getClientIp(request);
  const count = await bumpRate(env, `captcha:${ip}`, 60);
  if (count > 60) throw badRequest("验证码请求过于频繁，请稍后再试", 429);

  const rand = crypto.getRandomValues(new Uint32Array(1))[0];
  const code = String(100000 + (rand % 900000));
  const nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  // 验证码答案必须对客户端不可读：使用 AES-GCM 加密，而不是仅签名明文。
  const cid = await encryptData(
    JSON.stringify({ code, nonce, ip, exp: Date.now() + CAPTCHA_TTL * 1000 }),
    getSessionSecret(env),
    "captcha"
  );
  return { captcha_id: cid, captchaId: cid, svg: generateCaptchaSvg(code, theme === "light" ? "light" : "dark") };
}

async function verifyCaptcha(env, request, cid, ccode) {
  if (!cid || !ccode) throw badRequest("请输入验证码");
  const raw = await decryptWithSecret(String(cid), getSessionSecret(env), "captcha");
  if (!raw) throw badRequest("验证码已过期，请刷新后重试");
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    throw badRequest("验证码无效，请刷新后重试");
  }
  if (!payload || Number(payload.exp) < Date.now()) throw badRequest("验证码已过期，请刷新后重试");
  const ip = getClientIp(request);
  if (payload.ip && ip && payload.ip !== ip) throw badRequest("验证码与当前网络不匹配，请刷新后重试");
  const consumed = await consumeOnce(env, `cap:${payload.nonce}`, CAPTCHA_TTL);
  if (!consumed) throw badRequest("验证码已使用，请刷新后重试");
  if (String(payload.code) !== String(ccode).trim()) throw badRequest("验证码错误");
}

function getClientIp(request) {
  return (
    request.headers.get("x-real-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
    request.headers.get("cf-connecting-ip") ||
    ""
  );
}

/* ---------------- Origin / CSRF ---------------- */
function getRequestOrigin(request) {
  const url = new URL(request.url);
  let proto = url.protocol.replace(":", "");
  if (proto === "http" && request.headers.get("x-forwarded-proto") === "https") proto = "https";
  return `${proto}://${url.host}`;
}

function getConfiguredOrigins(env) {
  return String(env.APP_ORIGIN || "")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, ""))
    .filter(Boolean);
}

function getExpectedOrigin(request, env) {
  const configured = getConfiguredOrigins(env);
  if (!configured.length) return getRequestOrigin(request);
  const actual = getRequestOrigin(request);
  return configured.includes(actual) ? actual : configured[0];
}

function getRpId(request, env) {
  const explicit = String(env.RP_ID || "").trim();
  if (explicit) return explicit;
  try {
    return new URL(getExpectedOrigin(request, env)).hostname;
  } catch {
    return new URL(request.url).hostname;
  }
}

function isAllowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && !["same-origin", "none"].includes(fetchSite)) return false;
  if (!origin) return true;
  const allowed = new Set([getRequestOrigin(request), ...getConfiguredOrigins(env)]);
  return allowed.has(origin.replace(/\/+$/, ""));
}

/* ---------------- Cookie 与会话 ---------------- */
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(";").forEach((part) => {
    const [k, v] = part.trim().split("=");
    if (!k || !v) return;
    try {
      cookies[k] = decodeURIComponent(v);
    } catch {
      cookies[k] = v;
    }
  });
  return cookies;
}

function emptySession(env = getEnv()) {
  return { accounts: [], activeUser: "", upstream: getDefaultUpstream(env) };
}

function isTokenUsable(token, skewSec = 60) {
  const exp = jwtExp(token);
  return Boolean(token) && (!exp || exp > Math.floor(Date.now() / 1000) + skewSec);
}

async function getSession(request) {
  const env = getEnv();
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const rawCookie = cookies[SESSION_COOKIE_NAME];
  if (!rawCookie) return emptySession(env);

  try {
    const secret = getSessionSecret(env);
    let session = null;

    if (rawCookie.startsWith("s.")) {
      if (!hasRemoteStore(env)) return emptySession(env);
      const sid = rawCookie.slice(2);
      if (!/^[A-Za-z0-9_-]{20,}$/.test(sid)) return emptySession(env);
      const stored = await kvGet(env, `sess:${sid}`);
      if (!stored) return emptySession(env);
      session = JSON.parse(stored);
      Object.defineProperty(session, "__sid", {
        value: sid,
        enumerable: false,
        configurable: true,
        writable: true,
      });
    } else if (rawCookie.startsWith("e.")) {
      // 配置远端存储后强制使用服务端会话，旧的无状态 Cookie 不再被接受。
      if (hasRemoteStore(env)) return emptySession(env);
      const plain = await decryptWithSecret(rawCookie.slice(2), secret, "session");
      if (!plain) return emptySession(env);
      session = JSON.parse(plain);
    } else {
      return emptySession(env);
    }

    if (!session || typeof session !== "object") return emptySession(env);
    if (session._exp && Number(session._exp) < Math.floor(Date.now() / 1000)) {
      if (session.__sid) {
        try { await kvDel(env, `sess:${session.__sid}`); } catch {}
      }
      return emptySession(env);
    }
    if (!Array.isArray(session.accounts)) session.accounts = [];
    const upCheck = validateUpstreamUrl(session.upstream || getDefaultUpstream(env), env);
    session.upstream = upCheck.valid ? upCheck.url : getDefaultUpstream(env);
    return session;
  } catch (e) {
    console.error("[session]", e && e.message);
    return emptySession(env);
  }
}

async function createSessionCookie(sessionData, maxAge = SESSION_TTL) {
  if (maxAge <= 0) {
    return `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`;
  }
  const env = getEnv();
  const secret = getSessionSecret(env);
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    accounts: sessionData.accounts || [],
    activeUser: sessionData.activeUser || "",
    upstream: sessionData.upstream || getDefaultUpstream(env),
    _exp: nowSec + maxAge,
  };

  let value;
  if (hasRemoteStore(env)) {
    const sid = sessionData.__sid || base64UrlEncode(crypto.getRandomValues(new Uint8Array(24)));
    await kvSet(env, `sess:${sid}`, JSON.stringify(payload), maxAge);
    value = `s.${sid}`;
  } else {
    value = `e.${await encryptData(JSON.stringify(payload), secret, "session")}`;
  }
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax; Secure`;
}

async function rotateSessionId(session) {
  if (!session || !session.__sid) return;
  try { await kvDel(getEnv(), `sess:${session.__sid}`); } catch {}
  try { delete session.__sid; } catch {}
}

async function destroySession(session) {
  if (!session || !session.__sid) return;
  try { await kvDel(getEnv(), `sess:${session.__sid}`); } catch {}
  try { delete session.__sid; } catch {}
}

function getPanelKey(env = getEnv()) {
  return typeof env.PANEL_KEY === "string" ? env.PANEL_KEY.trim() : "";
}

async function makePanelCookie(env) {
  const key = getPanelKey(env);
  if (!key) return "";
  const token = await signData(
    JSON.stringify({ exp: Date.now() + PANEL_COOKIE_TTL * 1000 }),
    `${getSessionSecret(env)}::${key}`,
    "panel"
  );
  return `${PANEL_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=${PANEL_COOKIE_TTL}; HttpOnly; SameSite=Lax; Secure`;
}

async function isPanelAuthorized(request, env) {
  const key = getPanelKey(env);
  if (!key) return true;

  const headerKey = request.headers.get("X-Panel-Key");
  if (headerKey && safeEqual(headerKey, key)) return true;

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const raw = cookies[PANEL_COOKIE_NAME];
  if (!raw) return false;
  const data = await verifyData(raw, `${getSessionSecret(env)}::${key}`, "panel");
  if (!data) return false;
  try {
    return Number(JSON.parse(data).exp) > Date.now();
  } catch {
    return false;
  }
}

/* ---------------- 响应头 ---------------- */
function applySecurityHeaders(headers) {
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("X-Permitted-Cross-Domain-Policies", "none");
  headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)"
  );
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; " +
    "frame-ancestors 'none'; worker-src 'none'"
  );
}

function jsonRsp(data, status = 200, extraHeaders = {}) {
  const h = new Headers(extraHeaders);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store, no-cache, must-revalidate");
  applySecurityHeaders(h);
  return new Response(JSON.stringify(data), { status, headers: h });
}

/* ---------------- WebAuthn：CBOR / COSE / 签名校验 ---------------- */
function decodeCbor(bytes, start = 0) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let pos = start;

  const need = (n) => {
    if (pos + n > u8.length) throw new Error("CBOR 数据不完整");
  };
  const readLength = (ai) => {
    if (ai < 24) return ai;
    if (ai === 24) { need(1); return u8[pos++]; }
    if (ai === 25) { need(2); const v = (u8[pos] << 8) | u8[pos + 1]; pos += 2; return v; }
    if (ai === 26) {
      need(4);
      const v = ((u8[pos] << 24) | (u8[pos + 1] << 16) | (u8[pos + 2] << 8) | u8[pos + 3]) >>> 0;
      pos += 4;
      return v;
    }
    if (ai === 27) {
      need(8);
      let v = 0n;
      for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(u8[pos++]);
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("CBOR 长度过大");
      return Number(v);
    }
    throw new Error("CBOR 不支持的长度编码");
  };

  need(1);
  const initial = u8[pos++];
  const major = initial >> 5;
  const ai = initial & 0x1f;
  const len = readLength(ai);

  switch (major) {
    case 0:
      return [len, pos];
    case 1:
      return [-1 - len, pos];
    case 2: {
      need(len);
      const v = u8.slice(pos, pos + len);
      pos += len;
      return [v, pos];
    }
    case 3: {
      need(len);
      const v = new TextDecoder().decode(u8.slice(pos, pos + len));
      pos += len;
      return [v, pos];
    }
    case 4: {
      if (len > 100000) throw new Error("CBOR 数组过大");
      const arr = [];
      for (let i = 0; i < len; i++) {
        const [v, p] = decodeCbor(u8, pos);
        arr.push(v);
        pos = p;
      }
      return [arr, pos];
    }
    case 5: {
      if (len > 100000) throw new Error("CBOR 映射过大");
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const [k, p1] = decodeCbor(u8, pos);
        const [v, p2] = decodeCbor(u8, p1);
        map.set(k, v);
        pos = p2;
      }
      return [map, pos];
    }
    case 6:
      return decodeCbor(u8, pos);
    case 7:
      if (ai === 20) return [false, pos];
      if (ai === 21) return [true, pos];
      if (ai === 22) return [null, pos];
      return [undefined, pos];
    default:
      throw new Error("CBOR 类型不支持");
  }
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function parseAuthData(authData) {
  if (!(authData instanceof Uint8Array) || authData.length < 37) {
    throw new Error("authenticatorData 不完整");
  }
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = ((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]) >>> 0;
  const out = { rpIdHash, flags, signCount, credentialId: null, coseKey: null };

  if (flags & 0x40) {
    let o = 37;
    if (authData.length < o + 18) throw new Error("凭据公钥数据不完整");
    o += 16; // AAGUID
    const credLen = (authData[o] << 8) | authData[o + 1];
    o += 2;
    if (!credLen || o + credLen > authData.length) throw new Error("凭据 ID 长度异常");
    out.credentialId = authData.slice(o, o + credLen);
    o += credLen;
    const [coseKey] = decodeCbor(authData, o);
    out.coseKey = coseKey;
  }
  return out;
}

function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new Error("通行密钥公钥格式不正确");
  const kty = cose.get(1);
  const alg = cose.get(3);

  if (kty === 2 && alg === -7) {
    const crv = cose.get(-1);
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
      throw new Error("不支持的 EC 通行密钥公钥");
    }
    return {
      alg: "ES256",
      jwk: { kty: "EC", crv: "P-256", x: base64UrlEncode(x), y: base64UrlEncode(y) },
    };
  }

  if (kty === 3 && alg === -257) {
    const n = cose.get(-1);
    const e = cose.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) {
      throw new Error("不支持的 RSA 通行密钥公钥");
    }
    return {
      alg: "RS256",
      jwk: { kty: "RSA", n: base64UrlEncode(n), e: base64UrlEncode(e) },
    };
  }

  throw new Error("不支持的通行密钥算法");
}

function parseDerLength(sig, state) {
  let len = sig[state.pos++];
  if ((len & 0x80) !== 0) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("DER 长度编码不合法");
    len = 0;
    for (let i = 0; i < n; i++) {
      if (state.pos >= sig.length) throw new Error("DER 数据不完整");
      len = (len << 8) | sig[state.pos++];
    }
  }
  return len;
}

function derToRawEcdsa(sig, size = 32) {
  const state = { pos: 0 };
  if (sig[state.pos++] !== 0x30) throw new Error("ECDSA 签名不是 DER 序列");
  const seqLen = parseDerLength(sig, state);
  if (state.pos + seqLen !== sig.length) throw new Error("ECDSA DER 序列长度不匹配");

  const readInt = () => {
    if (sig[state.pos++] !== 0x02) throw new Error("ECDSA DER 整数标记错误");
    const len = parseDerLength(sig, state);
    if (!len || state.pos + len > sig.length) throw new Error("ECDSA DER 整数长度错误");
    const v = sig.slice(state.pos, state.pos + len);
    state.pos += len;
    return v;
  };

  const r = readInt();
  const s = readInt();
  if (state.pos !== sig.length) throw new Error("ECDSA DER 尾部存在多余数据");

  const raw = new Uint8Array(size * 2);
  const writeInt = (v, offset) => {
    let start = 0;
    while (start < v.length - 1 && v[start] === 0) start++;
    const trimmed = v.slice(start);
    if (trimmed.length > size) throw new Error("ECDSA 整数超出曲线长度");
    raw.set(trimmed, offset + size - trimmed.length);
  };
  writeInt(r, 0);
  writeInt(s, size);
  return raw;
}

function normalizeEcdsaSignature(sig, size = 32) {
  if (sig.length === size * 2) return sig;
  if (sig.length > 0 && sig[0] === 0x30) return derToRawEcdsa(sig, size);
  throw new Error("ECDSA 签名格式不正确");
}

async function importPublicKey(jwk, alg) {
  if (alg === "ES256") {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  }
  if (alg === "RS256") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  }
  throw new Error("不支持的签名算法");
}

async function verifySignature({ jwk, alg, signature, data }) {
  const key = await importPublicKey(jwk, alg);
  if (alg === "ES256") {
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      normalizeEcdsaSignature(signature, 32),
      data
    );
  }
  return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
}

function parseClientDataJSON(b64) {
  const raw = base64UrlDecodeBytes(b64);
  const text = new TextDecoder().decode(raw);
  return { data: JSON.parse(text), raw };
}

function verifyClientData(b64, expectedType, expectedChallenge, expectedOrigin) {
  let parsed;
  try {
    parsed = parseClientDataJSON(b64);
  } catch {
    throw badRequest("通行密钥客户端数据解析失败");
  }
  const d = parsed.data;
  if (!d || d.type !== expectedType) throw badRequest("通行密钥操作类型不匹配");
  if (d.challenge !== expectedChallenge) throw badRequest("通行密钥挑战不匹配");
  if (d.origin !== expectedOrigin) throw badRequest("通行密钥来源不匹配");
  if (d.crossOrigin === true) throw badRequest("不允许跨来源的通行密钥操作");
  return parsed.raw;
}

async function verifyRegistration({
  attestationObject,
  clientDataJSON,
  expectedChallenge,
  expectedOrigin,
  expectedRpId,
  credentialId,
}) {
  verifyClientData(clientDataJSON, "webauthn.create", expectedChallenge, expectedOrigin);

  let att;
  try {
    [att] = decodeCbor(base64UrlDecodeBytes(attestationObject || ""));
  } catch (e) {
    throw badRequest("通行密钥注册数据解析失败");
  }
  if (!(att instanceof Map)) throw badRequest("通行密钥注册数据结构不正确");
  const authData = att.get("authData");
  if (!(authData instanceof Uint8Array)) throw badRequest("通行密钥注册数据缺少 authenticatorData");

  const parsed = parseAuthData(authData);
  const expectedRpHash = await sha256(new TextEncoder().encode(expectedRpId));
  if (!bytesEqual(parsed.rpIdHash, expectedRpHash)) throw badRequest("通行密钥 RP ID 不匹配");
  if (!(parsed.flags & 0x01)) throw badRequest("通行密钥未完成用户存在验证");
  if (!(parsed.flags & 0x40)) throw badRequest("通行密钥注册数据缺少公钥");
  if (!parsed.credentialId) throw badRequest("通行密钥注册数据缺少凭据 ID");

  const actualCredentialId = base64UrlEncode(parsed.credentialId);
  if (credentialId && actualCredentialId !== credentialId) {
    throw badRequest("通行密钥凭据 ID 不一致");
  }

  const { jwk, alg } = coseToJwk(parsed.coseKey);
  return { alg, jwk, signCount: parsed.signCount, credentialId: actualCredentialId };
}

async function verifyAssertion({
  authenticatorData,
  clientDataJSON,
  signature,
  expectedChallenge,
  expectedOrigin,
  expectedRpId,
  publicKeyJwk,
  alg,
  storedSignCount = 0,
  requireUV = false,
}) {
  const clientDataHash = await sha256(
    verifyClientData(clientDataJSON, "webauthn.get", expectedChallenge, expectedOrigin)
  );
  const authBytes = base64UrlDecodeBytes(authenticatorData || "");
  let parsed;
  try {
    parsed = parseAuthData(authBytes);
  } catch {
    throw badRequest("通行密钥认证数据解析失败");
  }

  const expectedRpHash = await sha256(new TextEncoder().encode(expectedRpId));
  if (!bytesEqual(parsed.rpIdHash, expectedRpHash)) throw badRequest("通行密钥 RP ID 不匹配");
  if (!(parsed.flags & 0x01)) throw badRequest("通行密钥未完成用户存在验证");
  if (requireUV && !(parsed.flags & 0x04)) throw badRequest("通行密钥未完成用户验证");
  if (parsed.signCount > 0 && storedSignCount > 0 && parsed.signCount <= storedSignCount) {
    throw badRequest("通行密钥签名计数器异常，可能被重放");
  }

  const signed = new Uint8Array(authBytes.length + clientDataHash.length);
  signed.set(authBytes, 0);
  signed.set(clientDataHash, authBytes.length);

  let ok = false;
  try {
    ok = await verifySignature({
      jwk: publicKeyJwk,
      alg,
      signature: base64UrlDecodeBytes(signature || ""),
      data: signed,
    });
  } catch {
    throw badRequest("通行密钥签名校验失败");
  }
  if (!ok) throw badRequest("通行密钥签名无效");

  return { signCount: parsed.signCount };
}

/* ---------------- 挑战令牌 ---------------- */
async function createChallengeToken(env, request, type) {
  const challenge = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const payload = {
    type,
    challenge,
    nonce,
    rpId: getRpId(request, env),
    origin: getExpectedOrigin(request, env),
    exp: Date.now() + CHALLENGE_TTL * 1000,
  };
  const challengeToken = await signData(JSON.stringify(payload), getSessionSecret(env), "challenge");
  return {
    error: 0,
    challenge,
    challengeToken,
    rpId: payload.rpId,
    requireUV: isTruthy(env.PASSKEY_REQUIRE_UV),
    expiresIn: CHALLENGE_TTL,
  };
}

async function verifyChallengeToken(env, request, token, expectedType) {
  if (!token) throw badRequest("缺少通行密钥挑战令牌");
  const raw = await verifyData(String(token), getSessionSecret(env), "challenge");
  if (!raw) throw badRequest("通行密钥挑战无效或已过期");
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    throw badRequest("通行密钥挑战格式不正确");
  }
  if (!payload || Number(payload.exp) < Date.now()) throw badRequest("通行密钥挑战已过期，请重试");
  if (payload.type !== expectedType) throw badRequest("通行密钥挑战类型不匹配");
  if (payload.rpId !== getRpId(request, env)) throw badRequest("通行密钥 RP ID 已变化，请重试");
  if (payload.origin !== getExpectedOrigin(request, env)) throw badRequest("通行密钥来源已变化，请重试");

  const consumed = await consumeOnce(env, `chal:${payload.nonce}`, CHALLENGE_TTL);
  if (!consumed) throw badRequest("通行密钥挑战已使用，请重新发起");
  return payload;
}

/* ---------------- 通行密钥注册表 ---------------- */
async function getPasskeyRecord(env, credentialId) {
  if (!hasRemoteStore(env)) return null;
  const raw = await kvGet(env, `pk:${credentialId}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function savePasskeyRecord(env, record) {
  if (!hasRemoteStore(env)) return;
  await kvSet(env, `pk:${record.credentialId}`, JSON.stringify(record), PASSKEY_TTL);
  await kvSAdd(env, `pkidx:${record.user}`, record.credentialId, PASSKEY_TTL + 30 * 24 * 3600);
}

async function removePasskeyRecord(env, record) {
  if (!hasRemoteStore(env)) return;
  await kvDel(env, `pk:${record.credentialId}`);
  await kvSRem(env, `pkidx:${record.user}`, record.credentialId);
}

async function refreshUserPasskeys(env, user, token, upstream) {
  if (!hasRemoteStore(env) || !user || !token) return;
  try {
    const ids = await kvSMembers(env, `pkidx:${user}`);
    for (const id of ids.slice(0, 30)) {
      const rec = await getPasskeyRecord(env, id);
      if (!rec || rec.user !== user) continue;
      rec.token = token;
      if (upstream) rec.upstream = upstream;
      rec.expiresAt = Date.now() + PASSKEY_TTL * 1000;
      await savePasskeyRecord(env, rec);
    }
  } catch (e) {
    console.warn("[passkey:refresh]", e.message);
  }
}

function publicPasskeyRecord(record) {
  return {
    credentialId: record.credentialId,
    user: record.user,
    deviceName: record.deviceName || "当前设备",
    createdAt: record.createdAt || 0,
    lastUsedAt: record.lastUsedAt || 0,
    expiresAt: record.expiresAt || 0,
  };
}

function buildClientPasskeyCipher(record, env) {
  const payload = { ...record };
  // 服务端注册表存在时，浏览器缓存中不保存上游 token。
  if (hasRemoteStore(env)) delete payload.token;
  return encryptData(JSON.stringify(payload), getSessionSecret(env), "passkey");
}

/* ---------------- 上游请求 ---------------- */
async function fetchWithTimeout(url, opts = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function applyUpstream(body, session, env) {
  const raw = String((body && body.upstream) || "").trim().replace(/\/+$/, "");
  if (!raw) {
    const current = validateUpstreamUrl(session.upstream || getDefaultUpstream(env), env);
    return { ok: true, upstream: current.valid ? current.url : getDefaultUpstream(env) };
  }
  const check = validateUpstreamUrl(raw, env);
  if (!check.valid) return { ok: false, reason: check.reason };
  session.upstream = check.url;
  return { ok: true, upstream: check.url };
}

/* ---------------- 主入口 ---------------- */
export default async function handler(request) {
  try {
    return await handleRequest(request);
  } catch (err) {
    console.error("[openp2p] unhandled:", err && err.message);
    const detail = /SESSION_SECRET/.test(String((err && err.message) || ""))
      ? err.message
      : "服务端处理失败，请稍后重试";
    return jsonRsp({ error: 500, detail }, 500);
  }
}

async function handleRequest(request) {
  const env = getEnv();
  const url = new URL(request.url);
  const rawPath =
    url.searchParams.get("_vercel_path") ||
    request.headers.get("x-matched-path") ||
    request.headers.get("x-forwarded-uri") ||
    url.pathname;
  url.searchParams.delete("_vercel_path");

  const pathname = rawPath.split("?")[0];
  const method = request.method;

  if (method === "OPTIONS") {
    const h = new Headers();
    applySecurityHeaders(h);
    return new Response(null, { status: 204, headers: h });
  }

  // CSRF：所有写请求必须同源（或携带合法 Origin）；curl 等无 Origin 的客户端仍可用。
  if (!["GET", "HEAD"].includes(method) && !isAllowedOrigin(request, env)) {
    return jsonRsp({ error: 403, detail: "跨站请求已被拒绝" }, 403);
  }

  if (!["GET", "HEAD"].includes(method)) {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > MAX_BODY_BYTES) {
      return jsonRsp({ error: 413, detail: "请求体过大" }, 413);
    }
  }

  // 面板口令：浏览器通过 /api/panel-auth 换取 HttpOnly Cookie，不再把口令放在 localStorage。
  const panelKey = getPanelKey(env);
  const publicPaths = new Set(["/", "/index.html", "/app.css", "/app.js", "/favicon.ico"]);
  if (panelKey && pathname !== "/api/panel-auth" && !publicPaths.has(pathname)) {
    if (!(await isPanelAuthorized(request, env))) {
      return jsonRsp({ error: 401, detail: "本面板已启用访问口令，需要正确口令" }, 401);
    }
  }

  /* ---------- 反向代理 /pxp/* 与 /api/pxp/* ---------- */
  if (pathname.startsWith("/api/pxp/") || pathname.startsWith("/pxp/")) {
    const session = await getSession(request);
    if (!session.activeUser) {
      return jsonRsp({ error: 401, detail: "请先登录后再访问上游接口" }, 401);
    }

    let upstream = session.upstream || getDefaultUpstream(env);
    const upstreamCheck = validateUpstreamUrl(upstream, env);
    upstream = upstreamCheck.valid ? upstreamCheck.url : getDefaultUpstream(env);
    const upstreamOrigin = new URL(upstream).origin;

    const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
    const token = acc ? acc.token : "";
    if (!isTokenUsable(token, 0)) {
      return jsonRsp({ error: 401, detail: "登录凭据已过期，请重新登录" }, 401);
    }

    const subPath = pathname.replace(/^\/api\/pxp/, "").replace(/^\/pxp/, "");
    const targetUrl = `${upstream}${subPath}${url.search}`;

    const fwdHeaders = new Headers();
    const stripHeaders = new Set([
      "host", "cookie", "connection", "accept-encoding", "content-length",
      "x-panel-key", "x-session-id", "authorization",
      "x-forwarded-for", "x-real-ip", "forwarded", "cf-connecting-ip",
      "origin", "referer",
      "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    ]);
    for (const [k, v] of request.headers.entries()) {
      if (!stripHeaders.has(k.toLowerCase())) fwdHeaders.set(k, v);
    }
    fwdHeaders.set("Host", new URL(upstream).host);
    fwdHeaders.set("Authorization", token);

    try {
      const reqBody = ["GET", "HEAD"].includes(method) ? undefined : await request.arrayBuffer();
      let curUrl = targetUrl;
      let upstreamRsp = null;
      let redirectHops = 0;

      while (redirectHops < 5) {
        const curMethod =
          redirectHops === 0
            ? method
            : upstreamRsp && [301, 302, 303].includes(upstreamRsp.status)
              ? "GET"
              : method;
        const curBody = redirectHops === 0 ? reqBody : undefined;

        upstreamRsp = await fetchWithTimeout(curUrl, {
          method: curMethod,
          headers: fwdHeaders,
          body: curBody,
          redirect: "manual",
        });

        if (upstreamRsp.status >= 300 && upstreamRsp.status < 400) {
          const loc = upstreamRsp.headers.get("Location") || "";
          if (!loc) break;
          let nextUrl;
          try {
            nextUrl = new URL(loc, curUrl);
          } catch {
            return jsonRsp({ error: 400, detail: "上游重定向目标不合法" }, 400);
          }
          // 禁止跨源重定向，避免把上游 Authorization token 带到第三方站点。
          if (nextUrl.origin !== upstreamOrigin) {
            return jsonRsp({ error: 403, detail: "上游跨域重定向已被拦截" }, 403);
          }
          if (nextUrl.protocol !== "https:" || isPrivateHost(nextUrl.hostname)) {
            return jsonRsp({ error: 403, detail: "上游重定向至私有或非安全地址已被拦截" }, 403);
          }
          curUrl = nextUrl.toString();
          fwdHeaders.set("Host", nextUrl.host);
          redirectHops++;
        } else {
          break;
        }
      }

      if (!upstreamRsp) return jsonRsp({ error: -2, detail: "上游服务暂时不可用" }, 502);
      if (redirectHops >= 5 && upstreamRsp.status >= 300 && upstreamRsp.status < 400) {
        return jsonRsp({ error: -2, detail: "上游重定向次数过多" }, 502);
      }

      const respData = await upstreamRsp.arrayBuffer();
      const respHeaders = new Headers(upstreamRsp.headers);
      for (const h of [
        "content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive",
        "set-cookie", "set-cookie2", "location",
        "access-control-allow-origin", "access-control-allow-credentials",
        "access-control-allow-methods", "access-control-allow-headers",
        "access-control-expose-headers", "access-control-max-age",
      ]) {
        respHeaders.delete(h);
      }
      respHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate");
      respHeaders.set("Cross-Origin-Resource-Policy", "same-origin");
      applySecurityHeaders(respHeaders);

      return new Response(respData, { status: upstreamRsp.status, headers: respHeaders });
    } catch (err) {
      console.error("[proxy]", err && err.message);
      return jsonRsp({ error: -2, detail: "上游服务暂时不可用" }, 502);
    }
  }

  /* ---------- 面板口令兑换 ---------- */
  if (pathname === "/api/panel-auth" && method === "POST") {
    if (!panelKey) return jsonRsp({ error: 0, required: false });
    const ip = getClientIp(request);
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
    }
    const key = String(body.key || "");
    if (!key || key.length > 256 || !safeEqual(key, panelKey)) {
      const fails = await bumpRate(env, `panel:${ip}`, 900);
      if (fails >= 10) return jsonRsp({ error: 429, detail: "口令尝试次数过多，请稍后再试" }, 429);
      return jsonRsp({ error: 401, detail: "访问口令错误" }, 401);
    }
    await clearRate(env, `panel:${ip}`);
    return jsonRsp({ error: 0, required: true }, 200, {
      "Set-Cookie": await makePanelCookie(env),
    });
  }

  /* ---------- 管理 API ---------- */
  if (pathname.startsWith("/api/")) {
    const session = await getSession(request);
    const upstream = session.upstream || getDefaultUpstream(env);

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
        hasCustomSecret: Boolean(String(env.SESSION_SECRET || "").trim()),
        insecureSsl: false,
        serverSideSessions: hasRemoteStore(env),
        passkeyServerSide: hasRemoteStore(env),
        panelRequired: Boolean(panelKey),
        accounts: pool.map((a) => ({
          user: a.user,
          hasToken: Boolean(a.token),
          tokenExp: jwtExp(a.token || ""),
          hasPassword: false,
          active: a.user === user,
        })),
      });
    }

    if (pathname === "/api/captcha" && (method === "GET" || method === "POST")) {
      const theme = url.searchParams.get("theme") || request.headers.get("X-Panel-Theme") || "dark";
      try {
        return jsonRsp(await createCaptcha(env, request, theme));
      } catch (err) {
        return jsonRsp({ error: -1, detail: err.message }, err.status || 400);
      }
    }

    if (pathname === "/api/passkey/challenge" && (method === "GET" || method === "POST")) {
      const type = url.searchParams.get("type") || "get";
      if (!["get", "create"].includes(type)) {
        return jsonRsp({ error: -1, detail: "通行密钥挑战类型不合法" }, 400);
      }
      if (type === "create" && !session.activeUser) {
        return jsonRsp({ error: 401, detail: "请先登录后再绑定通行密钥" }, 401);
      }
      const challengeCount = await bumpRate(env, `chal:${getClientIp(request)}`, 60);
      if (challengeCount > 60) {
        return jsonRsp({ error: 429, detail: "通行密钥请求过于频繁，请稍后再试" }, 429);
      }
      try {
        return jsonRsp(await createChallengeToken(env, request, type));
      } catch (err) {
        return jsonRsp({ error: -1, detail: err.message }, err.status || 400);
      }
    }

    if (pathname === "/api/passkey/bind" && method === "POST") {
      if (!session.activeUser) {
        return jsonRsp({ error: 401, detail: "请先登录后再绑定通行密钥" }, 401);
      }
      const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
      if (!acc || !acc.token) {
        return jsonRsp({ error: 401, detail: "未找到当前账户凭据，请重新登录" }, 401);
      }
      if (!isTokenUsable(acc.token, 60)) {
        return jsonRsp({ error: 401, detail: "登录凭据已过期，请重新登录后再绑定通行密钥" }, 401);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
      }

      const credentialId = String(body.credentialId || "").trim();
      const deviceName = cleanLabel(body.deviceName, "当前设备");
      if (!credentialId || credentialId.length < 16 || credentialId.length > 2048) {
        return jsonRsp({ error: -1, detail: "通行密钥凭据标识不合法" }, 400);
      }
      if (!body.clientDataJSON || !body.attestationObject || !body.challengeToken) {
        return jsonRsp({ error: -1, detail: "通行密钥注册数据不完整" }, 400);
      }

      try {
        const challenge = await verifyChallengeToken(env, request, body.challengeToken, "create");
        const registration = await verifyRegistration({
          attestationObject: body.attestationObject,
          clientDataJSON: body.clientDataJSON,
          expectedChallenge: challenge.challenge,
          expectedOrigin: challenge.origin,
          expectedRpId: challenge.rpId,
          credentialId,
        });

        if (hasRemoteStore(env)) {
          const existing = await getPasskeyRecord(env, registration.credentialId);
          if (existing && existing.user !== acc.user) {
            return jsonRsp({ error: 409, detail: "该通行密钥已绑定到其他账户" }, 409);
          }
        }

        const now = Date.now();
        const record = {
          v: 2,
          credentialId: registration.credentialId,
          user: acc.user,
          token: acc.token,
          upstream: session.upstream || getDefaultUpstream(env),
          deviceName,
          createdAt: now,
          lastUsedAt: now,
          expiresAt: now + PASSKEY_TTL * 1000,
          rpId: challenge.rpId,
          publicKeyJwk: registration.jwk,
          alg: registration.alg,
          signCount: registration.signCount,
        };

        await savePasskeyRecord(env, record);
        const passkeyCipher = await buildClientPasskeyCipher(record, env);

        return jsonRsp({
          error: 0,
          credentialId: record.credentialId,
          passkeyCipher,
          user: record.user,
          deviceName: record.deviceName,
          createdAt: record.createdAt,
          serverSide: hasRemoteStore(env),
        });
      } catch (err) {
        if (err.status === 503) {
          return jsonRsp({ error: 503, detail: err.message }, 503);
        }
        return jsonRsp({ error: -1, detail: err.message || "通行密钥绑定失败" }, err.status || 400);
      }
    }

    if (pathname === "/api/passkey/login" && method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
      }

      const credentialId = String(body.credentialId || "").trim();
      const clientCipher = String(body.passkeyCipher || "").trim();
      if (!credentialId || credentialId.length < 16 || credentialId.length > 2048) {
        return jsonRsp({ error: -1, detail: "通行密钥凭据标识不合法" }, 400);
      }
      if (!body.clientDataJSON || !body.authenticatorData || !body.signature || !body.challengeToken) {
        return jsonRsp({ error: -1, detail: "通行密钥认证数据不完整" }, 400);
      }

      const passkeyAttempts = await bumpRate(env, `pklogin:${getClientIp(request)}`, 60);
      if (passkeyAttempts > 30) {
        return jsonRsp({ error: 429, detail: "通行密钥登录尝试过于频繁，请稍后再试" }, 429);
      }

      try {
        const challenge = await verifyChallengeToken(env, request, body.challengeToken, "get");

        let cipherPayload = null;
        if (clientCipher) {
          const plain = await decryptWithSecret(clientCipher, getSessionSecret(env), "passkey");
          if (!plain) {
            return jsonRsp({ error: 401, detail: "通行密钥本地缓存无效，请使用密码登录后重新绑定" }, 401);
          }
          try {
            cipherPayload = JSON.parse(plain);
          } catch {
            return jsonRsp({ error: 401, detail: "通行密钥本地缓存损坏，请重新绑定" }, 401);
          }
          if (!cipherPayload || cipherPayload.credentialId !== credentialId) {
            return jsonRsp({ error: 401, detail: "通行密钥凭据不匹配" }, 401);
          }
        }

        let record = null;
        if (hasRemoteStore(env)) {
          record = await getPasskeyRecord(env, credentialId);
          if (!record) {
            return jsonRsp({
              error: 401,
              code: "NEEDS_REBIND",
              needsRebind: true,
              detail: "该通行密钥已在服务器端失效或解绑，请使用密码登录后重新绑定",
            }, 401);
          }
        } else {
          record = cipherPayload;
        }

        if (!record) {
          return jsonRsp({
            error: 401,
            code: "NEEDS_PASSWORD",
            needsPasswordLogin: true,
            detail: "本机没有该通行密钥的凭据，请使用密码登录",
          }, 401);
        }

        if (record.user && cipherPayload && cipherPayload.user && record.user !== cipherPayload.user) {
          return jsonRsp({ error: 401, detail: "通行密钥账户信息不匹配" }, 401);
        }

        const rpId = getRpId(request, env);
        if (!record.publicKeyJwk || !record.alg || record.rpId !== rpId) {
          return jsonRsp({
            error: 401,
            code: "NEEDS_REBIND",
            needsRebind: true,
            detail: "旧版通行密钥缺少服务端可验证公钥，请使用密码登录后重新绑定",
          }, 401);
        }

        const now = Date.now();
        if (record.expiresAt && Number(record.expiresAt) < now) {
          return jsonRsp({
            error: 401,
            code: "NEEDS_REBIND",
            needsRebind: true,
            detail: "通行密钥已过期，请使用密码登录后重新绑定",
          }, 401);
        }

        const assertion = await verifyAssertion({
          authenticatorData: body.authenticatorData,
          clientDataJSON: body.clientDataJSON,
          signature: body.signature,
          expectedChallenge: challenge.challenge,
          expectedOrigin: challenge.origin,
          expectedRpId: challenge.rpId,
          publicKeyJwk: record.publicKeyJwk,
          alg: record.alg,
          storedSignCount: Number(record.signCount || 0),
          requireUV: isTruthy(env.PASSKEY_REQUIRE_UV),
        });

        let token = record.token || "";
        if (
          cipherPayload &&
          cipherPayload.user === record.user &&
          isTokenUsable(cipherPayload.token, 60) &&
          jwtExp(cipherPayload.token) > jwtExp(token)
        ) {
          token = cipherPayload.token;
        }
        if (!isTokenUsable(token, 60)) {
          return jsonRsp({
            error: 401,
            code: "NEEDS_PASSWORD",
            needsPasswordLogin: true,
            detail: "通行密钥对应的登录凭据已过期，请使用密码登录后重新绑定",
          }, 401);
        }

        await rotateSessionId(session);
        const pool = (session.accounts || []).filter((a) => a.user !== record.user);
        pool.push({ user: record.user, token });
        session.accounts = pool;
        session.activeUser = record.user;
        const upCheck = validateUpstreamUrl(record.upstream || upstream, env);
        session.upstream = upCheck.valid ? upCheck.url : getDefaultUpstream(env);

        const updated = {
          ...record,
          token,
          upstream: session.upstream,
          signCount: assertion.signCount,
          lastUsedAt: now,
          expiresAt: now + PASSKEY_TTL * 1000,
        };
        await savePasskeyRecord(env, updated);

        const passkeyCipher = await buildClientPasskeyCipher(updated, env);
        const cookie = await createSessionCookie(session);
        return jsonRsp({
          error: 0,
          user: updated.user,
          credentialId: updated.credentialId,
          passkeyCipher,
          deviceName: updated.deviceName || "当前设备",
          createdAt: updated.createdAt || now,
        }, 200, { "Set-Cookie": cookie });
      } catch (err) {
        if (err.status === 503) {
          return jsonRsp({ error: 503, detail: err.message }, 503);
        }
        return jsonRsp({ error: -1, detail: err.message || "通行密钥登录失败" }, err.status || 400);
      }
    }

    if (pathname === "/api/passkey/list" && (method === "GET" || method === "POST")) {
      if (!session.activeUser) return jsonRsp({ error: 401, detail: "请先登录" }, 401);
      if (!hasRemoteStore(env)) {
        return jsonRsp({ error: 0, serverSide: false, credentials: [] });
      }
      try {
        const ids = await kvSMembers(env, `pkidx:${session.activeUser}`);
        const credentials = [];
        for (const id of ids.slice(0, 30)) {
          const rec = await getPasskeyRecord(env, id);
          if (rec && rec.user === session.activeUser) credentials.push(publicPasskeyRecord(rec));
        }
        credentials.sort((a, b) => b.createdAt - a.createdAt);
        return jsonRsp({ error: 0, serverSide: true, credentials });
      } catch (err) {
        return jsonRsp({ error: 503, detail: err.message }, 503);
      }
    }

    if (pathname === "/api/passkey/revoke" && method === "POST") {
      if (!session.activeUser) return jsonRsp({ error: 401, detail: "请先登录" }, 401);
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
      }
      const credentialId = String(body.credentialId || "").trim();
      if (!credentialId) return jsonRsp({ error: -1, detail: "缺少凭据标识" }, 400);
      if (!hasRemoteStore(env)) {
        return jsonRsp({ error: 0, serverSide: false, revoked: false });
      }
      try {
        const record = await getPasskeyRecord(env, credentialId);
        if (record && record.user !== session.activeUser) {
          return jsonRsp({ error: 403, detail: "无权解绑该通行密钥" }, 403);
        }
        if (record) await removePasskeyRecord(env, record);
        return jsonRsp({ error: 0, serverSide: true, revoked: Boolean(record) });
      } catch (err) {
        return jsonRsp({ error: 503, detail: err.message }, 503);
      }
    }

    if ((pathname === "/api/login" || pathname === "/api/login-token") && method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
      }

      try {
        await verifyCaptcha(env, request, body.captchaId || body.captcha_id, body.captcha || body.captcha_code);
      } catch (err) {
        return jsonRsp({ error: -1, detail: err.message }, err.status || 400);
      }

      const ip = getClientIp(request);
      const attempts = await bumpRate(env, `login:${ip}`, 60);
      if (attempts > 20) {
        return jsonRsp({ error: 429, detail: "登录尝试过于频繁，请稍后再试" }, 429);
      }

      const token = String(body.token || "").trim();
      const user = String(body.user || "").trim();
      const password = String(body.password || "");
      const upResult = applyUpstream(body, session, env);
      if (!upResult.ok) return jsonRsp({ error: -1, detail: upResult.reason }, 400);
      const activeUpstream = upResult.upstream;

      if (token) {
        try {
          const profRsp = await fetchWithTimeout(`${activeUpstream}/api/v1/user/profile`, {
            method: "POST",
            headers: { Authorization: token, "Content-Type": "application/json" },
            body: "{}",
          });
          const profData = await profRsp.json().catch(() => ({ error: -1 }));
          if (profData.error !== 0) throw new Error("invalid token");
          const loginUser = profData.user || jwtUser(token);
          if (!loginUser) throw new Error("invalid token");

          await rotateSessionId(session);
          const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
          pool.push({ user: loginUser, token });
          session.accounts = pool;
          session.activeUser = loginUser;

          await refreshUserPasskeys(env, loginUser, token, activeUpstream);
          const cookie = await createSessionCookie(session);
          await clearRate(env, `fail:${ip}`);
          return jsonRsp({ error: 0, user: loginUser }, 200, { "Set-Cookie": cookie });
        } catch {
          const fails = await bumpRate(env, `fail:${ip}`, 900);
          if (fails > 5) return jsonRsp({ error: 429, detail: "登录失败次数过多，请稍后再试" }, 429);
          return jsonRsp({ error: -1, detail: "Token 无效或已失效" }, 401);
        }
      }

      if (user && password) {
        try {
          const loginRsp = await fetchWithTimeout(`${activeUpstream}/api/v1/user/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user, password }),
          });
          const loginData = await loginRsp.json().catch(() => ({ error: -1 }));
          if (loginData.error !== 0 || !loginData.token) {
            const fails = await bumpRate(env, `fail:${ip}`, 900);
            if (fails > 5) return jsonRsp({ error: 429, detail: "登录失败次数过多，请稍后再试" }, 429);
            return jsonRsp({ error: loginData.error || -1, detail: loginData.detail || "用户名或密码错误" });
          }

          const loginUser = loginData.user || user;
          await rotateSessionId(session);
          const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
          pool.push({ user: loginUser, token: loginData.token });
          session.accounts = pool;
          session.activeUser = loginUser;

          await refreshUserPasskeys(env, loginUser, loginData.token, activeUpstream);
          const cookie = await createSessionCookie(session);
          await clearRate(env, `fail:${ip}`);
          return jsonRsp({ error: 0, user: loginUser }, 200, { "Set-Cookie": cookie });
        } catch {
          const fails = await bumpRate(env, `fail:${ip}`, 900);
          if (fails > 5) return jsonRsp({ error: 429, detail: "登录失败次数过多，请稍后再试" }, 429);
          return jsonRsp({ error: -1, detail: "上游登录服务暂时不可用" }, 502);
        }
      }

      return jsonRsp({ error: -1, detail: "缺少凭据" }, 400);
    }

    if (pathname === "/api/logout" && method === "POST") {
      let body = {};
      try {
        body = await request.json();
      } catch {}

      if (body.all) {
        await destroySession(session);
        session.accounts = [];
        session.activeUser = "";
        const cookie = await createSessionCookie(session, 0);
        return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
      }

      // 退出当前账户但保留多账户列表：删除旧服务端会话并换新 SID。
      await rotateSessionId(session);
      session.activeUser = "";
      const cookie = await createSessionCookie(session);
      return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
    }

    if (pathname === "/api/accounts/switch" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const targetUser = String(body.user || "");
      const acc = (session.accounts || []).find((a) => a.user === targetUser);
      if (!acc) return jsonRsp({ error: -1, detail: "未找到该账户" }, 404);
      if (!isTokenUsable(acc.token, 60)) {
        return jsonRsp({
          error: 401,
          code: "NEEDS_PASSWORD",
          needsPasswordLogin: true,
          detail: "该账户的登录凭据已过期，请重新输入密码登录",
        }, 401);
      }

      await rotateSessionId(session);
      session.activeUser = targetUser;
      const cookie = await createSessionCookie(session);
      return jsonRsp({ error: 0, user: targetUser }, 200, { "Set-Cookie": cookie });
    }

    if (pathname === "/api/accounts/remove" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const targetUser = String(body.user || "");
      await rotateSessionId(session);
      session.accounts = (session.accounts || []).filter((a) => a.user !== targetUser);
      if (session.activeUser === targetUser) {
        session.activeUser = session.accounts.length > 0 ? session.accounts[0].user : "";
      }
      const cookie = await createSessionCookie(session);
      return jsonRsp({ error: 0, ok: true }, 200, { "Set-Cookie": cookie });
    }

    if (pathname === "/api/upstream" && method === "POST") {
      if (!session.activeUser) return jsonRsp({ error: 401, detail: "请先登录" }, 401);
      const body = await request.json().catch(() => ({}));
      const newUp = String(body.upstream || "").trim().replace(/\/+$/, "");
      const upCheck = validateUpstreamUrl(newUp, env);
      if (!upCheck.valid) return jsonRsp({ error: -1, detail: upCheck.reason }, 400);
      session.upstream = upCheck.url;
      const cookie = await createSessionCookie(session);
      return jsonRsp({ error: 0, upstream: upCheck.url }, 200, { "Set-Cookie": cookie });
    }

    return jsonRsp({ error: -1, detail: "未知接口" }, 404);
  }

  const notFoundHeaders = new Headers();
  applySecurityHeaders(notFoundHeaders);
  return new Response("Not Found", { status: 404, headers: notFoundHeaders });
}

/* ---------------- 供安全测试使用 ---------------- */
export {
  isPrivateHost,
  validateUpstreamUrl,
  decodeCbor,
  derToRawEcdsa,
  verifyRegistration,
  verifyAssertion,
  createChallengeToken,
  verifyChallengeToken,
  getSession,
  createSessionCookie,
  rotateSessionId,
  destroySession,
  createCaptcha,
  verifyCaptcha,
  isAllowedOrigin,
  getRpId,
  getExpectedOrigin,
  getSessionSecret,
};
