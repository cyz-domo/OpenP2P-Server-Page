
      let global = globalThis;
      globalThis.global = globalThis;

      if (typeof global.navigator === 'undefined') {
        global.navigator = {
          userAgent: 'edge-runtime',
          language: 'en-US',
          languages: ['en-US'],
        };
      } else {
        if (typeof global.navigator.language === 'undefined') {
          global.navigator.language = 'en-US';
        }
        if (!global.navigator.languages || global.navigator.languages.length === 0) {
          global.navigator.languages = [global.navigator.language];
        }
        if (typeof global.navigator.userAgent === 'undefined') {
          global.navigator.userAgent = 'edge-runtime';
        }
      }

      class MessageChannel {
        constructor() {
          this.port1 = new MessagePort();
          this.port2 = new MessagePort();
        }
      }
      class MessagePort {
        constructor() {
          this.onmessage = null;
        }
        postMessage(data) {
          if (this.onmessage) {
            setTimeout(() => this.onmessage({ data }), 0);
          }
        }
      }
      global.MessageChannel = MessageChannel;

      '__MIDDLEWARE_BUNDLE_CODE__'

      function recreateRequest(request, overrides = {}) {
        const cloned = typeof request.clone === 'function' ? request.clone() : request;
        const headers = new Headers(cloned.headers);

        if (overrides.headerPatches) {
          Object.keys(overrides.headerPatches).forEach((key) => {
            const value = overrides.headerPatches[key];
            if (value === null || typeof value === 'undefined') {
              headers.delete(key);
            } else {
              headers.set(key, value);
            }
          });
        }

        if (overrides.headers) {
          const extraHeaders = new Headers(overrides.headers);
          extraHeaders.forEach((value, key) => headers.set(key, value));
        }

        const url = overrides.url || cloned.url;
        const method = overrides.method || cloned.method || 'GET';
        const canHaveBody = method && method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'HEAD';
        const body = overrides.body !== undefined ? overrides.body : canHaveBody ? cloned.body : undefined;

        // 如果rewrite传入的是完整URL（第三方地址），需要更新host
        if (overrides.url) {
          try {
            const newUrl = new URL(overrides.url, cloned.url);
            // 只有当新URL是绝对路径（包含协议和host）时才更新host
            if (overrides.url.startsWith('http://') || overrides.url.startsWith('https://')) {
              headers.set('host', newUrl.host);
            }
            // 相对路径时保持原有host不变
          } catch (e) {
            // URL解析失败时保持原有host
          }
        }

        const init = {
          method,
          headers,
          redirect: cloned.redirect,
          credentials: cloned.credentials,
          cache: cloned.cache,
          mode: cloned.mode,
          referrer: cloned.referrer,
          referrerPolicy: cloned.referrerPolicy,
          integrity: cloned.integrity,
          keepalive: cloned.keepalive,
          signal: cloned.signal,
        };

        if (canHaveBody && body !== undefined) {
          init.body = body;
        }

        if ('duplex' in cloned) {
          init.duplex = cloned.duplex;
        }

        return new Request(url, init);

      }

      
      async function executeMiddleware(context) {
        return null; // 没有中间件，继续执行后续函数
      }
    

      function usercode(ev, hookCtx) {
        hookCtx = hookCtx || { fetch: globalThis.fetch };
        const { fetch } = hookCtx;
        const globalthis = hookCtx;
        "use strict";
        // ↓ 用户原始代码
        return (async function handleRequest(context) {
          let routeParams = {};
          let pagesFunctionResponse = null;
          let request = context.request;
          const waitUntil = context.waitUntil;
          let urlInfo = new URL(request.url);
          const eo = request.eo || {};


          const normalizePathname = () => {
            if (urlInfo.pathname !== '/' && urlInfo.pathname.endsWith('/')) {
              urlInfo.pathname = urlInfo.pathname.slice(0, -1);
            }
          };

          function getSuffix(pathname = '') {
            // Use a regular expression to extract the file extension from the URL
            const suffix = pathname.match(/\.([^\.]+)$/);
            // If an extension is found, return it, otherwise return an empty string
            return suffix ? '.' + suffix[1] : null;
          }

          normalizePathname();

          let matchedFunc = false;

          
        const runEdgeFunctions = () => {
          
          if(!matchedFunc && /^\/api\/(.+?)$/.test(urlInfo.pathname)) {
            routeParams = {"id":"path","mode":2,"left":"/api/"};
            matchedFunc = true;
            (() => {
  // functions/api/[[path]].js
  var DEFAULT_UPSTREAM = "https://console.openpxp.com";
  var SESSION_COOKIE_NAME = "openp2p_session";
  var SESSION_TTL = 30 * 24 * 3600;
  var DEFAULT_SECRET = "openp2p-edgeone-secret-key-32bytes-min";
  function base64UrlEncode(strOrBuffer) {
    let bytes = typeof strOrBuffer === "string" ? new TextEncoder().encode(strOrBuffer) : new Uint8Array(strOrBuffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
      base64 += "=";
    let binary = atob(base64);
    let bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
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
    if (!signedStr || !signedStr.includes("."))
      return null;
    const [b64Data, b64Sig] = signedStr.split(".");
    try {
      const rawData = base64UrlDecode(b64Data);
      const key = await getHmacKey(secret);
      let sigBase64 = b64Sig.replace(/-/g, "+").replace(/_/g, "/");
      while (sigBase64.length % 4)
        sigBase64 += "=";
      let sigBin = atob(sigBase64);
      let sigBytes = new Uint8Array(sigBin.length);
      for (let i = 0; i < sigBin.length; i++)
        sigBytes[i] = sigBin.charCodeAt(i);
      const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(rawData));
      return valid ? rawData : null;
    } catch {
      return null;
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
  function generateCaptchaSvg(code, theme = "dark") {
    const isLight = theme === "light";
    const bg = isLight ? "#e2ebe6" : "#16241f";
    const noise = isLight ? "#b8c6bf" : "#3a4a44";
    const colors = isLight ? ["#0d9e73", "#b07d1a", "#3d7fb8", "#8a5cb8"] : ["#35d9a4", "#e8b64c", "#7db4e8", "#c98ce8"];
    const W = 120, H = 44;
    let chars = "";
    for (let i = 0; i < code.length; i++) {
      const x = 21 + i * 26;
      const y = 31;
      const color = colors[i % colors.length];
      chars += `<text x="${x}" y="${y}" text-anchor="middle" font-family="Consolas,monospace" font-size="24" font-weight="bold" fill="${color}">${code[i]}</text>`;
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><rect width="${W}" height="${H}" fill="${bg}" rx="6"/><line x1="10" y1="12" x2="110" y2="34" stroke="${noise}" stroke-width="1"/><line x1="10" y1="36" x2="110" y2="10" stroke="${noise}" stroke-width="1"/>${chars}</svg>`;
  }
  function parseCookies(header) {
    const cookies = {};
    if (!header)
      return cookies;
    header.split(";").forEach((part) => {
      const [k, v] = part.trim().split("=");
      if (k && v)
        cookies[k] = decodeURIComponent(v);
    });
    return cookies;
  }
  async function getSession(request, env) {
    const secret = env && env.SESSION_SECRET || DEFAULT_SECRET;
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = parseCookies(cookieHeader);
    const rawCookie = cookies[SESSION_COOKIE_NAME] || request.headers.get("X-Session-Id");
    if (!rawCookie)
      return { accounts: [], activeUser: "", upstream: env && env.UPSTREAM_URL || DEFAULT_UPSTREAM };
    const verified = await verifyData(rawCookie, secret);
    if (!verified)
      return { accounts: [], activeUser: "", upstream: env && env.UPSTREAM_URL || DEFAULT_UPSTREAM };
    try {
      const session = JSON.parse(verified);
      if (!session.upstream)
        session.upstream = env && env.UPSTREAM_URL || DEFAULT_UPSTREAM;
      return session;
    } catch {
      return { accounts: [], activeUser: "", upstream: env && env.UPSTREAM_URL || DEFAULT_UPSTREAM };
    }
  }
  async function createSessionCookie(sessionData, env) {
    const secret = env && env.SESSION_SECRET || DEFAULT_SECRET;
    const signed = await signData(JSON.stringify(sessionData), secret);
    return `${SESSION_COOKIE_NAME}=${encodeURIComponent(signed)}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; SameSite=Lax; Secure`;
  }
  function jsonRsp(data, status = 200, headers = {}) {
    const h = new Headers(headers);
    h.set("Content-Type", "application/json; charset=utf-8");
    h.set("Cache-Control", "no-store, no-cache, must-revalidate");
    h.set("X-Content-Type-Options", "nosniff");
    return new Response(JSON.stringify(data), { status, headers: h });
  }
  async function onRequest(context) {
    const { request, env = {} } = context;
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;
    const panelKey = env.PANEL_KEY || "";
    if (panelKey) {
      const clientKey = request.headers.get("X-Panel-Key");
      if (clientKey !== panelKey) {
        return jsonRsp({ error: 401, detail: "\u672C\u9762\u677F\u5DF2\u542F\u7528\u8BBF\u95EE\u53E3\u4EE4\uFF0C\u9700\u8981\u6B63\u786E\u53E3\u4EE4" }, 401);
      }
    }
    const session = await getSession(request, env);
    const upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;
    if (pathname === "/api/state" && method === "GET") {
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
          active: a.user === user
        }))
      });
    }
    if (pathname === "/api/captcha" && method === "GET") {
      const secret = env.SESSION_SECRET || DEFAULT_SECRET;
      const theme = url.searchParams.get("theme") || "dark";
      const code = Math.floor(1e3 + Math.random() * 9e3).toString();
      const cid = await signData(JSON.stringify({ code, exp: Date.now() + 3e5 }), secret);
      const svg = generateCaptchaSvg(code, theme);
      return jsonRsp({ captcha_id: cid, svg });
    }
    if (pathname === "/api/login" && method === "POST") {
      const secret = env.SESSION_SECRET || DEFAULT_SECRET;
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonRsp({ error: -1, detail: "\u8BF7\u6C42\u683C\u5F0F\u9519\u8BEF" }, 400);
      }
      const { captcha_id, captcha_code, user, password, token } = body;
      if (captcha_id && captcha_code) {
        const verified = await verifyData(captcha_id, secret);
        if (!verified)
          return jsonRsp({ error: -1, detail: "\u9A8C\u8BC1\u7801\u5DF2\u8FC7\u671F\u6216\u65E0\u6548" }, 400);
        try {
          const parsed = JSON.parse(verified);
          if (Date.now() > parsed.exp || parsed.code !== String(captcha_code).trim()) {
            return jsonRsp({ error: -1, detail: "\u9A8C\u8BC1\u7801\u9519\u8BEF\u6216\u5DF2\u5931\u6548" }, 400);
          }
        } catch {
          return jsonRsp({ error: -1, detail: "\u9A8C\u8BC1\u7801\u89E3\u6790\u5931\u8D25" }, 400);
        }
      }
      if (token) {
        const profRsp = await fetch(`${upstream}/api/v1/user/profile`, {
          method: "POST",
          headers: { Authorization: token, "Content-Type": "application/json" },
          body: "{}"
        });
        const profData = await profRsp.json();
        if (profData.error !== 0) {
          return jsonRsp({ error: -1, detail: "Token \u65E0\u6548\u6216\u5DF2\u5931\u6548" }, 401);
        }
        const loginUser = profData.user || jwtUser(token);
        const pool = session.accounts.filter((a) => a.user !== loginUser);
        pool.push({ user: loginUser, token, password: "" });
        session.accounts = pool;
        session.activeUser = loginUser;
        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ error: 0, user: loginUser, token }, 200, { "Set-Cookie": cookie });
      }
      if (user && password) {
        const loginRsp = await fetch(`${upstream}/api/v1/user/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user, password })
        });
        const loginData = await loginRsp.json();
        if (loginData.error === 0 && loginData.token) {
          const loginUser = loginData.user || user;
          const pool = session.accounts.filter((a) => a.user !== loginUser);
          pool.push({ user: loginUser, token: loginData.token, password });
          session.accounts = pool;
          session.activeUser = loginUser;
          const cookie = await createSessionCookie(session, env);
          return jsonRsp({ error: 0, user: loginUser, token: loginData.token }, 200, { "Set-Cookie": cookie });
        }
        return jsonRsp({ error: loginData.error || -1, detail: loginData.detail || "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF" });
      }
      return jsonRsp({ error: -1, detail: "\u7F3A\u5C11\u51ED\u636E" }, 400);
    }
    if (pathname === "/api/logout" && method === "POST") {
      const pool = (session.accounts || []).filter((a) => a.user !== session.activeUser);
      session.accounts = pool;
      session.activeUser = pool.length > 0 ? pool[0].user : "";
      const cookie = await createSessionCookie(session, env);
      return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
    }
    if (pathname === "/api/accounts/switch" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const targetUser = body.user;
      const acc = (session.accounts || []).find((a) => a.user === targetUser);
      if (!acc)
        return jsonRsp({ error: -1, detail: "\u672A\u627E\u5230\u8BE5\u8D26\u6237" }, 404);
      session.activeUser = targetUser;
      const cookie = await createSessionCookie(session, env);
      return jsonRsp({ error: 0, user: targetUser }, 200, { "Set-Cookie": cookie });
    }
    if (pathname === "/api/upstream" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const newUp = (body.upstream || "").trim().replace(/\/+$/, "");
      if (newUp.startsWith("http://") || newUp.startsWith("https://")) {
        session.upstream = newUp;
        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ error: 0, upstream: newUp }, 200, { "Set-Cookie": cookie });
      }
      return jsonRsp({ error: -1, detail: "\u5730\u5740\u5FC5\u987B\u4EE5 http:// \u6216 https:// \u5F00\u5934" }, 400);
    }
    return jsonRsp({ error: -1, detail: "\u672A\u77E5\u63A5\u53E3" }, 404);
  }

        pagesFunctionResponse = onRequest;
      })();
          }
        

          if(!matchedFunc && /^\/pxp\/(.+?)$/.test(urlInfo.pathname)) {
            routeParams = {"id":"path","mode":2,"left":"/pxp/"};
            matchedFunc = true;
            (() => {
  // functions/pxp/[[path]].js
  var DEFAULT_UPSTREAM = "https://console.openpxp.com";
  var SESSION_COOKIE_NAME = "openp2p_session";
  var DEFAULT_SECRET = "openp2p-edgeone-secret-key-32bytes-min";
  function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
      base64 += "=";
    let binary = atob(base64);
    let bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
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
  async function verifyData(signedStr, secret) {
    if (!signedStr || !signedStr.includes("."))
      return null;
    const [b64Data, b64Sig] = signedStr.split(".");
    try {
      const rawData = base64UrlDecode(b64Data);
      const key = await getHmacKey(secret);
      let sigBase64 = b64Sig.replace(/-/g, "+").replace(/_/g, "/");
      while (sigBase64.length % 4)
        sigBase64 += "=";
      let sigBin = atob(sigBase64);
      let sigBytes = new Uint8Array(sigBin.length);
      for (let i = 0; i < sigBin.length; i++)
        sigBytes[i] = sigBin.charCodeAt(i);
      const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(rawData));
      return valid ? rawData : null;
    } catch {
      return null;
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
  function parseCookies(header) {
    const cookies = {};
    if (!header)
      return cookies;
    header.split(";").forEach((part) => {
      const [k, v] = part.trim().split("=");
      if (k && v)
        cookies[k] = decodeURIComponent(v);
    });
    return cookies;
  }
  async function getSession(request, env) {
    const secret = env && env.SESSION_SECRET || DEFAULT_SECRET;
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = parseCookies(cookieHeader);
    const rawCookie = cookies[SESSION_COOKIE_NAME] || request.headers.get("X-Session-Id");
    if (!rawCookie)
      return { accounts: [], activeUser: "", upstream: env && env.UPSTREAM_URL || DEFAULT_UPSTREAM };
    const verified = await verifyData(rawCookie, secret);
    if (!verified)
      return { accounts: [], activeUser: "", upstream: env && env.UPSTREAM_URL || DEFAULT_UPSTREAM };
    try {
      const session = JSON.parse(verified);
      if (!session.upstream)
        session.upstream = env && env.UPSTREAM_URL || DEFAULT_UPSTREAM;
      return session;
    } catch {
      return { accounts: [], activeUser: "", upstream: env && env.UPSTREAM_URL || DEFAULT_UPSTREAM };
    }
  }
  function jsonRsp(data, status = 200) {
    const h = new Headers();
    h.set("Content-Type", "application/json; charset=utf-8");
    h.set("Cache-Control", "no-store, no-cache, must-revalidate");
    return new Response(JSON.stringify(data), { status, headers: h });
  }
  async function onRequest(context) {
    const { request, env = {} } = context;
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;
    const panelKey = env.PANEL_KEY || "";
    if (panelKey) {
      const clientKey = request.headers.get("X-Panel-Key");
      if (clientKey !== panelKey) {
        return jsonRsp({ error: 401, detail: "\u672C\u9762\u677F\u5DF2\u542F\u7528\u8BBF\u95EE\u53E3\u4EE4\uFF0C\u9700\u8981\u6B63\u786E\u53E3\u4EE4" }, 401);
      }
    }
    const session = await getSession(request, env);
    const upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;
    const subPath = pathname.slice(4);
    const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
    let token = acc ? acc.token : "";
    if (acc && acc.password && (!token || jwtExp(token) < Date.now() / 1e3 + 60)) {
      try {
        const r = await fetch(`${upstream}/api/v1/user/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user: acc.user, password: acc.password })
        });
        const d = await r.json();
        if (d.error === 0 && d.token) {
          token = d.token;
          acc.token = token;
        }
      } catch {
      }
    }
    const targetUrl = `${upstream}${subPath}${url.search}`;
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.delete("host");
    fwdHeaders.delete("cookie");
    if (token)
      fwdHeaders.set("Authorization", token);
    try {
      const upstreamRsp = await fetch(targetUrl, {
        method,
        headers: fwdHeaders,
        body: ["GET", "HEAD"].includes(method) ? void 0 : await request.arrayBuffer(),
        redirect: "follow"
      });
      const respHeaders = new Headers(upstreamRsp.headers);
      respHeaders.set("Cache-Control", "no-store");
      return new Response(upstreamRsp.body, {
        status: upstreamRsp.status,
        headers: respHeaders
      });
    } catch (err) {
      return jsonRsp({ error: -2, detail: `Upstream error: ${err.message}` }, 502);
    }
  }

        pagesFunctionResponse = onRequest;
      })();
          }
        
        };
      

          
        const runMiddleware = typeof executeMiddleware !== 'undefined' ? executeMiddleware : async function() { return null; };
        let middlewareResponseHeaders = null; // 保存中间件设置的响应头
        const middlewareResponse = await runMiddleware({
          request,
          urlInfo: new URL(urlInfo.toString()),
          env: {"ProjectId":"makers-bcn5hrlqbodq","NG_CLI_ANALYTICS":"false","NUXT_TELEMETRY_DISABLED":"1","COREPACK_ENABLE_DOWNLOAD_PROMPT":"0","COREPACK_ENABLE_STRICT":"0","YARN_ENABLE_INTERACTIVE":"0","NPM_CONFIG_YES":"true","CI":"true","EDGEONE_PROJECT_ID":"makers-bcn5hrlqbodq","PAGES_PROJECT_ID":"makers-bcn5hrlqbodq"},
          waitUntil,
          hookCtx
        });

        if (middlewareResponse) {
          const headers = middlewareResponse.headers;
          const hasNext = headers && headers.get('x-middleware-next') === '1';
          const rewriteTarget = headers && headers.get('x-middleware-rewrite');
          const requestHeadersOverride = headers && headers.get('x-middleware-request-headers');
          // Next.js 使用 x-middleware-override-headers 传递需要修改的请求头列表
          const overrideHeadersList = headers && headers.get('x-middleware-override-headers');

          if (rewriteTarget) {
            try {
              const rewrittenUrl = rewriteTarget.startsWith('http://') || rewriteTarget.startsWith('https://')
                ? rewriteTarget
                : new URL(rewriteTarget, urlInfo.origin).toString();
              request = recreateRequest(request, { url: rewrittenUrl });
              urlInfo = new URL(rewrittenUrl);
              normalizePathname();
            } catch (rewriteError) {
              console.error('Middleware rewrite error:', rewriteError);
            }
          }

          // 处理 Next.js 的 x-middleware-override-headers 机制
          if (overrideHeadersList) {
            try {
              const overrideKeys = overrideHeadersList.split(',').map(k => k.trim());
              for (const key of overrideKeys) {
                const newValue = headers.get('x-middleware-request-' + key);
                if (newValue !== null) {
                  request.headers.set(key, newValue);
                } else {
                  request.headers.delete(key);
                }
              }
            } catch (overrideError) {
              console.error('Middleware override headers error:', overrideError);
            }
          }
          // 处理旧的 x-middleware-request-headers 机制（兼容）
          else if (requestHeadersOverride) {
            try {
              const decoded = decodeURIComponent(requestHeadersOverride);
              const headerPatch = JSON.parse(decoded);
              Object.keys(headerPatch).forEach((key) => {
                const value = headerPatch[key];
                if (value === null || typeof value === 'undefined') {
                  request.headers.delete(key);
                } else {
                  request.headers.set(key, value);
                }
              });
            } catch (requestPatchError) {
              console.error('Middleware request header override error:', requestPatchError);
            }
          }

          if (!hasNext && !rewriteTarget) {
            return middlewareResponse;
          }

          if (hasNext) {
            middlewareResponseHeaders = new Headers();
            const skipHeaders = new Set([
              'x-middleware-next',
              'x-middleware-rewrite',
              'x-middleware-request-headers',
              'x-middleware-override-headers',
              'x-middleware-set-cookie',
              'date',
              'connection',
              'content-length',
              'content-encoding', // 避免中间件传递的压缩头覆盖到最终响应，破坏流式响应
              'transfer-encoding',
              'set-cookie', // Set-Cookie 需要特殊处理，避免重复
            ]);
            headers.forEach((value, key) => {
              const lowerKey = key.toLowerCase();
              // 过滤内部使用的 header：skipHeaders 中的 + x-middleware-request-* 前缀的请求头修改标记
              if (!skipHeaders.has(lowerKey) && !lowerKey.startsWith('x-middleware-request-')) {
                middlewareResponseHeaders.set(key, value);
              }
            });
            // 特殊处理 Set-Cookie，可能有多个，使用 getSetCookie 获取完整的 cookie 值
            const setCookies = headers.getSetCookie ? headers.getSetCookie() : [];
            setCookies.forEach(cookie => {
              middlewareResponseHeaders.append('Set-Cookie', cookie);
            });
          }
        }
      

          // 走到这里说明：
          // 1. 没有中间件响应（middlewareResponse 为 null/undefined）
          // 2. 或者中间件返回了 next
          // 需要判断是否命中边缘函数

          runEdgeFunctions();

          // 动态路由命中时，检查该路径的 runtime 是否为 edge
          // 如果不是 edge（如 node/file），则跳出边缘函数，走回源逻辑
          if (matchedFunc && routeParams.mode > 0 && hookCtx && hookCtx.getPathRuntime) {
            try {
              const pathRuntime = await hookCtx.getPathRuntime(urlInfo.pathname);
              if (pathRuntime && pathRuntime !== 'edge') {
                matchedFunc = false;
              }
            } catch(e) {
              // getPathRuntime 调用失败时不阻断，继续执行边缘函数
            }
          }

          //没有命中边缘函数，执行回源
          if (!matchedFunc) {
            const originResponse = await fetch(request);

            // 如果中间件设置了响应头，合并到回源响应中
            if (middlewareResponseHeaders) {
              const mergedHeaders = new Headers(originResponse.headers);
              // 删除可能导致问题的编码相关头
              mergedHeaders.delete('content-encoding');
              mergedHeaders.delete('content-length');
              middlewareResponseHeaders.forEach((value, key) => {
                if (key.toLowerCase() === 'set-cookie') {
                  mergedHeaders.append(key, value);
                } else {
                  mergedHeaders.set(key, value);
                }
              });
              return new Response(originResponse.body, {
                status: originResponse.status,
                statusText: originResponse.statusText,
                headers: mergedHeaders,
              });
            }

            return originResponse;
          }

          // 命中了边缘函数，继续执行边缘函数逻辑

          const params = {};
          if (routeParams.id) {
            if (routeParams.mode === 1) {
              const value = urlInfo.pathname.match(routeParams.left);
              for (let i = 1; i < value.length; i++) {
                params[routeParams.id[i - 1]] = value[i];
              }
            } else {
              const value = urlInfo.pathname.replace(routeParams.left, '');
              const splitedValue = value.split('/');
              if (splitedValue.length === 1) {
                params[routeParams.id] = splitedValue[0];
              } else {
                params[routeParams.id] = splitedValue;
              }
            }

          }
          const edgeFunctionResponse = await pagesFunctionResponse({request, params, env: {"ProjectId":"makers-bcn5hrlqbodq","NG_CLI_ANALYTICS":"false","NUXT_TELEMETRY_DISABLED":"1","COREPACK_ENABLE_DOWNLOAD_PROMPT":"0","COREPACK_ENABLE_STRICT":"0","YARN_ENABLE_INTERACTIVE":"0","NPM_CONFIG_YES":"true","CI":"true","EDGEONE_PROJECT_ID":"makers-bcn5hrlqbodq","PAGES_PROJECT_ID":"makers-bcn5hrlqbodq"}, waitUntil, eo });

          // 如果中间件设置了响应头，合并到边缘函数响应中
          if (middlewareResponseHeaders && edgeFunctionResponse) {
            const mergedHeaders = new Headers(edgeFunctionResponse.headers);
            // 删除可能导致问题的编码相关头
            mergedHeaders.delete('content-encoding');
            mergedHeaders.delete('content-length');
            middlewareResponseHeaders.forEach((value, key) => {
              if (key.toLowerCase() === 'set-cookie') {
                mergedHeaders.append(key, value);
              } else {
                mergedHeaders.set(key, value);
              }
            });
            return new Response(edgeFunctionResponse.body, {
              status: edgeFunctionResponse.status,
              statusText: edgeFunctionResponse.statusText,
              headers: mergedHeaders,
            });
          }

          return edgeFunctionResponse;
        })({request: ev.request, params: {}, env: {"ProjectId":"makers-bcn5hrlqbodq","NG_CLI_ANALYTICS":"false","NUXT_TELEMETRY_DISABLED":"1","COREPACK_ENABLE_DOWNLOAD_PROMPT":"0","COREPACK_ENABLE_STRICT":"0","YARN_ENABLE_INTERACTIVE":"0","NPM_CONFIG_YES":"true","CI":"true","EDGEONE_PROJECT_ID":"makers-bcn5hrlqbodq","PAGES_PROJECT_ID":"makers-bcn5hrlqbodq"}, waitUntil: ev.waitUntil.bind(ev) });
        // ↑ 用户原始代码结束
      }

      addEventListener('fetch', (event, hookCtx) => {
        const res = usercode(event, hookCtx);
        event.respondWith(res);
      });