/* OpenP2P 管理面板前端 — 原生 JS，无构建步骤 */
"use strict";

const $ = (id) => document.getElementById(id);
const API = "/api/pxp"; // 反向代理前缀 (统一走 /api/ 路由以适配 Vercel/Edge/Server)

/* ---------------- 状态 ---------------- */
const tunnelSort = { key: "state", dir: 1 }; // 隧道表排序（默认按连接状态，已连接在前）
let tlSub = "pf"; // 隧道子视图：pf=端口转发 sd=虚拟组网
const state = {
  devices: [],
  latestVer: "",
  sdwan: null,
  tunnelByNode: {},   // node -> Apps[]
  memApps: [],        // 当前查看成员的组网隧道明细
  profile: null,      // 含 installToken
  user: "",
  upstream: "https://console.openpxp.com",
  accounts: [],       // 多账户列表（服务端 /api/state）
  memByNode: {},      // node -> MemApps[]（subtype=17 成员级组网隧道状态）
  ruleCtxNode: "",    // 新建规则的上下文设备（从设备卡/组网成员跳转时记录）
  disabledApps: new Set(), // 本会话内停用过的规则 key（设备停用后上报不再带 enabled 字段）
  selView: "devices",
};

/* ---------------- 基础工具 ---------------- */
function toast(msg, type = "") {
  const el = $("toast");
  el.textContent = msg;
  el.className = type;
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), type === "err" ? 6000 : 3000);
}

function panelHeaders(extra = {}) {
  const h = { ...extra };
  const key = localStorage.getItem("panelKey");
  if (key) h["X-Panel-Key"] = key;
  const sid = localStorage.getItem("panelSession");
  if (sid) h["X-Session-Id"] = sid;
  return h;
}

async function pxp(path, opts = {}) {
  const headers = opts.body ? { "Content-Type": "application/json" } : {};
  const key = localStorage.getItem("panelKey");
  if (key) headers["X-Panel-Key"] = key;
  const sid = localStorage.getItem("panelSession");
  if (sid) headers["X-Session-Id"] = sid;
  const rsp = await fetch(API + path, {
    method: opts.method || "GET",
    headers,
    credentials: "same-origin",
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await rsp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (rsp.status === 401) {
    if (data && data.detail && data.detail.includes("口令")) {
      const key2 = prompt("本面板已启用访问口令，请输入：");
      if (key2) {
        localStorage.setItem("panelKey", key2);
        location.reload();
      }
    } else {
      localStorage.removeItem("panelSession");
      location.reload();
    }
  }
  return { status: rsp.status, data };
}

/** push 指令：默认 rsp=0（不阻塞等待回执），随后由调用方轮询确认 */
function pushCmd(node, subtype, body, rsp = 0) {
  const q = `subtype=${subtype}&rsp=${rsp}&edgeserver=`;
  return pxp(`/api/v1/device/${encodeURIComponent(node)}/push?${q}`, { method: "POST", body: body || {} });
}

function fmtTime(s) { return s ? String(s).replace("T", " ").slice(0, 19) : "-"; }
function onlineDev(d) { return d.isActive === 1; }
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/** IP 等可复制值：文本 + 小复制按钮 */
function copyBtn(value, cls = "") {
  const v = String(value ?? "").trim();
  if (!v || v === "-") return `<span class="muted">-</span>`;
  return `<span class="copyable ${cls}"><span class="copy-text">${esc(v)}</span>` +
    `<button class="copy-mini" data-copy-text="${esc(v)}" title="复制">⧉</button></span>`;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`已复制 ${text}`, "ok");
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast(`已复制 ${text}`, "ok");
  }
}

function confirmDlg(title, msg) {
  return new Promise((resolve) => {
    $("cfTitle").textContent = title;
    $("cfMsg").textContent = msg;
    const dlg = $("confirmDialog");
    dlg.onclose = () => resolve(dlg.returnValue === "ok");
    dlg.showModal();
  });
}

/* ================= SearchSelect 可搜索下拉组件 ================= */
class SearchSelect {
  constructor(selectEl, options = {}) {
    this.selectEl = typeof selectEl === "string" ? document.getElementById(selectEl) : selectEl;
    if (!this.selectEl) return;
    this.options = options;
    this.items = []; // [{ value, label, subtext, online, disabled }]
    this.filteredItems = [];
    this.value = this.selectEl.value || "";
    this.disabled = !!this.selectEl.disabled;
    this.isOpen = false;
    this.highlightIndex = -1;
    this.placeholder = options.placeholder || "请选择…";
    this.searchPlaceholder = options.searchPlaceholder || "输入关键字检索…";

    this._initDom();
    this._bindEvents();
    this.selectEl._searchSelect = this;
  }

  _initDom() {
    this.selectEl.classList.add("search-select-native-hidden");
    this.container = document.createElement("div");
    this.container.className = "search-select";
    if (this.options.className) this.container.classList.add(this.options.className);

    // 触发按钮
    this.trigger = document.createElement("button");
    this.trigger.type = "button";
    this.trigger.className = "search-select-trigger";
    this.trigger.setAttribute("aria-haspopup", "listbox");
    this.trigger.setAttribute("aria-expanded", "false");
    if (this.disabled) this.trigger.disabled = true;

    this.triggerContent = document.createElement("span");
    this.triggerContent.className = "search-select-trigger-content";
    this.triggerContent.textContent = this.placeholder;

    const arrow = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    arrow.setAttribute("viewBox", "0 0 24 24");
    arrow.setAttribute("width", "14");
    arrow.setAttribute("height", "14");
    arrow.setAttribute("fill", "none");
    arrow.setAttribute("stroke", "currentColor");
    arrow.setAttribute("stroke-width", "2");
    arrow.classList.add("search-select-arrow");
    const polyline = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    polyline.setAttribute("points", "6 9 12 15 18 9");
    arrow.appendChild(polyline);

    this.trigger.appendChild(this.triggerContent);
    this.trigger.appendChild(arrow);
    this.container.appendChild(this.trigger);

    // 下拉浮层
    this.dropdown = document.createElement("div");
    this.dropdown.className = "search-select-dropdown";

    // 搜索栏
    this.searchBox = document.createElement("div");
    this.searchBox.className = "search-select-search";

    const sIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    sIcon.setAttribute("viewBox", "0 0 24 24");
    sIcon.setAttribute("width", "13");
    sIcon.setAttribute("height", "13");
    sIcon.setAttribute("fill", "none");
    sIcon.setAttribute("stroke", "currentColor");
    sIcon.setAttribute("stroke-width", "2");
    const sCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    sCircle.setAttribute("cx", "11");
    sCircle.setAttribute("cy", "11");
    sCircle.setAttribute("r", "8");
    const sLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
    sLine.setAttribute("x1", "21");
    sLine.setAttribute("y1", "21");
    sLine.setAttribute("x2", "16.65");
    sLine.setAttribute("y2", "16.65");
    sIcon.appendChild(sCircle);
    sIcon.appendChild(sLine);

    this.searchInput = document.createElement("input");
    this.searchInput.type = "text";
    this.searchInput.className = "search-select-input";
    this.searchInput.placeholder = this.searchPlaceholder;
    this.searchInput.autocomplete = "off";

    this.clearBtn = document.createElement("button");
    this.clearBtn.type = "button";
    this.clearBtn.className = "search-select-clear-btn";
    this.clearBtn.title = "清空检索";
    this.clearBtn.style.display = "none";
    this.clearBtn.innerHTML = `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;

    this.searchBox.appendChild(sIcon);
    this.searchBox.appendChild(this.searchInput);
    this.searchBox.appendChild(this.clearBtn);
    this.dropdown.appendChild(this.searchBox);

    // 选项列表
    this.optionsList = document.createElement("div");
    this.optionsList.className = "search-select-options";
    this.optionsList.setAttribute("role", "listbox");
    this.dropdown.appendChild(this.optionsList);

    this.container.appendChild(this.dropdown);
    this.selectEl.parentNode.insertBefore(this.container, this.selectEl.nextSibling);
  }

  _bindEvents() {
    this.trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      if (this.disabled) return;
      this.toggle();
    });

    this.searchInput.addEventListener("input", () => {
      const q = this.searchInput.value.trim().toLowerCase();
      this.clearBtn.style.display = q ? "flex" : "none";
      this.filter(q);
    });

    this.clearBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      this.searchInput.value = "";
      this.clearBtn.style.display = "none";
      this.filter("");
      this.searchInput.focus();
    });

    this.searchInput.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        this._moveHighlight(1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        this._moveHighlight(-1);
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (this.highlightIndex >= 0 && this.highlightIndex < this.filteredItems.length) {
          const it = this.filteredItems[this.highlightIndex];
          if (!it.disabled) this.selectItem(it.value);
        }
      } else if (e.key === "Escape") {
        this.close();
      }
    });

    document.addEventListener("click", (e) => {
      if (!this.container.contains(e.target)) {
        this.close();
      }
    });
  }

  toggle() {
    if (this.isOpen) this.close();
    else this.open();
  }

  open() {
    document.querySelectorAll(".search-select.open").forEach((el) => {
      if (el !== this.container) el.classList.remove("open");
    });
    this.isOpen = true;
    this.container.classList.add("open");
    this.trigger.setAttribute("aria-expanded", "true");
    this.searchInput.value = "";
    this.clearBtn.style.display = "none";
    this.filter("");
    setTimeout(() => this.searchInput.focus(), 50);
  }

  close() {
    this.isOpen = false;
    this.container.classList.remove("open");
    this.trigger.setAttribute("aria-expanded", "false");
    this.highlightIndex = -1;
  }

  setDisabled(disabled) {
    this.disabled = !!disabled;
    this.trigger.disabled = this.disabled;
    this.selectEl.disabled = this.disabled;
    if (this.disabled && this.isOpen) this.close();
  }

  setOptions(items) {
    this.items = items.map((it) => {
      if (typeof it === "string") {
        return { value: it, label: it, subtext: "", online: undefined, disabled: false };
      }
      return {
        value: it.value !== undefined ? String(it.value) : "",
        label: it.label || it.value || "",
        subtext: it.subtext || "",
        online: it.online,
        disabled: !!it.disabled
      };
    });

    // 同步到原生 <select>
    this.selectEl.innerHTML = this.items.map((it) =>
      `<option value="${esc(it.value)}"${it.disabled ? ' disabled' : ''}>${esc(it.label)}</option>`
    ).join("");

    this.filter("");
    this._updateTrigger();
  }

  filter(keyword) {
    const q = (keyword || "").trim().toLowerCase();
    if (!q) {
      this.filteredItems = [...this.items];
    } else {
      this.filteredItems = this.items.filter((it) =>
        (it.label && it.label.toLowerCase().includes(q)) ||
        (it.value && it.value.toLowerCase().includes(q)) ||
        (it.subtext && it.subtext.toLowerCase().includes(q))
      );
    }
    this.highlightIndex = -1;
    this._renderOptions();
  }

  _renderOptions() {
    this.optionsList.innerHTML = "";
    if (!this.filteredItems.length) {
      const empty = document.createElement("div");
      empty.className = "search-select-empty";
      empty.textContent = this.options.emptyText || "未找到匹配设备";
      this.optionsList.appendChild(empty);
      return;
    }

    this.filteredItems.forEach((it, idx) => {
      const opt = document.createElement("div");
      opt.className = "search-select-opt";
      if (String(it.value) === String(this.value)) opt.classList.add("selected");
      if (it.disabled) opt.classList.add("disabled");
      if (idx === this.highlightIndex) opt.classList.add("focused");

      const left = document.createElement("div");
      left.className = "search-select-opt-left";

      if (it.online !== undefined) {
        const dot = document.createElement("span");
        dot.className = `dot ${it.online ? "on" : "off"}`;
        dot.style.marginRight = "6px";
        left.appendChild(dot);
      }

      const labelSpan = document.createElement("span");
      labelSpan.className = "search-select-opt-label";
      labelSpan.textContent = it.label;
      left.appendChild(labelSpan);

      opt.appendChild(left);

      if (it.subtext) {
        const sub = document.createElement("span");
        sub.className = "search-select-opt-sub";
        sub.textContent = it.subtext;
        opt.appendChild(sub);
      }

      opt.addEventListener("click", (e) => {
        e.stopPropagation();
        if (it.disabled) return;
        this.selectItem(it.value);
      });

      this.optionsList.appendChild(opt);
    });
  }

  _moveHighlight(delta) {
    if (!this.filteredItems.length) return;
    this.highlightIndex = Math.max(0, Math.min(this.filteredItems.length - 1, this.highlightIndex + delta));
    this._renderOptions();
    const focusedEl = this.optionsList.children[this.highlightIndex];
    if (focusedEl) focusedEl.scrollIntoView({ block: "nearest" });
  }

  selectItem(val, triggerChange = true) {
    this.value = String(val);
    this.selectEl.value = this.value;
    this._updateTrigger();
    this.close();
    if (triggerChange) {
      this.selectEl.dispatchEvent(new Event("change", { bubbles: true }));
      if (typeof this.options.onChange === "function") {
        const cur = this.items.find((x) => String(x.value) === String(this.value));
        this.options.onChange(this.value, cur);
      }
    }
  }

  setValue(val, triggerChange = false) {
    this.value = val !== undefined && val !== null ? String(val) : "";
    this.selectEl.value = this.value;
    this._updateTrigger();
    if (triggerChange) {
      this.selectEl.dispatchEvent(new Event("change", { bubbles: true }));
      if (typeof this.options.onChange === "function") {
        const cur = this.items.find((x) => String(x.value) === String(this.value));
        this.options.onChange(this.value, cur);
      }
    }
  }

  getValue() {
    return this.value;
  }

  _updateTrigger() {
    const cur = this.items.find((it) => String(it.value) === String(this.value));
    this.triggerContent.innerHTML = "";
    if (cur) {
      if (cur.online !== undefined) {
        const dot = document.createElement("span");
        dot.className = `dot ${cur.online ? "on" : "off"}`;
        dot.style.marginRight = "6px";
        this.triggerContent.appendChild(dot);
      }
      const textNode = document.createElement("span");
      textNode.className = "search-select-trigger-text";
      textNode.textContent = cur.label;
      this.triggerContent.appendChild(textNode);
    } else {
      const ph = document.createElement("span");
      ph.className = "muted";
      ph.textContent = this.placeholder;
      this.triggerContent.appendChild(ph);
    }
  }
}

/** 限制最大并发数的 Promise 批处理执行器，防止突发流量冲击源站连接池 */
async function runBatchLimit(taskFns, limit = 4) {
  const results = new Array(taskFns.length);
  const executing = [];
  for (let i = 0; i < taskFns.length; i++) {
    const fn = taskFns[i];
    const p = Promise.resolve().then(() => fn())
      .then((val) => { results[i] = { status: "fulfilled", value: val }; })
      .catch((err) => { results[i] = { status: "rejected", reason: err }; });
    executing.push(p);
    const clean = () => {
      const idx = executing.indexOf(p);
      if (idx !== -1) executing.splice(idx, 1);
    };
    p.then(clean, clean);
    if (executing.length >= limit) {
      await Promise.race(executing);
    }
  }
  await Promise.all(executing);
  return results;
}

let tlNodeFilterSS, ruNodeSS, ruPeerSS, netCentralSS, memSelSS;

function initSearchSelects() {
  if ($("tlNodeFilter") && !tlNodeFilterSS) {
    tlNodeFilterSS = new SearchSelect($("tlNodeFilter"), {
      placeholder: "全部设备",
      searchPlaceholder: "检索设备以筛选…",
      onChange: () => renderTunnels()
    });
  }
  if ($("ruNode") && !ruNodeSS) {
    ruNodeSS = new SearchSelect($("ruNode"), {
      placeholder: "请选择所在设备…",
      searchPlaceholder: "检索设备名 / IP / 系统…"
    });
  }
  if ($("ruPeer") && !ruPeerSS) {
    ruPeerSS = new SearchSelect($("ruPeer"), {
      placeholder: "请选择对端设备…",
      searchPlaceholder: "检索设备名 / IP / 系统…"
    });
  }
  if ($("netCentral") && !netCentralSS) {
    netCentralSS = new SearchSelect($("netCentral"), {
      placeholder: "不指定 (自动选路)",
      searchPlaceholder: "检索中心节点…"
    });
  }
  if ($("memSel") && !memSelSS) {
    memSelSS = new SearchSelect($("memSel"), {
      placeholder: "选择网络成员…",
      searchPlaceholder: "检索成员节点…"
    });
  }
}

/* ---------------- 登录 / 会话 ---------------- */
async function checkState() {
  try {
    const rsp = await fetch("/api/state", { headers: panelHeaders(), credentials: "same-origin" });
    if (rsp.status === 401) {
      const key2 = prompt("本面板已启用访问口令，请输入：");
      if (key2) {
        localStorage.setItem("panelKey", key2);
        location.reload();
      }
      return false;
    }
    const st = await rsp.json();
    state.accounts = st.accounts || [];
    state.upstream = st.upstream || "https://console.openpxp.com";
    if ($("loginUpstream")) $("loginUpstream").value = state.upstream;
    if ($("setCurUpstream")) $("setCurUpstream").value = state.upstream;
    if (st.hasToken && (!st.tokenExp || st.tokenExp * 1000 > Date.now())) {
      state.user = st.user;
      return true;
    }
  } catch (e) { /* server down */ }
  return false;
}

/* ---------------- 登录页：双模式 + 验证码 + 上游地址 ---------------- */
let loginMode = "password";
let captchaId = "";

document.querySelectorAll("[data-upstream]").forEach((btn) => {
  btn.addEventListener("click", () => {
    if ($("loginUpstream")) $("loginUpstream").value = btn.dataset.upstream;
  });
});

async function reloadCaptcha() {
  try {
    const headers = panelHeaders({ "Content-Type": "application/json", "X-Panel-Theme": document.documentElement.dataset.theme || "dark" });
    const rsp = await fetch(`/api/captcha?_t=${Date.now()}`, { method: "POST", headers, credentials: "same-origin", cache: "no-store" });
    const data = await rsp.json();
    captchaId = data.captchaId || data.captcha_id || "";
    let svgSrc = data.svg || "";
    if (svgSrc && !svgSrc.startsWith("data:") && svgSrc.startsWith("<svg")) {
      svgSrc = "data:image/svg+xml;utf8," + encodeURIComponent(svgSrc);
    }
    if ($("captchaImg")) $("captchaImg").src = svgSrc;
    if ($("loginCaptcha")) $("loginCaptcha").value = "";
  } catch (e) {
    if ($("captchaImg")) $("captchaImg").alt = "验证码加载失败";
  }
}

document.querySelectorAll(".seg-btn").forEach((btn) =>
  btn.addEventListener("click", () => {
    loginMode = btn.dataset.mode;
    document.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
    $("modePassword").classList.toggle("hidden", loginMode !== "password");
    $("modeToken").classList.toggle("hidden", loginMode !== "token");
    $("loginErr").classList.add("hidden");
    reloadCaptcha();
  })
);

if ($("captchaWrap")) $("captchaWrap").addEventListener("click", reloadCaptcha);
if ($("captchaImg")) $("captchaImg").addEventListener("click", reloadCaptcha);

$("loginForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("loginErr").classList.add("hidden");
  const captcha = $("loginCaptcha").value.trim();
  if (!captcha) {
    $("loginErr").textContent = "请输入验证码";
    $("loginErr").classList.remove("hidden");
    return;
  }
  const headers = panelHeaders({ "Content-Type": "application/json" });
  const url = loginMode === "password" ? "/api/login" : "/api/login-token";
  const upstream = $("loginUpstream") ? $("loginUpstream").value.trim() : "";
  const body = loginMode === "password"
    ? {
        user: $("loginUser").value.trim(),
        password: $("loginPass").value,
        remember: $("loginRemember").checked,
        captchaId,
        captcha,
        upstream,
      }
    : { token: $("loginToken").value.trim(), captchaId, captcha, upstream };
  if (loginMode === "password" && (!$("loginUser").value.trim() || !$("loginPass").value)) {
    $("loginErr").textContent = "请输入用户名和密码";
    $("loginErr").classList.remove("hidden");
    return;
  }
  if (loginMode === "token" && !$("loginToken").value.trim()) {
    $("loginErr").textContent = "请粘贴官方控制台的 token";
    $("loginErr").classList.remove("hidden");
    return;
  }
  const rsp = await fetch(url, { method: "POST", headers, credentials: "same-origin", body: JSON.stringify(body) });
  const data = await rsp.json();
  if (data.error === 0) {
    if (data.sessionId) localStorage.setItem("panelSession", data.sessionId);
    state.user = data.user || (loginMode === "password" ? $("loginUser").value.trim() : "");
    // 登录成功后刷新账户列表（新账户已入池）
    try {
      const st = await (await fetch("/api/state", { headers: panelHeaders(), credentials: "same-origin" })).json();
      state.accounts = st.accounts || [];
    } catch {}
    enterMain();
  } else {
    $("loginErr").textContent = "登录失败: " + (data.detail || data.error);
    $("loginErr").classList.remove("hidden");
    reloadCaptcha(); // 验证码单次有效，失败后必须换新的
  }
});

$("btnLogout").addEventListener("click", async () => {
  localStorage.removeItem("panelSession");
  await fetch("/api/logout", { method: "POST", headers: panelHeaders(), credentials: "same-origin" });
  location.reload();
});

async function enterMain() {
  $("loginView").classList.add("hidden");
  $("mainView").classList.remove("hidden");
  if ($("topBar")) $("topBar").classList.remove("hidden");
  $("connState").textContent = "已连接";
  $("connState").className = "badge on";
  $("userInfo").textContent = state.user || "";
  renderAcctMenu(state.accounts || []);
  await refreshAll();
}

/* ---------------- 多账户切换 ---------------- */
function renderAcctMenu(accounts) {
  const menu = $("acctMenu");
  if (!accounts.length) {
    menu.innerHTML = `<div class="acct-empty">尚无账户</div>`;
    return;
  }
  menu.innerHTML = accounts.map((a) => {
    const exp = a.tokenExp ? new Date(a.tokenExp * 1000).toLocaleDateString() : "无凭据";
    return `<button class="acct-item ${a.active ? "current" : ""}" data-user="${esc(a.user)}" data-active="${a.active ? 1 : 0}">
      <span class="name">${esc(a.user)}</span>
      <span class="meta">${a.hasToken ? "有效期至 " + exp : "未登录"}${a.hasPassword ? " · 密码✓" : ""}</span>
      ${a.active ? "" : '<span class="rm" data-rm="' + esc(a.user) + '" title="移除该账户">✕</span>'}
    </button>`;
  }).join("") + `<div class="acct-sep"></div><button class="acct-add" data-add="1">＋ 添加账户</button>`;
}

$("btnAcct").addEventListener("click", async () => {
  const menu = $("acctMenu");
  if (menu.classList.contains("hidden")) {
    const st = await (await fetch("/api/state", { headers: panelHeaders() })).json();
    state.accounts = st.accounts || [];
    renderAcctMenu(state.accounts);
    menu.classList.remove("hidden");
  } else {
    menu.classList.add("hidden");
  }
});

document.addEventListener("click", async (ev) => {
  const menu = $("acctMenu");
  if (!menu || menu.classList.contains("hidden")) return;
  // 点在菜单外则收起（菜单内部动作自行处理后再收起）
  const rm = ev.target.closest(".rm[data-rm]");
  if (rm) {
    ev.stopPropagation();
    const user = rm.dataset.rm;
    if (!(await confirmDlg("移除账户", `将从面板移除账户「${user}」的本地凭据（不影响官方账号本身）。继续？`))) return;
    const rsp = await pxp2("/api/accounts/remove", { user });
    if (rsp.error === 0) {
      toast(`已移除 ${user}`);
      menu.classList.add("hidden");
      const st = await (await fetch("/api/state", { headers: panelHeaders() })).json();
      if (st.hasToken) {
        state.user = st.user;
        $("userInfo").textContent = st.user;
        await refreshAll();
      } else {
        location.reload();
      }
    } else {
      toast(rsp.detail || "移除失败", "err");
    }
    return;
  }
  const add = ev.target.closest(".acct-add");
  if (add) {
    menu.classList.add("hidden");
    $("topBar").classList.add("hidden");
    $("mainView").classList.add("hidden");
    $("loginView").classList.remove("hidden");
    $("linkCancelLogin").classList.remove("hidden");
    $("loginErr").classList.add("hidden");
    await reloadCaptcha();
    return;
  }
  const item = ev.target.closest(".acct-item[data-user]");
  if (item && item.dataset.active !== "1") {
    const rsp = await pxp2("/api/accounts/switch", { user: item.dataset.user });
    if (rsp.error === 0) {
      menu.classList.add("hidden");
      toast(`已切换到 ${rsp.user}`, "ok");
      state.user = rsp.user;
      $("userInfo").textContent = rsp.user;
      await refreshAll();
    } else {
      toast(rsp.detail || "切换失败", "err");
    }
    return;
  }
  // 点击菜单空白处不关闭
  if (ev.target.closest(".acct-menu")) return;
  if (!ev.target.closest(".acct-wrap")) menu.classList.add("hidden");
});

async function pxp2(path, body) {
  const rsp = await fetch(path, {
    method: "POST",
    headers: panelHeaders({ "Content-Type": "application/json" }),
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  return rsp.json();
}

/* ---------------- 数据加载 ---------------- */
let _refreshing = false; // 防并发：refreshAll 重入会交错重绘 DOM 导致 null 引用
let _lastRefreshAllTs = 0;

async function refreshAll(force = false) {
  if (_refreshing) return;
  const now = Date.now();
  if (!force && now - _lastRefreshAllTs < 1500) return;
  _lastRefreshAllTs = now;
  _refreshing = true;
  try {
    const [devs, sdw, prof] = await Promise.all([
      pxp("/api/v1/devices"),
      pxp("/api/v1/sdwans/"),
      pxp("/api/v1/user/profile", { method: "POST", body: {} }),
    ]);
    if (devs.status === 200 && devs.data.nodes) {
      state.devices = devs.data.nodes;
      state.latestVer = devs.data.latestVer || "";
    } else {
      toast("设备列表拉取失败: " + JSON.stringify(devs.data).slice(0, 120), "err");
    }
    state.sdwan = sdw.status === 200 && sdw.data.Nodes ? sdw.data : null;
    if (prof.status === 200 && prof.data.profile) state.profile = prof.data.profile;
    renderDevices();
    renderNetwork();
    renderDownload();

    // 优化：按需加载。在非隧道/网络页时避免向所有在线节点突发下发推送指令
    if (state.selView === "tunnels" || state.selView === "networks" || force) {
      await refreshTunnels(true);
    }
  } catch (e) {
    console.error("[refreshAll]", e);
    toast("网络错误: " + e, "err");
  } finally {
    _refreshing = false;
  }
}

/** 并发受限拉取所有在线设备的规则列表（最大并发3，配合 15s SWR 缓存大幅减负源站）。
 *  端口转发来自 subtype=7（本机发起的隧道应用）；
 *  组网隧道全拓扑来自 subtype=17（成员视角，含未活跃对端）——两者合并去重，并同步填充成员状态缓存。 */
let _refreshingTunnels = false;
let _lastRefreshTunnelsTs = 0;
let _tunnelsCacheTs = 0;

async function refreshTunnels(quiet = false, force = false) {
  const now = Date.now();
  // 15s SWR 快照：若未强制刷新且已有数据在 15s 内，直接复用内存渲染，0ms 响应不向源站发包
  if (!force && Object.keys(state.tunnelByNode || {}).length > 0 && (now - _tunnelsCacheTs < 15000)) {
    renderTunnels();
    if (state.selView === "networks") renderNetwork();
    return;
  }
  if (_refreshingTunnels) return;
  if (now - _lastRefreshTunnelsTs < 1500 && quiet) return;
  _lastRefreshTunnelsTs = now;
  _refreshingTunnels = true;

  try {
    const online = state.devices.filter(onlineDev);
    if (!online.length) {
      state.tunnelByNode = {};
      _tunnelsCacheTs = now;
      renderTunnels();
      return;
    }
    if (!quiet) toast(`正在拉取 ${online.length} 台在线设备的规则…`);

    // 限制同时最多 3 个长轮询连接，大幅降低源站并发突发压力
    const [r7, r17] = await Promise.all([
      runBatchLimit(online.map((d) => () => pushCmd(d.name, 7, {}, 1)), 3),
      runBatchLimit(online.map((d) => () => pushCmd(d.name, 17, {}, 1)), 3),
    ]);

    const map = {};
    for (const d of state.devices) map[d.name] = map[d.name] || [];
    const put = (i, arr) => { map[online[i].name] = arr; };
    const get = (resArr, i) => (resArr[i] && resArr[i].status === "fulfilled"
      && resArr[i].value.status === 200 && Array.isArray(resArr[i].value.data.Apps))
      ? resArr[i].value.data.Apps : null;

    for (let i = 0; i < online.length; i++) {
      const apps = get(r7, i);
      if (apps) put(i, apps.filter((a) => a.srcPort));
    }

    for (let i = 0; i < online.length; i++) {
      const mem = get(r17, i);
      if (!mem) continue;
      state.memByNode[online[i].name] = mem;
      const existing = new Set(map[online[i].name].map((a) => a.peerNode + "|" + (a.appName || "")));
      for (const a of mem) {
        const k = a.peerNode + "|" + (a.appName || "");
        if (!existing.has(k)) map[online[i].name].push(a);
      }
    }

    state.tunnelByNode = map;
    _tunnelsCacheTs = Date.now();
    renderTunnels();
    if (state.selView === "networks") renderNetwork();
    if (!quiet) toast("规则已刷新", "ok");
  } catch (err) {
    console.error("[refreshTunnels]", err);
  } finally {
    _refreshingTunnels = false;
  }
}

function renderOsTag(osStr, devName) {
  const os = String(osStr || "").toLowerCase();
  const name = String(devName || "").toLowerCase();
  const combo = `${os} ${name}`;
  let cls = "";
  let iconSvg = "";

  // 1. Docker
  if (combo.includes("docker")) {
    cls = "docker";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.186.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.186.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.186.186.186m5.893 2.715h2.118a.186.186 0 00.186-.186V9.006a.186.186 0 00-.186-.186h-2.118a.186.186 0 00-.186.185v1.888c0 .102.082.185.186.185m-2.929 0h2.12a.185.185 0 00.184-.186V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.186V9.006a.185.185 0 00-.185-.186H5.136a.186.186 0 00-.186.185v1.888c0 .102.084.185.186.185m-2.928 0h2.119a.185.185 0 00.185-.186V9.006a.185.185 0 00-.185-.186H2.208a.186.186 0 00-.186.185v1.888c0 .102.084.185.186.185m21.644 1.458a7.876 7.876 0 00-4.041-3.666c-.309-.138-.636-.217-.968-.236l-.328-.014-.23.238c-.808.835-1.895 1.34-3.056 1.422H.857a.857.857 0 00-.857.858c0 2.21.677 4.34 1.947 6.134 1.765 2.494 4.544 4.024 7.545 4.156 5.86.257 11.233-3.153 13.565-8.318.368-.815.65-1.675.836-2.559.043-.2.062-.32.062-.32s-.044.17-.099.29z"/></svg>`;
  }
  // 2. Android
  else if (os.includes("android")) {
    cls = "android";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-1.0007s.4482-1.0007.9993-1.0007c.5511 0 .9993.4486.9993 1.0007s-.4482 1.0007-.9993 1.0007m-11.046 0c-.5511 0-.9993-.4486-.9993-1.0007s.4482-1.0007.9993-1.0007c.5511 0 .9993.4486.9993 1.0007s-.4482 1.0007-.9993 1.0007m11.4045-6.02l1.9973-3.4592a.416.416 0 00-.1521-.5676.416.416 0 00-.5676.1521l-2.0223 3.503C15.5902 8.356 13.8533 8 12 8s-3.5902.356-5.1367.9497L4.841 5.4467a.4161.4161 0 00-.5677-.1521.4157.4157 0 00-.1521.5676l1.9973 3.4592C2.6889 11.1867.3432 14.6589 0 18.761h24c-.3432-4.1021-2.6889-7.5743-6.1185-9.4396"/></svg>`;
  }
  // 3. Apple / macOS / iOS
  else if (os.includes("darwin") || os.includes("mac") || os.includes("apple") || os.includes("ios")) {
    cls = "mac";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.61-.75 1.04-1.8 0.92-2.87-.9.04-2.02.6-2.66 1.34-.56.65-1.06 1.7-0.93 2.73.99.08 2.04-.45 2.67-1.2z"/></svg>`;
  }
  // 4. Windows
  else if (os.includes("windows") || os.includes("win")) {
    cls = "win";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.901-1.799"/></svg>`;
  }
  // 5. Synology / NAS / 存储
  else if (os.includes("synology") || os.includes("dsm") || os.includes("qnap") || combo.includes("nas")) {
    cls = "nas";
    iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
  }
  // 6. Ubuntu (如 Ubuntu 22.04.5 LTS)
  else if (combo.includes("ubuntu")) {
    cls = "ubuntu";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm.012 3.82c1.472 0 2.665 1.193 2.665 2.665 0 1.472-1.193 2.665-2.665 2.665-1.472 0-2.665-1.193-2.665-2.665 0-1.472 1.193-2.665 2.665-2.665zm-6.19 5.35c.895 0 1.62.726 1.62 1.62 0 .895-.725 1.62-1.62 1.62-.894 0-1.62-.725-1.62-1.62 0-.894.726-1.62 1.62-1.62zm12.38 0c.894 0 1.62.726 1.62 1.62 0 .895-.726 1.62-1.62 1.62-.895 0-1.62-.725-1.62-1.62 0-.894.725-1.62 1.62-1.62zM12.012 9.9c2.18 0 4.07 1.16 5.12 2.89-.5.36-.88.89-1.07 1.5-.78-.96-1.95-1.58-3.28-1.58-.93 0-1.79.3-2.49.81l-1.45-1.45c.87-.71 1.98-1.17 3.17-1.17zm-5.06 2.05l1.45 1.45c-.37.53-.59 1.18-.59 1.88 0 .62.18 1.2.49 1.69l-1.47 1.47c-.77-.87-1.25-2-1.25-3.25 0-1.28.51-2.43 1.37-3.24zm10.12 0c.86.81 1.37 1.96 1.37 3.24 0 1.25-.48 2.38-1.25 3.25l-1.47-1.47c.31-.49.49-1.07.49-1.69 0-.7-.22-1.35-.59-1.88zm-5.06 3.65c1.33 0 2.5.62 3.28 1.58.19.61.57 1.14 1.07 1.5-1.05 1.73-2.94 2.89-5.12 2.89-1.19 0-2.3-.46-3.17-1.17l1.45-1.45c.7.51 1.56.81 2.49.81z"/></svg>`;
  }
  // 7. Debian
  else if (combo.includes("debian")) {
    cls = "debian";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12.04 0C5.4 0 .04 5.37.04 12c0 6.64 5.36 12 12 12 6.63 0 12-5.36 12-12C24.04 5.37 18.67 0 12.04 0zm.06 1.88c5.6 0 10.13 4.53 10.13 10.12 0 5.6-4.53 10.13-10.13 10.13-5.59 0-10.12-4.53-10.12-10.13 0-5.59 4.53-10.12 10.12-10.12zm.88 2.38c-3.1 0-5.7 1.6-6.66 4.06-.95 2.47-.42 5.32 1.38 7.22 1.8 1.88 4.6 2.4 7.06 1.38.7-.28 1.3-.72 1.78-1.25-.52-.16-1.02-.4-1.47-.75-.4-.3-.72-.7-.94-1.12-.5.5-.9 1.1-1.7.9-1.4-.3-2.1-1.8-1.5-3 .5-1.1 1.7-1.7 2.8-1.5 1 .2 1.7 1 1.8 2 .1.4.1.8 0 1.2.6.2 1.2.2 1.7 0 .8-.4 1.3-1.1 1.5-1.9.4-1.6-.3-3.2-1.6-4.2-1.2-1-2.8-1.4-4.3-1.02z"/></svg>`;
  }
  // 8. Alpine Linux
  else if (combo.includes("alpine")) {
    cls = "alpine";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12.003 3.652a1.05 1.05 0 0 0-.909.527l-5.6 9.695a1.05 1.05 0 0 0 .909 1.575h11.2a1.05 1.05 0 0 0 .91-1.575l-5.6-9.695a1.05 1.05 0 0 0-.91-.527zm-5.46 9.447l4.13-7.152 2.65 4.59-1.55 2.562H6.543zm6.65-2.062l1.66 2.062h-3.32l1.66-2.062z"/></svg>`;
  }
  // 9. OpenWrt / 软路由 / LEDE / 爱快
  else if (combo.includes("openwrt") || combo.includes("lede") || combo.includes("router") || combo.includes("ikuai") || combo.includes("istore")) {
    cls = "router";
    iconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 18h.01M10 18h.01"/><path d="M5 14V6a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v8"/><path d="M12 4v4"/></svg>`;
  }
  // 10. CentOS / RedHat / Fedora / Rocky / AlmaLinux
  else if (combo.includes("centos") || combo.includes("redhat") || combo.includes("rhel") || combo.includes("fedora") || combo.includes("rocky") || combo.includes("alma")) {
    cls = "centos";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 3.5v4.25l3.5-3.5zm1.5.75l3.5 3.5H12.75zm5.75 3.5l-3.5 3.5h4.25zm-.75 1.5h-4.25v4.25zm-3.5 5.75l3.5 3.5V14.25zm-1.5-.75v4.25H12zm-5.75-3.5l3.5-3.5H3.5zm.75-1.5h4.25V8.25zm3.5-5.75L4.75 4.75V9zm1.5.75V4.25H12z"/></svg>`;
  }
  // 11. Arch / Manjaro
  else if (combo.includes("arch") || combo.includes("manjaro")) {
    cls = "arch";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.5L2.5 21.5h4.2l2.3-5.2c.7.3 1.6.5 2.5.5s1.8-.2 2.5-.5l2.3 5.2h4.2L12 2.5zm0 8.2l2 4.6c-.6.2-1.3.3-2 .3s-1.4-.1-2-.3l2-4.6z"/></svg>`;
  }
  // 12. Raspberry Pi / 树莓派 / Armbian
  else if (combo.includes("raspberry") || combo.includes("raspbian") || combo.includes("armbian")) {
    cls = "rpi";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a3 3 0 0 0-3 3c0 .35.07.68.18.98A4.5 4.5 0 0 0 7 9.5c0 1.25.5 2.38 1.32 3.2A4.98 4.98 0 0 0 8 15c0 2.76 2.24 5 5 5s5-2.24 5-5c0-.82-.2-1.59-.55-2.27.79-.82 1.28-1.93 1.28-3.16 0-1.63-.87-3.06-2.18-3.85.11-.3.18-.63.18-.98a3 3 0 0 0-3-3c-.92 0-1.74.42-2.28 1.07A3.01 3.01 0 0 0 12 2z"/></svg>`;
  }
  // 13. 通用 Linux 或其它 Linux 发行版（SUSE、Gentoo、Mint、Kali、Kylin、Deepin、UOS 等）
  else if (
    combo.includes("linux") ||
    combo.includes("unix") ||
    combo.includes("gnu") ||
    combo.includes("bsd") ||
    combo.includes("posix") ||
    combo.includes("suse") ||
    combo.includes("gentoo") ||
    combo.includes("mint") ||
    combo.includes("kali") ||
    combo.includes("deepin") ||
    combo.includes("uos") ||
    combo.includes("kylin") ||
    combo.includes("opencloudos") ||
    combo.includes("tencentos")
  ) {
    cls = "linux";
    iconSvg = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.242 17.514c-.31-.806-1.045-1.34-1.848-1.515-.59-.129-1.205.083-1.683.473-.38.311-.75.768-1.056 1.253-.804-1.516-1.92-2.73-3.298-3.567 1.39-1.22 2.193-2.924 2.193-4.758 0-3.64-2.884-6.6-6.425-6.6-3.54 0-6.425 2.96-6.425 6.6 0 1.834.803 3.538 2.193 4.758-1.378.837-2.494 2.05-3.298 3.567-.306-.485-.676-.942-1.056-1.253-.478-.39-1.093-.602-1.683-.473-.803.175-1.538.709-1.848 1.515-.355.923-.198 1.968.41 2.766.72.946 1.874 1.488 3.09 1.488.243 0 .49-.021.737-.066.86-.157 1.637-.624 2.19-1.298 1.34 1.05 3.018 1.642 4.785 1.642 1.767 0 3.445-.592 4.785-1.642.553.674 1.33 1.141 2.19 1.298.247.045.494.066.737.066 1.216 0 2.37-.542 3.09-1.488.608-.798.765-1.843.41-2.766zM12.125 3.8c2.44 0 4.425 2.064 4.425 4.6 0 1.427-.645 2.748-1.744 3.606-.395.308-.636.772-.65 1.27-.014.498.198.975.578 1.306 1.087.948 1.815 2.215 2.112 3.655-.494-.094-1.002-.037-1.46.166-.462.204-.84.558-1.077 1.007-.803.352-1.696.54-2.61.54-.914 0-1.807-.188-2.61-.54-.237-.449-.615-.803-1.077-1.007-.458-.203-.966-.26-1.46-.166.297-1.44 1.025-2.707 2.112-3.655.38-.331.592-.808.578-1.306-.014-.498-.255-.962-.65-1.27-1.099-.858-1.744-2.179-1.744-3.606 0-2.536 1.985-4.6 4.425-4.6z"/></svg>`;
  }

  const rawOs = String(osStr || "").trim();
  let labelText = rawOs || "-";
  if (cls === "docker" && !os.includes("docker")) {
    labelText = `${rawOs || "linux"} (docker)`;
  }
  return `<span class="tag os ${cls}">${iconSvg}${esc(labelText)}</span>`;
}

/* ---------------- 设备总览 ---------------- */
function renderDevices() {
  const total = state.devices.length;
  const onlineCount = state.devices.filter(onlineDev).length;
  const offlineCount = total - onlineCount;
  if ($("statTotalDev")) $("statTotalDev").textContent = total;
  if ($("statOnlineDev")) $("statOnlineDev").textContent = onlineCount;
  if ($("statOfflineDev")) $("statOfflineDev").textContent = offlineCount;

  const kw = $("devSearch").value.trim().toLowerCase();
  const onlyOnline = $("devOnlyOnline").checked;
  const list = state.devices.filter((d) => {
    if (onlyOnline && !onlineDev(d)) return false;
    if (!kw) return true;
    return [d.name, d.ip, d.lanip, d.os].join(" ").toLowerCase().includes(kw);
  });
  const tbody = $("devTable").querySelector("tbody");
  tbody.innerHTML = list.map((d) => {
    const on = onlineDev(d);
    const upd = d.version !== state.latestVer && state.latestVer;
    return `<tr data-node="${esc(d.name)}">
      <td class="col-chk"><input type="checkbox" class="dev-chk" data-node="${esc(d.name)}"></td>
      <td class="col-status"><span class="dot ${on ? "on" : "off"}"></span>${on ? "在线" : "离线"}</td>
      <td class="col-name col-pinned-end"><div class="name-scroll" title="${esc(d.name)}"><span>${esc(d.name)}</span></div></td>
      <td class="ip">${copyBtn(d.lanip)}</td>
      <td class="ip">${copyBtn(d.ip)}</td>
      <td>${renderOsTag(d.os, d.name)}</td>
      <td><span class="tag">NAT${esc(d.natType ?? "-")}</span></td>
      <td>${esc(d.version || "-")}${upd ? ` <a class="tag" style="color:var(--amber)">可升级</a>` : ""}</td>
      <td>${esc(d.bandwidth ?? "-")}</td>
      <td>${esc(fmtTime(d.activetime))}</td>
      <td class="op">
        <button class="btn" data-act="tunnels">规则</button>
        <button class="btn" data-act="editdev">编辑</button>
        <button class="btn" data-act="restart">重启</button>
        <button class="btn" data-act="upgrade" ${upd ? "" : "disabled"}>升级</button>
        <button class="btn danger" data-act="delete">删除</button>
      </td>
    </tr>`;
  }).join("") || `<tr><td colspan="11" class="muted" style="text-align:center">无设备</td></tr>`;
  updateBatchButtons();
}

function updateBatchButtons() {
  const n = document.querySelectorAll(".dev-chk:checked").length;
  for (const [id, label] of [["btnBatchRestart", "⚡ 重启所选"], ["btnBatchUpgrade", "⬆ 升级所选"], ["btnBatchDelete", "🗑 删除所选"]]) {
    const b = $(id);
    b.disabled = n === 0;
    b.textContent = n ? `${label} (${n})` : label;
  }
}

/** 从账号移除设备（官方同款接口，设备端需在线接受卸载推送） */
async function doDeleteDevices(nodes) {
  const offline = nodes.filter((n) => { const d = state.devices.find((x) => x.name === n); return d && !onlineDev(d); });
  const msg = `将从账号移除 ${nodes.length} 台设备：${nodes.join("、")}。` +
    (offline.length ? `\n⚠️ 其中 ${offline.length} 台当前离线，离线设备可能无法响应移除指令，需重新上线后处理。` : "") +
    `\n此操作不可撤销（需在设备上重装客户端才能重新加入）。继续？`;
  if (!(await confirmDlg("批量删除设备", msg))) return;
  let ok = 0, fail = 0;
  for (const n of nodes) {
    try {
      const rsp = await pxp(`/api/v1/device/${encodeURIComponent(n)}/delete`);
      (rsp.status === 200 && rsp.data.error === 0) ? ok++ : fail++;
    } catch { fail++; }
  }
  toast(`删除完成：成功 ${ok} 台${fail ? `，失败 ${fail} 台` : ""}`, fail ? "err" : "ok");
  await refreshAll();
}

/* ---------------- 设备编辑（改名/带宽/forcev6/公网端口，官方 POST /device/<n>/edit 同款） ---------------- */
function openDevDialog(node) {
  const d = state.devices.find((x) => x.name === node);
  if (!d) return;
  $("devDlgTitle").textContent = `编辑设备：${node}`;
  $("dvName").value = node;
  $("dvBandwidth").value = d.bandwidth ?? 0;
  $("dvPublicPort").value = d.publicIPPort ?? 0;
  $("dvForcev6").checked = d.forcev6 === 1 || d.forcev6 === "1";
  $("devErr").classList.add("hidden");
  $("dvName").dataset.orig = node;
  $("devDialog").showModal();
}

$("dvCancel").addEventListener("click", () => $("devDialog").close());

$("devForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const orig = $("dvName").dataset.orig;
  const newName = $("dvName").value.trim();
  if (newName.length < 8) {
    $("devErr").textContent = "设备名不能少于 8 个字符（官方限制）";
    $("devErr").classList.remove("hidden");
    return;
  }
  const saveBtn = $("dvSave");
  saveBtn.disabled = true;
  saveBtn.textContent = "保存中…";
  try {
    const rsp = await pxp(`/api/v1/device/${encodeURIComponent(orig)}/edit`, {
      method: "POST",
      body: {
        newName,
        bandwidth: +$("dvBandwidth").value || 0,
        forcev6: $("dvForcev6").checked ? 1 : 0,
        publicIPPort: +$("dvPublicPort").value || 0,
      },
    });
    if (rsp.status === 200 && rsp.data.error === 0) {
      $("devDialog").close();
      toast(`设备 ${orig} 已更新`, "ok");
      await refreshAll();
    } else {
      $("devErr").textContent = "保存失败: " + JSON.stringify(rsp.data).slice(0, 140);
      $("devErr").classList.remove("hidden");
    }
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = "保存";
  }
});

async function doRestart(nodes) {
  if (!(await confirmDlg("重启设备", `将对 ${nodes.length} 台设备下发重启指令，期间其转发/组网会短暂中断。继续？`))) return;
  for (const n of nodes) await pushCmd(n, 11, {});
  toast(`已向 ${nodes.length} 台设备下发重启指令`);
}

async function doUpgrade(nodes) {
  if (!(await confirmDlg("升级设备", `将对 ${nodes.length} 台设备下发升级指令（目标版本 ${state.latestVer}）。继续？`))) return;
  for (const n of nodes) await pushCmd(n, 6, {});
  toast(`已向 ${nodes.length} 台设备下发升级指令`);
}

$("devSearch").addEventListener("input", renderDevices);
$("devOnlyOnline").addEventListener("change", renderDevices);
$("devChkAll").addEventListener("change", (ev) => {
  document.querySelectorAll(".dev-chk").forEach((c) => (c.checked = ev.target.checked));
  updateBatchButtons();
});
$("devTable").addEventListener("click", (ev) => {
  const chk = ev.target.closest(".dev-chk");
  if (chk) { updateBatchButtons(); return; }
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const node = btn.closest("tr").dataset.node;
  const act = btn.dataset.act;
  if (act === "tunnels") {
    switchView("tunnels");
    initSearchSelects();
    if (tlNodeFilterSS) tlNodeFilterSS.setValue(node);
    else $("tlNodeFilter").value = node;
    state.ruleCtxNode = node; // 记住上下文：新建规则时默认落在该设备
    renderTunnels();
  } else if (act === "editdev") openDevDialog(node);
  else if (act === "restart") doRestart([node]);
  else if (act === "upgrade") doUpgrade([node]);
  else if (act === "delete") doDeleteDevices([node]);
});
$("devTable").addEventListener("mouseover", (ev) => {
  const el = ev.target.closest(".name-scroll");
  if (!el || el._scrolling) return;
  const max = el.scrollWidth - el.clientWidth;
  if (max > 0) {
    el._scrolling = true;
    el.scrollTo({ left: max, behavior: "smooth" });
  }
});
$("devTable").addEventListener("mouseout", (ev) => {
  const el = ev.target.closest(".name-scroll");
  if (!el) return;
  el._scrolling = false;
  el.scrollTo({ left: 0, behavior: "smooth" });
});
$("btnBatchRestart").addEventListener("click", () => doRestart(selNodes()));
$("btnBatchUpgrade").addEventListener("click", () => doUpgrade(selNodes()));
$("btnBatchDelete").addEventListener("click", () => doDeleteDevices(selNodes()));
function selNodes() {
  return [...document.querySelectorAll(".dev-chk:checked")].map((c) => c.dataset.node);
}

/* ---------------- 隧道规则 ---------------- */
function ruleType(rule) {
  return rule.srcPort ? "pf" : "sd"; // 有监听端口 = 端口转发，否则为组网隧道
}

function renderTunnels() {
  initSearchSelects();
  const curFilter = tlNodeFilterSS ? tlNodeFilterSS.getValue() : ($("tlNodeFilter").value || "");
  const filterOptions = [
    { value: "", label: "全部设备", subtext: `共 ${state.devices.length} 台` },
    ...state.devices.map((d) => ({
      value: d.name,
      label: d.name,
      online: onlineDev(d),
      subtext: `${d.ip || "-"}${d.os ? " · " + d.os : ""}`
    }))
  ];
  if (tlNodeFilterSS) {
    tlNodeFilterSS.setOptions(filterOptions);
    tlNodeFilterSS.setValue(curFilter);
  }
  const nodeFilter = tlNodeFilterSS ? tlNodeFilterSS.getValue() : ($("tlNodeFilter").value || "");
  const kw = $("tlSearch").value.trim().toLowerCase();


  const devMap = Object.fromEntries(state.devices.map((d) => [d.name, d]));
  // 连接状态四态推导（字段语义来自实测：isActive=1 已连接；connectTime 为 0001-01-01 零值表示从未连上）
  const ZERO_TIME = "0001-01-01";
  const isEnabled = (a, node) => {
    // 设备停用规则后上报的 JSON 里 enabled 字段会消失（实测），因此：
    // 有 enabled 字段 → 以设备为准；无字段 → 默认启用，但本会话下发过停用指令的视为停用
    if (a.enabled === undefined || a.enabled === null) {
      return !state.disabledApps.has(node + "|" + a.appName + "|" + a.srcPort);
    }
    return a.enabled !== 0;
  };
  const connStateOf = (a, node) => {
    if (!isEnabled(a, node)) return { txt: "已停用", cls: "cs-off", key: "off" };
    if (a.isActive === 1) return { txt: "✅ 已连接", cls: "cs-ok", key: "ok" };
    const never = !a.connectTime || String(a.connectTime).startsWith(ZERO_TIME);
    const peerDev = devMap[a.peerNode];
    if (peerDev && !onlineDev(peerDev)) return { txt: "等待对端上线", cls: "cs-wait", key: "peeroff" };
    if (never) return { txt: "正在连接…", cls: "cs-wait", key: "wait" };
    return { txt: "重试中", cls: "cs-wait", key: "wait" };
  };

    const rows = [];
  for (const [node, apps] of Object.entries(state.tunnelByNode)) {
    if (nodeFilter && node !== nodeFilter) continue;
    for (const a of apps) {
      const t = ruleType(a);
      if (kw) {
        const hay = [a.appName, a.peerNode, a.dstHost, a.relayNode, a.specRelayNode, a.linkMode].join(" ").toLowerCase();
        if (!hay.includes(kw)) continue;
      }
      const cs = connStateOf(a, node);
      rows.push({ node, a, t, cs });
    }
  }

  // 排序：peer=对端字母序；state=连接状态优先级（已连接 > 连接中 > 等待对端 > 停用）
  const stateOrder = { ok: 0, wait: 1, peeroff: 2, off: 3 };
  if (tunnelSort.key === "peer") {
    rows.sort((x, y) => (x.a.peerNode || "").localeCompare(y.a.peerNode || "") * tunnelSort.dir);
  } else if (tunnelSort.key === "state") {
    rows.sort((x, y) => ((stateOrder[x.cs.key] ?? 9) - (stateOrder[y.cs.key] ?? 9)) * tunnelSort.dir);
  }
  // 拆分：端口转发 → tlTable；组网隧道 → sdTable
  const pfRows = rows.filter((r) => r.t === "pf");
  const sdRows = rows.filter((r) => r.t === "sd");
  if (!$("cntPf") || !$("cntSd") || !$("tlSummary")) return; // 视图元素未就绪（极端时序）直接跳过本轮渲染
  $("cntPf").textContent = pfRows.length;
  $("cntSd").textContent = sdRows.length;
  const visible = tlSub === "pf" ? pfRows : sdRows;
  $("tlSummary").textContent = `共 ${visible.length} 条`;

  if (tlSub === "pf") {
    const tbody = $("tlTable") && $("tlTable").querySelector("tbody");
    if (!tbody) return;
    tbody.innerHTML = pfRows.map(({ node, a, cs }) => {
    const dev = devMap[node];
    const relay = a.specRelayNode
      ? `${esc(a.specRelayNode)}${a.relayNode && a.relayNode !== a.specRelayNode ? ` (实际:${esc(a.relayNode)})` : ""}`
      : (a.relayNode ? `<span class="muted">自动:</span> ${esc(a.relayNode)}` : `<span class="muted">P2P 直连</span>`);
    const peerDev = devMap[a.peerNode];
    return `<tr>
      <td>${esc(node)}${dev && !onlineDev(dev) ? ' <span class="tag">离线</span>' : ""}</td>
      <td class="name">${esc(a.appName)}</td>
      <td><span class="tag pf">${esc((a.protocol || "tcp").toUpperCase())}</span></td>
      <td><b class="ip">${esc(a.srcPort)}</b></td>
      <td>${esc(a.peerNode || "-")}${peerDev && !onlineDev(peerDev) ? ' <span class="tag">对端离线</span>' : ""}</td>
      <td class="ip">${esc(a.dstHost || "localhost")}:${esc(a.dstPort)}</td>
      <td><span class="tag">${esc(a.linkMode || "-")}</span></td>
      <td class="relay">${relay}</td>
      <td class="${cs.cls}">${cs.txt}</td>
      <td>${isEnabled(a, node) ? "✅" : `<a class="tag" style="color:var(--danger)">停用</a>`}</td>
      <td class="op">
        <button class="btn" data-act="toggle" data-node="${esc(node)}" data-app="${esc(a.appName)}"
          data-pf="${esc(a.protocol || "")}" data-port="${esc(a.srcPort || 0)}" data-peer="${esc(a.peerNode || "")}"
          data-en="${isEnabled(a, node) ? 0 : 1}">${isEnabled(a, node) ? "停用" : "启用"}</button>
        <button class="btn" data-act="edit" data-node="${esc(node)}" data-app="${esc(a.appName)}">编辑</button>
        <button class="btn danger" data-act="del" data-node="${esc(node)}" data-app="${esc(a.appName)}"
          data-pf="${esc(a.protocol || "")}" data-port="${esc(a.srcPort || 0)}">删除</button>
      </td>
    </tr>`;
    }).join("") || `<tr><td colspan="11" class="muted" style="text-align:center">无端口转发规则</td></tr>`;
  } else {
    const tbody = $("sdTable") && $("sdTable").querySelector("tbody");
    if (!tbody) return;
    tbody.innerHTML = sdRows.map(({ node, a, cs }) => {
    const dev = devMap[node];
    const peerDev = devMap[a.peerNode];
    const relay = a.specRelayNode || a.relayNode || "";
    const peerIp = a.peerIP || "-";
    const nat = a.peerNatType != null ? "NAT" + a.peerNatType : "-";
    return `<tr>
      <td>${esc(node)}${dev && !onlineDev(dev) ? ' <span class="tag">离线</span>' : ""}</td>
      <td class="name">${esc(a.peerNode || "-")}${peerDev && !onlineDev(peerDev) ? ' <span class="tag">对端离线</span>' : ""}</td>
      <td class="ip">${copyBtn(peerIp)}</td>
      <td>${esc(nat)}</td>
      <td><span class="tag">${esc(a.linkMode || "-")}</span></td>
      <td class="relay">${relay ? esc(relay) : '<span class="muted">P2P 直连</span>'}</td>
      <td class="${cs.cls}">${cs.txt}</td>
      <td class="ip">${esc(fmtTime(a.connectTime))}</td>
    </tr>`;
    }).join("") || `<tr><td colspan="8" class="muted" style="text-align:center">无组网隧道</td></tr>`;
  }

  // 排序列头箭头（两张表各自处理）
  document.querySelectorAll("#tlTable th.sortable, #sdTable th.sortable").forEach((th) => {
    const arrow = th.querySelector(".sort-arrow");
    if (arrow) arrow.textContent = tunnelSort.key === th.dataset.sort ? (tunnelSort.dir === 1 ? " ▲" : " ▼") : "";
    th.classList.toggle("sorted", tunnelSort.key === th.dataset.sort);
  });

  let activeCount = 0;
  for (const apps of Object.values(state.tunnelByNode)) {
    for (const a of apps) {
      if (a.isActive === 1) activeCount++;
    }
  }
  if ($("statActiveTunnels")) $("statActiveTunnels").textContent = activeCount;


}

document.querySelectorAll(".subtab[data-tl]").forEach((b) =>
  b.addEventListener("click", () => {
    tlSub = b.dataset.tl;
    document.querySelectorAll(".subtab[data-tl]").forEach((x) => x.classList.toggle("active", x === b));
    $("tlPfWrap").classList.toggle("hidden", tlSub !== "pf");
    $("tlSdWrap").classList.toggle("hidden", tlSub !== "sd");
    renderTunnels();
  })
);
document.querySelectorAll("#tlTable th.sortable, #sdTable th.sortable").forEach((th) =>
  th.addEventListener("click", () => {
    const k = th.dataset.sort;
    if (tunnelSort.key === k) tunnelSort.dir *= -1;
    else { tunnelSort.key = k; tunnelSort.dir = 1; }
    renderTunnels();
  })
);
$("tlSearch").addEventListener("input", renderTunnels);
$("tlNodeFilter").addEventListener("change", renderTunnels);

$("tlTable").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const { act, node, app, pf, port, peer, en } = btn.dataset;
  if (act === "toggle") {
    const key = node + "|" + app + "|" + port;
    const target = (state.tunnelByNode[node] || []).find((a) => a.appName === app && a.srcPort == port);
    const newEnabled = en === "1" ? 1 : 0; // 按钮上写的是"将变成的状态"
    // 乐观更新：本地立即翻转状态列与按钮，不等设备回执
    if (target) target.enabled = newEnabled;
    if (newEnabled) state.disabledApps.delete(key);
    else state.disabledApps.add(key);
    renderTunnels();
    toast(newEnabled ? `已启用 ${app}` : `已停用 ${app}`, "ok");
    const rsp = await pushCmd(node, 10, { appName: app, peerNode: peer, protocol: pf, srcPort: +port, enabled: newEnabled });
    if (rsp.status !== 200) {
      // 下发失败：回滚本地状态
      if (target) target.enabled = newEnabled ? 0 : 1;
      renderTunnels();
      toast(`指令下发失败（${JSON.stringify(rsp.data).slice(0, 80)}），已恢复显示`, "err");
      return;
    }
    // 轮询确认真实状态（设备应用有延迟），以设备回报为准纠正
    setTimeout(async () => {
      await refreshTunnels(true);
      const real = (state.tunnelByNode[node] || []).find((a) => a.appName === app && a.srcPort == port);
      const realEnabled = real ? isEnabled(real, node) : true;
      if (real && realEnabled !== !!newEnabled) {
        if (realEnabled) state.disabledApps.delete(key); // 设备实际是启用 → 清本地停用标记
        toast(`${app} 设备侧状态为 ${realEnabled ? "启用" : "停用"}（与指令不符，已按设备实际状态显示）`, "err");
        renderTunnels();
      }
    }, 2500);
  } else if (act === "del") {
    if (!(await confirmDlg("删除规则", `确认在 ${node} 上删除规则「${app}」(${pf}:${port})？该操作直接下发到设备。`))) return;
    await pushCmd(node, 9, { appName: app, protocol0: pf, srcPort0: +port, protocol: pf, srcPort: 0, peerNode: peer });
    toast(`已下发删除指令: ${app}`);
    setTimeout(() => refreshTunnels(true), 2000);
  } else if (act === "edit") {
    const rule = (state.tunnelByNode[node] || []).find((a) => a.appName === app && a.srcPort == port);
    if (rule) openRuleDialog(node, rule);
  }
});

$("btnRefreshAll").addEventListener("click", () => refreshAll());

/* ---------------- 新建/编辑转发规则 ---------------- */
function fillNodeSelects() {
  initSearchSelects();
  const items = state.devices.map((d) => ({
    value: d.name,
    label: d.name,
    online: onlineDev(d),
    subtext: `${d.ip || "-"}${d.os ? " · " + d.os : ""}${onlineDev(d) ? "" : "（离线）"}`
  }));
  if (ruNodeSS) ruNodeSS.setOptions(items);
  else {
    const opts = state.devices.map((d) =>
      `<option value="${esc(d.name)}">${esc(d.name)}${onlineDev(d) ? "" : "（离线）"}</option>`).join("");
    $("ruNode").innerHTML = opts;
  }
  if (ruPeerSS) ruPeerSS.setOptions(items);
  else {
    const opts = state.devices.map((d) =>
      `<option value="${esc(d.name)}">${esc(d.name)}${onlineDev(d) ? "" : "（离线）"}</option>`).join("");
    $("ruPeer").innerHTML = opts;
  }
}

function openRuleDialog(node, existing) {
  fillNodeSelects();
  $("ruleErr").classList.add("hidden");
  const editing = !!existing;
  $("ruleDlgTitle").textContent = editing ? `编辑规则（${node}）` : "新建转发规则";
  if (ruNodeSS) {
    ruNodeSS.setValue(node);
    ruNodeSS.setDisabled(editing);
  } else {
    $("ruNode").value = node;
    $("ruNode").disabled = editing;
  }
  if (editing) {
    $("ruAppName").value = existing.appName;
    $("ruSrcPort").value = existing.srcPort;
    $("ruProto").value = existing.protocol || "tcp";
    if (ruPeerSS) ruPeerSS.setValue(existing.peerNode || "");
    else $("ruPeer").value = existing.peerNode || "";
    $("ruDstHost").value = existing.dstHost || "localhost";
    $("ruDstPort").value = existing.dstPort || "";
    $("ruWhitelist").value = existing.whitelist || "";
    $("ruAppName").dataset.protocol0 = existing.protocol || "tcp";
    $("ruAppName").dataset.srcPort0 = existing.srcPort;
  } else {
    $("ruAppName").value = "";
    $("ruSrcPort").value = "";
    $("ruProto").value = "tcp";
    const peerCandidate = state.devices.find((d) => d.name !== node && onlineDev(d)) || state.devices.find((d) => d.name !== node) || state.devices[0];
    if (ruPeerSS) ruPeerSS.setValue(peerCandidate ? peerCandidate.name : "");
    else $("ruPeer").selectedIndex = 0;
    $("ruDstHost").value = "localhost";
    $("ruDstPort").value = "";
    $("ruWhitelist").value = "";
    $("ruCheckResult").textContent = "";
    delete $("ruAppName").dataset.protocol0;
    delete $("ruAppName").dataset.srcPort0;
  }
  $("ruleDialog").showModal();
}

$("btnAddRule").addEventListener("click", () => {
  const online = state.devices.filter(onlineDev);
  if (!online.length) { toast("无在线设备，无法下发规则", "err"); return; }
  // 默认所在设备优先级：当前筛选设备 > 跳转来源上下文 > 第一台在线设备
  const ctx = state.ruleCtxNode;
  const filter = tlNodeFilterSS ? tlNodeFilterSS.getValue() : $("tlNodeFilter").value;
  const preferred = [filter, ctx].filter(Boolean)
    .find((n) => onlineDev(state.devices.find((d) => d.name === n) || {}));
  openRuleDialog(preferred || online[0].name, null);
});

$("ruCancel").addEventListener("click", () => $("ruleDialog").close());

// 对端服务探测：在对端设备上检查 dstHost:dstPort 是否可达（MsgPushCheckRemoteService=19）
$("ruCheckSvc").addEventListener("click", async () => {
  const peer = ruPeerSS ? ruPeerSS.getValue() : $("ruPeer").value;
  const host = $("ruDstHost").value.trim() || "localhost";
  const port = +$("ruDstPort").value;
  const out = $("ruCheckResult");
  if (!peer || !port) { out.textContent = "请先填写目标端口并选择对端设备"; out.style.color = "var(--red)"; return; }
  const dev = state.devices.find((d) => d.name === peer);
  if (!dev || !onlineDev(dev)) { out.textContent = `对端 ${peer} 离线，无法探测`; out.style.color = "var(--red)"; return; }
  out.textContent = `正在 ${peer} 上探测 ${host}:${port} …`;
  out.style.color = "var(--muted)";
  const rsp = await pushCmd(peer, 19, { host, port }, 1);
  if (rsp.status === 200 && !rsp.data.error) {
    out.textContent = `✅ ${host}:${port} 在 ${peer} 上可达`;
    out.style.color = "var(--accent)";
  } else {
    out.textContent = `✗ 不可达或超时（${(rsp.data.detail || rsp.data.raw || "error " + rsp.status).slice(0, 60)}）`;
    out.style.color = "var(--red)";
  }
});

$("ruleForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const node = ruNodeSS ? ruNodeSS.getValue() : $("ruNode").value;
  const peer = ruPeerSS ? ruPeerSS.getValue() : $("ruPeer").value;
  const body = {
    appName: $("ruAppName").value.trim(),
    protocol: $("ruProto").value,
    srcPort: +$("ruSrcPort").value,
    peerNode: peer,
    dstHost: $("ruDstHost").value.trim() || "localhost",
    dstPort: +$("ruDstPort").value,
    whitelist: $("ruWhitelist").value.trim(),
    enabled: 1,
  };
  if (!body.appName || !body.srcPort || !body.dstPort || !body.peerNode) {
    $("ruleErr").textContent = "请完整填写所有字段";
    $("ruleErr").classList.remove("hidden");
    return;
  }
  if ($("ruAppName").dataset.protocol0) {
    body.protocol0 = $("ruAppName").dataset.protocol0;
    body.srcPort0 = +$("ruAppName").dataset.srcPort0;
  }
  const rsp = await pushCmd(node, 9, body, 0);
  if (rsp.status === 200) {
    $("ruleDialog").close();
    toast(`规则已下发到 ${node}，正在确认…`);
    setTimeout(() => refreshTunnels(true), 2000);
  } else {
    $("ruleErr").textContent = "下发失败: " + JSON.stringify(rsp.data).slice(0, 160);
    $("ruleErr").classList.remove("hidden");
  }
});

/* ---------------- 虚拟网络 ---------------- */
function nextVirtualIP(used) {
  const gw = ($("netGateway").value || "").split("/");
  const base = (gw[0] || "10.11.1.254").split(".").slice(0, 3).join(".");
  for (let i = 2; i < 254; i++) {
    const cand = `${base}.${i}`;
    if (!used.has(cand)) { used.add(cand); return cand; }
  }
  return "";
}

function renderNetwork() {
  if (!state.sdwan) {
    $("netLoading").textContent = "未获取到虚拟网络配置";
    return;
  }
  $("netLoading").classList.add("hidden");
  $("netEditor").classList.remove("hidden");
  initSearchSelects();
  const s = state.sdwan;
  $("netName").value = s.name || "";
  $("netGateway").value = s.gateway || "";
  $("netMode").value = s.mode || "fullmesh";
  $("netMtu").value = s.mtu || 1420;
  $("netPunch").value = String(s.punchPriority ?? 1);

  const centralItems = [
    { value: "", label: "不指定 (自动选路)", subtext: "" },
    ...state.devices.map((d) => ({
      value: d.name,
      label: d.name,
      online: onlineDev(d),
      subtext: `${d.ip || "-"}${d.os ? " · " + d.os : ""}`
    }))
  ];
  if (netCentralSS) {
    netCentralSS.setOptions(centralItems);
    netCentralSS.setValue(s.centralNode || "");
  } else {
    $("netCentral").innerHTML = [`<option value="">不指定</option>`]
      .concat(state.devices.map((d) => `<option value="${esc(d.name)}">${esc(d.name)}</option>`)).join("");
    $("netCentral").value = s.centralNode || "";
  }
  $("netCentralWrap").style.display = $("netMode").value === "central" ? "" : "none";

  const devMap = Object.fromEntries(state.devices.map((d) => [d.name, d]));
  const members = s.Nodes || [];
  // 连接状态：优先用 MemApps 实时缓存（subtype=17，成员级组网隧道权威数据）；
  // 未拉取过时提示拉取，由 loadMemStatus() 异步填充
  const memApps = state.memByNode || {};
  const statusOf = (name) => {
    const apps = memApps[name];
    if (!apps) return { txt: "点击「刷新状态」拉取", cls: "dim" };
    if (!apps.length) return { txt: "· 无隧道", cls: "dim" };
    const active = apps.filter((a) => a.isActive === 1).length;
    return active > 0
      ? { txt: `✅ ${active}/${apps.length} 条活跃`, cls: "ok" }
      : { txt: `· 0/${apps.length} 条活跃`, cls: "dim" };
  };

  const tbody = $("netTable").querySelector("tbody");
  tbody.innerHTML = members.map((m, i) => {
    const dev = devMap[m.name];
    const st = statusOf(m.name);
    const on = dev && onlineDev(dev);
    const pubIp = dev ? dev.ip : "-";
    return `<tr data-idx="${i}">
      <td class="name"><a class="member-link" data-jump="${esc(m.name)}" title="查看该成员的隧道连接状态">${esc(m.name)}</a>${dev ? "" : ' <span class="tag" style="color:var(--red)">不在设备列表</span>'}</td>
      <td><input class="input ip-input" style="width:140px" value="${esc(m.ip || "")}" data-k="ip"></td>
      <td class="ip">${copyBtn(pubIp, "ip")}</td>
      <td><span class="dot ${on ? "on" : "off"}"></span>${dev ? (on ? "在线" : "离线") : "-"}</td>
      <td class="${st.cls}">${st.txt}</td>
      <td><input class="input res-input" style="width:260px" value="${esc(m.resource || "")}" data-k="resource" placeholder="192.168.3.0/24,192.168.1.8/32"></td>
      <td class="op"><button class="btn danger" data-act="rm">移除</button></td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="muted" style="text-align:center">无成员</td></tr>`;

  // 成员明细下拉
  const memberItems = members.map((m) => {
    const dev = devMap[m.name];
    return {
      value: m.name,
      label: m.name,
      online: dev ? onlineDev(dev) : undefined,
      subtext: m.ip || (dev ? dev.ip : "")
    };
  });
  if (memSelSS) {
    const curMem = memSelSS.getValue() || (members[0] ? members[0].name : "");
    memSelSS.setOptions(memberItems);
    memSelSS.setValue(curMem);
  } else {
    $("memSel").innerHTML = members.map((m) => `<option value="${esc(m.name)}">${esc(m.name)}</option>`).join("");
  }
}

$("netMode").addEventListener("change", () => {
  $("netCentralWrap").style.display = $("netMode").value === "central" ? "" : "none";
});

/* 批量加入成员 */
let mdCandidates = [];
let mdSelected = new Set();

function renderMemberCandidates(keyword = "") {
  const q = (keyword || "").trim().toLowerCase();
  const filtered = !q ? mdCandidates : mdCandidates.filter((d) =>
    d.name.toLowerCase().includes(q) ||
    (d.ip && d.ip.toLowerCase().includes(q)) ||
    (d.os && d.os.toLowerCase().includes(q))
  );

  $("mdCount").textContent = `已选 ${mdSelected.size} 台`;

  const visibleSelectedCount = filtered.filter((d) => mdSelected.has(d.name)).length;
  $("mdChkAll").checked = filtered.length > 0 && visibleSelectedCount === filtered.length;
  $("mdChkAll").indeterminate = visibleSelectedCount > 0 && visibleSelectedCount < filtered.length;

  if (!filtered.length) {
    $("mdList").innerHTML = `<div class="muted" style="text-align:center;padding:24px 0">未找到匹配的待添加设备</div>`;
    return;
  }

  $("mdList").innerHTML = filtered.map((d) => {
    const isChecked = mdSelected.has(d.name);
    const isOnline = onlineDev(d);
    return `<label class="md-item ${isChecked ? "selected" : ""}" data-name="${esc(d.name)}">
      <input type="checkbox" value="${esc(d.name)}" ${isChecked ? "checked" : ""}>
      <span class="dot ${isOnline ? "on" : "off"}"></span>
      <span class="name">${esc(d.name)}</span>
      <span class="muted">${esc(d.ip || "-")}${d.os ? " · " + esc(d.os) : ""} · ${isOnline ? "在线" : "离线"}</span>
    </label>`;
  }).join("");
}

$("btnBatchAddMember").addEventListener("click", () => {
  const members = new Set((state.sdwan.Nodes || []).map((m) => m.name));
  mdCandidates = state.devices.filter((d) => !members.has(d.name));
  if (!mdCandidates.length) { toast("所有设备都已在网络中", "err"); return; }
  mdSelected = new Set();
  $("mdSearch").value = "";
  renderMemberCandidates("");
  $("memberDialog").showModal();
});

$("mdSearch").addEventListener("input", () => renderMemberCandidates($("mdSearch").value));

$("mdChkAll").addEventListener("change", () => {
  const q = $("mdSearch").value.trim().toLowerCase();
  const filtered = !q ? mdCandidates : mdCandidates.filter((d) =>
    d.name.toLowerCase().includes(q) ||
    (d.ip && d.ip.toLowerCase().includes(q)) ||
    (d.os && d.os.toLowerCase().includes(q))
  );
  if ($("mdChkAll").checked) {
    filtered.forEach((d) => mdSelected.add(d.name));
  } else {
    filtered.forEach((d) => mdSelected.delete(d.name));
  }
  renderMemberCandidates($("mdSearch").value);
});

$("mdList").addEventListener("change", (e) => {
  const chk = e.target.closest("input[type=checkbox]");
  if (!chk) return;
  if (chk.checked) mdSelected.add(chk.value);
  else mdSelected.delete(chk.value);
  renderMemberCandidates($("mdSearch").value);
});

$("mdCancel").addEventListener("click", () => $("memberDialog").close());

$("memberForm").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const picked = Array.from(mdSelected);
  if (!picked.length) { $("memberDialog").close(); return; }
  const used = new Set((state.sdwan.Nodes || []).map((m) => m.ip).filter(Boolean));
  for (const name of picked) {
    state.sdwan.Nodes.push({ name, ip: nextVirtualIP(used) });
  }
  $("memberDialog").close();
  renderNetwork();
  toast(`已添加 ${picked.length} 台设备（虚拟 IP 已自动分配），点击「保存整网配置」生效`);
});

$("netTable").addEventListener("click", (ev) => {
  // 点击成员名 → 跳转隧道规则页并按该成员筛选
  const link = ev.target.closest(".member-link[data-jump]");
  if (link) {
    switchView("tunnels");
    initSearchSelects();
    if (tlNodeFilterSS) tlNodeFilterSS.setValue(link.dataset.jump);
    else $("tlNodeFilter").value = link.dataset.jump;
    state.ruleCtxNode = link.dataset.jump;
    renderTunnels();
    toast(`已按设备「${link.dataset.jump}」筛选隧道`, "ok");
    return;
  }
  const btn = ev.target.closest("button[data-act=rm]");
  if (!btn) return;
  const idx = +btn.closest("tr").dataset.idx;
  const name = state.sdwan.Nodes[idx].name;
  state.sdwan.Nodes.splice(idx, 1);
  renderNetwork();
  toast(`已移除 ${name}（未保存）`);
});

$("btnNetSave").addEventListener("click", async () => {
  if (!(await confirmDlg("保存虚拟网络", "将把整网配置（成员/虚拟 IP/子网代理 resource 变更）全量提交并下发到各成员，网络会短暂收敛。继续？"))) return;
  const s = state.sdwan;
  s.name = $("netName").value.trim();
  s.gateway = $("netGateway").value.trim();
  s.mode = $("netMode").value;
  s.centralNode = netCentralSS ? netCentralSS.getValue() : $("netCentral").value;
  s.punchPriority = +$("netPunch").value;
  s.mtu = +$("netMtu").value || 1420;
  document.querySelectorAll("#netTable tbody tr").forEach((tr) => {
    const idx = +tr.dataset.idx;
    if (s.Nodes[idx]) {
      s.Nodes[idx].ip = tr.querySelector(".ip-input").value.trim();
      s.Nodes[idx].resource = tr.querySelector(".res-input").value.trim();
    }
  });
  const saveBtn = $("btnNetSave");
  saveBtn.disabled = true;
  saveBtn.textContent = "保存中…";
  try {
    const rsp = await pxp("/api/v1/sdwan/edit", { method: "POST", body: s });
    if (rsp.status === 200) {
      // 回读服务端配置，确认子网代理等变更真实生效
      const verify = await pxp("/api/v1/sdwans/");
      const saved = verify.status === 200 && verify.data.Nodes ? verify.data : null;
      const savedRes = saved ? saved.Nodes.map((n) => `${n.name}:${n.resource || "∅"}`).join(" ") : "";
      const localRes = s.Nodes.map((n) => `${n.name}:${n.resource || "∅"}`).join(" ");
      const synced = saved && savedRes === localRes;
      toast(synced
        ? "✓ 已保存：子网代理配置已生效并下发"
        : "已提交保存（服务端确认回执中，如未生效请稍后点「↻ 刷新」核对）", "ok");
      if (saved) { state.sdwan = saved; renderNetwork(); }
    } else {
      toast("保存失败: " + JSON.stringify(rsp.data).slice(0, 160), "err");
    }
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = "保存整网配置";
  }
});

$("btnMemStatus").addEventListener("click", async () => {
  toast("正在拉取各成员隧道状态…");
  await loadMemStatus();
  toast("连接状态已更新", "ok");
});

/* 成员隧道明细（MsgPushReportMemApps=17，仅在线成员可查） */
$("btnMemRefresh").addEventListener("click", async () => {
  const member = memSelSS ? memSelSS.getValue() : $("memSel").value;
  if (!member) return;
  const dev = state.devices.find((d) => d.name === member);
  if (!dev || !onlineDev(dev)) { toast(`${member} 离线，无法读取隧道状态`, "err"); return; }
  $("memSummary").textContent = `正在读取 ${member} 的组网隧道…`;
  const rsp = await pushCmd(member, 17, {}, 1);
  if (rsp.status === 200 && Array.isArray(rsp.data.Apps)) {
    state.memApps = rsp.data.Apps.slice().sort((a, b) => (a.peerNode || "").localeCompare(b.peerNode || ""));
    $("memSummary").textContent = `${member} 共 ${state.memApps.length} 条组网隧道`;
  } else {
    state.memApps = [];
    $("memSummary").textContent = `${member} 无隧道数据或读取超时（对端全离线时可能发生）`;
  }
  renderMemApps();
});

/** 并发受限拉取全部在线成员的组网隧道状态（subtype=17），刷新成员表连接状态列 */
async function loadMemStatus() {
  const members = (state.sdwan && state.sdwan.Nodes) || [];
  const online = members.filter((m) => {
    const d = state.devices.find((x) => x.name === m.name);
    return d && onlineDev(d);
  });
  if (!online.length) return;
  const results = await runBatchLimit(online.map((m) => () => pushCmd(m.name, 17, {}, 1)), 4);
  for (let i = 0; i < online.length; i++) {
    const r = results[i];
    if (r && r.status === "fulfilled" && r.value && r.value.status === 200 && Array.isArray(r.value.data.Apps)) {
      state.memByNode[online[i].name] = r.value.data.Apps;
    }
  }
  if (state.selView === "networks") renderNetwork();
}

function renderMemApps() {
  const curMember = memSelSS ? memSelSS.getValue() : $("memSel").value;
  const tbody = $("memTable").querySelector("tbody");
  tbody.innerHTML = state.memApps.map((a) => {
    const relay = a.specRelayNode || a.relayNode || "";
    return `<tr>
      <td>${esc(curMember)}</td>
      <td class="name">${esc(a.peerNode || "-")}</td>
      <td><span class="tag">${esc(a.linkMode || "-")}</span></td>
      <td class="relay">${relay ? esc(relay) : '<span class="muted">P2P 直连</span>'}</td>
      <td>${a.isActive ? "✅ 活跃" : (a.enabled === 0 ? "⏸ 停用" : "· 未连接")}</td>
      <td>${esc(fmtTime(a.connectTime))}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="6" class="muted" style="text-align:center">点击右上「查看」读取所选成员的隧道状态</td></tr>`;
}

/* ---------------- 下载安装 ---------------- */
function renderDownload() {
  if (!state.latestVer) return;
  const it = state.profile?.token || (state.sdwan ? "" : "");
  let domain = "console.openpxp.com";
  try {
    domain = new URL(state.upstream || "https://console.openpxp.com").host;
  } catch {
    domain = (state.upstream || "").replace(/^https?:\/\//, "").split("/")[0] || "console.openpxp.com";
  }
  const ver = state.latestVer;
  $("dlVer").textContent = ver;
  if (it) {
    $("dlWin64").href = `https://${domain}/download/v1/${ver}/openp2p64-api.openp2p.cn-${it}-setup${ver}.exe`;
    $("dlWin32").href = `https://${domain}/download/v1/${ver}/openp2p32-api.openp2p.cn-${it}-setup${ver}.exe`;
    $("dlWinArm64").href = `https://${domain}/download/v1/${ver}/openp2parm64-api.openp2p.cn-${it}-setup${ver}.exe`;
    $("dlAndroid").href = `https://${domain}/download/v1/${ver}/openp2p-${ver}.apk`;
    const shCmd = (tool) =>
      `${tool} --no-check-certificate -O install.sh "https://${domain}/download/v1/${ver}/install.sh" && ` +
      `sudo bash ./install.sh --token ${it} --ver ${ver} --domain ${domain}`;
    $("dlLinuxCmd").textContent = shCmd("curl -k");
    $("dlWgetCmd").textContent = shCmd("wget");
    $("dlMacCmd").textContent = shCmd("curl -k");
    $("dlDockerCmd").textContent =
      `docker run -d --privileged --cap-add=NET_ADMIN --device=/dev/net/tun ` +
      `-e OPENP2P_TOKEN=${it} --name openp2p openp2p/openp2p:latest`;
  }
}

document.addEventListener("click", async (ev) => {
  // IP/值迷你复制按钮
  const mini = ev.target.closest(".copy-mini");
  if (mini) {
    ev.stopPropagation();
    await copyToClipboard(mini.dataset.copyText);
    const oldText = mini.textContent;
    mini.textContent = "✓";
    mini.style.color = "var(--accent)";
    setTimeout(() => {
      mini.textContent = oldText;
      mini.style.color = "";
    }, 1500);
    return;
  }
  // 下载页命令块复制按钮
  const btn = ev.target.closest(".copy-btn");
  if (!btn) return;
  await copyToClipboard($(btn.dataset.copy).textContent);
  const oldText = btn.textContent;
  btn.textContent = "已复制 ✓";
  btn.style.borderColor = "var(--accent)";
  btn.style.color = "var(--accent)";
  setTimeout(() => {
    btn.textContent = oldText;
    btn.style.borderColor = "";
    btn.style.color = "";
  }, 1800);
});

/* ---------------- 忘记密码（官方邮箱验证码流程） ---------------- */
$("linkForgot").addEventListener("click", () => {
  $("resetErr").classList.add("hidden");
  $("resetDialog").showModal();
});
$("rpCancel").addEventListener("click", () => $("resetDialog").close());

$("rpSendCode").addEventListener("click", async () => {
  const email = $("rpEmail").value.trim();
  const out = $("resetErr");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    out.textContent = "请输入合法邮箱地址";
    out.classList.remove("hidden");
    return;
  }
  const btn = $("rpSendCode");
  btn.disabled = true;
  btn.textContent = "发送中…";
  try {
    const rsp = await pxp(`/api/v2/verificationcode?email=${encodeURIComponent(email)}`, { method: "GET" });
    if (rsp.status === 200 && rsp.data.error === 0) {
      out.textContent = "✓ 验证码已发送，请查收邮箱";
      out.style.color = "var(--accent)";
      out.classList.remove("hidden");
      let sec = 60;
      const timer = setInterval(() => {
        btn.textContent = `${sec--}s`;
        if (sec < 0) { clearInterval(timer); btn.textContent = "发送验证码"; btn.disabled = false; }
      }, 1000);
    } else {
      out.textContent = "发送失败: " + JSON.stringify(rsp.data).slice(0, 100);
      out.style.color = "var(--red)";
      out.classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = "发送验证码";
    }
  } catch (e) {
    out.textContent = "发送异常: " + e;
    out.style.color = "var(--red)";
    out.classList.remove("hidden");
    btn.disabled = false;
  }
});

$("resetForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("resetErr");
  const pass = $("rpPass").value, pass2 = $("rpPass2").value;
  if (pass !== pass2) { out.textContent = "两次输入的密码不一致"; out.style.color = "var(--red)"; out.classList.remove("hidden"); return; }
  const rsp = await pxp("/api/v2/user/resetpwd", {
    method: "POST",
    body: { code: $("rpCode").value.trim(), password: pass, email: $("rpEmail").value.trim() },
  });
  if (rsp.status === 200 && rsp.data.error === 0) {
    $("resetDialog").close();
    toast("密码已重置，请用新密码登录", "ok");
  } else {
    out.textContent = "重置失败: " + JSON.stringify(rsp.data).slice(0, 120);
    out.style.color = "var(--red)";
    out.classList.remove("hidden");
  }
});

/* ---------------- 主题切换（暗色/亮色） ---------------- */
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("panelTheme", theme);
  const icon = theme === "light" ? "☀️" : "🌙";
  if ($("btnTheme")) $("btnTheme").textContent = icon;
  if ($("btnLoginTheme")) $("btnLoginTheme").textContent = icon;
}
$("btnTheme").addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
  reloadCaptcha(); // 验证码配色跟随主题
});
if ($("btnLoginTheme")) {
  $("btnLoginTheme").addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
    reloadCaptcha();
  });
}
applyTheme(localStorage.getItem("panelTheme") || "dark");

if ($("linkCancelLogin")) {
  $("linkCancelLogin").addEventListener("click", () => {
    $("loginView").classList.add("hidden");
    $("topBar").classList.remove("hidden");
    $("mainView").classList.remove("hidden");
  });
}

/* ---------------- 控制台设置与上游域名切换 ---------------- */
$("btnSettings").addEventListener("click", () => {
  $("settingsErr").classList.add("hidden");
  if ($("setCurUpstream")) $("setCurUpstream").value = state.upstream || "https://console.openpxp.com";
  $("settingsDialog").showModal();
});

$("setCancel").addEventListener("click", () => $("settingsDialog").close());

document.querySelectorAll("[data-upstream-set]").forEach((btn) => {
  btn.addEventListener("click", () => {
    if ($("setCurUpstream")) $("setCurUpstream").value = btn.dataset.upstreamSet;
  });
});

$("settingsForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("settingsErr").classList.add("hidden");
  const newUp = $("setCurUpstream").value.trim().replace(/\/+$/, "");
  if (!newUp.startsWith("http://") && !newUp.startsWith("https://")) {
    $("settingsErr").textContent = "官方控制台地址必须以 http:// 或 https:// 开头";
    $("settingsErr").classList.remove("hidden");
    return;
  }
  const rsp = await pxp2("/api/upstream", { upstream: newUp });
  if (rsp.error === 0) {
    state.upstream = rsp.upstream;
    if ($("loginUpstream")) $("loginUpstream").value = state.upstream;
    $("settingsDialog").close();
    toast(`已更新官方控制台地址为 ${state.upstream}`, "ok");
    renderDownload();
    await refreshAll();
  } else {
    $("settingsErr").textContent = rsp.detail || "保存设置失败";
    $("settingsErr").classList.remove("hidden");
  }
});

/* ---------------- 视图切换 ---------------- */
function switchView(name) {
  state.selView = name;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.id !== "view-" + name));
}
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    switchView(t.dataset.view);
    if (t.dataset.view === "tunnels" && !Object.keys(state.tunnelByNode).length) refreshTunnels();
    if (t.dataset.view === "networks" && !Object.keys(state.memByNode).length) loadMemStatus();
  })
);

/* ---------------- 启动 ---------------- */
(async () => {
  if (await checkState()) {
    await enterMain();
  } else {
    if ($("topBar")) $("topBar").classList.add("hidden");
    $("loginView").classList.remove("hidden");
    if ($("linkCancelLogin")) $("linkCancelLogin").classList.add("hidden");
    $("connState").textContent = "未登录";
    if (state.user) $("loginUser").value = state.user;
    await reloadCaptcha();
  }
})();
