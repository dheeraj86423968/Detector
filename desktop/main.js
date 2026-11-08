// PDP console desktop wrapper (Electron). Loads the analyst console served by the gateway over TLS. The server is
// on-premises with a self-signed CA, so the wrapper pins the CA certificate fingerprint the operator configured (see
// pin.js) and rejects any other certificate — this is stricter than a browser clicking through a warning.
//
// Two windows (security review 2026-11-08, F12): the console window loads the remote page with NO preload, so page
// script has no bridge into the app; the settings window loads the local settings.html with the preload that exposes
// the configuration bridge, and the IPC handlers accept calls from that local page only. Navigation of the console
// window is confined to the configured server; links to other places open in the system browser (http/https only).
const { app, BrowserWindow, Menu, ipcMain, shell } = require("electron");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { certMatchesPin, electronChainPems, verifyPinned } = require("./pin");

const CONFIG = path.join(app.getPath("userData"), "config.json");
const SETTINGS_URL = "file://" + path.join(__dirname, "settings.html");

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG, "utf8"));
  } catch {
    return { serverUrl: process.env.PDP_SERVER_URL || "https://localhost", caFingerprint: process.env.PDP_CA_FINGERPRINT || "" };
  }
}
function saveConfig(c) {
  fs.mkdirSync(path.dirname(CONFIG), { recursive: true });
  fs.writeFileSync(CONFIG, JSON.stringify(c, null, 2));
}

// The configuration the settings page may set: an https URL (the gateway) and a fingerprint in one of pin.js's
// formats. Anything else is refused; the renderer never gets to write arbitrary keys into the configuration.
function validateConfig(c) {
  if (!c || typeof c !== "object") throw new Error("configuration must be an object");
  const out = {};
  if ("serverUrl" in c) {
    let u; try { u = new URL(String(c.serverUrl)); } catch { throw new Error("the gateway URL is not a valid URL"); }
    if (u.protocol !== "https:") throw new Error("the gateway URL must start with https://");
    if (u.username || u.password) throw new Error("the gateway URL must not carry credentials");
    out.serverUrl = u.origin + (u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, ""));
  }
  if ("caFingerprint" in c) {
    const fp = String(c.caFingerprint || "").trim();
    if (fp && !/^(sha256\/[A-Za-z0-9+/=]{40,48}|[0-9A-Fa-f]{64}|([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2})$/.test(fp)) {
      throw new Error("the CA fingerprint must be a hex sha256 (colons allowed) or an sha256/<base64> SPKI pin");
    }
    out.caFingerprint = fp;
  }
  return out;
}

let cfg = loadConfig();
let win = null;
let settingsWin = null;

// Certificate pinning (see pin.js): trust only a server whose leaf certificate is the pinned one, or chains by
// signature to the pinned CA and is valid for the hostname -- accepted even though the on-premises CA is self-signed
// and Chromium's own verdict (req.verificationResult) rejects it. The gateway presents only its leaf, so the CA is
// fetched from <server>/dl/ca.pem; that fetch needs no trust because the CA is used only if it matches the pin.
// Without a configured pin, trust only localhost (first-run convenience); everything else is rejected.
let pinnedCa = { pin: null, pem: null, at: 0, pending: null };

function fetchText(url, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const r = https.get(url, { rejectUnauthorized: false, timeout: timeoutMs }, (res) => {
      let b = ""; res.setEncoding("utf8");
      res.on("data", (d) => { b += d; if (b.length > 65536) r.destroy(); });
      res.on("end", () => resolve(res.statusCode === 200 ? b : null));
    });
    r.on("timeout", () => r.destroy()); r.on("error", () => resolve(null));
  });
}

function pinnedCaPem() {
  const pin = cfg.caFingerprint;
  if (pinnedCa.pin !== pin) pinnedCa = { pin, pem: null, at: 0, pending: null };
  if (pinnedCa.pem || pinnedCa.pending) return pinnedCa.pending || Promise.resolve(pinnedCa.pem);
  if (Date.now() - pinnedCa.at < 30000) return Promise.resolve(null); // failed recently, do not hammer the server
  let url; try { url = new URL("/dl/ca.pem", cfg.serverUrl); } catch { return Promise.resolve(null); }
  const slot = pinnedCa;
  slot.pending = fetchText(url).then((pem) => {
    let ok = false; try { ok = !!pem && certMatchesPin(pem, pin); } catch { ok = false; }
    slot.pem = ok ? pem : null; slot.at = Date.now(); slot.pending = null;
    if (!ok) console.warn(`could not obtain a CA matching the pin from ${url}`);
    return slot.pem;
  });
  return slot.pending;
}

function serverHost() { try { return new URL(cfg.serverUrl).hostname; } catch { return null; } }
function serverOrigin() { try { return new URL(cfg.serverUrl).origin; } catch { return null; } }

function installPinning(ses) {
  ses.setCertificateVerifyProc((req, cb) => {
    if (!cfg.caFingerprint) return cb(req.hostname === "localhost" || req.hostname === "127.0.0.1" ? 0 : -2);
    const pems = electronChainPems(req.certificate);
    const check = (caPem) => verifyPinned(pems, cfg.caFingerprint, { hostname: req.hostname, caPem });
    const v = check(pinnedCa.pin === cfg.caFingerprint ? pinnedCa.pem : null);
    if (v.ok || req.hostname !== serverHost()) {
      if (!v.ok) console.warn(`rejecting certificate for ${req.hostname}: ${v.reason} (chromium: ${req.verificationResult})`);
      return cb(v.ok ? 0 : -2);
    }
    pinnedCaPem().then((caPem) => {
      const v2 = check(caPem);
      if (!v2.ok) console.warn(`rejecting certificate for ${req.hostname}: ${v2.reason} (chromium: ${req.verificationResult})`);
      cb(v2.ok ? 0 : -2);
    });
  });
}

// Only http(s) leaves the app; file:, ms-msdt:, smb: and the like never reach the system (shell.openExternal on an
// attacker-chosen URL is a code-execution vector on Windows and macOS).
function openOutside(url) {
  let u; try { u = new URL(url); } catch { return; }
  if (u.protocol === "https:" || u.protocol === "http:") shell.openExternal(u.href);
  else console.warn(`refusing to open ${u.protocol} link outside the app`);
}

// The console window may only navigate within the configured server (its origin); anything else is refused and,
// for http(s), handed to the system browser instead.
function confine(contents) {
  const allowed = (url) => { try { const u = new URL(url); return u.origin === serverOrigin(); } catch { return false; } };
  contents.on("will-navigate", (ev, url) => {
    if (allowed(url)) return;
    ev.preventDefault(); openOutside(url);
  });
  contents.on("will-redirect", (ev, url) => { if (!allowed(url)) ev.preventDefault(); });
  contents.setWindowOpenHandler(({ url }) => { if (!allowed(url)) openOutside(url); return { action: "deny" }; });
  contents.on("will-attach-webview", (ev) => ev.preventDefault());
}

function createWindow() {
  win = new BrowserWindow({
    width: 1400, height: 900, backgroundColor: "#0e141b",
    // the remote console gets no preload and no Node: it is an ordinary web page with no bridge into this app
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, webviewTag: false },
  });
  installPinning(win.webContents.session);
  confine(win.webContents);
  win.on("closed", () => { win = null; });
  openConsole();
  buildMenu();
}

function openConsole() {
  if (!win) return;
  const target = cfg.serverUrl || "https://localhost";
  win.loadURL(target).catch(() => openSettings());
}

function openSettings() {
  if (settingsWin) { settingsWin.focus(); return; }
  settingsWin = new BrowserWindow({
    width: 680, height: 720, backgroundColor: "#0e141b", parent: win || undefined,
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  settingsWin.setMenuBarVisibility(false);
  settingsWin.webContents.on("will-navigate", (ev) => ev.preventDefault());       // the settings page never leaves itself
  settingsWin.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  settingsWin.on("closed", () => { settingsWin = null; });
  settingsWin.loadFile("settings.html");
}

function buildMenu() {
  const template = [
    { label: "File", submenu: [
      { label: "Server settings…", click: () => openSettings() },
      { label: "Open console", click: () => openConsole() },
      { type: "separator" }, { role: "quit" },
    ]},
    { label: "View", submenu: [ { role: "reload" }, { role: "forceReload" }, { type: "separator" }, { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { role: "togglefullscreen" } ]},
    { label: "Edit", submenu: [ { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" } ]},
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// IPC: only the local settings page (file://.../settings.html, loaded with the preload) may read or change the
// configuration. A call from any other frame - the remote console included - is refused.
function fromSettingsPage(event) {
  const frame = event.senderFrame;
  const url = frame && frame.url ? frame.url : "";
  return event.sender === (settingsWin && settingsWin.webContents) && url.startsWith("file://") && url.startsWith(SETTINGS_URL);
}

ipcMain.handle("get-config", (e) => {
  if (!fromSettingsPage(e)) throw new Error("not allowed");
  return cfg;
});
ipcMain.handle("save-config", (e, c) => {
  if (!fromSettingsPage(e)) throw new Error("not allowed");
  cfg = { ...cfg, ...validateConfig(c) }; saveConfig(cfg);
  if (win) {
    installPinning(win.webContents.session); // re-installing the proc also drops Chromium's cached verdicts for the old pin
    openConsole();
  } else {
    createWindow();
  }
  if (settingsWin) settingsWin.close();
  return cfg;
});

app.whenReady().then(createWindow);
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
// every new web contents (should there ever be one) is confined the same way
app.on("web-contents-created", (_e, contents) => { if (contents.getType() === "webview") contents.destroy(); });
