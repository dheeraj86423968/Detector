// PDP console desktop wrapper (Electron). Loads the analyst console served by the gateway over TLS. The server is
// on-premises with a self-signed CA, so the wrapper pins the CA certificate fingerprint the operator configured (see
// pin.js) and rejects any other certificate — this is stricter than a browser clicking through a warning.
const { app, BrowserWindow, Menu, ipcMain, shell, dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { certMatchesPin, electronChainPems, verifyPinned } = require("./pin");

const CONFIG = path.join(app.getPath("userData"), "config.json");

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

let cfg = loadConfig();
let win = null;

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

function createWindow() {
  win = new BrowserWindow({
    width: 1400, height: 900, backgroundColor: "#0e141b",
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false },
  });
  installPinning(win.webContents.session);
  const target = cfg.serverUrl || "https://localhost";
  win.loadURL(target).catch(() => win.loadFile("settings.html"));
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: "deny" }; });
  buildMenu();
}

function buildMenu() {
  const template = [
    { label: "File", submenu: [
      { label: "Server settings…", click: () => win.loadFile("settings.html") },
      { label: "Open console", click: () => win.loadURL(cfg.serverUrl) },
      { type: "separator" }, { role: "quit" },
    ]},
    { label: "View", submenu: [ { role: "reload" }, { role: "forceReload" }, { role: "toggleDevTools" }, { type: "separator" }, { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { role: "togglefullscreen" } ]},
    { label: "Edit", submenu: [ { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" } ]},
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

ipcMain.handle("get-config", () => cfg);
ipcMain.handle("save-config", (_e, c) => {
  cfg = { ...cfg, ...c }; saveConfig(cfg);
  installPinning(win.webContents.session); // re-installing the proc also drops Chromium's cached verdicts for the old pin
  win.loadURL(cfg.serverUrl).catch(() => win.loadFile("settings.html"));
  return cfg;
});

app.whenReady().then(createWindow);
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
