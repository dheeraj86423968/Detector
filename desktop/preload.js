// Minimal, isolated bridge for the settings page only. The console itself runs as a normal web app with no Node
// access (contextIsolation on, nodeIntegration off).
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("pdp", {
  getConfig: () => ipcRenderer.invoke("get-config"),
  saveConfig: (c) => ipcRenderer.invoke("save-config", c),
});
