'use strict';
/*
 * NexDesk - main process
 * Responsibilities:
 *   - window + security hardening
 *   - screen capture source selection
 *   - remote input injection (Windows, via a hidden PowerShell/user32 helper)
 *   - config persistence + unattended-access password verifier (PBKDF2 + HMAC challenge/response)
 *   - safe file receiving (streamed to Downloads/NexDesk, sanitized names)
 */
const {
  app, BrowserWindow, ipcMain, desktopCapturer, session, screen,
  shell, clipboard, Notification, Menu
} = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

// ---------------------------------------------------------------------------
// Profiles (lets you run two instances on one PC for testing: NEXDESK_PROFILE=a / b)
// ---------------------------------------------------------------------------
const PROFILE = (process.env.NEXDESK_PROFILE || '').replace(/[^a-z0-9_-]/gi, '');
if (PROFILE) {
  app.setPath('userData', path.join(app.getPath('appData'), 'NexDesk-' + PROFILE));
} else if (!app.requestSingleInstanceLock()) {
  app.quit();
}

app.setAppUserModelId('io.github.nexdesk');

// Screen capture should not be throttled when the window is in the background.
app.commandLine.appendSwitch('disable-renderer-backgrounding');
app.commandLine.appendSwitch('disable-background-timer-throttling');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const CONFIG_FILE = () => path.join(app.getPath('userData'), 'config.json');
const PBKDF2_ITER = 210000;

const DEFAULTS = {
  id: null,
  name: os.hostname(),
  lang: null,
  unattended: false,
  unattendedSalt: null,
  unattendedKey: null,
  turn: { url: '', username: '', credential: '' },
  recent: [],
  quality: 'balanced',
  askBeforeFiles: false
};

let config = { ...DEFAULTS };

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE(), 'utf8'));
    config = { ...DEFAULTS, ...raw, turn: { ...DEFAULTS.turn, ...(raw.turn || {}) } };
  } catch {
    config = { ...DEFAULTS };
  }
  if (!config.lang) {
    config.lang = (app.getLocale() || '').toLowerCase().startsWith('tr') ? 'tr' : 'en';
  }
}

function saveConfig() {
  try {
    fs.mkdirSync(app.getPath('userData'), { recursive: true });
    const tmp = CONFIG_FILE() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, CONFIG_FILE());
  } catch (e) {
    console.error('config save failed', e);
  }
}

// Never hand secrets to the renderer.
function publicConfig() {
  const { unattendedKey, unattendedSalt, ...rest } = config;
  return { ...rest, hasUnattendedPassword: !!unattendedKey, platform: process.platform, version: app.getVersion() };
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------
let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 940,
    minHeight: 620,
    backgroundColor: '#0b0d17',
    show: false,
    title: 'NexDesk',
    icon: path.join(__dirname, 'renderer', 'assets', 'icon.png'),
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#00000000', symbolColor: '#c9cfe6', height: 44 },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
      backgroundThrottling: false
    }
  });

  Menu.setApplicationMenu(null);
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.once('ready-to-show', () => win.show());

  // Hardening: no navigation, no popups.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  if (process.env.NEXDESK_DEVTOOLS) win.webContents.openDevTools({ mode: 'detach' });

  // Development-only automation (used to test two instances and capture README screenshots).
  if (!app.isPackaged && process.env.NEXDESK_DEBUG) {
    win.webContents.on('console-message', (_e, level, message) => console.log(`[${PROFILE || 'main'}] ${message}`));
    if (process.env.NEXDESK_AUTOMATE) {
      win.webContents.once('did-finish-load', () => {
        const code = fs.readFileSync(process.env.NEXDESK_AUTOMATE, 'utf8');
        setTimeout(() => win.webContents.executeJavaScript(code).catch((e) => console.error(e)), 500);
      });
    }
    ipcMain.handle('debug:shot', async (_e, name) => {
      const img = await win.webContents.capturePage();
      const dir = process.env.NEXDESK_SHOT_DIR || app.getPath('temp');
      const file = path.join(dir, String(name).replace(/[^a-z0-9_-]/gi, '') + '.png');
      fs.writeFileSync(file, img.toPNG());
      return file;
    });
  }
  win.on('closed', () => { win = null; stopInput(); });
}

app.on('second-instance', () => {
  if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
});

app.whenReady().then(() => {
  loadConfig();

  const ses = session.defaultSession;

  // Only allow the permissions we actually need.
  ses.setPermissionRequestHandler((wc, permission, cb) => {
    cb(['media', 'display-capture', 'notifications', 'fullscreen', 'clipboard-sanitized-write'].includes(permission));
  });

  // Screen capture: pick the selected (default: primary) display without a picker.
  ses.setDisplayMediaRequestHandler(async (_req, cb) => {
    try {
      const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 0, height: 0 } });
      const target = captureDisplay();
      const src = sources.find((s) => String(s.display_id) === String(target.id)) || sources[0];
      cb({ video: src });
    } catch (e) {
      console.error(e);
      cb({});
    }
  });

  createWindow();
});

app.on('window-all-closed', () => app.quit());
app.on('before-quit', stopInput);

// Prevent any webview / unexpected web contents.
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-attach-webview', (e) => e.preventDefault());
});

// ---------------------------------------------------------------------------
// Displays (input mapping targets the captured display)
// ---------------------------------------------------------------------------
let captureDisplayId = null;
function captureDisplay() {
  const all = screen.getAllDisplays();
  return all.find((d) => d.id === captureDisplayId) || screen.getPrimaryDisplay();
}

// ---------------------------------------------------------------------------
// Remote input (Windows). A tiny C# shim compiled at runtime by PowerShell;
// commands are plain numeric lines on stdin, so there is no code injection surface.
// ---------------------------------------------------------------------------
const INPUT_PS1 = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$src = @"
using System;
using System.Runtime.InteropServices;
public static class NxInput {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, int data, UIntPtr extra);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr extra);
  [DllImport("user32.dll")] public static extern int GetSystemMetrics(int i);
}
"@
Add-Type -TypeDefinition $src
[void][NxInput]::SetProcessDPIAware()
$z = [UIntPtr]::Zero
$down = @(0x0002, 0x0008, 0x0020)
$up   = @(0x0004, 0x0010, 0x0040)
[Console]::Out.WriteLine('ready')
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($line -eq $null) { break }
  $p = $line.Split(' ')
  switch ($p[0]) {
    'm' { [NxInput]::mouse_event(0xC001, [int]$p[1], [int]$p[2], 0, $z) }
    'd' { [NxInput]::mouse_event($down[[int]$p[1]], 0, 0, 0, $z) }
    'u' { [NxInput]::mouse_event($up[[int]$p[1]], 0, 0, 0, $z) }
    'w' { [NxInput]::mouse_event(0x0800, 0, 0, [int]$p[1], $z) }
    'h' { [NxInput]::mouse_event(0x1000, 0, 0, [int]$p[1], $z) }
    'k' {
      $fl = 0x0008
      if ($p[2] -eq '1') { $fl = $fl -bor 0x0001 }
      if ($p[3] -eq '1') { $fl = $fl -bor 0x0002 }
      [NxInput]::keybd_event(0, [byte][int]$p[1], $fl, $z)
    }
    'q' { break }
  }
}
`;

let inputProc = null;

function startInput() {
  if (process.platform !== 'win32') return false;
  if (inputProc) return true;
  const scriptPath = path.join(app.getPath('userData'), 'nexdesk-input.ps1');
  fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
  fs.writeFileSync(scriptPath, INPUT_PS1, 'utf8');
  inputProc = spawn('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath
  ], { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
  inputProc.stdin.on('error', () => {});
  inputProc.stdout.on('data', () => {});
  inputProc.on('exit', () => { inputProc = null; });
  return true;
}

function stopInput() {
  if (!inputProc) return;
  try { inputProc.stdin.write('q\n'); inputProc.stdin.end(); } catch {}
  const p = inputProc;
  setTimeout(() => { try { p.kill(); } catch {} }, 500);
  inputProc = null;
}

const clampInt = (v, lo, hi) => {
  const n = Math.round(Number(v));
  if (!Number.isFinite(n)) return null;
  return Math.min(hi, Math.max(lo, n));
};

// Map normalized (0..1) coords on the captured display to the virtual desktop
// absolute space (0..65535) used by MOUSEEVENTF_VIRTUALDESK.
function toAbsolute(nx, ny) {
  const d = captureDisplay();
  const all = screen.getAllDisplays();
  const minX = Math.min(...all.map((a) => a.bounds.x));
  const minY = Math.min(...all.map((a) => a.bounds.y));
  const maxX = Math.max(...all.map((a) => a.bounds.x + a.bounds.width));
  const maxY = Math.max(...all.map((a) => a.bounds.y + a.bounds.height));
  const px = d.bounds.x + nx * (d.bounds.width - 1);
  const py = d.bounds.y + ny * (d.bounds.height - 1);
  return [
    Math.round(((px - minX) * 65535) / Math.max(1, maxX - minX - 1)),
    Math.round(((py - minY) * 65535) / Math.max(1, maxY - minY - 1))
  ];
}

ipcMain.handle('input:start', () => startInput());
ipcMain.handle('input:stop', () => stopInput());

ipcMain.on('input:event', (_e, ev) => {
  if (!inputProc || !ev || typeof ev !== 'object') return;
  let line = null;
  switch (ev.t) {
    case 'm': {
      const x = Number(ev.x), y = Number(ev.y);
      if (!(x >= 0 && x <= 1 && y >= 0 && y <= 1)) return;
      const [ax, ay] = toAbsolute(x, y);
      line = `m ${ax} ${ay}`;
      break;
    }
    case 'd': case 'u': {
      const b = clampInt(ev.b, 0, 2);
      if (b === null) return;
      line = `${ev.t} ${b}`;
      break;
    }
    case 'w': case 'h': {
      const d = clampInt(ev.d, -2400, 2400);
      if (!d) return;
      line = `${ev.t} ${d}`;
      break;
    }
    case 'k': {
      const s = clampInt(ev.s, 1, 0x7f);
      if (s === null) return;
      line = `k ${s} ${ev.e ? 1 : 0} ${ev.u ? 1 : 0}`;
      break;
    }
    default: return;
  }
  try { inputProc.stdin.write(line + '\n'); } catch {}
});

// ---------------------------------------------------------------------------
// Config IPC
// ---------------------------------------------------------------------------
ipcMain.handle('config:get', () => publicConfig());

ipcMain.handle('config:set', (_e, patch) => {
  if (!patch || typeof patch !== 'object') return publicConfig();
  const allowed = ['id', 'name', 'lang', 'unattended', 'turn', 'recent', 'quality', 'askBeforeFiles'];
  for (const k of allowed) {
    if (k in patch) config[k] = patch[k];
  }
  if (typeof config.name === 'string') config.name = config.name.slice(0, 48);
  if (Array.isArray(config.recent)) config.recent = config.recent.slice(0, 12);
  saveConfig();
  return publicConfig();
});

// ---------------------------------------------------------------------------
// Unattended access: PBKDF2-SHA256 verifier + HMAC challenge/response.
// The password itself never travels over the network; the proof is bound to the
// session's DTLS fingerprints, so a relayed (MITM) proof is useless.
// ---------------------------------------------------------------------------
ipcMain.handle('auth:setPassword', (_e, pw) => {
  if (typeof pw !== 'string' || pw.length === 0) {
    config.unattendedKey = null;
    config.unattendedSalt = null;
    config.unattended = false;
  } else {
    if (pw.length < 8) throw new Error('too-short');
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(pw, salt, PBKDF2_ITER, 32, 'sha256');
    config.unattendedSalt = salt.toString('base64');
    config.unattendedKey = key.toString('base64');
  }
  saveConfig();
  return publicConfig();
});

ipcMain.handle('auth:challenge', () => {
  if (!config.unattended || !config.unattendedKey) return null;
  return {
    salt: config.unattendedSalt,
    iter: PBKDF2_ITER,
    nonce: crypto.randomBytes(32).toString('base64')
  };
});

ipcMain.handle('auth:prove', (_e, { password, salt, iter, nonce, binding }) => {
  if (typeof password !== 'string' || typeof salt !== 'string' || typeof nonce !== 'string') return null;
  const it = clampInt(iter, 10000, 2000000);
  const key = crypto.pbkdf2Sync(password, Buffer.from(salt, 'base64'), it, 32, 'sha256');
  return crypto.createHmac('sha256', key).update(nonce + '|' + String(binding || '')).digest('base64');
});

ipcMain.handle('auth:verify', (_e, { nonce, binding, proof }) => {
  if (!config.unattended || !config.unattendedKey || typeof proof !== 'string') return false;
  const key = Buffer.from(config.unattendedKey, 'base64');
  const expected = crypto.createHmac('sha256', key).update(String(nonce) + '|' + String(binding || '')).digest();
  let given;
  try { given = Buffer.from(proof, 'base64'); } catch { return false; }
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
});

ipcMain.handle('crypto:sha256', (_e, text) =>
  crypto.createHash('sha256').update(String(text)).digest('hex'));

// ---------------------------------------------------------------------------
// Files: streamed to Downloads/NexDesk, names sanitized, never executed.
// ---------------------------------------------------------------------------
const MAX_FILE = 512 * 1024 * 1024;
const receiving = new Map();

function receiveDir() {
  const dir = path.join(app.getPath('downloads'), 'NexDesk');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function sanitizeName(name) {
  let n = path.basename(String(name || 'file')).normalize('NFC');
  n = n.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '');
  if (/^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(n)) n = '_' + n;
  if (!n) n = 'file';
  return n.slice(0, 180);
}

function uniquePath(dir, name) {
  const ext = path.extname(name);
  const base = name.slice(0, name.length - ext.length);
  let p = path.join(dir, name);
  for (let i = 1; fs.existsSync(p); i++) p = path.join(dir, `${base} (${i})${ext}`);
  return p;
}

ipcMain.handle('file:begin', (_e, { id, name, size }) => {
  if (typeof id !== 'string' || receiving.has(id)) throw new Error('bad-id');
  if (!(size >= 0 && size <= MAX_FILE)) throw new Error('too-large');
  const dir = receiveDir();
  const finalPath = uniquePath(dir, sanitizeName(name));
  const partPath = finalPath + '.nxpart';
  const stream = fs.createWriteStream(partPath, { flags: 'wx' });
  receiving.set(id, { stream, partPath, finalPath, size, written: 0 });
  return { path: finalPath, name: path.basename(finalPath) };
});

ipcMain.handle('file:chunk', (_e, { id, data }) => new Promise((resolve, reject) => {
  const r = receiving.get(id);
  if (!r) return reject(new Error('unknown'));
  const buf = Buffer.from(data);
  r.written += buf.length;
  if (r.written > r.size) return reject(new Error('overflow'));
  r.stream.write(buf, (err) => (err ? reject(err) : resolve(r.written)));
}));

ipcMain.handle('file:end', (_e, { id }) => new Promise((resolve, reject) => {
  const r = receiving.get(id);
  if (!r) return reject(new Error('unknown'));
  receiving.delete(id);
  r.stream.end(() => {
    if (r.written !== r.size) {
      fs.rm(r.partPath, { force: true }, () => {});
      return reject(new Error('size-mismatch'));
    }
    const finalPath = fs.existsSync(r.finalPath) ? uniquePath(path.dirname(r.finalPath), path.basename(r.finalPath)) : r.finalPath;
    fs.rename(r.partPath, finalPath, (err) => (err ? reject(err) : resolve(finalPath)));
  });
}));

ipcMain.handle('file:abort', (_e, { id }) => {
  const r = receiving.get(id);
  if (!r) return;
  receiving.delete(id);
  r.stream.destroy();
  fs.rm(r.partPath, { force: true }, () => {});
});

ipcMain.handle('file:reveal', (_e, p) => {
  const dir = receiveDir();
  if (typeof p === 'string' && path.resolve(p).startsWith(path.resolve(dir))) shell.showItemInFolder(p);
  else shell.openPath(dir);
});

ipcMain.handle('file:openDir', () => shell.openPath(receiveDir()));

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------
ipcMain.handle('clip:read', () => clipboard.readText().slice(0, 1_000_000));
ipcMain.handle('clip:write', (_e, text) => { clipboard.writeText(String(text).slice(0, 1_000_000)); });

ipcMain.handle('displays:list', () => screen.getAllDisplays().map((d, i) => ({
  id: d.id, index: i, primary: d.id === screen.getPrimaryDisplay().id,
  width: Math.round(d.bounds.width * d.scaleFactor), height: Math.round(d.bounds.height * d.scaleFactor)
})));
ipcMain.handle('displays:select', (_e, id) => { captureDisplayId = Number(id) || null; return captureDisplay().id; });

ipcMain.handle('win:attention', () => {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.flashFrame(true);
  setTimeout(() => win && win.flashFrame(false), 8000);
});

ipcMain.handle('win:notify', (_e, { title, body }) => {
  if (Notification.isSupported()) new Notification({ title: String(title), body: String(body), silent: false }).show();
});

ipcMain.handle('win:fullscreen', (_e, on) => { if (win) win.setFullScreen(!!on); return win ? win.isFullScreen() : false; });

ipcMain.handle('win:overlay', (_e, color) => {
  try { win && win.setTitleBarOverlay({ color: '#00000000', symbolColor: color || '#c9cfe6', height: 44 }); } catch {}
});

ipcMain.handle('open:external', (_e, url) => {
  if (typeof url === 'string' && /^https:\/\/github\.com\//.test(url)) shell.openExternal(url);
});
