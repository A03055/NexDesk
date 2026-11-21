'use strict';
/* global Peer, NX_I18N, NX_KEYMAP, nx */

// ===========================================================================
// Constants
// ===========================================================================
const PREFIX = 'nexdesk-v1-';
const PROTO = 1;
const CHUNK = 64 * 1024;
const MAX_FILE = 512 * 1024 * 1024;
const ACCEPT_TIMEOUT = 60;           // seconds the host has to answer
const MAX_FAILS = 5;                 // wrong passwords before lockout
const LOCK_MS = 5 * 60 * 1000;
// maxH caps the encoded height: software encoders (no GPU, VMs, Windows Sandbox)
// can't keep up with 1440p/4K, and 1080p is plenty for remote support.
const QUALITY = {
  high:     { bitrate: 12_000_000, fps: 60, maxH: 2160, pref: 'maintain-resolution', hint: 'detail' },
  balanced: { bitrate: 5_000_000,  fps: 30, maxH: 1080, pref: 'balanced',            hint: 'detail' },
  fast:     { bitrate: 1_500_000,  fps: 24, maxH: 720,  pref: 'maintain-framerate',  hint: 'motion' }
};
const HEARTBEAT_TIMEOUT = 8000;      // ms without any sign of life -> connection lost
const RT_CHANNEL_ID = 1000;          // negotiated low-latency channel (mouse, cursor, heartbeat)

// ===========================================================================
// State
// ===========================================================================
let cfg = null;
let peer = null;
let peerOpenRetries = 0;

const S = {
  mode: null,            // null | 'connecting' | 'viewer' | 'host'
  conn: null,            // PeerJS DataConnection
  call: null,            // PeerJS MediaConnection
  stream: null,          // local capture stream (host)
  partner: null,         // { id, name }
  perms: { control: true, files: true },
  allowControl: true,
  sas: null,
  binding: null,
  pending: null,         // host: pending incoming request
  auth: null,            // viewer: challenge from host
  timers: [],
  statsTimer: null,
  lastStats: null,
  unread: 0,
  drawerTab: 'chat',
  downKeys: new Set(),   // viewer: keys currently held
  hostDown: new Set(),   // host: keys/buttons injected and still held
  failLog: [],           // host: timestamps of failed password attempts
  rt: null,              // RTCDataChannel: unordered, unreliable, low latency
  hbTimer: null,
  cursorTimer: null,
  lastSeen: 0
};
const transfers = new Map();
let sendQueue = Promise.resolve();

// ===========================================================================
// Tiny helpers
// ===========================================================================
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function t(key, vars) {
  const lang = (cfg && cfg.lang) || 'tr';
  let s = (NX_I18N[lang] && NX_I18N[lang][key]) || NX_I18N.en[key] || key;
  if (vars) for (const k in vars) s = s.split('{' + k + '}').join(vars[k]);
  return s;
}

function applyI18n() {
  document.documentElement.lang = cfg.lang;
  $$('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$('[data-i18n-title]').forEach((el) => { el.title = t(el.dataset.i18nTitle); });
  $$('[data-i18n-ph]').forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  renderRecent();
  renderPwState();
  setStatus(currentStatus);
}

const fmtId = (id) => String(id || '').replace(/\D/g, '').replace(/(\d{3})(?=\d)/g, '$1 ').trim();
const cleanId = (v) => String(v || '').replace(/\D/g, '').slice(0, 9);
const initials = (name) => (String(name || '?').trim().split(/\s+/).map((p) => p[0]).join('').slice(0, 2) || '?').toUpperCase();
const fmtBytes = (n) => {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
};
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeName = (s) => String(s || '').replace(/[\u0000-\u001f‪-‮⁦-⁩]/g, '').trim().slice(0, 48) || 'NexDesk';

function newId() {
  const a = crypto.getRandomValues(new Uint32Array(2));
  return String(100000000 + ((a[0] * 4294967296 + a[1]) % 900000000));
}

function toast(msg, type = '', action = null) {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = '<span class="t-dot"></span><span></span>';
  el.children[1].textContent = msg;
  if (action) {
    const b = document.createElement('button');
    b.textContent = action.label;
    b.onclick = action.fn;
    el.appendChild(b);
  }
  $('#toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, action ? 6000 : 3600);
}

function later(fn, ms) { const id = setTimeout(fn, ms); S.timers.push(id); return id; }
function clearTimers() { S.timers.forEach(clearTimeout); S.timers = []; }

// ===========================================================================
// Status pill
// ===========================================================================
let currentStatus = 'connecting';
function setStatus(st) {
  currentStatus = st;
  const pill = $('#statusPill');
  pill.className = 'pill status-' + st;
  $('#statusText').textContent = t('status.' + st);
}

// ===========================================================================
// Security code (short authentication string) from the DTLS fingerprints.
// Both peers see the same code only if nobody sits in the middle.
// ===========================================================================
async function computeSas(conn) {
  for (let i = 0; i < 40; i++) {
    const pc = conn.peerConnection;
    const l = pc && pc.localDescription && pc.localDescription.sdp;
    const r = pc && pc.remoteDescription && pc.remoteDescription.sdp;
    if (l && r) {
      const fp = (sdp) => ((sdp.match(/a=fingerprint:\S+ ([0-9A-F:]+)/i) || [])[1] || '').toUpperCase();
      const both = [fp(l), fp(r)].sort().join('|');
      const hex = await nx.sha256('nexdesk-sas|' + both);
      const num = (parseInt(hex.slice(0, 12), 16) % 100000000).toString().padStart(8, '0');
      return { sas: num.slice(0, 4) + ' ' + num.slice(4), binding: hex };
    }
    await sleep(100);
  }
  return { sas: '—', binding: '' };
}

// ===========================================================================
// Peer (signaling)
// ===========================================================================
function iceServers() {
  const list = [
    { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
    { urls: 'stun:stun.cloudflare.com:3478' }
  ];
  if (cfg.turn && cfg.turn.url) {
    list.push({ urls: cfg.turn.url.trim(), username: cfg.turn.username || undefined, credential: cfg.turn.credential || undefined });
  }
  return list;
}

function startPeer() {
  if (peer) { try { peer.destroy(); } catch {} }
  setStatus('connecting');
  peer = new Peer(PREFIX + cfg.id, { config: { iceServers: iceServers() }, debug: 1 });

  peer.on('open', () => { peerOpenRetries = 0; setStatus('online'); });

  peer.on('disconnected', () => {
    setStatus('connecting');
    setTimeout(() => { if (peer && !peer.destroyed && peer.disconnected) try { peer.reconnect(); } catch {} }, 2500);
  });

  peer.on('error', async (err) => {
    console.warn('peer error', err.type, err.message);
    switch (err.type) {
      case 'unavailable-id':
        // Our ID is still registered (e.g. quick restart). Retry a few times, then pick a new one.
        if (++peerOpenRetries > 4) { cfg = await nx.setConfig({ id: newId() }); renderMe(); peerOpenRetries = 0; }
        setTimeout(startPeer, 3000);
        break;
      case 'peer-unavailable':
        if (S.mode === 'connecting') failConnect('err.offline');
        break;
      case 'network': case 'server-error': case 'socket-error': case 'socket-closed':
        setStatus('offline');
        setTimeout(() => { if (peer && peer.disconnected && !peer.destroyed) try { peer.reconnect(); } catch { startPeer(); } else if (!peer || peer.destroyed) startPeer(); }, 5000);
        break;
      default:
        break;
    }
  });

  peer.on('connection', onIncomingConnection);
  peer.on('call', onIncomingCall);
}

// ===========================================================================
// VIEWER: connect to someone
// ===========================================================================
async function connectTo(rawId) {
  const id = cleanId(rawId);
  if (id.length !== 9) return toast(t('err.badId'), 'err');
  if (id === cfg.id) return toast(t('err.self'), 'err');
  if (S.mode) return toast(t('err.busySelf'), 'err');
  if (!peer || !peer.open) return toast(t('err.notReady'), 'err');

  S.mode = 'connecting';
  S.partner = { id, name: id };
  S.auth = null;
  showConnecting();

  const conn = peer.connect(PREFIX + id, { reliable: true, serialization: 'binary', metadata: { app: 'nexdesk', v: PROTO } });
  S.conn = conn;

  later(() => { if (S.mode === 'connecting' && S.conn === conn && !conn.open) failConnect('err.offline'); }, 25000);
  later(() => { if (S.mode === 'connecting' && S.conn === conn) failConnect('err.timeout'); }, (ACCEPT_TIMEOUT + 15) * 1000);

  conn.on('open', async () => {
    if (S.conn !== conn) return;
    const { sas, binding } = await computeSas(conn);
    S.sas = sas; S.binding = binding;
    $('#cnSas').textContent = sas;
    $('#cnSasBox').hidden = false;
    $('#cnText').textContent = t('cn.waiting');
    conn.send({ type: 'hello', v: PROTO, id: cfg.id, name: cfg.name });
  });
  conn.on('data', (m) => onData(conn, m));
  conn.on('close', () => onConnClosed(conn));
  conn.on('error', (e) => { console.warn('conn error', e); onConnClosed(conn); });
}

function failConnect(key) {
  if (S.mode !== 'connecting') return;
  const c = S.conn;
  resetSession();
  try { c && c.close(); } catch {}
  hideConnecting();
  toast(t(key), 'err');
}

function showConnecting() {
  $('#cnTitle').textContent = t('cn.title');
  $('#cnText').textContent = t('cn.reaching');
  $('#cnSasBox').hidden = true;
  $('#pwForm').hidden = true;
  $('#pwInput').value = '';
  $('#connectingModal').hidden = false;
}
function hideConnecting() { $('#connectingModal').hidden = true; }

async function submitPassword(e) {
  e.preventDefault();
  const pw = $('#pwInput').value;
  if (!pw || !S.auth || !S.conn) return;
  $('#cnText').textContent = t('cn.checking');
  const proof = await nx.prove({ password: pw, salt: S.auth.salt, iter: S.auth.iter, nonce: S.auth.nonce, binding: S.binding });
  $('#pwInput').value = '';
  if (proof && S.conn && S.conn.open) S.conn.send({ type: 'auth', proof });
}

// The host calls us with its screen once it accepted.
function onIncomingCall(call) {
  const ok = (S.mode === 'viewer' || S.mode === 'connecting') && S.conn && call.peer === S.conn.peer;
  if (!ok) { try { call.close(); } catch {} return; }
  S.call = call;
  call.answer();
  call.on('stream', (stream) => {
    // Lowest possible latency: don't let the jitter buffer hold frames back.
    try {
      call.peerConnection.getReceivers().forEach((r) => {
        try { r.jitterBufferTarget = 0; } catch {}
        try { r.playoutDelayHint = 0; } catch {}
      });
    } catch {}
    const v = $('#remoteVideo');
    v.srcObject = stream;
    v.play().catch(() => {});
    $('#remoteWaiting').hidden = true;
  });
  call.on('close', () => { if (S.call === call && S.mode === 'viewer') endSession('end.lost', false); });
  call.on('error', () => {});
}

function onAccepted(msg) {
  clearTimers();
  S.mode = 'viewer';
  S.partner.name = safeName(msg.name);
  S.perms = { control: !!(msg.perms && msg.perms.control), files: !!(msg.perms && msg.perms.files) };
  hideConnecting();
  openRealtime();
  openViewerUI();
  addRecent(S.partner.id, S.partner.name);
  toast(t('ok.connected', { name: S.partner.name }), 'ok');
  addSysMsg(t('sys.joined'));
  S.conn.send({ type: 'quality', level: cfg.quality });
  renderDisplayMenu(Array.isArray(msg.displays) ? msg.displays : [], msg.display);
}

// Viewer: let the user switch between the host's monitors.
function renderDisplayMenu(displays, current) {
  const menu = $('#displayMenu');
  menu.innerHTML = '';
  $('#displayWrap').hidden = displays.length < 2;
  displays.slice(0, 8).forEach((d, i) => {
    const b = document.createElement('button');
    const w = Number(d.width) || 0, h = Number(d.height) || 0;
    b.textContent = `${t('set.screen')} ${i + 1} — ${w}×${h}${d.primary ? ' (' + t('set.primary') + ')' : ''}`;
    b.classList.toggle('active', current ? String(d.id) === String(current) : !!d.primary);
    b.onclick = () => {
      menu.hidden = true;
      $$('#displayMenu button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      try { S.conn.send({ type: 'display', id: String(d.id) }); } catch {}
    };
    menu.appendChild(b);
  });
}

// Host: switch the shared monitor without dropping the session.
async function switchDisplay(id) {
  if (S.mode !== 'host' || !/^\d+$/.test(String(id))) return;
  try {
    await nx.selectDisplay(id);
    const ns = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: 30, max: 60 } }, audio: false });
    const nt = ns.getVideoTracks()[0];
    const sender = S.call.peerConnection.getSenders().find((s) => s.track && s.track.kind === 'video');
    await sender.replaceTrack(nt);
    if (S.stream) S.stream.getTracks().forEach((tr) => tr.stop());
    S.stream = ns;
    $('#setDisplay').value = String(id);
    applyQuality(S.quality || cfg.quality);
  } catch (e) {
    console.warn('switch display failed', e);
  }
}

// ===========================================================================
// HOST: someone wants to connect to me
// ===========================================================================
function onIncomingConnection(conn) {
  const meta = conn.metadata || {};
  if (meta.app !== 'nexdesk') { try { conn.close(); } catch {} return; }

  conn.on('data', (m) => onData(conn, m));
  conn.on('close', () => onConnClosed(conn));
  conn.on('error', () => onConnClosed(conn));
}

function isLocked() {
  const now = Date.now();
  S.failLog = S.failLog.filter((ts) => now - ts < LOCK_MS);
  return S.failLog.length >= MAX_FAILS;
}

async function onHello(conn, msg) {
  if (S.mode || S.pending) {
    conn.send({ type: 'reject', reason: 'busy' });
    setTimeout(() => { try { conn.close(); } catch {} }, 600);
    return;
  }
  const remoteId = cleanId(msg.id);
  const name = safeName(msg.name);
  const { sas, binding } = await computeSas(conn);
  const challenge = isLocked() ? null : await nx.challenge();

  S.pending = { conn, id: remoteId, name, sas, binding, challenge, deadline: Date.now() + ACCEPT_TIMEOUT * 1000 };
  conn.send({ type: 'hi', v: PROTO, name: cfg.name, auth: challenge ? { salt: challenge.salt, iter: challenge.iter, nonce: challenge.nonce } : null });

  // Ask the user
  $('#inAvatar').textContent = initials(name);
  $('#inTitle').textContent = name;
  $('#inId').textContent = fmtId(remoteId);
  $('#inSas').textContent = sas;
  $('#permControl').checked = true;
  $('#permFiles').checked = true;
  $('#incomingModal').hidden = false;
  nx.inputStart(); // pre-warm the input helper so control is instant after "Accept"
  nx.attention();
  nx.notify(t('notify.incoming'), t('notify.incomingBody', { name, id: fmtId(remoteId) }));
  tickCountdown();
}

function tickCountdown() {
  const p = S.pending;
  if (!p) return;
  const left = Math.max(0, Math.round((p.deadline - Date.now()) / 1000));
  $('#inCountdown').textContent = '(' + left + ')';
  if (left <= 0) { denyPending('timeout'); return; }
  p.cdTimer = setTimeout(tickCountdown, 1000);
}

function closeIncoming(accepting = false) {
  if (S.pending && S.pending.cdTimer) clearTimeout(S.pending.cdTimer);
  $('#incomingModal').hidden = true;
  if (!accepting && !S.mode) nx.inputStop();
}

// Put H.264 first in the offer: Chromium can then use the GPU's hardware encoder
// (lower CPU, lower latency). Falls back to VP8/VP9 automatically if unsupported.
function preferH264(sdp) {
  try {
    const lines = sdp.split('\r\n');
    const mi = lines.findIndex((l) => l.startsWith('m=video'));
    if (mi < 0) return sdp;
    const h264 = new Set(), pm1 = new Set();
    for (const l of lines) {
      let m = l.match(/^a=rtpmap:(\d+) H264\/90000/i);
      if (m) h264.add(m[1]);
      m = l.match(/^a=fmtp:(\d+) .*packetization-mode=1/);
      if (m) pm1.add(m[1]);
    }
    if (!h264.size) return sdp;
    const parts = lines[mi].split(' ');
    const rank = (pt) => (h264.has(pt) && pm1.has(pt) ? 0 : h264.has(pt) ? 1 : 2);
    lines[mi] = [...parts.slice(0, 3), ...parts.slice(3).sort((a, b) => rank(a) - rank(b))].join(' ');
    return lines.join('\r\n');
  } catch {
    return sdp;
  }
}

function denyPending(reason = 'denied') {
  const p = S.pending;
  if (!p) return;
  closeIncoming();
  S.pending = null;
  try { p.conn.send({ type: 'reject', reason }); } catch {}
  setTimeout(() => { try { p.conn.close(); } catch {} }, 600);
}

async function onAuth(conn, msg) {
  const p = S.pending;
  if (!p || p.conn !== conn || !p.challenge) return;
  if (isLocked()) { conn.send({ type: 'authfail', locked: true }); return; }
  const ok = await nx.verify({ nonce: p.challenge.nonce, binding: p.binding, proof: msg.proof });
  if (ok) {
    acceptPending({ control: true, files: true });
  } else {
    S.failLog.push(Date.now());
    // fresh nonce for the next attempt
    p.challenge = isLocked() ? null : await nx.challenge();
    conn.send({ type: 'authfail', locked: isLocked(), auth: p.challenge ? { salt: p.challenge.salt, iter: p.challenge.iter, nonce: p.challenge.nonce } : null });
  }
}

async function acceptPending(perms) {
  const p = S.pending;
  if (!p) return;
  closeIncoming(true);
  S.pending = null;

  let stream;
  try {
    const sel = $('#setDisplay').value;
    if (sel) await nx.selectDisplay(sel);
    stream = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: 30, max: 60 }, cursor: 'always' }, audio: false });
  } catch (e) {
    console.error(e);
    toast(t('err.capture'), 'err');
    nx.inputStop();
    try { p.conn.send({ type: 'reject', reason: 'capture' }); } catch {}
    setTimeout(() => { try { p.conn.close(); } catch {} }, 600);
    return;
  }
  const track = stream.getVideoTracks()[0];
  if (track) track.contentHint = 'detail';

  S.mode = 'host';
  S.conn = p.conn;
  S.stream = stream;
  S.partner = { id: p.id, name: p.name };
  S.sas = p.sas; S.binding = p.binding;
  S.perms = { control: !!perms.control, files: !!perms.files };
  S.allowControl = S.perms.control;

  let displays = [];
  try { displays = await nx.displays(); } catch {}
  S.conn.send({ type: 'accept', name: cfg.name, perms: S.perms, displays, display: $('#setDisplay').value || null });
  openRealtime();
  S.call = peer.call(S.conn.peer, stream, { metadata: { app: 'nexdesk' }, sdpTransform: preferH264 });
  S.call.on('error', () => {});
  S.call.on('close', () => { if (S.mode === 'host') endSession('end.lost', false); });
  applyQuality(cfg.quality);
  startCursorShare();

  if (S.perms.control) nx.inputStart(); else nx.inputStop();
  openHostUI();
  addSysMsg(t('sys.joined'));
  toast(t('ok.hostConnected', { name: S.partner.name }), 'ok');
  nx.notify('NexDesk', t('ok.hostConnected', { name: S.partner.name }));
}

// ===========================================================================
// Realtime channel + heartbeat (both roles)
// A second, *negotiated* data channel on the same peer connection: unordered and
// without retransmits, so mouse moves / cursor updates never wait behind file chunks.
// ===========================================================================
function openRealtime() {
  S.lastSeen = Date.now();
  const pc = S.conn && S.conn.peerConnection;
  if (pc) {
    try {
      const rt = pc.createDataChannel('nx-rt', { negotiated: true, id: RT_CHANNEL_ID, ordered: false, maxRetransmits: 0 });
      rt.onmessage = (e) => {
        S.lastSeen = Date.now();
        let m;
        try { m = JSON.parse(e.data); } catch { return; }
        onRealtime(m);
      };
      S.rt = rt;
    } catch (e) { console.warn('rt channel', e); }
    pc.addEventListener('connectionstatechange', () => {
      if ((pc.connectionState === 'failed' || pc.connectionState === 'closed') && S.conn && S.conn.peerConnection === pc) {
        endSession('end.lost', false);
      }
    });
  }
  clearInterval(S.hbTimer);
  S.hbTimer = setInterval(() => {
    if (!S.mode || S.mode === 'connecting') return;
    if (!rtSend({ t: 'p' })) { try { S.conn.send({ type: 'ping' }); } catch {} }
    if (Date.now() - S.lastSeen > HEARTBEAT_TIMEOUT) endSession('end.lost', false);
  }, 1000);
}

function rtSend(m) {
  const rt = S.rt;
  if (!rt || rt.readyState !== 'open') return false;
  try { rt.send(JSON.stringify(m)); return true; } catch { return false; }
}

function onRealtime(m) {
  if (!m || typeof m !== 'object') return;
  if (m.t === 'm' && S.mode === 'host') onRemoteInput({ t: 'm', x: m.x, y: m.y });
  else if (m.t === 'c' && S.mode === 'viewer') drawRemoteCursor(m.x, m.y);
}

// Host: share the real cursor position (screen capture doesn't always draw it).
function startCursorShare() {
  let busy = false, last = '', lastSent = 0;
  clearInterval(S.cursorTimer);
  S.cursorTimer = setInterval(async () => {
    if (busy || S.mode !== 'host') return;
    busy = true;
    try {
      const p = await nx.cursor();
      const key = p ? p.x + ',' + p.y : 'out';
      // send on change, and re-send every 500 ms (the channel is lossy by design)
      if (key !== last || Date.now() - lastSent > 500) {
        if (rtSend(p ? { t: 'c', x: p.x, y: p.y } : { t: 'c', x: -1, y: -1 })) { last = key; lastSent = Date.now(); }
      }
    } catch {}
    busy = false;
  }, 30);
}

// Viewer: draw the host's cursor on top of the video.
let lastCursor = null;
function drawRemoteCursor(x, y) {
  lastCursor = [x, y];
  const c = $('#remoteCursor');
  const v = video();
  // While the viewer is steering, their own pointer is already there: don't show two cursors.
  const steering = canControl() && Date.now() - lastLocalMove < 700;
  if (!(x >= 0 && y >= 0) || !v.videoWidth || steering) { c.hidden = true; return; }
  const r = v.getBoundingClientRect();
  const s = Math.min(r.width / v.videoWidth, r.height / v.videoHeight);
  const cw = v.videoWidth * s, ch = v.videoHeight * s;
  const left = r.left + (r.width - cw) / 2 + x * cw;
  const top = r.top + (r.height - ch) / 2 + y * ch;
  c.style.transform = `translate(${left}px, ${top}px)`;
  c.hidden = false;
}

async function applyQuality(level) {
  const q = QUALITY[level] || QUALITY.balanced;
  S.quality = QUALITY[level] ? level : 'balanced';
  const track = S.stream && S.stream.getVideoTracks()[0];
  const h = (track && track.getSettings().height) || 1080;
  const scale = Math.max(1, h / q.maxH);
  if (track) { try { track.contentHint = q.hint; } catch {} }
  for (let i = 0; i < 50; i++) {
    const pc = S.call && S.call.peerConnection;
    const sender = pc && pc.getSenders().find((s) => s.track && s.track.kind === 'video');
    if (sender) {
      try {
        const params = sender.getParameters();
        if (!params.encodings || !params.encodings.length) params.encodings = [{}];
        params.encodings[0].maxBitrate = q.bitrate;
        params.encodings[0].maxFramerate = q.fps;
        params.encodings[0].scaleResolutionDownBy = scale;
        params.degradationPreference = q.pref;
        await sender.setParameters(params);
        return;
      } catch (e) { /* not negotiated yet */ }
    }
    await sleep(200);
  }
}

function setAllowControl(on) {
  S.allowControl = !!on;
  if (S.mode !== 'host') return;
  if (on) nx.inputStart(); else releaseHostInput();
  S.perms.control = S.allowControl;
  try { S.conn.send({ type: 'perms', perms: S.perms }); } catch {}
}

function releaseHostInput() {
  for (const k of S.hostDown) {
    const [kind, a, b] = k.split(':');
    if (kind === 'k') nx.input({ t: 'k', s: +a, e: +b, u: 1 });
    else nx.input({ t: 'u', b: +a });
  }
  S.hostDown.clear();
}

function onRemoteInput(ev) {
  if (S.mode !== 'host' || !S.allowControl || !S.perms.control || !ev) return;
  // clicks carry their own position, so they land correctly even if a move packet was dropped
  if ((ev.t === 'd' || ev.t === 'u') && ev.x >= 0 && ev.x <= 1 && ev.y >= 0 && ev.y <= 1) {
    nx.input({ t: 'm', x: ev.x, y: ev.y });
  }
  if (ev.t === 'k') {
    const key = `k:${ev.s}:${ev.e ? 1 : 0}`;
    if (ev.u) S.hostDown.delete(key); else S.hostDown.add(key);
  } else if (ev.t === 'd') S.hostDown.add('b:' + ev.b);
  else if (ev.t === 'u') S.hostDown.delete('b:' + ev.b);
  nx.input(ev);
}

// ===========================================================================
// Data channel message router (both roles)
// ===========================================================================
function onData(conn, m) {
  if (!m || typeof m !== 'object' || typeof m.type !== 'string') return;
  const isActive = S.conn === conn;
  if (isActive) S.lastSeen = Date.now();
  if (m.type === 'ping') return;

  switch (m.type) {
    // ---- handshake
    case 'hello': return onHello(conn, m);
    case 'auth': return onAuth(conn, m);
    case 'hi':
      if (!isActive || S.mode !== 'connecting') return;
      S.partner.name = safeName(m.name);
      $('#cnTitle').textContent = S.partner.name;
      S.auth = m.auth || null;
      $('#pwForm').hidden = !S.auth;
      return;
    case 'authfail':
      if (!isActive || S.mode !== 'connecting') return;
      toast(t(m.locked ? 'err.locked' : 'err.badPw'), 'err');
      S.auth = m.auth || null;
      $('#pwForm').hidden = !S.auth;
      $('#cnText').textContent = t('cn.waiting');
      return;
    case 'accept':
      if (isActive && S.mode === 'connecting') onAccepted(m);
      return;
    case 'reject':
      if (isActive && S.mode === 'connecting') {
        failConnect({ busy: 'err.busy', timeout: 'err.timeout', capture: 'err.capture', locked: 'err.locked' }[m.reason] || 'err.denied');
      }
      return;
    case 'bye':
      if (isActive && (S.mode === 'viewer' || S.mode === 'host')) endSession('end.remote', false);
      else if (S.pending && S.pending.conn === conn) { closeIncoming(); S.pending = null; }
      return;
  }

  if (!isActive || (S.mode !== 'viewer' && S.mode !== 'host')) return;

  switch (m.type) {
    case 'i': return onRemoteInput(m.e);
    case 'quality': if (S.mode === 'host' && QUALITY[m.level]) applyQuality(m.level); return;
    case 'display': if (S.mode === 'host') switchDisplay(m.id); return;
    case 'perms':
      if (S.mode !== 'viewer' || !m.perms) return;
      S.perms = { control: !!m.perms.control, files: !!m.perms.files };
      if (!S.perms.control) releaseViewerKeys();
      updateViewOnly();
      toast(t(S.perms.control ? 'ok.controlOn' : 'ok.controlOff'), S.perms.control ? 'ok' : '');
      return;
    case 'chat': return onChat(m);
    case 'clip':
      if (typeof m.text === 'string') { nx.clipWrite(m.text); toast(t('ok.clipRecv'), 'ok'); }
      return;
    case 'f-meta': return onFileMeta(m);
    case 'f-chunk': return onFileChunk(m);
    case 'f-end': return onFileEnd(m);
    case 'f-abort': return onFileAbort(m);
  }
}

function onConnClosed(conn) {
  if (S.pending && S.pending.conn === conn) { closeIncoming(); S.pending = null; return; }
  if (S.conn !== conn) return;
  if (S.mode === 'connecting') failConnect('err.denied');
  else if (S.mode) endSession('end.lost', false);
}

// ===========================================================================
// Session lifecycle
// ===========================================================================
function endSession(reasonKey = 'end.local', notify = true) {
  if (!S.mode) return;
  const conn = S.conn;
  if (notify && conn && conn.open) { try { conn.send({ type: 'bye' }); } catch {} }
  setTimeout(() => { try { conn && conn.close(); } catch {} }, 300);

  if (S.mode === 'host') { releaseHostInput(); nx.inputStop(); }
  if (S.mode === 'viewer') releaseViewerKeys();

  // abort running transfers
  for (const [id, tr] of transfers) {
    if (!tr.done) {
      tr.aborted = true;
      if (tr.dir === 'in') nx.fileAbort({ id: tr.rid });
      setTransferState(tr, 'failed');
    }
  }

  resetSession();
  closeUI();
  toast(t(reasonKey), reasonKey === 'end.local' ? '' : 'err');
}

function resetSession() {
  clearTimers();
  if (S.call) { try { S.call.close(); } catch {} }
  if (S.stream) S.stream.getTracks().forEach((tr) => tr.stop());
  clearInterval(S.statsTimer);
  clearInterval(S.hbTimer);
  clearInterval(S.cursorTimer);
  if (S.rt) { try { S.rt.close(); } catch {} }
  $('#remoteCursor').hidden = true;
  Object.assign(S, {
    rt: null, hbTimer: null, cursorTimer: null,
    mode: null, conn: null, call: null, stream: null, partner: null, auth: null,
    perms: { control: true, files: true }, allowControl: true, sas: null, binding: null,
    statsTimer: null, lastStats: null, unread: 0
  });
  S.downKeys.clear();
  S.hostDown.clear();
}

// ===========================================================================
// UI: viewer session
// ===========================================================================
function openViewerUI() {
  $('#sbAvatar').textContent = initials(S.partner.name);
  $('#sbName').textContent = S.partner.name;
  $('#sbId').textContent = fmtId(S.partner.id);
  $('#sbSas').textContent = S.sas;
  $('#sbQuality').value = cfg.quality;
  $('#remoteWaiting').hidden = false;
  $('#remoteWrap').classList.remove('original');
  $('#session').hidden = false;
  updateViewOnly();
  resetDrawer();
  $('#remoteWrap').focus();
  S.statsTimer = setInterval(updateStats, 1500);
}

function updateViewOnly() {
  $('#viewOnlyTag').hidden = S.perms.control;
  $('#remoteWrap').classList.toggle('controlling', S.perms.control);
  $('#sbKeysBtn').disabled = !S.perms.control;
  $('#sbFileBtn').disabled = !S.perms.files;
}

async function updateStats() {
  const pc = S.call && S.call.peerConnection;
  if (!pc) return;
  try {
    const stats = await pc.getStats();
    let inbound = null, pair = null, remoteCand = null;
    stats.forEach((r) => {
      if (r.type === 'inbound-rtp' && r.kind === 'video') inbound = r;
      if (r.type === 'candidate-pair' && r.nominated && r.state === 'succeeded') pair = r;
    });
    if (pair) stats.forEach((r) => { if (r.id === pair.remoteCandidateId) remoteCand = r; });
    if (!inbound) return;
    const now = inbound.timestamp;
    let mbps = 0;
    if (S.lastStats) mbps = ((inbound.bytesReceived - S.lastStats.bytes) * 8) / ((now - S.lastStats.ts) / 1000) / 1e6;
    S.lastStats = { bytes: inbound.bytesReceived, ts: now };
    const parts = [];
    if (inbound.frameWidth) parts.push(inbound.frameWidth + '×' + inbound.frameHeight);
    parts.push(Math.round(inbound.framesPerSecond || 0) + ' fps');
    parts.push(mbps.toFixed(1) + ' Mbps');
    if (pair && pair.currentRoundTripTime != null) parts.push(Math.round(pair.currentRoundTripTime * 1000) + ' ms');
    if (remoteCand) parts.push(remoteCand.candidateType === 'relay' ? 'TURN' : 'P2P');
    const codec = inbound.codecId && stats.get(inbound.codecId);
    if (codec && codec.mimeType) parts.push(codec.mimeType.split('/')[1].toUpperCase());
    $('#sbStats').textContent = parts.join(' · ');
  } catch {}
}

// ===========================================================================
// UI: host banner
// ===========================================================================
function openHostUI() {
  $('#hostPartnerName').textContent = S.partner.name + ' (' + fmtId(S.partner.id) + ')';
  $('#hostSas').textContent = S.sas;
  $('#hostAllowControl').checked = S.allowControl;
  $('#hostAllowControl').disabled = false;
  $('#hostFileBtn').disabled = !S.perms.files;
  $('#hostBar').hidden = false;
  resetDrawer();
  showPage('home');
}

function closeUI() {
  $('#session').hidden = true;
  $('#hostBar').hidden = true;
  $('#drawer').hidden = true;
  $('#keysMenu').hidden = true;
  const v = $('#remoteVideo');
  v.srcObject = null;
  $('#sbStats').textContent = '—';
  if (document.documentElement.classList.contains('fullscreen')) toggleFullscreen(false);
  setUnread(0);
}

// ===========================================================================
// Drawer (chat + files)
// ===========================================================================
function resetDrawer() {
  $('#chatList').innerHTML = `<div class="empty">${escapeHtml(t('chat.empty'))}</div>`;
  $('#fileList').innerHTML = '';
  transfers.clear();
  $('#drawer').hidden = true;
  setUnread(0);
}

function openDrawer(tab) {
  const d = $('#drawer');
  if (!d.hidden && S.drawerTab === tab) { d.hidden = true; return; }
  S.drawerTab = tab;
  d.hidden = false;
  $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.drawer-body').forEach((p) => { p.hidden = p.dataset.pane !== tab; });
  if (tab === 'chat') { setUnread(0); setTimeout(() => $('#chatInput').focus(), 50); }
}

function setUnread(n) {
  S.unread = n;
  $$('#sbChatBtn .badge-dot, #hostChatBtn .badge-dot').forEach((d) => { d.hidden = n === 0; });
}

function addMsg(text, who) {
  const list = $('#chatList');
  const empty = list.querySelector('.empty');
  if (empty) empty.remove();
  const el = document.createElement('div');
  el.className = 'msg ' + who;
  el.textContent = text;
  if (who !== 'sys') {
    const s = document.createElement('small');
    s.textContent = new Date().toLocaleTimeString(cfg.lang, { hour: '2-digit', minute: '2-digit' });
    el.appendChild(s);
  }
  list.appendChild(el);
  list.scrollTop = list.scrollHeight;
}
const addSysMsg = (text) => addMsg(text, 'sys');

function sendChat(e) {
  e.preventDefault();
  const inp = $('#chatInput');
  const text = inp.value.trim().slice(0, 2000);
  if (!text || !S.conn || !S.conn.open) return;
  S.conn.send({ type: 'chat', text });
  addMsg(text, 'me');
  inp.value = '';
}

function onChat(m) {
  if (typeof m.text !== 'string') return;
  const text = m.text.slice(0, 2000);
  addMsg(text, 'them');
  const d = $('#drawer');
  if (d.hidden || S.drawerTab !== 'chat') {
    setUnread(S.unread + 1);
    toast(t('chat.new', { name: S.partner.name, text: text.length > 60 ? text.slice(0, 60) + '…' : text }), '', {
      label: t('tb.chat'), fn: () => openDrawer('chat')
    });
  }
}

// ===========================================================================
// Files
// ===========================================================================
function transferRow(tr) {
  const el = document.createElement('div');
  el.className = 'file-item';
  el.innerHTML = `
    <div class="fi-top"><span class="fi-dir ${tr.dir}">${tr.dir === 'out' ? '↑' : '↓'}</span><span class="fi-name"></span></div>
    <div class="progress"><i></i></div>
    <div class="fi-meta"><span class="fi-state"></span><span class="fi-size"></span></div>`;
  el.querySelector('.fi-name').textContent = tr.name;
  el.querySelector('.fi-name').title = tr.name;
  $('#fileList').prepend(el);
  tr.el = el;
  setTransferState(tr, tr.dir === 'out' ? 'sending' : 'receiving');
  return el;
}

function setTransferProgress(tr) {
  const pct = tr.size ? Math.min(100, (tr.done_bytes / tr.size) * 100) : 100;
  tr.el.querySelector('.progress > i').style.width = pct.toFixed(1) + '%';
  tr.el.querySelector('.fi-size').textContent = fmtBytes(tr.done_bytes) + ' / ' + fmtBytes(tr.size);
}

function setTransferState(tr, st) {
  if (!tr.el) return;
  const s = tr.el.querySelector('.fi-state');
  s.className = 'fi-state';
  if (st === 'done') {
    tr.done = true;
    s.classList.add('ok');
    s.textContent = t('files.done');
    tr.el.querySelector('.progress > i').style.width = '100%';
    if (tr.dir === 'in' && tr.path) {
      const b = document.createElement('button');
      b.className = 'fi-open';
      b.textContent = t('files.show');
      b.onclick = () => nx.reveal(tr.path);
      s.replaceWith(b);
    }
  } else if (st === 'failed') {
    tr.done = true;
    s.classList.add('err');
    s.textContent = t('files.failed');
  } else {
    s.textContent = t(st === 'sending' ? 'files.sending' : 'files.receiving');
  }
  if (!tr.done) setTransferProgress(tr);
}

function sendFiles(fileList) {
  if (!S.conn || !S.conn.open || !(S.mode === 'viewer' || S.mode === 'host')) return;
  if (!S.perms.files) return toast(t('files.notAllowed'), 'err');
  for (const f of fileList) {
    if (f.size > MAX_FILE) { toast(t('files.tooBig', { name: f.name }), 'err'); continue; }
    const tr = { id: randHex(8), dir: 'out', name: f.name, size: f.size, done_bytes: 0, file: f };
    transfers.set(tr.id, tr);
    transferRow(tr);
    sendQueue = sendQueue.then(() => sendOne(tr)).catch(() => {});
  }
  if ($('#drawer').hidden || S.drawerTab !== 'files') openDrawer('files');
}

async function sendOne(tr) {
  const conn = S.conn;
  if (!conn || !conn.open || tr.aborted) return setTransferState(tr, 'failed');
  conn.send({ type: 'f-meta', id: tr.id, name: tr.name, size: tr.size });
  try {
    for (let off = 0; off < tr.size; off += CHUNK) {
      if (tr.aborted || !conn.open || S.conn !== conn) throw new Error('aborted');
      // back-pressure: keep the SCTP buffer reasonably small
      // small buffer => keystrokes/clicks on the same channel never queue behind a big file
      while (conn.dataChannel && conn.dataChannel.bufferedAmount > 1024 * 1024) await sleep(10);
      while (conn.bufferSize > 32) await sleep(15);
      const buf = await tr.file.slice(off, off + CHUNK).arrayBuffer();
      conn.send({ type: 'f-chunk', id: tr.id, data: buf });
      tr.done_bytes = Math.min(tr.size, off + buf.byteLength);
      setTransferProgress(tr);
    }
    conn.send({ type: 'f-end', id: tr.id });
    // completion is confirmed by the receiver ('f-abort' would mark it failed)
    setTransferState(tr, 'done');
  } catch {
    try { conn.send({ type: 'f-abort', id: tr.id }); } catch {}
    setTransferState(tr, 'failed');
  }
}

function onFileMeta(m) {
  if (typeof m.id !== 'string' || transfers.has('in:' + m.id)) return;
  const size = Number(m.size);
  if (!S.perms.files || !(size >= 0 && size <= MAX_FILE)) {
    S.conn.send({ type: 'f-abort', id: m.id });
    return;
  }
  const tr = { id: 'in:' + m.id, rid: m.id, dir: 'in', name: String(m.name || 'file').slice(0, 180), size, done_bytes: 0 };
  transfers.set(tr.id, tr);
  transferRow(tr);
  tr.chain = nx.fileBegin({ id: tr.rid, name: tr.name, size }).then((r) => { tr.name = r.name; tr.path = r.path; });
  tr.chain.catch(() => failIncoming(tr));
}

function onFileChunk(m) {
  const tr = transfers.get('in:' + m.id);
  if (!tr || tr.done || !(m.data instanceof ArrayBuffer || ArrayBuffer.isView(m.data))) return;
  const data = new Uint8Array(m.data instanceof ArrayBuffer ? m.data : m.data.buffer);
  tr.chain = tr.chain.then(() => nx.fileChunk({ id: tr.rid, data })).then((written) => {
    tr.done_bytes = written;
    setTransferProgress(tr);
  });
  tr.chain.catch(() => failIncoming(tr));
}

function onFileEnd(m) {
  const tr = transfers.get('in:' + m.id);
  if (!tr || tr.done) return;
  tr.chain = tr.chain.then(() => nx.fileEnd({ id: tr.rid })).then((p) => {
    tr.path = p;
    setTransferState(tr, 'done');
    toast(t('files.received', { name: tr.name }), 'ok', { label: t('files.show'), fn: () => nx.reveal(p) });
  });
  tr.chain.catch(() => failIncoming(tr));
}

function onFileAbort(m) {
  const tr = transfers.get('in:' + m.id) || transfers.get(m.id);
  if (!tr || tr.done) return;
  tr.aborted = true;
  if (tr.dir === 'in') nx.fileAbort({ id: tr.rid });
  setTransferState(tr, 'failed');
}

function failIncoming(tr) {
  if (tr.done) return;
  tr.aborted = true;
  nx.fileAbort({ id: tr.rid });
  setTransferState(tr, 'failed');
  try { S.conn.send({ type: 'f-abort', id: tr.rid }); } catch {}
}

async function sendClipboard() {
  if (!S.conn || !S.conn.open) return;
  const text = await nx.clipRead();
  if (!text) return toast(t('clip.empty'), 'err');
  S.conn.send({ type: 'clip', text });
  toast(t('ok.clipSent'), 'ok');
}

// ===========================================================================
// Viewer input capture
// ===========================================================================
const video = () => $('#remoteVideo');
let pendingMove = null;
let moveScheduled = false;
let lastLocalMove = 0;

function canControl() {
  return S.mode === 'viewer' && S.perms.control && S.conn && S.conn.open && !$('#session').hidden;
}
function sendInput(e) { try { S.conn.send({ type: 'i', e }); } catch {} }

function videoPoint(ev) {
  const v = video();
  const vw = v.videoWidth, vh = v.videoHeight;
  if (!vw || !vh) return null;
  const r = v.getBoundingClientRect();
  let cw = r.width, ch = r.height, ox = 0, oy = 0;
  const s = Math.min(r.width / vw, r.height / vh);
  cw = vw * s; ch = vh * s;
  ox = (r.width - cw) / 2; oy = (r.height - ch) / 2;
  const x = (ev.clientX - r.left - ox) / cw;
  const y = (ev.clientY - r.top - oy) / ch;
  if (x < 0 || y < 0 || x > 1 || y > 1) return null;
  return { x: +x.toFixed(5), y: +y.toFixed(5) };
}

function flushMove() {
  moveScheduled = false;
  if (pendingMove && canControl() && !rtSend({ t: 'm', x: pendingMove.x, y: pendingMove.y })) {
    sendInput({ t: 'm', x: pendingMove.x, y: pendingMove.y });
  }
  pendingMove = null;
}

function bindViewerInput() {
  const v = video();
  const wrap = $('#remoteWrap');
  const btn = (b) => ({ 0: 0, 2: 1, 1: 2 }[b]);

  v.addEventListener('mousemove', (e) => {
    if (!canControl()) return;
    const p = videoPoint(e);
    if (!p) return;
    lastLocalMove = Date.now();
    $('#remoteCursor').hidden = true;
    pendingMove = p;
    if (!moveScheduled) { moveScheduled = true; requestAnimationFrame(flushMove); }
  });
  v.addEventListener('mousedown', (e) => {
    wrap.focus();
    $('#keysMenu').hidden = true;
    if (!canControl()) return;
    e.preventDefault();
    const p = videoPoint(e);
    if (!p || btn(e.button) === undefined) return;
    sendInput({ t: 'd', b: btn(e.button), x: p.x, y: p.y });
    S.downKeys.add('b' + btn(e.button));
  });
  window.addEventListener('mouseup', (e) => {
    if (!canControl() || btn(e.button) === undefined || !S.downKeys.has('b' + btn(e.button))) return;
    sendInput({ t: 'u', b: btn(e.button) });
    S.downKeys.delete('b' + btn(e.button));
  });
  v.addEventListener('contextmenu', (e) => e.preventDefault());
  // keep the drawn host cursor glued to the video when its size/layout changes
  const redraw = () => { if (lastCursor && S.mode === 'viewer') drawRemoteCursor(lastCursor[0], lastCursor[1]); };
  v.addEventListener('resize', redraw);
  v.addEventListener('loadedmetadata', redraw);
  window.addEventListener('resize', redraw);
  wrap.addEventListener('scroll', redraw);
  v.addEventListener('wheel', (e) => {
    if (!canControl()) return;
    e.preventDefault();
    const mult = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? 800 : 1.2;
    const dy = Math.round(-e.deltaY * mult);
    const dx = Math.round(e.deltaX * mult);
    if (dy) sendInput({ t: 'w', d: Math.max(-2400, Math.min(2400, dy)) });
    if (dx) sendInput({ t: 'h', d: Math.max(-2400, Math.min(2400, dx)) });
  }, { passive: false });

  const typingInUi = () => {
    const a = document.activeElement;
    return a && (a.tagName === 'INPUT' || a.tagName === 'SELECT' || a.tagName === 'TEXTAREA') && !$('#drawer').hidden;
  };

  window.addEventListener('keydown', (e) => {
    if (!canControl() || typingInUi()) return;
    const k = NX_KEYMAP.get(e.code);
    if (!k) return;
    e.preventDefault();
    e.stopPropagation();
    S.downKeys.add(e.code);
    sendInput({ t: 'k', s: k[0], e: k[1] ? 1 : 0, u: 0 });
  }, true);
  window.addEventListener('keyup', (e) => {
    if (!canControl()) return;
    const k = NX_KEYMAP.get(e.code);
    if (!k || !S.downKeys.has(e.code)) return;
    e.preventDefault();
    S.downKeys.delete(e.code);
    sendInput({ t: 'k', s: k[0], e: k[1] ? 1 : 0, u: 1 });
  }, true);
  window.addEventListener('blur', releaseViewerKeys);
}

function releaseViewerKeys() {
  if (S.conn && S.conn.open && S.mode === 'viewer') {
    for (const code of S.downKeys) {
      if (code[0] === 'b' && code.length === 2) { sendInput({ t: 'u', b: +code[1] }); continue; }
      const k = NX_KEYMAP.get(code);
      if (k) sendInput({ t: 'k', s: k[0], e: k[1] ? 1 : 0, u: 1 });
    }
  }
  S.downKeys.clear();
}

async function sendCombo(name) {
  const keys = NX_KEYMAP.combos[name];
  if (!keys || !canControl()) return;
  for (const c of keys) { const k = NX_KEYMAP.get(c); sendInput({ t: 'k', s: k[0], e: k[1] ? 1 : 0, u: 0 }); await sleep(30); }
  for (const c of [...keys].reverse()) { const k = NX_KEYMAP.get(c); sendInput({ t: 'k', s: k[0], e: k[1] ? 1 : 0, u: 1 }); await sleep(30); }
  $('#remoteWrap').focus();
}

async function toggleFullscreen(force) {
  const want = typeof force === 'boolean' ? force : !document.documentElement.classList.contains('fullscreen');
  const on = await nx.fullscreen(want);
  document.documentElement.classList.toggle('fullscreen', on);
}

// ===========================================================================
// Home / settings rendering
// ===========================================================================
function renderMe() {
  $('#myId').textContent = fmtId(cfg.id);
  $('#myName').textContent = cfg.name;
  $('#unattendedChip').hidden = !(cfg.unattended && cfg.hasUnattendedPassword);
}

function renderRecent() {
  const list = $('#recentList');
  list.innerHTML = '';
  if (!cfg.recent || !cfg.recent.length) {
    list.innerHTML = `<div class="recent-empty">${escapeHtml(t('recent.empty'))}</div>`;
    $('#clearRecentBtn').hidden = true;
    return;
  }
  $('#clearRecentBtn').hidden = false;
  for (const r of cfg.recent) {
    const el = document.createElement('div');
    el.className = 'recent-item';
    el.innerHTML = `<div class="avatar"></div><div class="ri-text"><b></b><small></small></div>
      <button class="icon-btn ri-del" title="×"><svg><use href="#i-trash"/></svg></button>`;
    el.querySelector('.avatar').textContent = initials(r.name);
    el.querySelector('b').textContent = r.name;
    el.querySelector('small').textContent = fmtId(r.id);
    el.onclick = () => { $('#remoteId').value = fmtId(r.id); connectTo(r.id); };
    el.querySelector('.ri-del').onclick = async (e) => {
      e.stopPropagation();
      cfg = await nx.setConfig({ recent: cfg.recent.filter((x) => x.id !== r.id) });
      renderRecent();
    };
    list.appendChild(el);
  }
}

async function addRecent(id, name) {
  const recent = [{ id, name, ts: Date.now() }, ...(cfg.recent || []).filter((r) => r.id !== id)].slice(0, 12);
  cfg = await nx.setConfig({ recent });
  renderRecent();
}

function renderPwState() {
  const el = $('#pwState');
  if (!el || !cfg) return;
  el.className = cfg.hasUnattendedPassword ? 'ok' : '';
  el.textContent = t(cfg.hasUnattendedPassword ? 'set.pwSet' : 'set.pwNone');
}

async function renderSettings() {
  $('#setName').value = cfg.name;
  $('#setLang').value = cfg.lang;
  $('#setQuality').value = cfg.quality;
  $('#setUnattended').checked = !!cfg.unattended;
  $('#turnUrl').value = cfg.turn.url || '';
  $('#turnUser').value = cfg.turn.username || '';
  $('#turnPass').value = cfg.turn.credential || '';
  renderPwState();
  const sel = $('#setDisplay');
  const prev = sel.value;
  const displays = await nx.displays();
  sel.innerHTML = '';
  for (const d of displays) {
    const o = document.createElement('option');
    o.value = d.id;
    o.textContent = `${t('set.screen')} ${d.index + 1} — ${d.width}×${d.height}${d.primary ? ' (' + t('set.primary') + ')' : ''}`;
    if (d.primary) o.selected = true;
    sel.appendChild(o);
  }
  if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
}

function showPage(name) {
  $$('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.page === name));
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + name));
  if (name === 'settings') renderSettings();
}

// ===========================================================================
// Wire up
// ===========================================================================
function bindUi() {
  $$('.nav-btn').forEach((b) => (b.onclick = () => showPage(b.dataset.page)));

  $('#copyIdBtn').onclick = () => { navigator.clipboard.writeText(cfg.id).catch(() => nx.clipWrite(cfg.id)); toast(t('ok.copied'), 'ok'); };

  const rid = $('#remoteId');
  rid.addEventListener('input', () => { const pos = rid.value; rid.value = fmtId(cleanId(pos)); });
  rid.addEventListener('paste', (e) => { e.preventDefault(); rid.value = fmtId(cleanId(e.clipboardData.getData('text'))); });
  $('#connectForm').onsubmit = (e) => { e.preventDefault(); connectTo(rid.value); };
  $('#clearRecentBtn').onclick = async () => { cfg = await nx.setConfig({ recent: [] }); renderRecent(); };

  // connecting modal
  $('#cnCancel').onclick = () => {
    if (S.mode !== 'connecting') return hideConnecting();
    const c = S.conn;
    try { c && c.open && c.send({ type: 'bye' }); } catch {}
    resetSession();
    setTimeout(() => { try { c && c.close(); } catch {} }, 300);
    hideConnecting();
  };
  $('#pwForm').onsubmit = submitPassword;

  // incoming modal
  $('#inAccept').onclick = () => acceptPending({ control: $('#permControl').checked, files: $('#permFiles').checked });
  $('#inDeny').onclick = () => denyPending('denied');

  // host bar
  $('#hostAllowControl').onchange = (e) => setAllowControl(e.target.checked);
  $('#hostChatBtn').onclick = () => openDrawer('chat');
  $('#hostFileBtn').onclick = () => openDrawer('files');
  $('#hostEndBtn').onclick = () => endSession('end.local');

  // viewer toolbar
  $('#sbEndBtn').onclick = () => endSession('end.local');
  $('#sbChatBtn').onclick = () => openDrawer('chat');
  $('#sbFileBtn').onclick = () => openDrawer('files');
  $('#sbClipBtn').onclick = sendClipboard;
  $('#sbFullBtn').onclick = () => toggleFullscreen();
  $('#sbFitBtn').onclick = () => {
    const w = $('#remoteWrap');
    w.classList.toggle('original');
    $('#sbFitBtn').classList.toggle('active', w.classList.contains('original'));
  };
  $('#sbQuality').onchange = (e) => { if (S.conn) S.conn.send({ type: 'quality', level: e.target.value }); };
  $('#sbKeysBtn').onclick = (e) => { e.stopPropagation(); $('#displayMenu').hidden = true; $('#keysMenu').hidden = !$('#keysMenu').hidden; };
  $('#sbDisplayBtn').onclick = (e) => { e.stopPropagation(); $('#keysMenu').hidden = true; $('#displayMenu').hidden = !$('#displayMenu').hidden; };

  // Window is closing: say goodbye so the other side disconnects immediately.
  nx.onClosing(() => {
    if (S.pending) denyPending('denied');
    if (S.mode === 'viewer' || S.mode === 'host') endSession('end.local', true);
    else if (S.mode === 'connecting' && S.conn && S.conn.open) { try { S.conn.send({ type: 'bye' }); } catch {} }
  });
  $$('#keysMenu button').forEach((b) => (b.onclick = () => { $('#keysMenu').hidden = true; sendCombo(b.dataset.combo); }));
  document.addEventListener('click', (e) => { if (!e.target.closest('.menu-wrap')) { $('#keysMenu').hidden = true; $('#displayMenu').hidden = true; } });

  // drawer
  $('#drawerClose').onclick = () => { $('#drawer').hidden = true; if (S.mode === 'viewer') $('#remoteWrap').focus(); };
  $$('.tab').forEach((b) => (b.onclick = () => { S.drawerTab = ''; openDrawer(b.dataset.tab); }));
  $('#chatForm').onsubmit = sendChat;
  $('#fileInput').onchange = (e) => { sendFiles(e.target.files); e.target.value = ''; };
  $('#openDownloadsBtn2').onclick = () => nx.openDownloads();

  const dz = $('#dropzone');
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('over'); sendFiles(e.dataTransfer.files); });

  // drop files anywhere during a session
  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => {
    if (!(S.mode === 'viewer' || S.mode === 'host') || !e.dataTransfer.types.includes('Files')) return;
    dragDepth++;
    if (S.mode === 'viewer') $('#dropOverlay').hidden = false;
  });
  window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('#dropOverlay').hidden = true; } });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    $('#dropOverlay').hidden = true;
    if ((S.mode === 'viewer' || S.mode === 'host') && e.dataTransfer.files.length && !e.target.closest('#dropzone')) sendFiles(e.dataTransfer.files);
  });

  // settings
  $('#setName').onchange = async (e) => { cfg = await nx.setConfig({ name: safeName(e.target.value) || cfg.name }); renderMe(); toast(t('set.saved'), 'ok'); };
  $('#setLang').onchange = async (e) => { cfg = await nx.setConfig({ lang: e.target.value }); applyI18n(); renderSettings(); };
  $('#setQuality').onchange = async (e) => { cfg = await nx.setConfig({ quality: e.target.value }); toast(t('set.saved'), 'ok'); };
  $('#setUnattended').onchange = async (e) => {
    if (e.target.checked && !cfg.hasUnattendedPassword) {
      toast(t('set.pwNone'), 'err');
      $('#setPassword').focus();
    }
    cfg = await nx.setConfig({ unattended: e.target.checked });
    renderMe();
  };
  $('#savePasswordBtn').onclick = async () => {
    const pw = $('#setPassword').value;
    if (pw.length < 8) { $('#pwState').className = 'err'; $('#pwState').textContent = t('set.pwShort'); return; }
    cfg = await nx.setPassword(pw);
    $('#setPassword').value = '';
    if (!cfg.unattended) cfg = await nx.setConfig({ unattended: true });
    $('#setUnattended').checked = true;
    renderPwState();
    renderMe();
    toast(t('set.saved'), 'ok');
  };
  $('#saveNetworkBtn').onclick = async () => {
    cfg = await nx.setConfig({ turn: { url: $('#turnUrl').value.trim(), username: $('#turnUser').value.trim(), credential: $('#turnPass').value } });
    toast(t('set.saved'), 'ok');
    if (!S.mode) startPeer();
  };
  $('#openDownloadsBtn').onclick = () => nx.openDownloads();
  $('#githubBtn').onclick = () => nx.openExternal('https://github.com/A03055/NexDesk');

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('#drawer').hidden && !canControl()) $('#drawer').hidden = true;
  });

  bindViewerInput();
}

// ===========================================================================
// Boot
// ===========================================================================
(async function boot() {
  cfg = await nx.getConfig();
  if (!cfg.id || !/^\d{9}$/.test(cfg.id)) cfg = await nx.setConfig({ id: newId() });
  $('#aboutVersion').textContent = 'v' + cfg.version;
  bindUi();
  applyI18n();
  renderMe();
  renderSettings();
  startPeer();
})();
