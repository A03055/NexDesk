'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const invoke = (ch, ...a) => ipcRenderer.invoke(ch, ...a);

contextBridge.exposeInMainWorld('nx', {
  getConfig: () => invoke('config:get'),
  setConfig: (patch) => invoke('config:set', patch),

  inputStart: () => invoke('input:start'),
  inputStop: () => invoke('input:stop'),
  input: (ev) => ipcRenderer.send('input:event', ev),

  setPassword: (pw) => invoke('auth:setPassword', pw),
  challenge: () => invoke('auth:challenge'),
  prove: (args) => invoke('auth:prove', args),
  verify: (args) => invoke('auth:verify', args),
  sha256: (t) => invoke('crypto:sha256', t),

  fileBegin: (a) => invoke('file:begin', a),
  fileChunk: (a) => invoke('file:chunk', a),
  fileEnd: (a) => invoke('file:end', a),
  fileAbort: (a) => invoke('file:abort', a),
  reveal: (p) => invoke('file:reveal', p),
  openDownloads: () => invoke('file:openDir'),

  clipRead: () => invoke('clip:read'),
  clipWrite: (t) => invoke('clip:write', t),

  displays: () => invoke('displays:list'),
  selectDisplay: (id) => invoke('displays:select', id),

  attention: () => invoke('win:attention'),
  notify: (title, body) => invoke('win:notify', { title, body }),
  fullscreen: (on) => invoke('win:fullscreen', on),
  openExternal: (url) => invoke('open:external', url),

  // development only (handler is not registered in packaged builds)
  debugShot: (name) => invoke('debug:shot', name)
});
