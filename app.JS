/**

- A-SSC Sovereign Lab v6.0 — app.js
- Supplementary module: Settings, Service Worker, Error Logger,
- File System API, AES Project Save/Load, Monaco Worker fix
- Dr. Gazy A.A. Ebrahim — 2026
  */
  (function () {
  ‘use strict’;

/* ════════════════════════════════════════════════
1. ERROR BOUNDARY LOGGER
════════════════════════════════════════════════ */
const ErrorLog = {
entries: [],
maxEntries: 100,

```
capture(source, err, context = '') {
  const entry = {
    ts: new Date().toISOString(),
    source,
    message: err?.message || String(err),
    stack: err?.stack || '',
    context,
    url: location.href
  };
  this.entries.push(entry);
  if (this.entries.length > this.maxEntries) this.entries.shift();
  console.error(`[A-SSC Error] [${source}]`, err);
  this._updateBadge();
  return entry;
},

getLogs() { return [...this.entries]; },
clearLogs() { this.entries = []; this._updateBadge(); },

export() {
  const blob = new Blob([JSON.stringify(this.entries, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `assc-errors-${Date.now()}.json`;
  a.click();
},

_updateBadge() {
  const badge = document.getElementById('err-badge');
  if (!badge) return;
  const count = this.entries.length;
  badge.textContent = count > 0 ? count : '';
  badge.style.display = count > 0 ? 'inline-block' : 'none';
}
```

};

// Global error handlers
window.onerror = (msg, src, line, col, err) => {
ErrorLog.capture(‘window.onerror’, err || { message: msg }, `${src}:${line}:${col}`);
return false; // don’t suppress
};
window.addEventListener(‘unhandledrejection’, e => {
ErrorLog.capture(‘unhandledrejection’, e.reason, ‘Promise rejection’);
});

// Expose globally for use in main app
window.ErrorLog = ErrorLog;

/* ════════════════════════════════════════════════
2. SETTINGS SYSTEM
Stores: apiKey (AES-encrypted), lang, theme, monacoFontSize
════════════════════════════════════════════════ */
const Settings = {
STORAGE_KEY: ‘assc_settings_v6’,
_cache: null,

```
defaults: {
  lang: 'ar',
  monacoFontSize: 13,
  autoSave: true,
  compactMode: false,
  apiKeyEnc: '' // AES-encrypted API key
},

load() {
  try {
    const raw = localStorage.getItem(this.STORAGE_KEY);
    this._cache = raw ? { ...this.defaults, ...JSON.parse(raw) } : { ...this.defaults };
  } catch (e) {
    ErrorLog.capture('Settings.load', e);
    this._cache = { ...this.defaults };
  }
  return this._cache;
},

save(data) {
  try {
    this._cache = { ...this._cache, ...data };
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this._cache));
    return true;
  } catch (e) {
    ErrorLog.capture('Settings.save', e);
    return false;
  }
},

get(key) {
  if (!this._cache) this.load();
  return this._cache[key] ?? this.defaults[key];
},

set(key, value) { return this.save({ [key]: value }); },

/** Store API key encrypted with a device-derived key */
async setApiKey(rawKey) {
  try {
    const enc = await CryptoHelper.encryptText(rawKey, 'assc-settings-key-v1');
    return this.set('apiKeyEnc', enc);
  } catch (e) {
    ErrorLog.capture('Settings.setApiKey', e);
    return false;
  }
},

async getApiKey() {
  const enc = this.get('apiKeyEnc');
  if (!enc) return '';
  try {
    return await CryptoHelper.decryptText(enc, 'assc-settings-key-v1');
  } catch (e) {
    return ''; // key changed or corrupted
  }
},

clear() {
  localStorage.removeItem(this.STORAGE_KEY);
  this._cache = { ...this.defaults };
}
```

};

window.Settings = Settings;
Settings.load();

/* ════════════════════════════════════════════════
3. CRYPTO HELPER
AES-256-GCM for API key & project encryption
════════════════════════════════════════════════ */
const CryptoHelper = {
async deriveKey(password, salt) {
const enc = new TextEncoder();
const keyMaterial = await crypto.subtle.importKey(
‘raw’, enc.encode(password), { name: ‘PBKDF2’ }, false, [‘deriveKey’]
);
return crypto.subtle.deriveKey(
{ name: ‘PBKDF2’, salt: enc.encode(salt), iterations: 100000, hash: ‘SHA-256’ },
keyMaterial,
{ name: ‘AES-GCM’, length: 256 },
false, [‘encrypt’, ‘decrypt’]
);
},

```
async encryptText(text, password) {
  const key = await this.deriveKey(password, 'assc-salt-v1');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  // Combine iv + ciphertext → base64
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv); combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
},

async decryptText(b64, password) {
  const key = await this.deriveKey(password, 'assc-salt-v1');
  const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(dec);
},

/** Encrypt arbitrary object → encrypted blob string */
async encryptObject(obj, password) {
  return this.encryptText(JSON.stringify(obj), password);
},

async decryptObject(blob, password) {
  const text = await this.decryptText(blob, password);
  return JSON.parse(text);
},

/** Encrypt a File/Blob, returns {ivHex, encryptedBlob, fileName} */
async encryptFile(file) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ab = await file.arrayBuffer();
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, ab);
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const keyHex = Array.from(new Uint8Array(rawKey)).map(b => b.toString(16).padStart(2, '0')).join('');
  const encBlob = new Blob([iv, new Uint8Array(enc)]);
  return { keyHex, encBlob, fileName: file.name + '.assc_enc', size: file.size };
}
```

};

window.CryptoHelper = CryptoHelper;

/* ════════════════════════════════════════════════
4. PROJECT SAVE / LOAD (AES-Encrypted)
Uses File System Access API when available,
falls back to download/upload
════════════════════════════════════════════════ */
const ProjectManager = {
VERSION: ‘6.0’,

```
/** Build a project snapshot from current app state */
buildSnapshot(state) {
  return {
    version: this.VERSION,
    timestamp: new Date().toISOString(),
    author: 'Dr. Gazy A.A. Ebrahim',
    lang: state.lang || 'ar',
    agentCode: state.agentCode || '',
    chatHistory: (state.chatHistory || []).slice(-20), // last 20 msgs
    pdfContext: (state.pdfContext || '').slice(0, 5000),
    board: state.board || 'esp32',
    notes: state.projectNotes || ''
  };
},

/** Save project as encrypted .assc file */
async saveEncrypted(state, password) {
  if (!password || password.length < 6) {
    throw new Error('Password must be at least 6 characters');
  }
  const snapshot = this.buildSnapshot(state);
  const encrypted = await CryptoHelper.encryptObject(snapshot, password);
  const blob = new Blob([encrypted], { type: 'application/octet-stream' });
  const name = `assc-project-${Date.now()}.assc`;

  // Try File System Access API first
  if ('showSaveFilePicker' in window) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: name,
        types: [{ description: 'A-SSC Project', accept: { 'application/octet-stream': ['.assc'] } }]
      });
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return { success: true, fileName: handle.name, method: 'filesystem' };
    } catch (e) {
      if (e.name !== 'AbortError') ErrorLog.capture('ProjectManager.saveEncrypted/FS', e);
      // Fall through to download
    }
  }

  // Fallback: trigger download
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return { success: true, fileName: name, method: 'download' };
},

/** Load & decrypt project */
async loadEncrypted(password) {
  return new Promise((resolve, reject) => {
    // Try File System Access API
    if ('showOpenFilePicker' in window) {
      window.showOpenFilePicker({
        types: [{ description: 'A-SSC Project', accept: { 'application/octet-stream': ['.assc'] } }]
      }).then(async ([handle]) => {
        try {
          const file = await handle.getFile();
          const text = await file.text();
          const snapshot = await CryptoHelper.decryptObject(text, password);
          if (snapshot.version !== this.VERSION) {
            console.warn('Version mismatch:', snapshot.version);
          }
          resolve({ success: true, data: snapshot, fileName: file.name });
        } catch (e) { reject(e); }
      }).catch(e => {
        if (e.name === 'AbortError') resolve({ success: false, aborted: true });
        else reject(e);
      });
    } else {
      // Fallback: file input
      const input = document.createElement('input');
      input.type = 'file'; input.accept = '.assc';
      input.onchange = async () => {
        try {
          const file = input.files[0]; if (!file) { resolve({ success: false }); return; }
          const text = await file.text();
          const snapshot = await CryptoHelper.decryptObject(text, password);
          resolve({ success: true, data: snapshot, fileName: file.name });
        } catch (e) { reject(e); }
      };
      input.click();
    }
  });
},

/** Quick auto-save to localStorage (unencrypted, just last state) */
autoSave(state) {
  try {
    const snap = this.buildSnapshot(state);
    localStorage.setItem('assc_autosave_v6', JSON.stringify(snap));
    return true;
  } catch (e) { return false; }
},

autoLoad() {
  try {
    const raw = localStorage.getItem('assc_autosave_v6');
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}
```

};

window.ProjectManager = ProjectManager;

/* ════════════════════════════════════════════════
5. MONACO EDITOR — WORKER FIX
Configures proper worker URLs before Monaco loads
════════════════════════════════════════════════ */
const MONACO_VERSION = ‘0.44.0’;
const MONACO_BASE = `https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/${MONACO_VERSION}/min`;

window.MonacoEnvironment = {
getWorkerUrl(moduleId, label) {
// All workers served from CDN via blob URL to avoid CORS
const workerPaths = {
‘editorWorkerService’: `${MONACO_BASE}/vs/editor/editor.worker.js`,
‘css’: `${MONACO_BASE}/vs/language/css/css.worker.js`,
‘html’: `${MONACO_BASE}/vs/language/html/html.worker.js`,
‘json’: `${MONACO_BASE}/vs/language/json/json.worker.js`,
‘typescript’: `${MONACO_BASE}/vs/language/typescript/ts.worker.js`,
‘javascript’: `${MONACO_BASE}/vs/language/typescript/ts.worker.js`,
};
const workerUrl = workerPaths[label] || workerPaths[‘editorWorkerService’];
// Create blob worker to bypass CORS
const blob = new Blob(
[`importScripts('${workerUrl}');`],
{ type: ‘application/javascript’ }
);
return URL.createObjectURL(blob);
}
};

/* ════════════════════════════════════════════════
6. SERVICE WORKER REGISTRATION
Enables offline mode for the app
════════════════════════════════════════════════ */
const SW = {
registration: null,

```
async register() {
  if (!('serviceWorker' in navigator)) return;
  try {
    // Generate SW code as blob (single-file approach)
    const swCode = `
```

const CACHE = ‘assc-v6-${Date.now()}’;
const PRECACHE = [
‘${location.href}’,
‘https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js’,
‘https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js’,
‘https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs/loader.min.js’,
‘https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js’,
];

self.addEventListener(‘install’, e => {
e.waitUntil(
caches.open(CACHE).then(cache => {
return Promise.allSettled(PRECACHE.map(url => cache.add(url).catch(() => {})));
}).then(() => self.skipWaiting())
);
});

self.addEventListener(‘activate’, e => {
e.waitUntil(
caches.keys().then(keys =>
Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
).then(() => self.clients.claim())
);
});

self.addEventListener(‘fetch’, e => {
// Skip non-GET and API calls
if (e.request.method !== ‘GET’) return;
if (e.request.url.includes(‘api.anthropic.com’)) return;
if (e.request.url.includes(‘pyodide’)) return; // pyodide too large

e.respondWith(
caches.match(e.request).then(cached => {
if (cached) return cached;
return fetch(e.request).then(response => {
if (!response || response.status !== 200 || response.type === ‘opaque’) return response;
const clone = response.clone();
caches.open(CACHE).then(cache => cache.put(e.request, clone));
return response;
}).catch(() => new Response(’’, { status: 503, statusText: ‘Offline’ }));
})
);
});
`;
const blob = new Blob([swCode], { type: ‘application/javascript’ });
const swUrl = URL.createObjectURL(blob);
this.registration = await navigator.serviceWorker.register(swUrl, { scope: ‘/’ });
console.log(’[A-SSC SW] Registered:’, this.registration.scope);
} catch (e) {
// SW registration can fail in some environments (file://, sandboxed iframes)
// This is non-critical — app works without it
ErrorLog.capture(‘ServiceWorker.register’, e, ‘non-critical’);
}
},

```
async unregister() {
  if (this.registration) {
    await this.registration.unregister();
    this.registration = null;
  }
},

isOnline() { return navigator.onLine; }
```

};

window.AppSW = SW;
SW.register();

// Online/offline indicator
const updateOnlineStatus = () => {
const indicator = document.getElementById(‘online-indicator’);
if (!indicator) return;
const online = navigator.onLine;
indicator.textContent = online ? ‘🟢 Online’ : ‘🔴 Offline’;
indicator.style.color = online ? ‘var(–c5)’ : ‘var(–rd)’;
};
window.addEventListener(‘online’, updateOnlineStatus);
window.addEventListener(‘offline’, updateOnlineStatus);

/* ════════════════════════════════════════════════
7. API CLIENT — with key from Settings
Fixes missing x-api-key header
════════════════════════════════════════════════ */
const API = {
MODEL: ‘claude-sonnet-4-20250514’,
ENDPOINT: ‘https://api.anthropic.com/v1/messages’,

```
async getKey() {
  return await Settings.getApiKey();
},

/** Standard (non-streaming) call */
async call(systemPrompt, userMessage, maxTokens = 1400) {
  const apiKey = await this.getKey();
  if (!apiKey) throw new Error(
    window._lang === 'ar'
      ? 'مفتاح API غير موجود. اذهب للإعدادات وأدخل مفتاح Anthropic API.'
      : 'API key missing. Go to Settings and enter your Anthropic API key.'
  );

  const resp = await fetch(this.ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    },
    body: JSON.stringify({
      model: this.MODEL,
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }]
    })
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`API ${resp.status}: ${errText}`);
  }

  const data = await resp.json();
  return data.content?.map(b => b.type === 'text' ? b.text : '').join('') || '';
},

/** Streaming call */
async stream(systemPrompt, messages, onChunk, maxTokens = 2000) {
  const apiKey = await this.getKey();
  if (!apiKey) throw new Error(
    window._lang === 'ar'
      ? 'مفتاح API غير موجود. اذهب للإعدادات.'
      : 'API key missing. Go to Settings.'
  );

  const resp = await fetch(this.ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    },
    body: JSON.stringify({
      model: this.MODEL,
      max_tokens: maxTokens,
      stream: true,
      system: systemPrompt,
      messages
    })
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`API ${resp.status}: ${errText}`);
  }

  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop() || '';
    for (const line of lines) {
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (data === '[DONE]') continue;
      try {
        const evt = JSON.parse(data);
        if (evt.type === 'content_block_delta' && evt.delta?.type === 'text_delta') {
          onChunk(evt.delta.text);
        }
      } catch (_) { /* ignore parse errors */ }
    }
  }
}
```

};

window.AppAPI = API;

/* ════════════════════════════════════════════════
8. FILE SYSTEM API — Save generated code to files
════════════════════════════════════════════════ */
const FileSystem = {
/** Save text content to file via File System Access API or download */
async saveText(content, suggestedName, mimeType = ‘text/plain’) {
const extMap = {
‘text/plain’: ‘.txt’,
‘application/json’: ‘.json’,
‘text/x-c++src’: ‘.cpp’,
‘text/x-python’: ‘.py’,
‘text/javascript’: ‘.js’,
‘text/x-csrc’: ‘.c’,
‘text/x-rustsrc’: ‘.rs’,
‘text/x-matlab’: ‘.m’
};
const ext = extMap[mimeType] || ‘.txt’;
const fileName = suggestedName.endsWith(ext) ? suggestedName : suggestedName + ext;

```
  if ('showSaveFilePicker' in window) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: fileName,
        types: [{ description: 'Code File', accept: { [mimeType]: [ext] } }]
      });
      const writable = await handle.createWritable();
      await writable.write(content);
      await writable.close();
      return { success: true, fileName: handle.name, method: 'filesystem' };
    } catch (e) {
      if (e.name !== 'AbortError') ErrorLog.capture('FileSystem.saveText/FS', e);
      // Fall through
    }
  }

  // Fallback: download
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = fileName; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return { success: true, fileName, method: 'download' };
},

/** Read text file via File System Access API or input */
async openText(accept = '*') {
  return new Promise((resolve, reject) => {
    if ('showOpenFilePicker' in window) {
      window.showOpenFilePicker().then(async ([handle]) => {
        const file = await handle.getFile();
        const text = await file.text();
        resolve({ text, name: file.name, size: file.size });
      }).catch(e => {
        if (e.name === 'AbortError') resolve(null);
        else reject(e);
      });
    } else {
      const input = document.createElement('input');
      input.type = 'file'; input.accept = accept;
      input.onchange = async () => {
        if (!input.files[0]) { resolve(null); return; }
        const file = input.files[0];
        const text = await file.text();
        resolve({ text, name: file.name, size: file.size });
      };
      input.click();
    }
  });
}
```

};

window.AppFS = FileSystem;

/* ════════════════════════════════════════════════
9. SETTINGS UI — Modal rendered on demand
════════════════════════════════════════════════ */
const SettingsUI = {
modal: null,

```
render() {
  if (this.modal) { this.modal.remove(); }

  const overlay = document.createElement('div');
  overlay.id = 'settings-modal';
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:9999;
    background:rgba(2,4,10,.88);backdrop-filter:blur(8px);
    display:flex;align-items:center;justify-content:center;padding:20px;
  `;
  overlay.addEventListener('click', e => { if (e.target === overlay) this.close(); });

  const isAr = (window._lang || 'ar') === 'ar';

  overlay.innerHTML = `
  <div style="background:#070b18;border:1px solid rgba(0,229,255,.25);border-radius:14px;
       width:100%;max-width:540px;padding:0;overflow:hidden;box-shadow:0 0 50px rgba(0,229,255,.12)">
    <!-- Header -->
    <div style="padding:16px 22px;background:rgba(0,0,0,.3);border-bottom:1px solid #0f1e38;
         display:flex;align-items:center;justify-content:space-between">
      <div style="font-family:Orbitron,sans-serif;font-size:.9rem;font-weight:700;
           background:linear-gradient(135deg,#00e5ff,#6c3ce1);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
        ⚙️ ${isAr ? 'إعدادات المختبر' : 'Lab Settings'}
      </div>
      <button id="settings-close" style="background:transparent;border:none;color:#3d5a7a;
           font-size:1.3rem;cursor:pointer;padding:0 4px;line-height:1">×</button>
    </div>
    <!-- Body -->
    <div style="padding:22px;display:flex;flex-direction:column;gap:18px">

      <!-- API Key -->
      <div>
        <div style="font-size:.8rem;font-weight:700;color:#00e5ff;margin-bottom:6px;font-family:Orbitron,sans-serif;letter-spacing:.5px">
          🔑 ${isAr ? 'مفتاح Anthropic API' : 'Anthropic API Key'}
        </div>
        <div style="font-size:.72rem;color:#3d5a7a;margin-bottom:8px;line-height:1.5">
          ${isAr
            ? 'مطلوب لتشغيل نظام الوكلاء والاستشاري. يُحفظ مشفراً بـ AES-256 في جهازك فقط.'
            : 'Required for Agents and Consultant. Stored AES-256 encrypted locally on your device only.'}
        </div>
        <div style="display:flex;gap:8px">
          <input type="password" id="set-apikey" placeholder="sk-ant-api03-..." style="
            flex:1;background:#0b1020;border:1px solid #162a4a;color:#cfe0ff;
            padding:9px 12px;border-radius:8px;font-family:'JetBrains Mono',monospace;
            font-size:.8rem;outline:none;
          " autocomplete="off" spellcheck="false">
          <button id="btn-set-apikey" style="
            padding:9px 16px;border-radius:8px;border:none;font-family:inherit;
            font-size:.79rem;font-weight:700;cursor:pointer;
            background:linear-gradient(135deg,#00e5ff,#6c3ce1);color:#000;
          ">${isAr ? 'حفظ' : 'Save'}</button>
        </div>
        <div id="apikey-status" style="font-size:.72rem;margin-top:6px;min-height:16px"></div>
      </div>

      <!-- Language -->
      <div>
        <div style="font-size:.8rem;font-weight:700;color:#00e5ff;margin-bottom:6px;font-family:Orbitron,sans-serif;letter-spacing:.5px">
          🌐 ${isAr ? 'اللغة' : 'Language'}
        </div>
        <select id="set-lang" style="background:#0b1020;border:1px solid #162a4a;color:#cfe0ff;
             padding:7px 11px;border-radius:8px;font-family:inherit;width:100%;outline:none;font-size:.81rem">
          <option value="ar" ${Settings.get('lang') === 'ar' ? 'selected' : ''}>العربية (Arabic)</option>
          <option value="en" ${Settings.get('lang') === 'en' ? 'selected' : ''}>English</option>
        </select>
      </div>

      <!-- Monaco Font Size -->
      <div>
        <div style="font-size:.8rem;font-weight:700;color:#00e5ff;margin-bottom:6px;font-family:Orbitron,sans-serif;letter-spacing:.5px">
          📝 ${isAr ? 'حجم خط المحرر' : 'Editor Font Size'}
        </div>
        <div style="display:flex;align-items:center;gap:12px">
          <input type="range" id="set-fontsize" min="11" max="20" value="${Settings.get('monacoFontSize')}"
            style="flex:1;height:4px;background:#162a4a;border-radius:3px;-webkit-appearance:none;outline:none">
          <span id="set-fontsize-val" style="font-family:'JetBrains Mono',monospace;color:#00e5ff;
               background:rgba(0,229,255,.08);padding:2px 8px;border-radius:4px;min-width:30px;text-align:center;font-size:.82rem">
            ${Settings.get('monacoFontSize')}
          </span>
        </div>
      </div>

      <!-- Auto Save -->
      <div style="display:flex;align-items:center;justify-content:space-between">
        <div>
          <div style="font-size:.8rem;font-weight:700;color:#00e5ff;font-family:Orbitron,sans-serif;letter-spacing:.5px">
            💾 ${isAr ? 'الحفظ التلقائي' : 'Auto Save'}
          </div>
          <div style="font-size:.71rem;color:#3d5a7a;margin-top:2px">
            ${isAr ? 'يحفظ حالة التطبيق تلقائياً' : 'Auto-saves app state locally'}
          </div>
        </div>
        <label style="position:relative;display:inline-block;width:44px;height:24px;cursor:pointer">
          <input type="checkbox" id="set-autosave" ${Settings.get('autoSave') ? 'checked' : ''}
            style="opacity:0;width:0;height:0">
          <span id="toggle-autosave" style="
            position:absolute;inset:0;border-radius:12px;transition:.3s;
            background:${Settings.get('autoSave') ? 'var(--c5,#00e676)' : '#162a4a'};
          ">
            <span style="position:absolute;height:18px;width:18px;left:${Settings.get('autoSave') ? '23px' : '3px'};
              bottom:3px;background:#fff;border-radius:50%;transition:.3s"></span>
          </span>
        </label>
      </div>

      <!-- Project Save/Load -->
      <div>
        <div style="font-size:.8rem;font-weight:700;color:#f0c040;margin-bottom:8px;font-family:Orbitron,sans-serif;letter-spacing:.5px">
          📦 ${isAr ? 'المشاريع المشفرة' : 'Encrypted Projects'}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button id="btn-save-project" style="flex:1;padding:8px;border-radius:8px;border:none;
               background:linear-gradient(135deg,#f0c040,#ff6b35);color:#000;font-weight:700;
               font-family:inherit;font-size:.79rem;cursor:pointer">
            💾 ${isAr ? 'حفظ مشفر' : 'Save Encrypted'}
          </button>
          <button id="btn-load-project" style="flex:1;padding:8px;border-radius:8px;border:1px solid #162a4a;
               background:transparent;color:#00e5ff;font-weight:700;font-family:inherit;font-size:.79rem;cursor:pointer">
            📂 ${isAr ? 'تحميل مشفر' : 'Load Encrypted'}
          </button>
        </div>
        <input type="password" id="proj-password" placeholder="${isAr ? 'كلمة مرور المشروع...' : 'Project password...'}"
          style="width:100%;margin-top:8px;background:#0b1020;border:1px solid #162a4a;color:#cfe0ff;
                 padding:8px 12px;border-radius:8px;font-family:inherit;font-size:.81rem;outline:none"
          autocomplete="off">
        <div id="proj-status" style="font-size:.72rem;margin-top:5px;min-height:16px"></div>
      </div>

      <!-- Error Log -->
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div style="font-size:.8rem;font-weight:700;color:#ff1744;font-family:Orbitron,sans-serif;letter-spacing:.5px">
            🚨 ${isAr ? 'سجل الأخطاء' : 'Error Log'}
            <span id="set-err-count" style="font-family:'JetBrains Mono',monospace;font-size:.7rem;
                 background:rgba(255,23,68,.12);color:#ff1744;padding:1px 6px;border-radius:3px;margin-right:5px">
              ${ErrorLog.getLogs().length}
            </span>
          </div>
          <div style="display:flex;gap:6px">
            <button id="btn-export-errors" style="padding:4px 10px;border-radius:6px;border:1px solid rgba(255,23,68,.3);
                 background:transparent;color:#ff1744;font-size:.7rem;font-family:inherit;cursor:pointer">
              ${isAr ? 'تصدير' : 'Export'}
            </button>
            <button id="btn-clear-errors" style="padding:4px 10px;border-radius:6px;border:1px solid #162a4a;
                 background:transparent;color:#3d5a7a;font-size:.7rem;font-family:inherit;cursor:pointer">
              ${isAr ? 'مسح' : 'Clear'}
            </button>
          </div>
        </div>
      </div>

      <!-- Online Status + SW -->
      <div style="padding:10px 12px;background:rgba(0,229,255,.03);border:1px solid #0f1e38;border-radius:8px;
           font-size:.74rem;display:flex;align-items:center;justify-content:space-between">
        <span id="online-indicator" style="color:#00e676">🟢 Online</span>
        <span style="color:#3d5a7a;font-family:'JetBrains Mono',monospace">
          ${isAr ? 'عمل بدون انترنت: ' : 'Offline mode: '}
          <span style="color:#00e5ff">${'serviceWorker' in navigator ? (isAr ? 'مفعّل' : 'Active') : (isAr ? 'غير مدعوم' : 'Unsupported')}</span>
        </span>
      </div>
    </div>
  </div>`;

  document.body.appendChild(overlay);
  this.modal = overlay;
  this._bindEvents();
  updateOnlineStatus();
},

_bindEvents() {
  // Close
  document.getElementById('settings-close').addEventListener('click', () => this.close());

  // API Key
  const apiKeyInput = document.getElementById('set-apikey');
  const apiKeyStatus = document.getElementById('apikey-status');

  // Pre-fill masked key if exists
  Settings.getApiKey().then(key => {
    if (key) apiKeyInput.placeholder = 'sk-ant-***' + key.slice(-6);
  });

  document.getElementById('btn-set-apikey').addEventListener('click', async () => {
    const val = apiKeyInput.value.trim();
    if (!val) { apiKeyStatus.style.color = '#ff1744'; apiKeyStatus.textContent = (window._lang === 'ar' ? 'أدخل مفتاح API' : 'Enter API key'); return; }
    if (!val.startsWith('sk-ant-')) { apiKeyStatus.style.color = '#f0c040'; apiKeyStatus.textContent = (window._lang === 'ar' ? 'تحقق من صحة المفتاح (يبدأ بـ sk-ant-)' : 'Key should start with sk-ant-'); }
    const ok = await Settings.setApiKey(val);
    if (ok) { apiKeyStatus.style.color = '#00e676'; apiKeyStatus.textContent = (window._lang === 'ar' ? '✓ تم الحفظ مشفراً' : '✓ Saved encrypted'); apiKeyInput.value = ''; }
    else { apiKeyStatus.style.color = '#ff1744'; apiKeyStatus.textContent = (window._lang === 'ar' ? '❌ فشل الحفظ' : '❌ Save failed'); }
  });

  // Font size
  const fsInput = document.getElementById('set-fontsize');
  const fsVal = document.getElementById('set-fontsize-val');
  fsInput.addEventListener('input', () => {
    fsVal.textContent = fsInput.value;
    Settings.set('monacoFontSize', parseInt(fsInput.value));
    // Update Monaco instances if open
    if (window.AppState?.mcAgent) window.AppState.mcAgent.updateOptions({ fontSize: parseInt(fsInput.value) });
    if (window.AppState?.mcChat) window.AppState.mcChat.updateOptions({ fontSize: parseInt(fsInput.value) });
  });

  // Language
  document.getElementById('set-lang').addEventListener('change', e => {
    Settings.set('lang', e.target.value);
  });

  // Auto save toggle
  const toggle = document.getElementById('set-autosave');
  const span = document.getElementById('toggle-autosave');
  toggle.addEventListener('change', () => {
    const v = toggle.checked;
    Settings.set('autoSave', v);
    span.style.background = v ? 'var(--c5,#00e676)' : '#162a4a';
    span.querySelector('span').style.left = v ? '23px' : '3px';
  });

  // Project save
  document.getElementById('btn-save-project').addEventListener('click', async () => {
    const pw = document.getElementById('proj-password').value;
    const st = document.getElementById('proj-status');
    if (!pw) { st.style.color = '#ff1744'; st.textContent = (window._lang === 'ar' ? 'أدخل كلمة مرور' : 'Enter password'); return; }
    st.style.color = '#f0c040'; st.textContent = (window._lang === 'ar' ? 'جاري الحفظ...' : 'Saving...');
    try {
      const appState = window.AppState || {};
      const result = await ProjectManager.saveEncrypted(appState, pw);
      st.style.color = '#00e676'; st.textContent = `✓ ${result.fileName}`;
    } catch (e) { st.style.color = '#ff1744'; st.textContent = '❌ ' + e.message; }
  });

  // Project load
  document.getElementById('btn-load-project').addEventListener('click', async () => {
    const pw = document.getElementById('proj-password').value;
    const st = document.getElementById('proj-status');
    if (!pw) { st.style.color = '#ff1744'; st.textContent = (window._lang === 'ar' ? 'أدخل كلمة مرور' : 'Enter password'); return; }
    st.style.color = '#f0c040'; st.textContent = (window._lang === 'ar' ? 'جاري التحميل...' : 'Loading...');
    try {
      const result = await ProjectManager.loadEncrypted(pw);
      if (!result.success) { st.textContent = ''; return; }
      // Apply loaded state
      if (window.AppState && result.data) {
        if (result.data.agentCode) window.AppState.agentCode = result.data.agentCode;
        if (result.data.chatHistory) window.AppState.chatHistory = result.data.chatHistory;
        if (result.data.lang) window._lang = result.data.lang;
      }
      st.style.color = '#00e676'; st.textContent = `✓ ${result.fileName}`;
    } catch (e) { st.style.color = '#ff1744'; st.textContent = '❌ ' + (window._lang === 'ar' ? 'كلمة مرور خاطئة أو ملف تالف' : 'Wrong password or corrupted file'); }
  });

  // Error log
  document.getElementById('btn-export-errors').addEventListener('click', () => ErrorLog.export());
  document.getElementById('btn-clear-errors').addEventListener('click', () => {
    ErrorLog.clearLogs();
    document.getElementById('set-err-count').textContent = '0';
  });
},

open() { this.render(); },
close() { if (this.modal) { this.modal.remove(); this.modal = null; } }
```

};

window.SettingsUI = SettingsUI;

/* ════════════════════════════════════════════════
10. SETTINGS BUTTON — Inject into header
════════════════════════════════════════════════ */
document.addEventListener(‘DOMContentLoaded’, () => {
// Inject settings button into header
const hdrR = document.querySelector(’.hdr-r’);
if (hdrR) {
const settingsBtn = document.createElement(‘button’);
settingsBtn.className = ‘btn bo bsm’;
settingsBtn.style.position = ‘relative’;
settingsBtn.innerHTML = `⚙️ <span id="err-badge" style=" display:none;position:absolute;top:-4px;right:-4px; background:#ff1744;color:#fff;border-radius:50%; width:16px;height:16px;font-size:.6rem; display:none;align-items:center;justify-content:center; font-family:'JetBrains Mono',monospace; "></span>`;
settingsBtn.addEventListener(‘click’, () => SettingsUI.open());
hdrR.insertBefore(settingsBtn, hdrR.firstChild);
}

```
// Expose AppState reference for settings to read
// The main app.js must set window.AppState = St after init
setTimeout(() => {
  if (!window.AppState) window.AppState = {};
}, 500);

// Auto-load last session
if (Settings.get('autoSave')) {
  const saved = ProjectManager.autoLoad();
  if (saved && saved.agentCode) {
    window.AppState = window.AppState || {};
    window.AppState.agentCode = saved.agentCode;
  }
}

// Check if API key is set
Settings.getApiKey().then(key => {
  if (!key) {
    // Show subtle hint after 3 seconds
    setTimeout(() => {
      const isAr = (Settings.get('lang') || 'ar') === 'ar';
      const hint = document.createElement('div');
      hint.style.cssText = `
        position:fixed;bottom:20px;right:20px;z-index:1000;
        background:#070b18;border:1px solid rgba(240,192,64,.3);
        border-radius:10px;padding:12px 16px;font-size:.78rem;
        color:#f0c040;max-width:300px;box-shadow:0 0 20px rgba(240,192,64,.1);
        animation:fu .3s ease;cursor:pointer;
      `;
      hint.textContent = isAr
        ? '⚙️ أدخل مفتاح Anthropic API في الإعدادات لتفعيل الوكلاء الذكية'
        : '⚙️ Enter Anthropic API key in Settings to activate AI agents';
      hint.addEventListener('click', () => { hint.remove(); SettingsUI.open(); });
      document.body.appendChild(hint);
      setTimeout(() => { if (hint.parentNode) hint.remove(); }, 8000);
    }, 3000);
  }
});
```

});

/* ════════════════════════════════════════════════
11. PATCH: Replace old API calls in main app
Monkey-patches window.claude and window.claudeStream
to use the fixed API client with proper headers
════════════════════════════════════════════════ */
// These will be available globally for the main IIFE to use
window.claude = (sys, msg, tokens) => API.call(sys, msg, tokens);
window.claudeStream = (sys, msgs, onChunk, tokens) => API.stream(sys, msgs, onChunk, tokens);

// Expose lang for API client error messages
Object.defineProperty(window, ‘_lang’, {
get() { return document.getElementById(‘HR’)?.getAttribute(‘lang’) || ‘ar’; },
configurable: true
});

console.log(’[A-SSC v6.0] app.js loaded — Settings, SW, ErrorLog, API, FileSystem ready’);

})();
