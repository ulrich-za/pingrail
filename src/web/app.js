'use strict';

// ---------------------------------------------------------------------------
// helpers

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return e;
}

/** A named control inside a form. */
const field = (form, name) => form.elements.namedItem(name);
/** The value of the checked radio button in a group. */
const radio = (form, name) => (form.querySelector(`input[name="${name}"]:checked`) || {}).value;

/** Where the light/dark choice is remembered (this browser only). */
const THEME_KEY = 'pingrail-theme';

/*@admin*/
const PAGE_TITLE = 'pingrail';
/*@end*/
/*@share*/
const PAGE_TITLE = 'pingrail · shared view';
// The share code from /s/<code>, and this link's API.
const SHARE = (location.pathname.match(/^\/s\/([A-Za-z0-9]{16,128})\/?$/) || [])[1] || '';
const SP = `/api/s/${SHARE}`;
// What this page was built for: a link's page carries only the controls it
// allows, so it reloads if the owner changes that.
const HAS_ADD = !!$('#target-dialog');
const HAS_EXPORT = !!$('#export-dialog');
/*@end*/

class ApiError extends Error {
  constructor(msg, status) { super(msg); this.status = status; }
}

async function api(path, opts = {}) {
  const init = { credentials: 'same-origin', headers: {}, method: opts.method || 'GET' };
  if (opts.json !== undefined) {
    init.method = opts.method || 'POST';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.json);
  }
  let r;
  try {
    r = await fetch(path, init);
  } catch (e) {
    throw new ApiError('Cannot reach the pingrail service.', 0);
  }
  /*@admin*/
  if (r.status === 401) {
    Login.show(S.inApp ? 'expired' : null);
    throw new ApiError('Please sign in again.', 401);
  }
  /*@end*/
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error || msg; } catch (_) { /* not JSON */ }
    /*@share*/
    // The link was switched off or expired while someone was looking at it.
    if (r.status === 410) showClosed(msg);
    /*@end*/
    throw new ApiError(msg, r.status);
  }
  if (r.status === 204) return null;
  return (r.headers.get('content-type') || '').includes('json') ? r.json() : r;
}

function fmtMs(v) {
  if (v === null || v === undefined) return '—';
  if (v < 1) return v.toFixed(2);
  if (v < 100) return v.toFixed(1);
  return Math.round(v).toString();
}

function fmtPct(v) {
  if (v === 0) return '0';
  return v < 10 ? v.toFixed(1) : Math.round(v).toString();
}

function fmtInterval(ms) {
  const s = ms / 1000;
  return Number.isInteger(s) ? `${s} s` : `${s.toFixed(s < 1 ? 2 : 1)} s`;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
const timeSecFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const dayFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' });
const dayTimeFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });

const dayTimeYearFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
/** A date and time, with the year only when it isn't this year. */
const fmtWhen = (ms) => (new Date(ms).getFullYear() === new Date().getFullYear() ? dayTimeFmt : dayTimeYearFmt).format(ms);

function localInputValue(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function percentile(values, pct) {
  if (!values.length) return null;
  const v = [...values].sort((a, b) => a - b);
  const idx = Math.min(v.length, Math.max(1, Math.ceil((pct / 100) * v.length))) - 1;
  return v[idx];
}

/** Axis maximum made of `div` equal "nice" steps, at least `raw`. */
function axisMax(raw, div) {
  if (!(raw > 0) || !isFinite(raw)) return div;
  const step = raw / div;
  const base = Math.pow(10, Math.floor(Math.log10(step)));
  const f = step / base;
  const nice = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((n) => f <= n + 1e-9) || 10;
  return nice * base * div;
}

function fmtAxis(v) {
  if (v === 0) return '0';
  if (v < 1) return v.toFixed(2);
  if (v < 10 && v % 1 !== 0) return v.toFixed(1);
  return Math.round(v).toString();
}

/** A colour token's value, as seen from `el` (a region can retune tokens:
 *  a dark sidebar, say). */
function css(name, el = document.documentElement) {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

const cap = (m) => (m ? m[0].toUpperCase() + m.slice(1) : m);

function clampNum(v, lo, hi, dflt) {
  const n = Number(v);
  return v !== '' && Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
}

function clampInt(v, lo, hi, dflt) {
  const n = Math.round(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
}

function ago(ms) {
  const s = (Date.now() - ms) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return fmtWhen(ms);
}

function setRadio(form, name, value) {
  const r = form.querySelector(`input[name="${name}"][value="${value}"]`);
  if (r) r.checked = true;
}

/** Copy text, falling back to selecting `input` where the clipboard API is
 *  unavailable (plain http on a LAN address). */
async function copyText(text, input) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) { /* fall back */ }
  if (input) {
    try {
      input.focus();
      input.select();
      if (document.execCommand('copy')) return true;
    } catch (_) { /* give up */ }
  }
  return false;
}

/** A yes/no question in a dialog; resolves true for yes. */
/*@admin*/
function confirmBox(title, body, okText, danger) {
  return new Promise((resolve) => {
    const dlg = $('#confirm-dialog');
    $('#confirm-title').textContent = title;
    $('#confirm-body').textContent = body;
    const go = $('#confirm-go');
    go.textContent = okText;
    go.className = danger ? 'primary danger-fill' : 'primary';
    dlg.returnValue = '';
    dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok'), { once: true });
    dlg.showModal();
  });
}
/*@end*/

function toast(msg) {
  const t = $('#toast');
  // An open modal dialog sits in the top layer; put the toast inside it so
  // it isn't hidden behind the dialog.
  const host = $$('dialog[open]').pop() || document.body;
  if (t.parentNode !== host) host.append(t);
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
}

// ---------------------------------------------------------------------------
// state

const WINDOWS = [
  [300000, '5 min'], [600000, '10 min'], [1800000, '30 min'], [3600000, '1 h'], [10800000, '3 h'],
  [21600000, '6 h'], [86400000, '24 h'], [604800000, '7 days'], [2592000000, '30 days'],
];

const S = {
  windowMs: 600000,
  viewEnd: null,
  selected: null,
  overview: null,
  detail: null,
  timer: null,
  hover: null,
  editing: null,
  hop: null,
  revealed: null,       // the target last scrolled into view in the phone strip
  anchor: null,         // a route row to hold in place while a hop is picked
  inApp: false,
  refreshing: false,
  /*@share*/
  visit: null,          // what this link allows
  /*@end*/
  /*@admin*/
  shares: null,         // /api/shares response
  sharesAt: 0,
  shareEditing: null,   // share being edited in the dialog
  cert: null,           // /api/certificate response
  /*@end*/
};

/*@share*/
/** Was this target added through this link? */
const isOwned = (id) => !!(S.visit && S.visit.owned_ids.includes(id));
/** How many more destinations the link allows. */
const addsLeft = () => (S.visit ? Math.max(0, S.visit.max_targets - S.visit.owned_ids.length) : 0);
/*@end*/

function thresholds() {
  return (S.overview && S.overview.thresholds) || { warn_ms: 100, crit_ms: 200, loss_warn_pct: 1, loss_crit_pct: 10 };
}

function latencyLevel(v) {
  const th = thresholds();
  if (v === null || v === undefined) return 'none';
  if (v >= th.crit_ms) return 'crit';
  if (v >= th.warn_ms) return 'warn';
  return 'good';
}

function lossLevel(pct, sent) {
  const th = thresholds();
  if (!sent) return 'none';
  if (pct >= th.loss_crit_pct) return 'crit';
  if (pct >= th.loss_warn_pct) return 'warn';
  return 'good';
}

const RANK = { none: 0, good: 1, warn: 2, crit: 3 };
const worst = (a, b) => (RANK[a] >= RANK[b] ? a : b);
const LEVEL_WORD = { good: 'Good', warn: 'Elevated', crit: 'High', none: 'No data' };

function mosWord(m) {
  if (m === null || m === undefined) return ['none', 'No data'];
  if (m >= 4.0) return ['good', 'Good call quality'];
  if (m >= 3.6) return ['warn', 'Fair call quality'];
  if (m >= 3.1) return ['crit', 'Poor call quality'];
  return ['crit', 'Bad call quality'];
}

function earliestMs() {
  /*@share*/
  if (S.visit) return S.visit.earliest_ms;
  /*@end*/
  return null;
}

function viewRange() {
  const to = S.viewEnd ?? Date.now() + 1;
  return [to - S.windowMs, to];
}

/** How often to fetch: in step with the target's own interval for short
 *  windows (new samples arrive that often), slower for long ones. */
function refreshInterval() {
  const w = S.windowMs;
  const iv = selectedOverview()?.target.interval_ms || 2500;
  if (S.viewEnd !== null) return 30000;
  if (w <= 3600000) return Math.min(5000, Math.max(1000, iv));
  if (w <= 21600000) return 5000;
  if (w <= 172800000) return 15000;
  return 30000;
}

function selectedOverview() {
  return S.overview?.targets.find((t) => t.target.id === S.selected) || null;
}

/*@admin*/
// ---------------------------------------------------------------------------
// passkeys: the browser's WebAuthn calls, with the server's JSON

const Passkey = (() => {
  const dec = (s) => {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
    return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
  };
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  // Browsers reject null where an option is merely absent.
  const clean = (v) => {
    if (Array.isArray(v)) return v.map(clean);
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v).filter(([, x]) => x !== null).map(([k, x]) => [k, clean(x)]));
    }
    return v;
  };
  const supported = () => typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
  // Signing in talks to the server directly: a refused passkey (401) is an
  // answer here, not an expired session.
  async function post(path, json) {
    let r;
    try {
      r = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json) });
    } catch (_) {
      throw new ApiError('Cannot reach the pingrail service.', 0);
    }
    let body = null;
    try { body = await r.json(); } catch (_) { /* not JSON */ }
    if (!r.ok) {
      const e = new ApiError((body && body.error) || r.statusText, r.status);
      e.retryAfter = Number(r.headers.get('Retry-After')) || 60;
      throw e;
    }
    return body;
  }

  /** Why a passkey request failed, in words; null when the person cancelled. */
  function explain(e) {
    switch (e && e.name) {
      case 'NotAllowedError':
      case 'AbortError':
        return null;
      case 'SecurityError':
        return 'This browser doesn’t trust this server’s certificate for this address yet. Set up this device first (menu › Set up a phone), then try again.';
      case 'InvalidStateError':
        return 'This device already has a passkey for pingrail here.';
      case 'NotSupportedError':
        return 'This browser or device can’t make passkeys.';
      default:
        return e && e.message ? e.message : 'The passkey request failed.';
    }
  }

  /** Sign in (or confirm it's you): 'conditional' fills the username box's
   *  suggestions, 'modal' asks straight away. Resolves to the /api/me reply. */
  async function signIn(mediation, signal) {
    const start = await post('/api/passkey/sign-in', {});
    const pk = clean(start.options.publicKey);
    pk.challenge = dec(pk.challenge);
    (pk.allowCredentials || []).forEach((c) => { c.id = dec(c.id); });
    const opts = { publicKey: pk, signal };
    if (mediation === 'conditional') opts.mediation = 'conditional';
    const cred = await navigator.credentials.get(opts);
    const r = cred.response;
    return post('/api/passkey/sign-in/finish', {
      ceremony: start.ceremony,
      credential: {
        id: cred.id,
        rawId: enc(cred.rawId),
        type: cred.type,
        response: {
          authenticatorData: enc(r.authenticatorData),
          clientDataJSON: enc(r.clientDataJSON),
          signature: enc(r.signature),
          userHandle: r.userHandle ? enc(r.userHandle) : null,
        },
        extensions: cred.getClientExtensionResults(),
      },
    });
  }

  /** Make a passkey for the signed-in user. Resolves to the new list. */
  async function register(label) {
    const start = await api('/api/passkeys/register', { json: { label } });
    const pk = clean(start.options.publicKey);
    pk.challenge = dec(pk.challenge);
    pk.user.id = dec(pk.user.id);
    (pk.excludeCredentials || []).forEach((c) => { c.id = dec(c.id); });
    const cred = await navigator.credentials.create({ publicKey: pk });
    const r = cred.response;
    return api('/api/passkeys/register/finish', {
      json: {
        ceremony: start.ceremony,
        credential: {
          id: cred.id,
          rawId: enc(cred.rawId),
          type: cred.type,
          response: {
            attestationObject: enc(r.attestationObject),
            clientDataJSON: enc(r.clientDataJSON),
            transports: typeof r.getTransports === 'function' ? r.getTransports() : undefined,
          },
          extensions: cred.getClientExtensionResults(),
        },
      },
    });
  }

  return { supported, explain, signIn, register };
})();

// ---------------------------------------------------------------------------
// sign in
//
// The page hangs from one rail: a live round trip from this browser to this
// server, drawn by pingrail's own graph rules. Signing in sends a pulse along
// it to the server's node; the right password brings it back and the rail
// lifts to become the dashboard's top edge, a wrong one loses it.

const Login = (() => {
  const root = document.documentElement;
  const reduce = matchMedia('(prefers-reduced-motion: reduce)');
  const E_OUT = 'cubic-bezier(0.16, 1, 0.3, 1)';
  const E_IO = 'cubic-bezier(0.65, 0, 0.35, 1)';
  const E_IN = 'cubic-bezier(0.7, 0, 0.84, 0)';
  const view = $('#login');
  const q = (s) => $(s, view);
  const L = {
    word: q('.word'), probe: q('.probe'), trace: q('.trace'), hang: q('.hang'),
    rail: q('[data-rail]'), node: q('[data-rail] .rail__node'), stem: q('[data-stem]'),
    svg: q('[data-trace]'), summary: q('[data-trace-summary]'),
    rtt: q('[data-rtt]'), jitter: q('[data-jitter]'), loss: q('[data-loss]'), note: q('[data-probe-note]'),
    form: $('#login-form'), user: $('#username'), pass: $('#password'), reveal: $('#reveal'),
    msg: $('#password-msg'), btn: $('#login-submit'), btnLabel: q('[data-btn-label]'),
    notice: $('#login-notice'), dot: q('[data-dot]'), theme: $('#login-theme'), themeLabel: q('[data-theme-label]'),
    host: q('[data-host]'), appRail: $('[data-app-rail]'),
    pw: $$('[data-pw]', view), alt: $('#passkey-alt'), altBtn: $('#passkey-signin'), lost: $('#passkey-lost'),
  };
  const NOTE_DEFAULT = L.note.textContent;
  L.host.textContent = location.host || 'this server';

  // ----- transport: the only code here that talks to the server -----

  const parseRetry = (v) => {
    const n = Number(v);
    if (v && Number.isFinite(n)) return Math.max(1, Math.round(n));
    const t = Date.parse(v || '');
    return Number.isFinite(t) ? Math.max(1, Math.round((t - Date.now()) / 1000)) : 60;
  };

  const transport = {
    /** The round trip in ms; rejects on a timeout or an error. */
    async probe(timeoutMs) {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      const t0 = performance.now();
      try {
        const r = await fetch('/api/ping', { cache: 'no-store', credentials: 'omit', signal: ctl.signal });
        if (!r.ok) throw new Error(`ping ${r.status}`);
        return performance.now() - t0;
      } finally {
        clearTimeout(timer);
      }
    },
    /** { kind: 'ok' | 'wrong' | 'blocked' | 'error' | 'unreachable', retryAfter?, message? } */
    async signIn(username, password) {
      let r;
      try {
        r = await fetch('/api/login', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
      } catch (_) {
        return { kind: 'unreachable' };
      }
      if (r.ok) return { kind: 'ok' };
      if (r.status === 401) return { kind: 'wrong' };
      if (r.status === 429) return { kind: 'blocked', retryAfter: parseRetry(r.headers.get('Retry-After')) };
      let message = '';
      try { message = (await r.json()).error || ''; } catch (_) { /* not JSON */ }
      return { kind: 'error', message };
    },
  };

  // ----- theme (the same setting as the app's menu) -----

  const labelTheme = () => {
    const next = effectiveTheme() === 'dark' ? 'Light theme' : 'Dark theme';
    L.themeLabel.textContent = next;
    L.theme.setAttribute('aria-label', `Switch to ${next.toLowerCase()}`);
  };
  L.theme.addEventListener('click', () => {
    const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, next); } catch (_) { /* not remembered */ }
    applyTheme(next);
  });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', labelTheme);
  new MutationObserver(labelTheme).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
  labelTheme();

  // ----- probe: real round trips from this browser to this server -----

  const PROBE = { interval: 1000, timeout: 2000, avg: 5 };
  const samples = [];            // { ms: number } | { ms: null } (lost) | { gap: true } (not measured)
  let warm = true;               // the first reply includes connection set-up, so it's dropped
  let probeTimer = 0;
  let pausedAt = 0;
  let lastMs = 0;
  let reducedDone = false;

  const visible = () => !view.hidden;
  const probing = () => document.visibilityState === 'visible' && visible() && !reducedDone;

  function next(ms) {
    clearTimeout(probeTimer);
    if (probing()) probeTimer = setTimeout(probeOnce, ms);
    else if (!pausedAt && !reducedDone) pausedAt = performance.now();   // the gap is drawn on return
  }

  async function probeOnce() {
    let ms = null;
    try { ms = await transport.probe(PROBE.timeout); } catch (_) { ms = null; }
    if (!visible()) return;
    if (warm) {
      warm = false;
      if (ms !== null) { next(120); return; }
    }
    samples.push({ ms });
    if (samples.length > 200) samples.splice(0, samples.length - 200);
    if (ms !== null) lastMs = ms;
    if (reduce.matches) {
      // Reduced motion: measure briefly, then draw one still picture.
      if (samples.filter((s) => !s.gap).length >= 8) {
        reducedDone = true;
        L.note.textContent = 'measured when this page opened';
        redraw(false);
        return;
      }
      next(250);
      return;
    }
    redraw(true);
    if (ms !== null) bumpNode();
    next(PROBE.interval);
  }

  function startProbe() {
    if (pausedAt) {
      const missed = Math.min(120, Math.round((performance.now() - pausedAt) / PROBE.interval));
      for (let i = 0; i < missed; i++) samples.push({ gap: true });
      pausedAt = 0;
    }
    warm = true;
    next(0);
  }
  function stopProbe() {
    clearTimeout(probeTimer);
    if (!pausedAt) pausedAt = performance.now();
  }
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') { if (visible()) startProbe(); } else stopProbe();
  });

  // ----- readout -----

  const mean = (a) => a.reduce((s, v) => s + v, 0) / a.length;
  const fmt = (ms) => (ms < 10 ? ms.toFixed(1) : String(Math.round(ms)));
  const setVal = (node, num, unit) => {
    node.classList.remove('is-wait');
    node.replaceChildren(num, el('span', { class: 'u', text: unit }));
  };

  let lastSummary = 0;
  function updateReadout() {
    const recent = samples.slice(-30).filter((s) => !s.gap);
    if (!recent.length) return;
    const okv = recent.filter((s) => s.ms !== null).map((s) => s.ms);
    const last5 = okv.slice(-PROBE.avg);
    const avg = last5.length ? mean(last5) : null;
    let jit = null;
    if (okv.length > 1) {
      const d = [];
      for (let i = 1; i < okv.length; i++) d.push(Math.abs(okv[i] - okv[i - 1]));
      jit = mean(d);
    }
    const lossPct = Math.round(((recent.length - okv.length) / recent.length) * 100);
    const tail = recent.slice(-3);
    // Not answering: the last three probes failed. Slow: a 5-sample average
    // above 250 ms or jitter above 40 ms.
    const down = tail.length === 3 && tail.every((s) => s.ms === null);
    const slow = !down && ((avg !== null && avg > 250) || (jit !== null && jit > 40));

    if (down || avg === null) { L.rtt.classList.add('is-wait'); L.rtt.textContent = 'no reply'; }
    else setVal(L.rtt, fmt(avg), 'ms');
    if (jit === null) L.jitter.textContent = '…'; else setVal(L.jitter, fmt(jit), 'ms');
    setVal(L.loss, String(lossPct), '%');

    L.probe.classList.toggle('is-down', down);
    L.probe.classList.toggle('is-slow', slow);
    L.trace.classList.toggle('is-slow', slow);
    if (!reducedDone) {
      L.note.textContent = down
        ? "This server isn't answering. Check that the pingrail service is running."
        : slow ? 'This server is answering slowly.' : NOTE_DEFAULT;
    }
    const now = performance.now();
    if (now - lastSummary > 15000 || reducedDone) {
      lastSummary = now;
      L.summary.textContent = down
        ? 'This server is not answering this browser.'
        : `Round trip from this browser to this server: average ${okv.length ? fmt(mean(okv)) : 'unknown'} milliseconds, jitter ${jit === null ? 'not yet known' : `${fmt(jit)} milliseconds`}, ${lossPct === 0 ? 'no loss' : `${lossPct} percent loss`}.`;
    }
  }

  // ----- trace: pingrail's graph rules, small -----
  //
  // Bold line = moving average (5 samples), light line and band = samples
  // and their spread, gaps only where samples are missing, loss marked on the
  // axis, a scale that follows the bulk of the data and steps only when it
  // moves well outside, and off-scale spikes marked with a triangle.

  const NS = 'http://www.w3.org/2000/svg';
  const svgEl = (tag, attrs = {}) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    return n;
  };
  const STEPS = [5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];
  let ceil = 10;
  let glideAnim = null;
  const quantile = (a, qq) => {
    const s = [...a].sort((x, y) => x - y);
    return s[Math.min(s.length - 1, Math.floor(qq * (s.length - 1)))];
  };
  const r1 = (n) => Math.round(n * 10) / 10;

  function draw(glide) {
    const W = L.svg.clientWidth;
    const H = L.svg.clientHeight;
    if (!W || !H) return;
    const full = Math.max(24, Math.min(90, Math.round(W / 7)));
    const N = Math.max(12, Math.min(full, samples.length));
    const padR = 16, padT = 15, padB = 3;
    const dx = (W - padR) / (N - 1);
    const shown = samples.slice(-(N + 1));
    const n = shown.length;
    const shift = glide ? dx : 0;
    const xOf = (i) => r1(W - padR - (n - 1 - i) * dx + shift);
    const isOk = (s) => typeof s.ms === 'number';
    const okv = shown.filter(isOk).map((s) => s.ms);
    if (okv.length) {
      const p90 = quantile(okv, 0.9);
      const want = STEPS.find((s) => s >= p90 * 1.3) ?? STEPS[STEPS.length - 1];
      if (want > ceil || p90 < ceil * 0.35) ceil = Math.max(5, want);
    }
    const yOf = (ms) => r1(H - padB - (Math.min(ms, ceil) / ceil) * (H - padB - padT));

    let raw = '', avg = '', band = '';
    const marks = [];
    let segRaw = false, segAvg = false;
    let top = [], bot = [];
    const flushBand = () => {
      if (top.length > 1) band += `M${top.map((p) => p.join(' ')).join('L')}L${bot.reverse().map((p) => p.join(' ')).join('L')}Z`;
      top = []; bot = [];
    };
    for (let i = 0; i < n; i++) {
      const s = shown[i];
      if (!isOk(s)) {
        segRaw = false; segAvg = false; flushBand();
        if (s.ms === null) marks.push(svgEl('rect', { class: 't-loss', x: r1(xOf(i) - 2), y: H - padB - 8, width: 4, height: 8 }));
        continue;
      }
      const x = xOf(i);
      raw += `${segRaw ? 'L' : 'M'}${x} ${yOf(s.ms)}`;
      segRaw = true;
      if (s.ms > ceil) marks.push(svgEl('path', { class: 't-spike', d: `M${r1(x - 4)} ${padT - 2}L${r1(x + 4)} ${padT - 2}L${x} ${padT - 9}Z` }));
      const win = [];
      for (let k = Math.max(0, i - PROBE.avg + 1); k <= i; k++) if (isOk(shown[k])) win.push(shown[k].ms);
      if (win.length >= 3) {
        avg += `${segAvg ? 'L' : 'M'}${x} ${yOf(mean(win))}`;
        segAvg = true;
        top.push([x, yOf(Math.max(...win))]);
        bot.push([x, yOf(Math.min(...win))]);
      } else { segAvg = false; flushBand(); }
    }
    flushBand();

    const right = W - padR;
    L.svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    const clip = svgEl('clipPath', { id: 'pr-clip' });
    clip.append(svgEl('rect', { x: 0, y: 0, width: right + 4, height: H }));
    const defs = svgEl('defs');
    defs.append(clip);
    const scale = svgEl('text', { class: 't-scale', x: 0, y: padT - 5 });
    scale.textContent = `${ceil} ms`;
    const moving = svgEl('g', { class: 't-glide' });
    moving.append(svgEl('path', { class: 't-band', d: band }), svgEl('path', { class: 't-raw', d: raw }), svgEl('path', { class: 't-avg', d: avg }), ...marks);
    const clipped = svgEl('g', { 'clip-path': 'url(#pr-clip)' });
    clipped.append(moving);
    L.svg.replaceChildren(defs, svgEl('path', { class: 't-grid', d: `M0 ${yOf(ceil)}H${right}M0 ${yOf(ceil / 2)}H${right}` }), scale, clipped);

    if (glideAnim) glideAnim.cancel();
    glideAnim = null;
    if (glide && !reduce.matches) {
      glideAnim = moving.animate(
        [{ transform: 'translateX(0)' }, { transform: `translateX(${-dx}px)` }],
        { duration: PROBE.interval + lastMs, easing: 'linear', fill: 'forwards' },
      );
    }
  }

  function redraw(glide) {
    updateReadout();
    draw(glide);
  }
  new ResizeObserver(() => draw(false)).observe(L.svg);

  function bumpNode() {
    if (reduce.matches || L.node.classList.contains('is-waiting') || L.node.classList.contains('is-lost')) return;
    L.node.animate([{ scale: 1 }, { scale: 1.22 }, { scale: 1 }], { duration: 520, easing: E_OUT });
  }

  // ----- messages -----

  let msgKind = '';                 // '', 'caps', 'error', 'blocked'
  function setMsg(kind, text, tone) {
    msgKind = kind;
    L.msg.className = `field__msg${tone ? ` is-${tone}` : ''}`;
    L.msg.textContent = text;
  }
  function clearMsg() { msgKind = ''; L.msg.className = 'field__msg'; L.msg.textContent = ''; }

  const NOTICES = {
    expired: 'Your session ended. Sign in again to carry on.',
    'password-changed': 'The password was changed, so every session was signed out. Sign in with the new one.',
    'signed-out': "You're signed out.",
  };
  let noPassword = false;
  // Passkeys usable at this address; needed instead of the password.
  let passkeys = false;
  let passkeyOnly = false;
  function showNotice(reason) {
    const text = noPassword && !passkeyOnly
      ? 'No password has been set for this monitor yet. Set one on the machine running the service: press P in pingrail’s terminal UI, or run pingrail passwd.'
      : NOTICES[reason];
    L.notice.hidden = !text;
    L.notice.textContent = text || '';
  }
  async function checkPassword(reason) {
    try {
      const h = await fetch('/api/health', { cache: 'no-store' }).then((r) => r.json());
      noPassword = !h.has_password;
      passkeys = !!h.passkeys && Passkey.supported();
      passkeyOnly = !!h.passkey_required;
    } catch (_) { /* the probe shows that the server isn't answering */ }
    if (!visible()) return;
    showNotice(reason);
    // With passkeys required the form is one button; otherwise a passkey is
    // the alternative under it (and in the username box's suggestions).
    L.pw.forEach((n) => { n.hidden = passkeyOnly; });
    L.lost.hidden = !passkeyOnly;
    L.alt.hidden = passkeyOnly || !passkeys;
    L.btnLabel.textContent = passkeyOnly ? 'Sign in with a passkey' : 'Sign in';
    if (passkeyOnly && !passkeys) {
      showNoticeText(Passkey.supported()
        ? 'This server needs a passkey to sign in. Open pingrail by its name (not an IP address) on a device that trusts its certificate.'
        : 'This server needs a passkey to sign in, and this browser can’t use passkeys.');
    }
    if (passkeys && !passkeyOnly) offerPasskeys();
  }
  function showNoticeText(text) {
    L.notice.hidden = false;
    L.notice.textContent = text;
  }

  // ----- passkeys: suggested by the username box, or asked for outright -----

  let conditional = null;   // AbortController of the autofill request
  async function offerPasskeys() {
    if (conditional || !PublicKeyCredential.isConditionalMediationAvailable) return;
    if (!(await PublicKeyCredential.isConditionalMediationAvailable().catch(() => false))) return;
    const ctl = new AbortController();
    conditional = ctl;
    try {
      await Passkey.signIn('conditional', ctl.signal);
      if (conditional !== ctl) return;
      conditional = null;
      clearMsg();
      setBusy(true);
      await sendPulse();
      await echo();
      setBusy(false);
      enter();
    } catch (e) {
      if (conditional === ctl) conditional = null;
      // A suggestion nobody picked fails quietly; only the server's answer
      // to a passkey someone chose is worth saying.
      if (!ctl.signal.aborted && e instanceof ApiError) setMsg('error', e.message, 'loss');
    }
  }
  function stopOffering() {
    if (conditional) { conditional.abort(); conditional = null; }
  }

  async function passkeySignIn() {
    if (busy || blockedUntil > Date.now()) return;
    stopOffering();
    clearMsg();
    setBusy(true);
    const travel = sendPulse();
    let failure = null;
    try {
      await Passkey.signIn('modal');
    } catch (e) {
      failure = e;
    }
    await travel;
    if (!failure) {
      await echo();
      setBusy(false);
      enter();
      return;
    }
    lose();
    setBusy(false);
    if (failure instanceof ApiError && failure.status === 429) {
      block(failure.retryAfter || 60);
    } else {
      const why = failure instanceof ApiError ? failure.message : Passkey.explain(failure);
      if (why) setMsg('error', why, 'loss');
      else { stopWaiting(); L.node.classList.remove('is-lost'); }
    }
    L.btn.focus();
    if (passkeys && !passkeyOnly) offerPasskeys();
  }
  L.altBtn.addEventListener('click', passkeySignIn);

  // ----- password field helpers -----

  L.reveal.addEventListener('click', () => {
    const show = L.pass.type === 'password';
    const { selectionStart, selectionEnd } = L.pass;
    L.pass.type = show ? 'text' : 'password';
    L.reveal.setAttribute('aria-pressed', String(show));
    L.reveal.firstChild.textContent = show ? 'Hide' : 'Show';
    L.pass.focus();
    try { L.pass.setSelectionRange(selectionStart, selectionEnd); } catch (_) { /* lost with the type */ }
  });
  const caps = (e) => {
    if (!e.getModifierState) return;
    const on = e.getModifierState('CapsLock');
    if (on && (msgKind === '' || msgKind === 'caps')) setMsg('caps', 'Caps Lock is on.', 'attn');
    else if (!on && msgKind === 'caps') clearMsg();
  };
  L.pass.addEventListener('keydown', caps);
  L.pass.addEventListener('keyup', caps);
  L.pass.addEventListener('blur', () => { if (msgKind === 'caps') clearMsg(); });
  L.pass.addEventListener('input', () => {
    if (msgKind === 'error') { clearMsg(); L.pass.removeAttribute('aria-invalid'); L.node.classList.remove('is-lost'); }
  });
  L.user.addEventListener('input', () => {
    L.user.removeAttribute('aria-invalid');
    if (msgKind === 'error') { clearMsg(); L.node.classList.remove('is-lost'); }
  });

  // ----- the pulse: a sign-in travels the rail -----

  let breathing = null;
  function route() {
    const [sx, sy] = [window.scrollX, window.scrollY];
    const b = L.btn.getBoundingClientRect();
    const st = L.stem.getBoundingClientRect();
    const rl = L.rail.getBoundingClientRect();
    const nd = L.node.getBoundingClientRect();
    const stemX = st.left + 1 + sx;
    const btnY = b.top + b.height / 2 + sy;
    const railY = rl.top + rl.height / 2 + sy;
    const nodeX = nd.left + nd.width / 2 + sx;
    return [[b.left + sx + 20, btnY], [stemX, btnY], [stemX, railY], [nodeX, railY]];
  }
  function keyframesAlong(pts) {
    const lens = [0];
    for (let i = 1; i < pts.length; i++) lens.push(lens[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
    const total = lens[lens.length - 1] || 1;
    return pts.map((p, i) => ({ translate: `${p[0] - window.scrollX}px ${p[1] - window.scrollY}px`, offset: lens[i] / total }));
  }
  async function sendPulse() {
    L.node.classList.remove('is-lost');
    if (reduce.matches) { L.node.classList.add('is-waiting'); return; }
    const frames = keyframesAlong(route());
    frames[0].opacity = 0; frames[1].opacity = 1;
    frames[frames.length - 1].opacity = 1;
    await L.dot.animate(frames, { duration: 700, easing: E_OUT, fill: 'forwards' }).finished.catch(() => {});
    L.dot.getAnimations().forEach((a) => a.cancel());
    L.node.classList.add('is-waiting');
    breathing = L.node.animate([{ scale: 1 }, { scale: 1.32 }, { scale: 1 }], { duration: 900, iterations: Infinity, easing: E_IO });
  }
  function stopWaiting() {
    if (breathing) { breathing.cancel(); breathing = null; }
    L.node.classList.remove('is-waiting');
  }
  async function echo() {
    stopWaiting();
    if (reduce.matches) return;
    const pts = route();
    const frames = keyframesAlong([pts[3], pts[2]]);
    frames[0].opacity = 1; frames[1].opacity = 0;
    await L.dot.animate(frames, { duration: 380, easing: E_IO, fill: 'forwards' }).finished.catch(() => {});
    L.dot.getAnimations().forEach((a) => a.cancel());
  }
  function lose() {
    stopWaiting();
    L.node.classList.add('is-lost');
    if (!reduce.matches) L.node.animate([{ scale: 1.35 }, { scale: 1 }], { duration: 420, easing: E_OUT });
  }

  // ----- signing in -----

  let busy = false;
  let blockedUntil = 0;
  let blockTimer = 0;
  const setDisabled = (on) => {
    if (on) L.btn.setAttribute('aria-disabled', 'true'); else L.btn.removeAttribute('aria-disabled');
  };
  function setBusy(on) {
    busy = on;
    L.btn.classList.toggle('is-busy', on);
    L.form.setAttribute('aria-busy', String(on));
    setDisabled(on || blockedUntil > Date.now());
    L.btnLabel.textContent = on ? 'Signing in' : passkeyOnly ? 'Sign in with a passkey' : 'Sign in';
  }

  const clock = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  function block(seconds) {
    blockedUntil = Date.now() + seconds * 1000;
    setDisabled(true);
    const railBox = L.rail.getBoundingClientRect();
    const stemBox = L.stem.getBoundingClientRect();
    L.rail.style.setProperty('--stem-x', `${Math.round(stemBox.left - railBox.left)}px`);
    L.rail.classList.add('is-blocked');
    msgKind = 'blocked';
    L.msg.className = 'field__msg is-loss';
    const count = el('span', { class: 'count', 'aria-hidden': 'true' });
    const spoken = el('span', { class: 'vh', text: seconds >= 120 ? `${Math.round(seconds / 60)} minutes` : `${seconds} seconds` });
    L.msg.replaceChildren('Too many sign-in attempts from this address. Try again in ', count, spoken, '.');
    const tick = () => {
      const left = Math.max(0, Math.ceil((blockedUntil - Date.now()) / 1000));
      count.textContent = clock(left);
      if (left > 0) return;
      clearInterval(blockTimer);
      blockedUntil = 0;
      L.rail.classList.remove('is-blocked');
      L.node.classList.remove('is-lost');
      setDisabled(busy);
      setMsg('', 'You can try again now.', 'attn');
      L.pass.focus();
    };
    clearInterval(blockTimer);
    blockTimer = setInterval(tick, 1000);
    tick();
  }

  L.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (passkeyOnly) { passkeySignIn(); return; }
    if (busy || blockedUntil > Date.now()) return;
    stopOffering();
    const username = L.user.value.trim();
    const password = L.pass.value;
    if (!username) {
      L.user.setAttribute('aria-invalid', 'true');
      setMsg('error', 'Enter the username.', 'loss');
      L.user.focus();
      return;
    }
    if (!password) {
      L.pass.setAttribute('aria-invalid', 'true');
      setMsg('error', 'Enter the password.', 'loss');
      L.pass.focus();
      return;
    }
    if (L.pass.type !== 'password') L.reveal.click();   // password managers watch type="password"
    clearMsg();
    L.pass.removeAttribute('aria-invalid');
    if (!noPassword) showNotice(null);
    setBusy(true);
    const travel = sendPulse();
    const result = await transport.signIn(username, password).catch(() => ({ kind: 'unreachable' }));
    await travel;
    if (result.kind === 'ok') {
      await echo();
      setBusy(false);
      enter();
      return;
    }
    lose();
    setBusy(false);
    if (result.kind === 'wrong') {
      L.pass.value = '';
      L.pass.setAttribute('aria-invalid', 'true');
      setMsg('error', "That username and password don't match. Try again.", 'loss');
      L.pass.focus();
      if (passkeys) offerPasskeys();
    } else if (result.kind === 'blocked') {
      L.pass.value = '';
      block(result.retryAfter || 60);
      L.pass.focus();
    } else if (result.kind === 'error' && result.message) {
      setMsg('error', `${cap(result.message.replace(/\.$/, ''))}.`, 'loss');
      L.btn.focus();
    } else {
      setMsg('error', "Couldn't reach this server. Check that the pingrail service is running, then try again.", 'loss');
      L.btn.focus();
    }
  });

  // ----- moving between sign-in and the app -----

  const parts = () => [L.word, L.probe, L.trace, L.hang];
  const appParts = () => [$('.topbar .wordmark'), $('#windows'), $('.topbar-actions'), $('.layout')];

  /** Signed in: the rail lifts to become the dashboard's top edge. */
  async function enter() {
    stopProbe();
    stopOffering();
    const from = L.rail.getBoundingClientRect().top;
    if (!reduce.matches) {
      await Promise.all(parts().map((p, i) => p.animate(
        [{ opacity: 1, translate: '0 0' }, { opacity: 0, translate: '0 28px' }],
        { duration: 360, delay: i * 40, easing: E_IN, fill: 'forwards' },
      ).finished.catch(() => {})));
    }
    view.hidden = true;
    parts().forEach((p) => p.getAnimations().forEach((a) => a.cancel()));
    L.pass.value = '';
    L.node.classList.remove('is-lost');
    showApp();
    const to = L.appRail.getBoundingClientRect().top;
    if (!reduce.matches) {
      L.appRail.animate([{ translate: `0 ${from - to}px` }, { translate: '0 0' }], { duration: 680, easing: E_IO });
      appParts().forEach((p, i) => p.animate([{ opacity: 0, translate: '0 14px' }, { opacity: 1, translate: '0 0' }],
        { duration: 520, delay: 300 + i * 40, easing: E_OUT, fill: 'backwards' }));
    }
    $('#app').focus({ preventScroll: true });
  }

  /** Back to sign-in, with the reason: 'expired', 'password-changed',
   *  'signed-out', or null. */
  async function show(reason) {
    if (visible()) {
      if (reason) showNotice(reason);
      return;
    }
    // Stop the app.
    S.inApp = false;
    clearTimeout(S.timer);
    cancelAnimationFrame(S.glideFrame);
    closeMenu();
    for (const d of $$('dialog[open]')) d.close();
    const app = $('#app');
    if (!app.hidden) {
      const from = L.appRail.getBoundingClientRect().top;
      if (!reduce.matches) {
        await $('.layout').animate([{ opacity: 1, translate: '0 0' }, { opacity: 0, translate: '0 18px' }],
          { duration: 260, easing: E_IN, fill: 'forwards' }).finished.catch(() => {});
      }
      app.hidden = true;
      $('.layout').getAnimations().forEach((a) => a.cancel());
      view.hidden = false;
      const to = L.rail.getBoundingClientRect().top;
      if (!reduce.matches) {
        L.rail.animate([{ translate: `0 ${from - to}px` }, { translate: '0 0' }], { duration: 680, easing: E_IO });
        parts().forEach((p, i) => p.animate([{ opacity: 0, translate: '0 28px' }, { opacity: 1, translate: '0 0' }],
          { duration: 520, delay: 260 + i * 50, easing: E_OUT, fill: 'backwards' }));
      }
    } else {
      view.hidden = false;
    }
    document.title = 'Sign in · pingrail';
    clearMsg();
    showNotice(reason);
    checkPassword(reason);
    draw(false);
    startProbe();
    L.pass.focus({ preventScroll: true });
  }

  return { show };
})();

async function logout() {
  closeMenu();
  try { await api('/api/logout', { method: 'POST', json: {} }); } catch (_) { /* signed out here anyway */ }
  Login.show('signed-out');
}
/*@end*/

function showApp() {
  S.inApp = true;
  glide();
  $('#app').hidden = false;
  document.title = PAGE_TITLE;
  const fromHash = Number(new URLSearchParams(location.hash.slice(1)).get('t'));
  if (fromHash) S.selected = fromHash;
  refresh();
}

/*@share*/
// ---------------------------------------------------------------------------
// share-link visitors

function showClosed(msg, status) {
  S.inApp = false;
  clearTimeout(S.timer);
  clearInterval(S.infoTimer);
  $('#app').hidden = true;
  $('#closed').hidden = false;
  $('#closed-code').textContent = String(status || 410);
  $('#closed-msg').textContent = msg || 'This link isn’t available.';
  for (const d of $$('dialog[open]')) d.close();
}

function showVisitor(info) {
  S.visit = info;
  $('#closed').hidden = true;
  applyVisit();
  // Pick up changes the owner makes to the link (rights, privacy, expiry).
  clearInterval(S.infoTimer);
  S.infoTimer = setInterval(async () => {
    if (document.hidden || !S.inApp) return;
    try {
      S.visit = await api(`${SP}/info?refresh=1`);
      applyVisit();
    } catch (_) { /* 410 shows the closed page; anything else retries */ }
  }, 60000);
  showApp();
}

/** Show what this link allows. */
function applyVisit() {
  const v = S.visit;
  if (v.can_add !== HAS_ADD || v.can_export !== HAS_EXPORT) {
    // The owner changed what the link allows: fetch the page built for that.
    location.reload();
    return;
  }
  /*@add*/
  const add = $('#add-open');
  const left = addsLeft();
  add.disabled = left === 0;
  add.textContent = left === 0 ? `All ${v.max_targets} destinations used` : `Add destination (${left} left)`;
  /*@end*/

  const bits = [el('strong', { text: 'Shared live view' })];
  const hidden = [];
  if (v.hide_private) hidden.push('private hops');
  if (v.hide_public_hops) hidden.push(v.hide_public_hops === 1 ? 'the first public hop' : `the first ${v.hide_public_hops} public hops`);
  if (v.hide_hostnames) hidden.push('hop host names');
  if (hidden.length) bits.push(el('span', { class: 'muted', text: `Hidden by the owner: ${hidden.join(', ')}` }));
  if (v.earliest_ms) bits.push(el('span', { class: 'muted', text: `History from ${fmtWhen(v.earliest_ms)}` }));
  if (v.can_add) bits.push(el('span', { class: 'muted', text: `You can add up to ${v.max_targets} destinations of your own` }));
  if (v.expires_ms) bits.push(el('span', { class: 'muted', text: `Link works until ${fmtWhen(v.expires_ms)}` }));
  $('#share-bar').replaceChildren(...bits);
  $('#share-bar').hidden = false;
}
/*@end*/

// ---------------------------------------------------------------------------
// refresh loop

function schedule(ms) {
  clearTimeout(S.timer);
  S.timer = setTimeout(refresh, ms);
}

/** What the graph is showing: a reply for any other view is out of date. */
const viewKey = () => `${S.selected}|${S.hop}|${S.windowMs}|${S.viewEnd}`;

async function refresh() {
  if (!S.inApp) return;
  if (document.hidden) { schedule(3000); return; }
  if (S.refreshing) {
    // A view change while a (possibly slow) request is out: fetch again as
    // soon as it returns rather than waiting for the next tick.
    S.again = true;
    return;
  }
  S.refreshing = true;
  try {
    // The target list changes slowly: fetch it every few seconds even when
    // the selected graph refreshes every second.
    if (!S.overview || S.overview.window_ms !== S.windowMs || Date.now() - S.ovAt > 4000) {
      let ov;
      /*@admin*/
      ov = await api(`/api/overview?window_ms=${S.windowMs}&spark=40`);
      /*@end*/
      /*@share*/
      try {
        ov = await api(`${SP}/overview?window_ms=${S.windowMs}`);
      } catch (e) {
        // An unknown link: it was deleted while open.
        if (e.status === 404) { showClosed(e.message, 404); return; }
        throw e;
      }
      /*@end*/
      S.overview = ov;
      S.ovAt = Date.now();
      /*@admin*/
      maybeLoadShares();
      /*@end*/
      const ids = ov.targets.map((t) => t.target.id);
      if (!ids.includes(S.selected)) S.selected = ids[0] ?? null;
      renderList();
    }
    setConn('ok');
    if (S.selected !== null) {
      const key = viewKey();
      const d = await api(detailPath(S.selected));
      // Drop a reply for a view that changed while it was on its way (say a
      // 30-day request finishing after you picked 5 min).
      if (key === viewKey()) acceptDetail(d);
      else S.again = true;
    } else {
      S.detail = null;
    }
    renderDetail();
  } catch (e) {
    if (e.status !== 401 && e.status !== 410) setConn('down', e.message);
  } finally {
    S.refreshing = false;
  }
  if (S.inApp) schedule(S.again ? 0 : refreshInterval());
  S.again = false;
}

function detailPath(id) {
  const hop = S.hop !== null ? `&hop=${S.hop}` : '';
  /*@share*/
  // Live views omit the end so every visitor shares one cached answer.
  const end = S.viewEnd !== null ? `&end_ms=${Math.round(S.viewEnd)}` : '';
  return `${SP}/targets/${id}/detail?window_ms=${S.windowMs}${end}&points=${maxPoints()}${hop}`;
  /*@end*/
  /*@admin*/
  const [from, to] = viewRange();
  return `/api/targets/${id}/detail?from=${from}&to=${to}&points=${maxPoints()}${hop}`;
  /*@end*/
}

function refreshSoon() {
  schedule(0);
}

function setConn(state, msg) {
  const c = $('#conn');
  const banner = $('#banner');
  c.classList.toggle('down', state === 'down');
  c.classList.toggle('paused', state === 'ok' && S.viewEnd !== null);
  if (state === 'down') {
    c.textContent = 'Offline';
    banner.textContent = `${msg || 'Lost contact with the pingrail service'}. Retrying…`;
    banner.hidden = false;
  } else {
    c.textContent = S.viewEnd === null ? 'Live' : 'Viewing history';
    banner.hidden = true;
  }
}

/** Most points the chart can show: one per 2 px, so every sample gets its
 *  own point whenever there is room for it. */
function maxPoints() {
  const w = ($('#chart').clientWidth || 800) - PAD.l - PAD.r;
  return Math.max(60, Math.min(2000, Math.floor(w / 2)));
}

// ---------------------------------------------------------------------------
// target list

/** Targets in list order (on a share link, the visitor's own come last). */
function listTargets() {
  const all = S.overview?.targets || [];
  /*@share*/
  return [...all.filter((t) => !isOwned(t.target.id)), ...all.filter((t) => isOwned(t.target.id))];
  /*@end*/
  /*@admin*/
  return all;
  /*@end*/
}

function renderList() {
  const ul = $('#target-list');
  const targets = listTargets();
  /*@admin*/
  const want = targets.map((t) => t.target.id).join(',');
  /*@end*/
  /*@share*/
  const want = targets.map((t) => `${t.target.id}${isOwned(t.target.id) ? 'o' : ''}`).join(',');
  /*@end*/
  if (ul.dataset.ids !== want) {
    const items = [];
    /*@share*/
    let grouped = false;
    /*@end*/
    for (const t of targets) {
      const id = t.target.id;
      /*@share*/
      if (isOwned(id) && !grouped) {
        items.push(el('li', { class: 'group', text: 'Added by you' }));
        grouped = true;
      }
      /*@end*/
      items.push(el('li', {},
        el('button', { 'data-id': id, onclick: () => select(id) },
          el('span', { class: 'dot' }),
          el('span', { class: 'name' }),
          el('span', { class: 'ms' }),
          el('span', { class: 'host' }),
          el('canvas', { width: 72, height: 18, 'aria-hidden': 'true' }))));
    }
    ul.replaceChildren(...items);
    ul.dataset.ids = want;
  }
  for (const t of targets) {
    const b = $(`button[data-id="${t.target.id}"]`, ul);
    if (!b) continue;
    const s = t.stats;
    const paused = !t.target.enabled;
    const lvl = paused ? 'off' : worst(latencyLevel(s.avg_ms), lossLevel(s.loss_pct, s.sent));
    $('.dot', b).className = `dot ${lvl === 'none' ? '' : lvl}`;
    $('.name', b).textContent = t.target.name;
    $('.ms', b).textContent = paused ? 'paused' : (s.cur_ms === null ? (s.sent ? 'lost' : '—') : `${fmtMs(s.cur_ms)} ms`);
    let host = t.live.ip && t.live.ip !== t.target.host ? `${t.target.host} (${t.live.ip})` : t.target.host;
    /*@admin*/
    if (t.target.share_id) host += ` · via ${shareLabel(t.target.share_id)}`;
    /*@end*/
    $('.host', b).textContent = host;
    b.classList.toggle('paused', paused);
    b.setAttribute('aria-current', t.target.id === S.selected ? 'true' : 'false');
    b.setAttribute('aria-label', `${t.target.name}, ${paused ? 'paused' : `${fmtMs(s.avg_ms)} ms average, ${fmtPct(s.loss_pct)}% loss`}`);
    drawSpark($('canvas', b), t);
  }
  $('#empty').hidden = targets.length > 0;
  $('#target-view').hidden = targets.length === 0;
  if (S.revealed !== S.selected) { S.revealed = S.selected; revealSelected(); }
}

function drawSpark(cv, t) {
  const dpr = window.devicePixelRatio || 1;
  const w = 72, h = 18;
  cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext('2d');
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  const vals = t.spark.filter((v) => v !== null);
  if (!vals.length) return;
  const top = axisMax((percentile(vals, 95) || 1) * 1.2, 1);
  const n = t.spark.length;
  const x = (i) => (i + 0.5) * (w / n);
  g.fillStyle = css('--crit', cv);
  t.spark_loss.forEach((l, i) => { if (l) g.fillRect(x(i) - 1, h - 3, 2, 3); });
  g.strokeStyle = t.target.enabled ? css('--series', cv) : css('--ink-3', cv);
  g.lineWidth = 1.5;
  g.lineJoin = 'round';
  g.beginPath();
  let pen = false;
  t.spark.forEach((v, i) => {
    if (v === null) { pen = false; return; }
    const y = h - 4 - Math.min(1, v / top) * (h - 6);
    if (pen) g.lineTo(x(i), y); else g.moveTo(x(i), y);
    pen = true;
  });
  g.stroke();
}

function select(id) {
  if (S.selected === id) return;
  S.selected = id;
  S.detail = null;
  S.hop = null;
  S.anchor = null;
  history.replaceState(null, '', `#t=${id}`);
  renderList();
  renderDetail();
  refreshSoon();
}

/** On narrow screens the list is a strip that scrolls sideways: bring the
 *  selected target into it without moving the page. */
function revealSelected() {
  const ul = $('#target-list');
  if (ul.scrollWidth <= ul.clientWidth) return;
  const li = $('button[aria-current="true"]', ul)?.parentElement;
  if (!li) return;
  const r = li.getBoundingClientRect();
  const u = ul.getBoundingClientRect();
  if (r.left < u.left || r.right > u.right) ul.scrollLeft += r.left - u.left - parseFloat(getComputedStyle(ul).paddingLeft || '0');
}

// ---------------------------------------------------------------------------
// detail

function renderDetail() {
  const ov = selectedOverview();
  if (!ov) return;
  const t = ov.target;
  const d = S.detail && S.detail.target.id === t.id ? S.detail : null;
  $('#t-name').textContent = t.name;

  const parts = [t.host];
  const ip = ov.live.ip;
  if (ip && ip !== t.host) parts.push(ip);
  const dest = d?.hops.find((h) => h.is_dest);
  if (dest) parts.push(`${dest.ttl} hop${dest.ttl === 1 ? '' : 's'}`);
  parts.push(`sampled every ${fmtInterval(t.interval_ms)}`);
  if (!t.enabled) parts.push('paused');
  /*@admin*/
  else if (t.session) parts.push('stops when the terminal app that added it closes');
  else parts.push('runs in the background');
  if (t.share_id) {
    const sh = S.shares?.shares.find((x) => x.id === t.share_id);
    const ended = sh && sh.status !== 'active' ? ` (link ${sh.status === 'revoked' ? 'switched off' : 'expired'})` : '';
    parts.push(`added by a visitor through share link “${shareLabel(t.share_id)}”${ended}`);
  }
  /*@end*/
  /*@share*/
  if (isOwned(t.id)) parts.push('added by you through this link');
  /*@add*/
  // Visitors may only change destinations they added themselves.
  for (const id of ['#t-pause', '#t-edit', '#t-remove']) $(id).hidden = !isOwned(t.id);
  /*@end*/
  /*@end*/
  $('#t-meta').textContent = parts.join(', ');
  /*@add*/
  $('#t-pause').textContent = t.enabled ? 'Pause' : 'Resume';
  /*@end*/
  /*@admin*/
  $('#t-bg').hidden = !(t.enabled && t.session);
  /*@end*/
  const err = $('#t-error');
  err.hidden = !ov.live.error;
  err.textContent = ov.live.error || '';

  // What the stats below describe. One line either way, so picking a hop
  // changes its words, not the layout under it.
  const hopInfo = graphedHop();
  $('#hop-bar').classList.toggle('is-hop', !!hopInfo);
  $('#hop-clear').hidden = !hopInfo;
  $('#hop-what').replaceChildren(...(hopInfo
    ? ['Trace probes to hop ',
      el('strong', { text: `${hopInfo.ttl} · ${hopInfo.addr || hopInfo.masked || 'no reply'}` }),
      hopInfo.is_dest ? ', the destination' : null,
      HOP_SAYS[hopInfo.reading] ? el('span', { class: 'hop-note', text: ` · ${HOP_SAYS[hopInfo.reading]}` }) : null]
    : ['Pings to the destination']).filter((x) => x !== null));
  $('#chart-sub').textContent = hopInfo ? `in ms, hop ${hopInfo.ttl}` : 'in ms';
  const notLoss = isNotLoss(hopInfo);
  $('#legend').classList.toggle('is-unanswered', notLoss);
  $('#legend-loss').textContent = notLoss ? 'unanswered probes' : 'packet loss';
  renderStats(d ? d.stats : ov.stats, hopInfo);
  updateRangeLabel();
  drawCharts();
  renderRoute(t, d);
  if (S.anchor && d && d.target.id === S.anchor.id && (d.hop ?? null) === S.hop) {
    const row = $(`#route-table tr[data-ttl="${S.anchor.ttl}"]`);
    if (row) window.scrollBy(0, row.getBoundingClientRect().top - S.anchor.top);
    S.anchor = null;
  }
}

/** The hop being graphed instead of the destination, if any. */
function graphedHop() {
  const d = S.detail;
  if (!d || d.hop === null || d.hop === undefined || (S.selected !== null && d.target.id !== S.selected)) return null;
  return d.hops.find((h) => h.ttl === d.hop) || null;
}

/** Unanswered probes at a hop that limits or ignores replies to itself are
 *  not loss on the path, so they are never drawn in the loss colour. */
const isNotLoss = (h) => !!h && (h.reading === 'limits_replies' || h.reading === 'no_reply');

const HOP_SAYS = {
  loss_starts: 'loss reaching the destination starts here',
  loss_carried: 'carries loss from an earlier hop',
  limits_replies: 'limits its replies, so this isn’t loss on the path',
  no_reply: 'doesn’t answer probes, the hops after it do',
};

function renderStats(s, hop = null) {
  const lat = latencyLevel(s.avg_ms);
  const notLoss = isNotLoss(hop);
  const loss = notLoss ? 'none' : lossLevel(s.loss_pct, s.sent);
  const [mosLvl, mosText] = mosWord(s.mos);
  // Call quality only means something end to end.
  const middle = hop && !hop.is_dest;
  const item = (label, value, unit, status) => el('div', {},
    el('dt', { text: label }),
    el('dd', {}, value, unit && value !== '—' ? el('small', { text: unit }) : null),
    status ? el('dd', { class: 'status', 'data-level': status[0] }, status[1]) : null);
  const items = [
    item('Average', fmtMs(s.avg_ms), 'ms', s.sent ? [lat, LEVEL_WORD[lat]] : null),
    item('Minimum', fmtMs(s.min_ms), 'ms'),
    item('Maximum', fmtMs(s.max_ms), 'ms'),
    item('95th percentile', fmtMs(s.p95_ms), 'ms'),
    item('Jitter', fmtMs(s.jitter_ms), 'ms'),
    item(notLoss ? 'Unanswered' : 'Packet loss', s.sent ? fmtPct(s.loss_pct) : '—', '%',
      s.sent ? [loss, `${s.sent - s.received} of ${s.sent} ${notLoss ? 'unanswered' : 'lost'}`] : null),
    middle ? null : item('MOS', s.mos === null || s.mos === undefined ? '—' : s.mos.toFixed(2), '', s.mos ? [mosLvl, mosText] : null),
  ].filter(Boolean);
  $('#t-stats').replaceChildren(...items);
  for (const st of $$('#t-stats .status')) {
    st.style.setProperty('--status', css(`--${st.dataset.level === 'none' ? 'ink-3' : st.dataset.level}`));
  }
}

function updateRangeLabel() {
  const [from, to] = viewRange();
  const label = WINDOWS.find((w) => w[0] === S.windowMs)?.[1] || '';
  const f = S.windowMs > 172800000 ? dayTimeFmt : timeFmt;
  $('#range-label').textContent = S.viewEnd === null
    ? `Live, last ${label}`
    : `${dayTimeFmt.format(from)} to ${f.format(to)}`;
  $('#pan-live').hidden = S.viewEnd === null;
  $('#pan-fwd').disabled = S.viewEnd === null;
  const earliest = earliestMs();
  $('#pan-back').disabled = earliest !== null && earliest !== undefined && from <= earliest;
}

// ----- charts ----------------------------------------------------------------
//
// The server sends either every sample (when there is room to draw them all)
// or clock-aligned slices of samples, plus the stretches with no samples at
// all. Everything is placed by time, so a refresh only adds the newest point
// and the chart glides with the clock in between.

const PAD = { l: 46, r: 12 };

/** Orange for loss; ink for probes a router just didn't answer. */
const lossInk = () => css(isNotLoss(graphedHop()) ? '--ink-3' : '--crit');

function setupCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
    cv.width = Math.round(w * dpr);
    cv.height = Math.round(h * dpr);
  }
  const g = cv.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  g.font = `11px ${css('--font')}`;
  return { g, w, h };
}

function timeTicks(from, to, max) {
  const steps = [1e3, 2e3, 5e3, 1e4, 15e3, 3e4, 6e4, 12e4, 3e5, 6e5, 9e5, 18e5, 36e5, 72e5, 108e5, 216e5, 432e5, 864e5, 1728e5, 6048e5];
  const span = Math.max(1, to - from);
  const step = steps.find((s) => span / s <= max) || 6048e5;
  const off = -new Date(from).getTimezoneOffset() * 60000;
  const out = [];
  for (let t = Math.ceil((from + off) / step) * step - off; t <= to; t += step) {
    const d = new Date(t);
    let label;
    if (step >= 864e5) label = dayFmt.format(d);
    else if (span > 864e5) label = (d.getHours() === 0 && d.getMinutes() === 0) ? dayFmt.format(d) : timeFmt.format(d);
    else label = step < 6e4 ? timeSecFmt.format(d) : timeFmt.format(d);
    out.push([t, label]);
  }
  return out;
}

/** The time range the charts show right now: it follows the clock when live. */
function chartRange() {
  if (S.viewEnd !== null) return viewRange();
  const now = Date.now();
  return [now - S.windowMs, now];
}

/** Moving-average window in samples mode: about 30 s, at least 5 samples. */
const maWindow = (tl) => Math.max(30000, tl.interval_ms * 5);

/** Centred moving average of the points' averages, restarting after gaps. */
function movingAverage(pts, windowMs) {
  const half = windowMs / 2;
  const out = new Array(pts.length).fill(null);
  let segStart = 0;
  for (let i = 0; i <= pts.length; i++) {
    if (i < pts.length && !(i > 0 && pts[i].gap)) continue;
    let lo = segStart, hi = segStart, sum = 0, n = 0;
    for (let k = segStart; k < i; k++) {
      const t = pts[k].t_ms;
      while (hi < i && pts[hi].t_ms <= t + half) {
        if (pts[hi].avg_ms !== null) { sum += pts[hi].avg_ms; n++; }
        hi++;
      }
      while (pts[lo].t_ms < t - half) {
        if (pts[lo].avg_ms !== null) { sum -= pts[lo].avg_ms; n--; }
        lo++;
      }
      out[k] = n > 0 ? sum / n : null;
    }
    segStart = i;
  }
  return out;
}

/** A new detail arrived: derive what the charts need and settle the scale. */
function acceptDetail(d) {
  S.detail = d;
  const tl = d.timeline;
  S.ma = tl.mode === 'samples' ? movingAverage(tl.points, maWindow(tl)) : tl.points.map((p) => p.avg_ms);
  updateScale(d);
}

/** Latency axis maximum. It grows at once for a spike, but only shrinks once
 *  the data has stayed well below it for a few refreshes, so the graph
 *  doesn't jump about while you watch it. */
function updateScale(d) {
  const pts = d.timeline.points;
  const vals = pts.map((p) => p.max_ms).filter((v) => v !== null);
  const avgMax = Math.max(0, ...pts.map((p) => p.avg_ms ?? 0));
  const want = axisMax(Math.max(avgMax * 1.15, percentile(vals, 98) || 0, 0.5), 4);
  const key = `${d.target.id}|${d.hop ?? ''}|${S.windowMs}|${S.viewEnd === null}`;
  const y = S.yScale;
  if (!y || y.key !== key || want > y.max) {
    S.yScale = { key, max: want, low: 0 };
  } else if (want < y.max * 0.6) {
    y.low += 1;
    if (y.low >= 3) S.yScale = { key, max: want, low: 0 };
  } else {
    y.low = 0;
  }
}

function drawCharts() {
  const d = S.detail && S.detail.target.id === S.selected ? S.detail : null;
  S.drawnAt = Date.now();
  drawLatency(d);
  drawLoss(d);
  updateLegend(d);
}

function updateLegend(d) {
  const samples = !d || d.timeline.mode === 'samples';
  $('#legend-avg').textContent = samples ? 'moving average' : 'average';
  $('#legend-spread').textContent = samples ? 'each sample' : 'lowest to highest';
  $('#legend-spread-key').className = samples ? 'key-sample' : 'key-band';
  $('#chart-caption').textContent = d ? timelineCaption(d.timeline) : '';
}

function fmtSpan(ms) {
  if (ms % 3600000 === 0) return ms === 3600000 ? '1-hour' : `${ms / 3600000}-hour`;
  if (ms % 60000 === 0) return `${ms / 60000}-minute`;
  const s = ms / 1000;
  return `${Number.isInteger(s) ? s : s.toFixed(1)}-second`;
}

function timelineCaption(tl) {
  if (tl.mode === 'samples') {
    const lo = tl.interval_min_ms, hi = tl.interval_max_ms;
    const every = lo > 0 && hi > lo ? `${fmtInterval(lo).replace(' s', '')}–${fmtInterval(hi)}` : fmtInterval(tl.interval_ms);
    return `Each point is one sample (every ${every}). The bold line is a moving average over ${fmtSpan(maWindow(tl)).replace('-', ' ')}s.`
      .replace('seconds', 'seconds').replace('1 minutes', '1 minute');
  }
  const per = (iv) => Math.max(1, Math.round(tl.step_ms / Math.max(1, iv)));
  const lo = tl.interval_min_ms, hi = tl.interval_max_ms;
  const n = lo > 0 && hi > lo && per(hi) !== per(lo) ? `${per(hi)}–${per(lo)}` : `about ${per(tl.interval_ms)}`;
  return `Each point is a ${fmtSpan(tl.step_ms)} slice of ${n} samples. The bold line is the average; the band runs from lowest to highest.`;
}

/** x position for time `t` on a plot of width `pw`. */
const xAt = (t, from, to, pw) => PAD.l + ((t - from) / Math.max(1, to - from)) * pw;

/** Where a point is drawn: a sample at its own time, a slice at its middle. */
function pointTime(tl, p) {
  return tl.mode === 'samples' ? p.t_ms : p.t_ms + tl.step_ms / 2;
}

function drawLatency(d) {
  const cv = $('#chart');
  const { g, w, h } = setupCanvas(cv);
  const top = 10, bottom = h - 4;
  const pw = w - PAD.l - PAD.r, ph = bottom - top;
  const ink3 = css('--ink-3'), line = css('--line'), series = css('--series');
  if (!d) {
    g.fillStyle = ink3;
    g.textAlign = 'center';
    g.fillText('Loading…', PAD.l + pw / 2, top + ph / 2);
    return;
  }
  const tl = d.timeline;
  const pts = tl.points;
  const [from, to] = chartRange();
  const ymax = S.yScale?.max || 1;
  const y = (v) => bottom - Math.min(1, v / ymax) * ph;
  const x = (t) => xAt(t, from, to, pw);
  const stepPx = Math.max(1, (tl.step_ms / Math.max(1, to - from)) * pw);

  g.save();
  g.beginPath();
  g.rect(PAD.l, top - 2, pw, ph + 4);
  g.clip();

  // Stretches with no samples at all (paused, monitor off, before it began).
  g.fillStyle = css('--gap');
  for (const [a, b] of tl.gaps) {
    const x0 = Math.max(PAD.l, x(a)), x1 = Math.min(PAD.l + pw, x(b));
    if (x1 > x0) g.fillRect(x0, top, x1 - x0, ph);
  }
  // Fully lost samples or slices: a tint behind the line.
  g.fillStyle = lossInk();
  g.globalAlpha = 0.12;
  for (const p of pts) {
    if (p.sent > 0 && p.lost === p.sent) {
      const px = tl.mode === 'samples' ? x(p.t_ms) - stepPx / 2 : x(p.t_ms);
      g.fillRect(px, top, Math.max(1.5, stepPx), ph);
    }
  }
  g.globalAlpha = 1;
  g.restore();

  // Grid
  g.textAlign = 'right';
  g.textBaseline = 'middle';
  for (let k = 0; k <= 4; k++) {
    const v = (ymax * k) / 4;
    g.strokeStyle = k === 0 ? css('--line-strong') : line;
    g.lineWidth = 1;
    g.beginPath();
    g.moveTo(PAD.l, Math.round(y(v)) + 0.5);
    g.lineTo(w - PAD.r, Math.round(y(v)) + 0.5);
    g.stroke();
    g.fillStyle = ink3;
    g.fillText(fmtAxis(v), PAD.l - 8, y(v));
  }
  for (const [t] of timeTicks(from, to, Math.max(3, Math.floor(pw / 110)))) {
    const xx = Math.round(x(t)) + 0.5;
    g.strokeStyle = line;
    g.beginPath(); g.moveTo(xx, top); g.lineTo(xx, bottom); g.stroke();
  }

  // Thresholds: dashed lines, labelled (colour alone doesn't carry them).
  const th = thresholds();
  for (const [v, col, name] of [[th.warn_ms, css('--ink-3'), 'warn'], [th.crit_ms, css('--crit'), 'crit']]) {
    if (v < ymax) {
      g.strokeStyle = col;
      g.lineWidth = name === 'crit' ? 1.5 : 1;
      g.setLineDash([5, 4]);
      g.beginPath(); g.moveTo(PAD.l, Math.round(y(v)) + 0.5); g.lineTo(w - PAD.r, Math.round(y(v)) + 0.5); g.stroke();
      g.setLineDash([]);
      g.lineWidth = 1;
      g.fillStyle = ink3;
      g.textAlign = 'right';
      g.textBaseline = 'bottom';
      g.fillText(`${name} ${fmtAxis(v)} ms`, w - PAD.r - 4, y(v) - 2);
    }
  }

  g.save();
  g.beginPath();
  g.rect(PAD.l, top - 2, pw, ph + 4);
  g.clip();
  // Runs of points between real gaps. Lost samples are skipped, not breaks.
  const runs = [];
  let cur = [];
  pts.forEach((p, i) => {
    if (p.gap && cur.length) { runs.push(cur); cur = []; }
    cur.push(i);
  });
  if (cur.length) runs.push(cur);
  const px = (i) => x(pointTime(tl, pts[i]));

  if (tl.mode === 'slices') {
    // Band: lowest to highest in each slice, in its own quiet colour so the
    // average line stands out against it.
    g.fillStyle = css('--band');
    for (const r of runs) {
      const ok = r.filter((i) => pts[i].max_ms !== null);
      if (!ok.length) continue;
      g.beginPath();
      ok.forEach((i, k) => (k ? g.lineTo(px(i), y(pts[i].max_ms)) : g.moveTo(px(i), y(pts[i].max_ms))));
      for (let k = ok.length - 1; k >= 0; k--) g.lineTo(px(ok[k]), y(pts[ok[k]].min_ms));
      g.closePath();
      g.fill();
    }
  } else {
    // Every sample as a thin line.
    g.strokeStyle = css('--sample');
    g.lineWidth = 1;
    g.lineJoin = 'round';
    for (const r of runs) {
      g.beginPath();
      let pen = false;
      for (const i of r) {
        if (pts[i].avg_ms === null) continue;
        if (pen) g.lineTo(px(i), y(pts[i].avg_ms)); else g.moveTo(px(i), y(pts[i].avg_ms));
        pen = true;
      }
      g.stroke();
    }
  }
  // The bold line: moving average (samples) or slice average (slices).
  const ma = S.ma || [];
  g.strokeStyle = series;
  g.lineWidth = 2.25;
  g.lineJoin = 'round';
  g.lineCap = 'round';
  for (const r of runs) {
    g.beginPath();
    let pen = false, n = 0;
    for (const i of r) {
      if (ma[i] === null || ma[i] === undefined) continue;
      if (pen) g.lineTo(px(i), y(ma[i])); else g.moveTo(px(i), y(ma[i]));
      pen = true;
      n++;
    }
    if (n === 1) { const i = r.find((k) => ma[k] !== null); g.arc(px(i), y(ma[i]), 1.5, 0, Math.PI * 2); }
    g.stroke();
  }
  // Spikes above the scale.
  g.fillStyle = css('--ink');
  for (const p of pts) {
    if (p.max_ms !== null && p.max_ms > ymax) {
      const xx = x(pointTime(tl, p));
      g.beginPath(); g.moveTo(xx, top + 1); g.lineTo(xx - 3.5, top + 7); g.lineTo(xx + 3.5, top + 7); g.closePath(); g.fill();
    }
  }
  g.restore();

  if (!pts.some((p) => p.avg_ms !== null)) {
    g.fillStyle = ink3;
    g.textAlign = 'center';
    g.textBaseline = 'middle';
    g.fillText(pts.length ? 'No replies in this period' : 'No samples in this period', PAD.l + pw / 2, top + ph / 2);
  }

  // Hover
  if (S.hover !== null && S.hover < pts.length) {
    const p = pts[S.hover];
    const xx = Math.round(px(S.hover)) + 0.5;
    g.strokeStyle = css('--ink-2');
    g.lineWidth = 1;
    g.beginPath(); g.moveTo(xx, top); g.lineTo(xx, bottom); g.stroke();
    const v = tl.mode === 'samples' ? p.avg_ms : ma[S.hover];
    if (v !== null && v !== undefined) {
      g.fillStyle = css('--surface');
      g.beginPath(); g.arc(xx, y(v), 6, 0, Math.PI * 2); g.fill();
      g.fillStyle = series;
      g.beginPath(); g.arc(xx, y(v), 4, 0, Math.PI * 2); g.fill();
    }
  }
}

function drawLoss(d) {
  const cv = $('#loss');
  const { g, w, h } = setupCanvas(cv);
  const top = 8, bottom = h - 22;
  const pw = w - PAD.l - PAD.r, ph = bottom - top;
  if (!d) return;
  const tl = d.timeline;
  const pts = tl.points;
  const [from, to] = chartRange();
  const x = (t) => xAt(t, from, to, pw);
  const stepPx = Math.max(1.5, (tl.step_ms / Math.max(1, to - from)) * pw);
  const samples = tl.mode === 'samples';
  const pcts = pts.map((p) => (p.sent ? (100 * p.lost) / p.sent : 0));
  const maxLoss = Math.max(0, ...pcts);
  const lmax = samples ? 100 : (maxLoss > 0 ? Math.min(100, axisMax(maxLoss, 1)) : 10);
  const ink3 = css('--ink-3'), line = css('--line');

  g.save();
  g.beginPath(); g.rect(PAD.l, top, pw, ph); g.clip();
  g.fillStyle = css('--gap');
  for (const [a, b] of tl.gaps) {
    const x0 = Math.max(PAD.l, x(a)), x1 = Math.min(PAD.l + pw, x(b));
    if (x1 > x0) g.fillRect(x0, top, x1 - x0, ph);
  }
  g.restore();

  g.textAlign = 'right';
  g.textBaseline = 'middle';
  for (const [v, strong] of [[0, true], [lmax, false]]) {
    const yy = Math.round(bottom - (v / lmax) * ph) + 0.5;
    g.strokeStyle = strong ? css('--line-strong') : line;
    g.beginPath(); g.moveTo(PAD.l, yy); g.lineTo(w - PAD.r, yy); g.stroke();
    g.fillStyle = ink3;
    g.fillText(`${fmtAxis(v)}%`, PAD.l - 8, yy);
  }
  g.save();
  g.beginPath(); g.rect(PAD.l, top, pw, ph); g.clip();
  g.fillStyle = lossInk();
  pts.forEach((p, i) => {
    if (pcts[i] > 0) {
      const hh = Math.max(1.5, (pcts[i] / lmax) * ph);
      const xx = samples ? x(p.t_ms) - stepPx / 2 : x(p.t_ms);
      g.fillRect(xx + 0.25, bottom - hh, Math.max(1, stepPx - 0.5), hh);
    }
  });
  g.restore();
  if (maxLoss === 0 && pts.length) {
    g.fillStyle = ink3;
    g.textAlign = 'center';
    g.fillText('No packet loss', PAD.l + pw / 2, top + ph / 2);
  }

  // time labels
  g.fillStyle = ink3;
  g.textAlign = 'center';
  g.textBaseline = 'top';
  let lastEnd = -Infinity;
  for (const [t, label] of timeTicks(from, to, Math.max(3, Math.floor(pw / 110)))) {
    const xx = x(t);
    const tw = g.measureText(label).width;
    if (xx - tw / 2 < lastEnd + 8 || xx + tw / 2 > w) continue;
    g.fillText(label, xx, bottom + 6);
    lastEnd = xx + tw / 2;
  }
  if (S.hover !== null && S.hover < pts.length) {
    const xx = Math.round(x(pointTime(tl, pts[S.hover]))) + 0.5;
    g.strokeStyle = css('--ink-2');
    g.beginPath(); g.moveTo(xx, top); g.lineTo(xx, bottom); g.stroke();
  }
}

/** Index of the point nearest to time `t` (points are in time order). */
function nearestPoint(tl, t) {
  const pts = tl.points;
  let lo = 0, hi = pts.length - 1;
  if (hi < 0) return -1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (pointTime(tl, pts[mid]) < t) lo = mid + 1; else hi = mid;
  }
  if (lo > 0 && Math.abs(pointTime(tl, pts[lo - 1]) - t) < Math.abs(pointTime(tl, pts[lo]) - t)) lo -= 1;
  return lo;
}

function onChartMove(ev) {
  const d = S.detail;
  if (!d || !d.timeline.points.length) return;
  const tl = d.timeline;
  const cv = ev.currentTarget;
  const rect = cv.getBoundingClientRect();
  const pw = rect.width - PAD.l - PAD.r;
  const xPos = ev.clientX - rect.left;
  if (xPos < PAD.l || xPos > PAD.l + pw) { hideTooltip(); return; }
  const [from, to] = chartRange();
  const t = from + ((xPos - PAD.l) / pw) * (to - from);
  const i = nearestPoint(tl, t);
  // Too far from any point (inside a gap): no tooltip.
  const reach = Math.max(tl.step_ms * 1.5, ((to - from) / pw) * 6);
  if (i < 0 || Math.abs(pointTime(tl, tl.points[i]) - t) > reach) { hideTooltip(); return; }
  if (S.hover !== i) { S.hover = i; drawCharts(); }
  const p = tl.points[i];
  const tip = $('#tooltip');
  const rows = [];
  const r = (k, v) => el('div', { class: 'r' }, el('span', { text: k }), el('strong', { text: v }));
  if (tl.mode === 'samples') {
    rows.push(el('div', { class: 't', text: (to - from > 864e5 ? dayTimeFmt : timeSecFmt).format(p.t_ms) }));
    rows.push(p.avg_ms === null ? r('Sample', 'lost') : r('Round trip', `${fmtMs(p.avg_ms)} ms`));
    if (S.ma?.[i] !== null && S.ma?.[i] !== undefined) rows.push(r('Moving average', `${fmtMs(S.ma[i])} ms`));
  } else {
    const f = tl.step_ms >= 6e4 ? dayTimeFmt : timeSecFmt;
    rows.push(el('div', { class: 't', text: `${f.format(p.t_ms)} – ${timeSecFmt.format(p.t_ms + tl.step_ms)}` }));
    rows.push(r('Average', `${fmtMs(p.avg_ms)} ms`));
    rows.push(r('Lowest / highest', `${fmtMs(p.min_ms)} / ${fmtMs(p.max_ms)} ms`));
    rows.push(r('Lost', `${p.lost} of ${p.sent} (${fmtPct((100 * p.lost) / p.sent)}%)`));
  }
  tip.replaceChildren(...rows);
  tip.hidden = false;
  const wrap = $('.chart-wrap').getBoundingClientRect();
  const tx = ev.clientX - wrap.left;
  const ty = ev.clientY - wrap.top;
  const tw = tip.offsetWidth;
  tip.style.left = `${tx + 14 + tw > wrap.width ? tx - tw - 14 : tx + 14}px`;
  tip.style.top = `${Math.max(4, ty - tip.offsetHeight - 10)}px`;
}

function hideTooltip() {
  $('#tooltip').hidden = true;
  if (S.hover !== null) { S.hover = null; drawCharts(); }
}

/** While live, slide the charts with the clock between refreshes, redrawing
 *  only when the picture would move by at least a pixel. */
function glide() {
  cancelAnimationFrame(S.glideFrame);
  const step = () => {
    S.glideFrame = requestAnimationFrame(step);
    if (!S.inApp || document.hidden || S.viewEnd !== null || !S.detail) return;
    const pw = ($('#chart').clientWidth || 800) - PAD.l - PAD.r;
    const msPerPx = S.windowMs / Math.max(1, pw);
    if (Date.now() - (S.drawnAt || 0) >= msPerPx) drawCharts();
  };
  S.glideFrame = requestAnimationFrame(step);
}

// ----- route -----------------------------------------------------------------

function renderRoute(t, d) {
  const tbody = $('#route-table tbody');
  const reading = $('#route-reading');
  const say = (text) => { reading.textContent = text; reading.hidden = !text; };
  const only = (text) => {
    tbody.replaceChildren(el('tr', {}, el('td', { colspan: 8, class: 'hint route-only', text })));
    drawRouteGraph(null);
  };
  $('#route').hidden = false;
  if (!t.trace) {
    $('#route-sub').textContent = '';
    say('');
    only('Route tracing is off for this target. Edit it to turn tracing on.');
    return;
  }
  if (!d) return;
  const hops = d.hops;
  const destI = hops.findIndex((h) => h.is_dest);
  $('#route-sub').textContent = !hops.length ? '' : destI >= 0 ? `${hops.length} hop${hops.length === 1 ? '' : 's'}` : 'destination not reached';
  if (!hops.length) {
    say('');
    only(t.enabled && S.viewEnd === null ? 'Tracing the route…' : 'No route samples in this period.');
    return;
  }
  say(routeReading(hops));

  // Loss that reaches the destination is hatched along the rail, from the
  // hop where it starts down to the destination.
  const startI = hops.findIndex((h) => h.reading === 'loss_starts');
  const hatch = startI >= 0 && destI > startI;
  const dl = destI >= 0 ? lossLevel(hops[destI].stats.loss_pct, hops[destI].stats.sent) : 'none';
  $('#route-table').dataset.loss = dl === 'crit' ? 'crit' : 'warn';

  // Rebuilding the rows drops keyboard focus: put it back where it was.
  const focusTtl = document.activeElement?.closest?.('#route-table tr[data-ttl]')?.dataset.ttl;
  const rows = hops.map((h, i) => {
    const s = h.stats;
    const r = h.reading;
    const silent = s.sent > 0 && s.received === 0;
    const kind = h.is_dest ? 'dest' : r === 'loss_starts' ? 'starts' : r === 'limits_replies' ? 'limited' : silent ? 'silent' : '';
    const rail = ['rail'];
    if (hatch && i >= startI && i < destI) rail.push('hatch-down');
    if (hatch && i > startI && i <= destI) rail.push('hatch-up');
    const lv = lossLevel(s.loss_pct, s.sent);
    const real = (r === 'loss_starts' || r === 'loss_carried') && (lv === 'warn' || lv === 'crit');
    const note = r === 'loss_starts' ? (h.is_dest ? 'loss only here' : 'loss starts here')
      : r === 'limits_replies' ? 'limits replies' : silent ? 'no reply' : '';
    const addr = el('td', { class: 'addr' },
      h.masked
        ? el('span', { class: 'masked', text: h.masked, title: 'Hidden by the person who shared this link' })
        : h.addr ? breakable(h.addr) : '*',
      h.responders > 1 ? el('span', { class: 'more', text: `+${h.responders - 1} more` }) : null,
      note || h.hostname
        ? el('small', { title: h.hostname || null },
          note ? el('span', { class: `note ${kind}`, text: note }) : null,
          note && h.hostname ? ' · ' : null,
          h.hostname || null)
        : null);
    const pick = () => toggleHop(h.ttl);
    return el('tr', {
      class: h.is_dest ? 'dest' : null,
      'data-ttl': h.ttl,
      tabindex: 0,
      'aria-selected': S.hop === h.ttl ? 'true' : 'false',
      title: S.hop === h.ttl ? 'Show the destination again' : `Graph hop ${h.ttl}`,
      onclick: pick,
      onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(); } },
    },
      el('td', { class: rail.join(' ') }, el('span', { class: `node ${kind}`, text: h.ttl })),
      addr,
      el('td', {
        class: `num${real ? ` lossy ${lv}` : ''}${r === 'limits_replies' ? ' limited' : ''}`,
        title: r === 'limits_replies' ? `Not carried on: ${fmtPct(h.carried_pct ?? 0)}% continues to later hops` : null,
        text: s.sent ? fmtPct(s.loss_pct) : '—',
      }),
      el('td', { class: 'num', text: fmtMs(s.avg_ms) }),
      el('td', { class: 'num extra', text: fmtMs(s.min_ms) }),
      el('td', { class: 'num extra', text: fmtMs(s.max_ms) }),
      el('td', { class: 'num extra', text: fmtMs(s.jitter_ms) }),
      el('td', { class: 'bar-col' }));
  });
  // A route that hasn't reached its destination ends in a gap.
  if (destI < 0) {
    rows.push(el('tr', { class: 'unreached' },
      el('td', { class: 'rail' }, el('span', { class: 'cut' })),
      el('td', { colspan: 7, class: 'hint', text: 'Destination not reached' })));
  }
  tbody.replaceChildren(...rows);
  if (focusTtl) $(`#route-table tr[data-ttl="${focusTtl}"]`)?.focus({ preventScroll: true });
  drawRouteGraph(hops);
}

/** An address that may wrap after its colons (IPv6) when the route is narrow. */
function breakable(a) {
  const parts = a.split(':');
  return parts.flatMap((p, i) => (i < parts.length - 1 ? [`${p}:`, el('wbr')] : [p]));
}

/** One plain sentence on what the route shows. */
function routeReading(hops) {
  const limited = hops.filter((h) => h.reading === 'limits_replies').map((h) => h.ttl);
  const also = !limited.length ? ''
    : limited.length === 1 ? ` Hop ${limited[0]} limits its replies, which isn’t loss on the path.`
    : ` Hops ${andList(limited)} limit their replies, which isn’t loss on the path.`;
  const dest = hops.find((h) => h.is_dest);
  if (!dest) {
    const last = [...hops].reverse().find((h) => h.stats.received > 0);
    return (last
      ? `The destination hasn’t answered the trace in this period. Replies stop after hop ${last.ttl}.`
      : 'No hop has answered the trace in this period.') + also;
  }
  const start = hops.find((h) => h.reading === 'loss_starts');
  if (!start) return `No loss reaches the destination.${also}`;
  const pct = fmtPct(dest.stats.loss_pct);
  if (start === dest) return `${pct}% loss shows only at the destination: its last link, or the destination limiting its own replies.${also}`;
  const who = start.addr || start.masked;
  return `${pct}% loss reaches the destination, starting at hop ${start.ttl}${who ? ` (${who})` : ''}.${also}`;
}

/** "3", "3 and 5", "3, 5 and 7" */
function andList(xs) {
  return xs.length < 2 ? String(xs[0] ?? '') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`;
}

/** PingPlotter-style latency graph down the route: per hop the current
 *  latency (bar), lowest (tick), average (dot) and highest (whisker), with
 *  the averages joined hop to hop, over the warn/crit colour zones. */
function drawRouteGraph(hops) {
  const cv = $('#route-graph');
  const table = $('#route-table');
  const head = $('#route-table thead th.bar-col');
  const rows = $$('#route-table tbody tr[data-ttl]');
  if (!hops || !rows.length || !head) { cv.hidden = true; return; }
  cv.hidden = false;
  const wrap = $('.route-scroll');
  const box = wrap.getBoundingClientRect();
  const hb = head.getBoundingClientRect();
  const first = rows[0].getBoundingClientRect();
  const last = rows[rows.length - 1].getBoundingClientRect();
  const left = hb.left - box.left + wrap.scrollLeft + 6;
  const width = Math.max(40, hb.width - 14);
  const topPx = first.top - box.top + wrap.scrollTop;
  const height = last.bottom - first.top;
  cv.style.left = `${left}px`;
  cv.style.top = `${topPx}px`;
  cv.style.width = `${width}px`;
  cv.style.height = `${height}px`;
  const { g, w } = setupCanvas(cv);
  const th = thresholds();
  const maxes = hops.map((h) => h.stats.max_ms).filter((v) => v !== null);
  const avgs = hops.map((h) => h.stats.avg_ms).filter((v) => v !== null);
  const scale = axisMax(Math.max(percentile(maxes, 90) || 0, Math.max(0, ...avgs) * 1.25, 1), 1);
  const x = (v) => Math.min(1, v / scale) * (w - 4) + 2;
  // Zones: good, elevated and high latency, each a tint of its own.
  const zones = [[0, th.warn_ms, '--zone-good'], [th.warn_ms, th.crit_ms, '--zone-warn'], [th.crit_ms, Infinity, '--zone-crit']];
  for (const [a, b, c] of zones) {
    if (a >= scale) continue;
    g.fillStyle = css(c);
    g.fillRect(x(a), 0, x(Math.min(b, scale)) - x(a), height);
  }
  const rowY = rows.map((r) => { const b = r.getBoundingClientRect(); return b.top - first.top + b.height / 2; });
  // Current latency bars: neutral, so the zone they reach says how it is.
  g.fillStyle = css('--bar');
  hops.forEach((h, i) => {
    const c = h.stats.cur_ms;
    if (c === null || c === undefined) return;
    g.fillRect(x(0), rowY[i] - 5, x(c) - x(0), 10);
  });
  // Whiskers: average to highest
  g.strokeStyle = css('--ink-3');
  g.lineWidth = 1;
  hops.forEach((h, i) => {
    const s = h.stats;
    if (s.avg_ms === null) return;
    g.beginPath(); g.moveTo(x(s.avg_ms), rowY[i] + 0.5); g.lineTo(x(s.max_ms), rowY[i] + 0.5); g.stroke();
    g.beginPath(); g.moveTo(x(s.max_ms) + 0.5, rowY[i] - 3); g.lineTo(x(s.max_ms) + 0.5, rowY[i] + 4); g.stroke();
  });
  // Averages joined hop to hop
  g.strokeStyle = css('--series');
  g.lineWidth = 1.75;
  g.lineJoin = 'round';
  g.beginPath();
  let pen = false;
  hops.forEach((h, i) => {
    const a = h.stats.avg_ms;
    if (a === null) return;
    if (pen) g.lineTo(x(a), rowY[i]); else g.moveTo(x(a), rowY[i]);
    pen = true;
  });
  g.stroke();
  // Lowest: a small tick
  g.strokeStyle = css('--series');
  g.lineWidth = 1.5;
  hops.forEach((h, i) => {
    const m = h.stats.min_ms;
    if (m === null) return;
    g.beginPath(); g.moveTo(x(m), rowY[i] - 4); g.lineTo(x(m), rowY[i] + 4); g.stroke();
  });
  // Average dots
  hops.forEach((h, i) => {
    const a = h.stats.avg_ms;
    if (a === null) return;
    g.fillStyle = css('--surface');
    g.beginPath(); g.arc(x(a), rowY[i], 5.5, 0, Math.PI * 2); g.fill();
    const lvl = latencyLevel(a);
    g.fillStyle = css(`--${lvl === 'none' ? 'ink-3' : lvl}`);
    g.beginPath(); g.arc(x(a), rowY[i], 4, 0, Math.PI * 2); g.fill();
    if (lvl === 'warn' || lvl === 'crit') {
      // Peach and orange always get an ink edge.
      g.strokeStyle = css('--edge');
      g.lineWidth = 1;
      g.stroke();
    }
  });
  head.title = `0 to ${fmtAxis(scale)} ms`;
  $('#route-scale').textContent = `0 – ${fmtAxis(scale)} ms`;
}

function toggleHop(ttl) {
  // The bar naming the hop comes or goes above the route: keep this row
  // where it is on screen once the new view is drawn.
  const row = $(`#route-table tr[data-ttl="${ttl}"]`);
  S.anchor = row ? { id: S.selected, ttl, top: row.getBoundingClientRect().top } : null;
  S.hop = S.hop === ttl ? null : ttl;
  S.detail = null;
  drawCharts();
  refreshSoon();
}

// ---------------------------------------------------------------------------
// actions

function buildWindows() {
  const nav = $('#windows');
  nav.replaceChildren(...WINDOWS.map(([ms, label]) => el('button', {
    'aria-pressed': ms === S.windowMs ? 'true' : 'false',
    onclick: () => setWindow(ms),
    text: label,
  })));
}

function setWindow(ms) {
  S.windowMs = ms;
  S.viewEnd = null;
  $$('#windows button').forEach((b, i) => b.setAttribute('aria-pressed', WINDOWS[i][0] === ms ? 'true' : 'false'));
  S.detail = null;
  drawCharts();
  refreshSoon();
}

function pan(dir) {
  const now = Date.now();
  const end = (S.viewEnd ?? now) + dir * (S.windowMs / 4);
  S.viewEnd = end >= now ? null : end;
  updateRangeLabel();
  setConn('ok');
  refreshSoon();
}

/*@add*/
function openTargetDialog(target, preset) {
  const dlg = $('#target-dialog');
  const f = $('#target-form');
  S.editing = target ? target.id : null;
  /*@admin*/
  const noun = 'target';
  /*@end*/
  /*@share*/
  const noun = 'destination';
  $('#target-hint').textContent = `The owner of this monitor can see destinations you add. They stop when this link ends. ${addsLeft()} of ${S.visit.max_targets} left.`;
  /*@end*/
  $('#target-dialog-title').textContent = target ? `Edit ${target.name}` : `Add ${noun}`;
  $('#target-save').textContent = target ? 'Save changes' : `Add ${noun}`;
  field(f, 'host').value = target ? target.host : (preset || '');
  field(f, 'host').readOnly = !!target;
  field(f, 'name').value = target && target.name !== target.host ? target.name : '';
  field(f, 'interval').value = target ? target.interval_ms / 1000 : 2.5;
  field(f, 'interval').min = minIntervalS();
  field(f, 'trace').checked = target ? target.trace : true;
  $('#target-error').textContent = '';
  $('.hint', f).hidden = !!target;
  dlg.showModal();
  (target ? field(f, 'name') : field(f, 'host')).focus();
}

async function onTargetSave(ev) {
  ev.preventDefault();
  const f = ev.target;
  const btn = $('#target-save');
  const interval = Number(field(f, 'interval').value);
  const lo = minIntervalS();
  if (!(interval >= lo && interval <= 3600)) {
    $('#target-error').textContent = `Seconds between samples must be between ${lo} and 3600.`;
    return;
  }
  btn.disabled = true;
  $('#target-error').textContent = S.editing ? '' : 'Checking the host…';
  try {
    let t;
    if (S.editing) {
      t = await api(targetPath(S.editing), { method: 'PATCH', json: { name: field(f, 'name').value, interval_ms: Math.round(interval * 1000), trace: field(f, 'trace').checked } });
      toast(`Saved ${t.name}`);
    } else {
      t = await api(targetPath(), { json: { host: field(f, 'host').value.trim(), name: field(f, 'name').value.trim() || null, interval_ms: Math.round(interval * 1000), trace: field(f, 'trace').checked } });
      /*@share*/
      gained(t);
      /*@end*/
      toast(`Added ${t.name}`);
    }
    $('#target-dialog').close();
    S.selected = t.id;
    S.detail = null;
    refreshSoon();
  } catch (e) {
    $('#target-error').textContent = e.message ? cap(e.message) : 'Could not save the target.';
  } finally {
    btn.disabled = false;
  }
}

/** Where targets are added and changed. */
function targetPath(id) {
  /*@admin*/
  const base = '/api/targets';
  /*@end*/
  /*@share*/
  const base = `${SP}/targets`;
  /*@end*/
  return id === undefined ? base : `${base}/${id}`;
}

function minIntervalS() {
  /*@share*/
  if (S.visit) return S.visit.min_interval_ms / 1000;
  /*@end*/
  return 0.25;
}

/*@share*/
/** A visitor added a destination: it's theirs to change now. */
function gained(t) {
  S.visit.owned_ids.push(t.id);
  applyVisit();
}
/*@end*/

/*@admin*/
async function quickAdd(host, name) {
  try {
    const t = await api(targetPath(), { json: { host, name, trace: true } });
    toast(`Added ${t.name}`);
    S.selected = t.id;
    refreshSoon();
  } catch (e) {
    toast(e.message);
  }
}
/*@end*/

async function patchSelected(patch, msg) {
  const ov = selectedOverview();
  if (!ov) return;
  try {
    await api(targetPath(ov.target.id), { method: 'PATCH', json: patch });
    toast(msg(ov.target));
    refreshSoon();
  } catch (e) {
    toast(e.message);
  }
}

function openRemove() {
  const ov = selectedOverview();
  if (!ov) return;
  $('#remove-name').textContent = ov.target.name;
  const dlg = $('#remove-dialog');
  dlg.returnValue = '';
  dlg.showModal();
  dlg.addEventListener('close', async () => {
    if (dlg.returnValue !== 'remove') return;
    try {
      await api(targetPath(ov.target.id), { method: 'DELETE' });
      /*@share*/
      S.visit.owned_ids = S.visit.owned_ids.filter((x) => x !== ov.target.id);
      applyVisit();
      /*@end*/
      toast(`Removed ${ov.target.name}`);
      S.selected = null;
      refreshSoon();
    } catch (e) {
      toast(e.message);
    }
  }, { once: true });
}
/*@end*/

/*@export*/
function openExport() {
  closeMenu();
  const targets = S.overview?.targets || [];
  if (!targets.length) { toast('Add a target before exporting a report.'); return; }
  const box = $('#export-targets');
  box.replaceChildren(
    ...targets.map((t) => el('label', {},
      el('input', { type: 'checkbox', name: 'target', value: t.target.id, checked: t.target.id === S.selected || targets.length === 1 }),
      t.target.name,
      el('span', { class: 'muted', text: t.target.host !== t.target.name ? ` ${t.target.host}` : '' }))),
  );
  if (targets.length > 2) {
    box.prepend(el('label', {}, el('input', {
      type: 'checkbox',
      onchange: (e) => $$('input[name=target]', box).forEach((c) => { c.checked = e.target.checked; }),
    }), el('strong', { text: 'All targets' })));
  }
  const [from, to] = viewRange();
  const f = $('#export-form');
  field(f, 'from').value = localInputValue(from);
  field(f, 'to').value = localInputValue(Math.min(to, Date.now()));
  $('#export-error').textContent = '';
  const viewLabel = WINDOWS.find((w) => w[0] === S.windowMs)?.[1];
  $('#export-ranges label').lastChild.textContent = ` Current view (${viewLabel})`;
  syncCustomRange();
  $('#export-dialog').showModal();
}

function syncCustomRange() {
  $('#custom-range').hidden = radio($('#export-form'), 'range') !== 'custom';
}

async function onExport(ev) {
  ev.preventDefault();
  const f = ev.target;
  const err = $('#export-error');
  const ids = $$('input[name=target]:checked', f).map((c) => c.value);
  if (!ids.length) { err.textContent = 'Choose at least one target.'; return; }
  const now = Date.now();
  let from, to;
  const r = radio(f, 'range');
  if (r === 'view') { [from, to] = viewRange(); to = Math.min(to, now); }
  else if (r === 'custom') {
    from = new Date(field(f, 'from').value).getTime();
    to = new Date(field(f, 'to').value).getTime();
    if (!from || !to) { err.textContent = 'Enter both a start and an end time.'; return; }
  } else { to = now; from = now - Number(r); }
  if (from >= to) { err.textContent = 'The start has to be before the end.'; return; }
  const earliest = earliestMs();
  if (earliest && to <= earliest) { err.textContent = `This link shows history from ${fmtWhen(earliest)} on. Pick a later range.`; return; }
  const format = radio(f, 'format');
  const btn = $('#export-go');
  btn.disabled = true;
  btn.textContent = 'Preparing report…';
  err.textContent = '';
  try {
    const tz = -new Date().getTimezoneOffset();
    /*@admin*/
    const base = '/api/report';
    /*@end*/
    /*@share*/
    const base = `${SP}/report`;
    /*@end*/
    const res = await fetch(`${base}?targets=${ids.join(',')}&from=${Math.round(from)}&to=${Math.round(to)}&format=${format}&tz=${tz}`, { credentials: 'same-origin' });
    if (!res.ok) {
      let msg = 'The report could not be created.';
      try { msg = (await res.json()).error || msg; } catch (_) { /* ignore */ }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const name = (res.headers.get('content-disposition') || '').match(/filename="([^"]+)"/)?.[1] || `pingrail-report.${format}`;
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    $('#export-dialog').close();
    toast(`Downloaded ${name}`);
  } catch (e) {
    err.textContent = e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Download report';
  }
}
/*@end*/

/*@admin*/
async function onPassword(ev) {
  ev.preventDefault();
  const f = ev.target;
  const err = $('#password-error');
  if (field(f, 'p1').value.length < 8) { err.textContent = 'Use at least 8 characters.'; return; }
  if (field(f, 'p1').value !== field(f, 'p2').value) { err.textContent = 'The two passwords don’t match.'; return; }
  try {
    await api('/api/password', { json: { password: field(f, 'p1').value } });
    f.reset();
    $('#password-dialog').close();
    Login.show('password-changed');
  } catch (e) {
    err.textContent = e.message;
  }
}

// ----- passkeys (admin) ------------------------------------------------------------

/** A name for a new passkey from what this device says it is. */
function deviceGuess() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/Android/.test(ua)) return 'Android phone';
  if (/Windows/.test(ua)) return 'Windows PC';
  if (/Macintosh/.test(ua)) return 'Mac';
  if (/Linux/.test(ua)) return 'Linux PC';
  return 'Passkey';
}

/** Why passkeys don't work at this address, and what to do about it. */
function unavailableNote(u, box) {
  if (!u) return false;
  if (u.reason === 'address') {
    box.replaceChildren('Passkeys need a name, not an IP address. Open pingrail by this server’s name, such as ',
      el('code', { text: `${(S.cert && S.cert.names.find((n) => n.includes('.') && n !== 'localhost')) || 'its-name.local'}:${location.port || 443}` }), '.');
  } else if (u.reason === 'custom') {
    box.replaceChildren(`${u.name} isn’t on the certificate configured in pingrail.toml, so passkeys can’t be used at this address.`);
  } else {
    const add = el('button', { type: 'button', class: 'small quiet', text: `Add ${u.name}` });
    add.addEventListener('click', () => addCertName(u.name, box, openPasskeys));
    box.replaceChildren(`${u.name} isn’t on this server’s certificate yet. `, add);
  }
  return true;
}

/** Put the name you browse to on the certificate (a new authority if it's
 *  outside the current one), then redraw with `after`. */
async function addCertName(name, box, after) {
  try {
    const r = await api('/api/certificate/names', { json: { name } });
    toast(r.ca ? `Added ${name} with a new certificate authority` : `Added ${name} to the certificate`);
    if (r.ca) {
      box.replaceChildren('pingrail made a new certificate authority so it can vouch for ', el('code', { text: name }),
        '. Devices that trusted the old one must trust this one: use Set up a phone. On the Windows PC running pingrail, run ',
        el('code', { text: 'pingrail service trust add' }), ' as administrator.');
      box.hidden = false;
      return;
    }
    await after();
  } catch (e) {
    box.replaceChildren(cap(e.message));
  }
}

let pkState = null;

async function openPasskeys() {
  closeMenu();
  const dlg = $('#passkeys-dialog');
  $('#pk-error').textContent = '';
  try {
    const [pk, cert] = await Promise.all([api('/api/passkeys'), api('/api/certificate')]);
    pkState = pk;
    S.cert = cert;
  } catch (e) {
    if (e.status === 401) return;
    toast(cap(e.message));
    return;
  }
  renderPasskeys();
  if (!dlg.open) dlg.showModal();
}

function renderPasskeys() {
  const p = pkState;
  const can = Passkey.supported();
  const usable = !p.unavailable && can;
  const note = $('#pk-unavailable');
  note.hidden = !unavailableNote(p.unavailable, note);
  if (!can) { note.hidden = false; note.replaceChildren('This browser can’t use passkeys.'); }
  // Changes need a sign-in from the last few minutes.
  const confirm = $('#pk-confirm');
  confirm.hidden = p.recent;
  $('#pk-confirm-pw').hidden = p.required;
  $('#pk-confirm-passkey').hidden = !usable;
  if (!p.recent && p.required && !usable) {
    confirm.hidden = true;
  }
  const list = $('#pk-list');
  if (!p.passkeys.length) {
    list.replaceChildren(el('li', { class: 'empty-note', text: 'No passkeys yet.' }));
  } else {
    list.replaceChildren(...p.passkeys.map((k) => {
      const facts = [`Added ${fmtWhen(k.created_ms)}`, k.last_used_ms ? `last used ${ago(k.last_used_ms)}` : 'not used yet'];
      if (!k.here) facts.push(`for ${k.rp_id}`);
      const rm = el('button', { type: 'button', class: 'small quiet danger', text: 'Remove' });
      rm.disabled = !p.recent;
      rm.addEventListener('click', () => removePasskey(k));
      return el('li', { class: k.here ? '' : 'off' },
        el('div', { class: 'top' }, el('span', { class: 'label', text: k.label }), el('span', { class: 'grow' }), rm),
        el('div', { class: 'facts', text: facts.join(' · ') }));
    }));
  }
  const add = $('#pk-add');
  add.hidden = !usable || !p.recent;
  const label = field(add, 'label');
  if (!label.value) label.value = deviceGuess();
  $('#pk-require-row').hidden = !p.recent || (!p.required && !p.passkeys.some((k) => k.here));
  $('#pk-required').checked = p.required;
}

async function pkCall(fn) {
  const err = $('#pk-error');
  err.textContent = '';
  try {
    const next = await fn();
    if (next) { pkState = next; renderPasskeys(); }
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 403) { await openPasskeys(); err.textContent = 'Confirm it’s you first.'; return; }
      err.textContent = cap(e.message);
    } else {
      const why = Passkey.explain(e);
      if (why) err.textContent = why;
    }
  }
}

async function onPasskeyAdd(ev) {
  ev.preventDefault();
  const label = field(ev.target, 'label').value.trim();
  const btn = $('#pk-add-go');
  btn.disabled = true;
  await pkCall(async () => {
    const next = await Passkey.register(label);
    toast(`Added ${label || 'the passkey'}`);
    field(ev.target, 'label').value = '';
    return next;
  });
  btn.disabled = false;
}

async function removePasskey(k) {
  if (!(await confirmBox(`Remove ${k.label}?`, 'It stops working for signing in here, and other sessions are signed out. The passkey itself stays on the device until you delete it there.', 'Remove', true))) return;
  await pkCall(() => api(`/api/passkeys/${k.id}`, { method: 'DELETE' }));
}

async function onRequiredChange(ev) {
  const on = ev.target.checked;
  ev.target.checked = !on;   // until the server agrees
  await pkCall(() => api('/api/passkeys/required', { json: { on } }));
}

async function onPasskeyConfirm(ev) {
  ev.preventDefault();
  const f = ev.target;
  const err = $('#pk-error');
  err.textContent = '';
  try {
    const me = await api('/api/me');
    const r = await fetch('/api/login', {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: me.user, password: field(f, 'password').value }),
    });
    if (!r.ok) {
      let msg = 'That password isn’t right.';
      if (r.status !== 401) { try { msg = (await r.json()).error || msg; } catch (_) { /* not JSON */ } }
      err.textContent = cap(msg);
      return;
    }
    f.reset();
    await openPasskeys();
  } catch (e) {
    err.textContent = cap(e.message);
  }
}

async function onPasskeyConfirmWithPasskey() {
  await pkCall(async () => {
    await Passkey.signIn('modal');
    await openPasskeys();
    return null;
  });
}

// ----- set up a phone (admin) ---------------------------------------------------------

/** The name a phone should open pingrail by: the one in the address bar
 *  when it's on the certificate, else the most specific other name. */
function phoneHosts(c) {
  const names = c.names.filter((n) => n !== 'localhost');
  const byDots = [...names].sort((a, b) => b.split('.').length - a.split('.').length);
  const ips = c.addresses.filter((a) => !a.startsWith('127.') && a !== '::1');
  const all = [...byDots, ...ips];
  if (c.host && c.host_covered && all.includes(c.host)) return [c.host, ...all.filter((h) => h !== c.host)];
  return all;
}

async function openPhone() {
  closeMenu();
  const err = $('#phone-error');
  err.textContent = '';
  let c;
  try {
    c = await api('/api/certificate');
    S.cert = c;
  } catch (e) {
    if (e.status !== 401) toast(cap(e.message));
    return;
  }
  const note = $('#phone-note');
  note.hidden = true;
  if (c.custom) {
    note.hidden = false;
    note.replaceChildren('This server uses a certificate configured in pingrail.toml. If the phone already trusts its issuer, only step 2 is needed.');
  } else if (c.host && !c.host_covered) {
    note.hidden = false;
    const add = el('button', { type: 'button', class: 'small quiet', text: `Add ${c.host}` });
    add.addEventListener('click', () => addCertName(c.host, note, openPhone));
    note.replaceChildren(`You opened pingrail as ${c.host}, which isn’t on its certificate yet. `, add);
  }
  $('#station-trust').hidden = c.custom;
  $('#phone-fp').replaceChildren(...(c.ca_sha256 || '').split(':').reduce((rows, b, i) => {
    if (i % 8 === 0) rows.push([]);
    rows[rows.length - 1].push(b);
    return rows;
  }, []).map((r) => el('span', { text: r.join(':') })));
  const hosts = phoneHosts(c);
  const sel = $('#phone-host');
  sel.replaceChildren(...hosts.map((h) => el('option', { value: h, text: h })));
  $('#phone-host-row').hidden = hosts.length < 2;
  showPhoneCodes(hosts[0]);
  if (!$('#phone-dialog').open) $('#phone-dialog').showModal();
}

function showPhoneCodes(host) {
  const c = S.cert;
  if (!host) {
    $('#phone-error').textContent = 'This server has no name or private address a phone could use.';
    return;
  }
  const shown = host.includes(':') ? `[${host}]` : host;
  const base = `${shown}:${c.port}`;
  for (const [id, what, path] of [['ca', 'ca', '/ca.crt'], ['app', 'app', '/']]) {
    const img = $(`#qr-${id}`);
    img.src = `/api/qr?for=${what}&host=${encodeURIComponent(host)}`;
    img.alt = `QR code for https://${base}${path}`;
    $(`#qr-${id}-url`).textContent = `${base}${path === '/' ? '' : path}`;
  }
}

// ----- share links (admin) --------------------------------------------------------

const SHARE_PRESETS = {
  // Safe to post anywhere: graphs only, your network hidden.
  public: {
    can_add: false, max_targets: 5, can_export: false, history: 'all', history_days: 7,
    hide_private: true, hide_public_hops: 0, hide_hostnames: false, expiry: 'never',
    min_interval_ms: 2500, visitor_retention_days: 0, visitor_storage_mb: 1024,
  },
  // For a support case: they can test their own destinations and pull reports.
  isp: {
    can_add: true, max_targets: 5, can_export: true, history: 'all', history_days: 7,
    hide_private: false, hide_public_hops: 0, hide_hostnames: false, expiry: '604800000',
    min_interval_ms: 1000, visitor_retention_days: 30, visitor_storage_mb: 1024,
  },
};

const SHARE_STATUS = { active: 'Active', expired: 'Expired', revoked: 'Switched off' };

async function loadShares() {
  S.shares = await api('/api/shares');
  S.sharesAt = Date.now();
  return S.shares;
}

function shareLabel(id) {
  const sh = S.shares?.shares.find((x) => x.id === id);
  return sh ? sh.label : 'a share link';
}

/** Fetch link labels when a visitor-added target shows up that we can't name. */
function maybeLoadShares() {
  const ids = (S.overview?.targets || []).map((t) => t.target.share_id).filter((x) => x !== null && x !== undefined);
  const known = new Set((S.shares?.shares || []).map((x) => x.id));
  if (ids.every((i) => known.has(i)) || Date.now() - S.sharesAt < 30000) return;
  S.sharesAt = Date.now();
  loadShares().then(() => { renderList(); renderDetail(); }).catch(() => { /* try later */ });
}

function targetName(id) {
  return S.overview?.targets.find((t) => t.target.id === id)?.target.name || null;
}

async function openShares(highlight, copyIt) {
  closeMenu();
  const dlg = $('#shares-dialog');
  if (!dlg.open) dlg.showModal();
  if (!S.shares) $('#share-list').replaceChildren(el('li', { class: 'empty-note', text: 'Loading…' }));
  try {
    await loadShares();
  } catch (e) {
    $('#share-list').replaceChildren(el('li', { class: 'empty-note', text: e.message }));
    return;
  }
  renderShares(highlight);
  if (copyIt && highlight !== undefined) {
    const sh = S.shares.shares.find((x) => x.id === highlight);
    const input = $(`#share-list li[data-id="${highlight}"] input`);
    if (sh && input) {
      const ok = await copyText(sh.url, input);
      toast(ok ? 'Link copied. Paste it wherever you want to share it.' : 'Link ready. Select it and copy it to share.');
    }
  }
}

function renderShares(highlight) {
  const r = S.shares;
  const note = $('#share-url-note');
  if (!r.public_url) {
    const port = r.share_port;
    note.replaceChildren(
      'These links use this monitor’s own address, so they open only on your network. To share them on the internet, point a Cloudflare Tunnel (or another reverse proxy) at ',
      port ? el('code', { text: `port ${port}` }) : 'the web UI port',
      ' and set ', el('code', { text: 'public_url' }), ' under ', el('code', { text: '[share]' }),
      ' in pingrail.toml, then restart the service.');
    note.hidden = false;
  } else {
    note.hidden = true;
  }
  const list = $('#share-list');
  if (!r.shares.length) {
    list.replaceChildren(el('li', { class: 'empty-note', text: 'No share links yet. Make one to let someone watch your graphs live without signing in.' }));
    return;
  }
  list.replaceChildren(...r.shares.map((sh) => shareItem(sh, sh.id === highlight)));
  if (highlight !== undefined) $(`#share-list li[data-id="${highlight}"]`)?.scrollIntoView?.({ block: 'nearest' });
}

function shareFacts(sh) {
  const facts = [];
  const names = sh.target_ids.map(targetName).filter(Boolean);
  if (names.length === 0) facts.push('none of your targets');
  else if (names.length <= 3) facts.push(names.join(', '));
  else facts.push(`${names.length} targets`);
  if (sh.can_add) {
    const n = sh.owned_ids.length;
    facts.push(`visitors can add up to ${sh.max_targets}${n ? ` (${n} added)` : ''}`);
    const mb = sh.visitor_storage_mb;
    const space = mb ? `up to ${mb >= 1024 && mb % 1024 === 0 ? `${mb / 1024} GB` : `${mb} MB`}` : 'no space limit';
    const keep = sh.visitor_retention_days ? `kept ${sh.visitor_retention_days} day${sh.visitor_retention_days === 1 ? '' : 's'}` : 'kept as long as yours';
    facts.push(`their destinations every ${fmtInterval(sh.min_interval_ms)} or slower, ${keep}, ${space}`);
  } else {
    facts.push('view only');
  }
  if (sh.can_export) facts.push('reports allowed');
  facts.push(sh.hide_private ? 'private hops hidden' : 'private hops shown');
  if (sh.hide_public_hops) facts.push(`first ${sh.hide_public_hops} public hop${sh.hide_public_hops === 1 ? '' : 's'} hidden`);
  if (sh.hide_hostnames) facts.push('host names hidden');
  if (sh.history === 'days') facts.push(`last ${sh.history_days} day${sh.history_days === 1 ? '' : 's'} of history`);
  if (sh.history === 'since') facts.push(`history from ${dayFmt.format(sh.created_ms)}`);
  if (sh.status === 'active') facts.push(sh.expires_ms ? `works until ${fmtWhen(sh.expires_ms)}` : 'no time limit');
  if (sh.status === 'expired' && sh.expires_ms) facts.push(`expired ${fmtWhen(sh.expires_ms)}`);
  facts.push(sh.views
    ? `opened ${sh.views} time${sh.views === 1 ? '' : 's'}${sh.last_seen_ms ? `, last ${ago(sh.last_seen_ms)}` : ''}${sh.last_seen_ip ? ` from ${sh.last_seen_ip}` : ''}`
    : 'not opened yet');
  return facts.join(' · ');
}

function shareItem(sh, highlight) {
  const off = sh.status !== 'active';
  const act = (label, fn, cls = 'quiet small') => el('button', { type: 'button', class: cls, onclick: fn, text: label });
  const input = el('input', { readonly: true, value: sh.url, 'aria-label': `Link for ${sh.label}`, onfocus: (e) => e.target.select() });
  const actions = [act('Edit', () => openShareDialog(sh))];
  if (sh.status === 'revoked') {
    actions.push(act('Turn on with a new link', () => regenerateShare(sh)));
  } else {
    actions.push(act('New link', () => regenerateShare(sh)));
    if (sh.status === 'active') actions.push(act('Switch off', () => revokeShare(sh), 'quiet small danger'));
  }
  actions.push(act('Delete', () => deleteShare(sh), 'quiet small danger'));
  return el('li', { 'data-id': sh.id, class: [off ? 'off' : '', highlight ? 'highlight' : ''].join(' ').trim() || null },
    el('div', { class: 'top' },
      el('span', { class: 'label', text: sh.label }),
      el('span', { class: `badge ${sh.status}`, text: SHARE_STATUS[sh.status] || sh.status })),
    el('div', { class: 'facts', text: shareFacts(sh) }),
    sh.status === 'revoked' ? null : el('div', { class: 'link' },
      input,
      act('Copy', async () => {
        toast(await copyText(sh.url, input) ? 'Link copied.' : 'Select the link and copy it.');
      }),
      el('a', { href: sh.url, target: '_blank', rel: 'noopener', class: 'small-text', text: 'Open' })),
    el('div', { class: 'row' }, actions));
}

async function regenerateShare(sh) {
  const revived = sh.status === 'revoked';
  const ok = await confirmBox(
    revived ? `Turn “${sh.label}” back on?` : `Make a new link for “${sh.label}”?`,
    revived
      ? 'It gets a new address; the old one stays switched off. Share the new link with whoever should see it.'
      : 'The current link stops working right away. Anyone you shared it with will need the new one.',
    revived ? 'Turn on' : 'Make new link');
  if (!ok) return;
  try {
    const n = await api(`/api/shares/${sh.id}/regenerate`, { json: {} });
    await openShares(n.id, true);
    refreshSoon();
  } catch (e) { toast(e.message); }
}

async function revokeShare(sh) {
  const extra = sh.owned_ids.length ? ' Destinations visitors added through it are paused, not deleted.' : '';
  const ok = await confirmBox(`Switch off “${sh.label}”?`, `The link stops working right away for everyone who has it.${extra}`, 'Switch off', true);
  if (!ok) return;
  try {
    await api(`/api/shares/${sh.id}/revoke`, { json: {} });
    toast(`Switched off ${sh.label}`);
    await openShares(sh.id);
    refreshSoon();
  } catch (e) { toast(e.message); }
}

async function deleteShare(sh) {
  const extra = sh.owned_ids.length ? ' Destinations visitors added through it stay in your list, paused.' : '';
  const ok = await confirmBox(`Delete “${sh.label}”?`, `The link stops working and disappears from this list.${extra}`, 'Delete', true);
  if (!ok) return;
  try {
    await api(`/api/shares/${sh.id}`, { method: 'DELETE' });
    toast(`Deleted ${sh.label}`);
    await openShares();
    refreshSoon();
  } catch (e) { toast(e.message); }
}

function fillShareForm(f, v) {
  field(f, 'can_add').checked = v.can_add;
  field(f, 'max_targets').value = v.max_targets;
  field(f, 'can_export').checked = v.can_export;
  setRadio(f, 'history', v.history);
  field(f, 'history_days').value = v.history_days;
  field(f, 'hide_private').checked = v.hide_private;
  field(f, 'hide_public_hops').value = v.hide_public_hops;
  field(f, 'hide_hostnames').checked = v.hide_hostnames;
  if (v.allow_private) field(f, 'allow_private').value = v.allow_private.join(', ');
  if (v.expiry) setRadio(f, 'expiry', v.expiry);
  field(f, 'min_interval').value = (v.min_interval_ms ?? 2500) / 1000;
  field(f, 'visitor_retention_days').value = v.visitor_retention_days ?? 0;
  field(f, 'visitor_storage_mb').value = v.visitor_storage_mb ?? 1024;
}

/** Create a link (share = null), optionally starting with one target ticked,
 *  or edit an existing one. */
function openShareDialog(share, targetId) {
  closeMenu();
  const targets = (S.overview?.targets || []).map((t) => t.target);
  const f = $('#share-form');
  f.reset();
  S.shareEditing = share || null;
  $('#share-dialog-title').textContent = share ? `Edit “${share.label}”` : 'New share link';
  $('#share-save').textContent = share ? 'Save changes' : 'Create link';
  $('#share-presets').closest('fieldset').hidden = !!share;
  $('#share-error').textContent = '';
  field(f, 'label').value = share ? share.label : '';

  const box = $('#share-targets');
  const picked = (id) => (share ? share.target_ids.includes(id) : id === targetId || targets.length === 1);
  box.replaceChildren(...targets.map((t) => el('label', {},
    el('input', { type: 'checkbox', name: 'target', value: t.id, checked: picked(t.id) }),
    t.name,
    el('span', { class: 'muted', text: t.host !== t.name ? ` ${t.host}` : '' }),
    t.share_id ? el('span', { class: 'muted', text: ` · added via ${shareLabel(t.share_id)}` }) : null)));
  if (!targets.length) box.replaceChildren(el('p', { class: 'hint', text: 'You have no targets yet. Visitors can still add their own if you allow it.' }));
  if (targets.length > 2) {
    box.prepend(el('label', {}, el('input', {
      type: 'checkbox',
      onchange: (e) => $$('input[name=target]', box).forEach((c) => { c.checked = e.target.checked; }),
    }), el('strong', { text: 'All targets' })));
  }

  const keep = $('#share-expiry input[value=keep]');
  const keepLabel = keep.closest('label');
  const exp = share?.expires_ms ?? null;
  keepLabel.hidden = exp === null;
  if (exp !== null) {
    keepLabel.lastChild.textContent = exp > Date.now() ? ` Until ${fmtWhen(exp)}` : ` Expired ${fmtWhen(exp)}`;
  }
  field(f, 'expires_at').value = localInputValue(exp && exp > Date.now() ? exp : Date.now() + 7 * 864e5);

  if (share) {
    fillShareForm(f, { ...share, expiry: exp === null ? 'never' : 'keep' });
  } else {
    setRadio(f, 'preset', 'public');
    fillShareForm(f, { ...SHARE_PRESETS.public, allow_private: [] });
  }
  syncShareForm();
  $('#share-dialog').showModal();
  field(f, 'label').focus();
}

function syncShareForm() {
  const f = $('#share-form');
  const add = field(f, 'can_add').checked;
  field(f, 'max_targets').disabled = !add;
  $('#allow-private-row').hidden = !add;
  $('#visitor-limits').hidden = !add;
  $('#share-expires-at').hidden = radio(f, 'expiry') !== 'custom';
}

function onShareFormChange(ev) {
  const f = $('#share-form');
  if (ev.target.name === 'preset') {
    fillShareForm(f, SHARE_PRESETS[ev.target.value]);
  }
  syncShareForm();
}

async function onShareSave(ev) {
  ev.preventDefault();
  const f = ev.target;
  const err = $('#share-error');
  const ids = $$('#share-targets input[name=target]:checked').map((c) => Number(c.value));
  const canAdd = field(f, 'can_add').checked;
  if (!ids.length && !canAdd) {
    err.textContent = 'Choose at least one target, or let visitors add their own destinations.';
    return;
  }
  let expires = null;
  const ex = radio(f, 'expiry');
  if (ex === 'keep') expires = S.shareEditing?.expires_ms ?? null;
  else if (ex === 'custom') {
    expires = new Date(field(f, 'expires_at').value).getTime();
    if (!expires) { err.textContent = 'Enter the date and time the link should stop working.'; return; }
    if (expires <= Date.now()) { err.textContent = 'Pick a time in the future.'; return; }
  } else if (ex !== 'never') {
    expires = Date.now() + Number(ex);
  }
  const settings = {
    label: field(f, 'label').value.trim(),
    target_ids: ids,
    can_add: canAdd,
    max_targets: clampInt(field(f, 'max_targets').value, 1, 20, 5),
    can_export: field(f, 'can_export').checked,
    history: radio(f, 'history') || 'all',
    history_days: clampInt(field(f, 'history_days').value, 1, 365, 7),
    hide_private: field(f, 'hide_private').checked,
    hide_public_hops: clampInt(field(f, 'hide_public_hops').value, 0, 10, 0),
    hide_hostnames: field(f, 'hide_hostnames').checked,
    allow_private: canAdd ? field(f, 'allow_private').value.split(/[\s,;]+/).filter(Boolean) : [],
    min_interval_ms: Math.round(clampNum(field(f, 'min_interval').value, 0.25, 3600, 2.5) * 1000),
    visitor_retention_days: clampInt(field(f, 'visitor_retention_days').value, 0, 3650, 0),
    visitor_storage_mb: clampInt(field(f, 'visitor_storage_mb').value, 0, 10000000, 1024),
    expires_ms: expires,
  };
  const btn = $('#share-save');
  btn.disabled = true;
  err.textContent = '';
  try {
    const editing = S.shareEditing;
    const sh = editing
      ? await api(`/api/shares/${editing.id}`, { method: 'PUT', json: settings })
      : await api('/api/shares', { json: settings });
    $('#share-dialog').close();
    if (editing) toast(`Saved ${sh.label}`);
    await openShares(sh.id, !editing);
    refreshSoon();
  } catch (e) {
    err.textContent = cap(e.message);
  } finally {
    btn.disabled = false;
  }
}
/*@end*/

// ----- menu & theme ------------------------------------------------------------

function openAbout() {
  closeMenu();
  $('#about-dialog').showModal();
}

function closeMenu() {
  $('#menu').hidden = true;
  $('#menu-open').setAttribute('aria-expanded', 'false');
}

function effectiveTheme() {
  const set = document.documentElement.dataset.theme;
  if (set) return set;
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  $('#theme-toggle').textContent = effectiveTheme() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
}

function toggleTheme() {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem(THEME_KEY, next); } catch (_) { /* storage blocked */ }
  applyTheme(next);
  closeMenu();
  renderList();
  drawCharts();
}

// ---------------------------------------------------------------------------
// wiring

function bind() {
  /*@admin*/
  $('#logout').addEventListener('click', logout);
  /*@end*/
  /*@add*/
  /*@admin*/
  $$('[data-quick]').forEach((b) => b.addEventListener('click', () => quickAdd(b.dataset.quick, b.dataset.name)));
  $('#t-bg').addEventListener('click', () => patchSelected({ session: null }, (t) => `${t.name} now keeps running in the background`));
  /*@end*/
  $('#add-open').addEventListener('click', () => openTargetDialog(null));
  $('#empty-add').addEventListener('click', () => openTargetDialog(null));
  $('#target-form').addEventListener('submit', onTargetSave);
  $('#t-edit').addEventListener('click', () => { const ov = selectedOverview(); if (ov) openTargetDialog(ov.target); });
  $('#t-remove').addEventListener('click', openRemove);
  $('#t-pause').addEventListener('click', () => {
    const ov = selectedOverview();
    if (!ov) return;
    const resume = !ov.target.enabled;
    patchSelected({ enabled: resume }, (t) => (resume ? `Resumed ${t.name}` : `Paused ${t.name}`));
  });
  /*@end*/
  $('#hop-clear').addEventListener('click', () => {
    // The bar goes away: keep focus on the hop that was being graphed.
    const ttl = S.hop;
    toggleHop(ttl);
    $(`#route-table tr[data-ttl="${ttl}"]`)?.focus({ preventScroll: true });
  });
  $('#pan-back').addEventListener('click', () => pan(-1));
  $('#pan-fwd').addEventListener('click', () => pan(1));
  $('#pan-live').addEventListener('click', () => { S.viewEnd = null; updateRangeLabel(); setConn('ok'); refreshSoon(); });
  /*@export*/
  $('#export-open').addEventListener('click', openExport);
  $('#export-form').addEventListener('submit', onExport);
  $('#export-form').addEventListener('change', syncCustomRange);
  /*@end*/
  $('#theme-toggle').addEventListener('click', toggleTheme);
  $('#about-open').addEventListener('click', openAbout);
  /*@admin*/
  $('#password-open').addEventListener('click', () => { closeMenu(); $('#password-error').textContent = ''; $('#password-dialog').showModal(); });
  $('#password-form').addEventListener('submit', onPassword);
  $('#passkeys-open').addEventListener('click', openPasskeys);
  $('#pk-add').addEventListener('submit', onPasskeyAdd);
  $('#pk-required').addEventListener('change', onRequiredChange);
  $('#pk-confirm').addEventListener('submit', onPasskeyConfirm);
  $('#pk-confirm-passkey').addEventListener('click', onPasskeyConfirmWithPasskey);
  $('#phone-open').addEventListener('click', openPhone);
  $('#phone-host').addEventListener('change', (e) => showPhoneCodes(e.target.value));
  $('#shares-open').addEventListener('click', () => openShares());
  $('#share-new').addEventListener('click', () => openShareDialog(null, S.selected));
  $('#t-share').addEventListener('click', () => openShareDialog(null, S.selected));
  $('#share-form').addEventListener('submit', onShareSave);
  $('#share-form').addEventListener('change', onShareFormChange);
  // Typing a number of days picks "Last N days".
  for (const ev of ['focus', 'input']) {
    field($('#share-form'), 'history_days').addEventListener(ev, () => setRadio($('#share-form'), 'history', 'days'));
  }
  /*@end*/
  $('#menu-open').addEventListener('click', (e) => {
    e.stopPropagation();
    const m = $('#menu');
    m.hidden = !m.hidden;
    $('#menu-open').setAttribute('aria-expanded', String(!m.hidden));
  });
  document.addEventListener('click', (e) => { if (!$('#menu').contains(e.target)) closeMenu(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
  $$('[data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));
  for (const id of ['#chart', '#loss']) {
    $(id).addEventListener('mousemove', onChartMove);
    $(id).addEventListener('mouseleave', hideTooltip);
  }
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { drawCharts(); if (S.detail) drawRouteGraph(S.detail.hops); refreshSoon(); }, 150);
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && S.inApp) refreshSoon(); });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { applyTheme(); renderList(); drawCharts(); });
}

async function boot() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch (_) { /* storage blocked */ }
  applyTheme(saved || undefined);
  buildWindows();
  bind();
  /*@share*/
  try {
    showVisitor(await api(`${SP}/info`));
  } catch (e) {
    showClosed(e.status ? e.message : 'Cannot reach this pingrail monitor right now. Try again in a minute.', e.status || 503);
  }
  /*@end*/
  /*@admin*/
  try {
    await api('/api/me');
    showApp();
  } catch (e) {
    // 401 has already shown the sign-in page; so does anything else, where
    // the live round trip shows whether the server is answering.
    if (e.status !== 401) Login.show(null);
  }
  /*@end*/
}

boot();
