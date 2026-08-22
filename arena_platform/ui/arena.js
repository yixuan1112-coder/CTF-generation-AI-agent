/* AutoCTF Arena — shared front-end helpers.
   No framework, no bundler: the server ships plain files. */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---- credentials -------------------------------------------------------- */
const Auth = {
  get()      { try { return JSON.parse(localStorage.getItem('arena.team') || 'null'); } catch { return null; } },
  set(team)  { localStorage.setItem('arena.team', JSON.stringify(team)); },
  clear()    { localStorage.removeItem('arena.team'); },
};

/* ---- API ---------------------------------------------------------------- */
async function api(path, { method = 'GET', body, raw, token } = {}) {
  const headers = {};
  const auth = token ?? Auth.get()?.token;
  if (auth) headers['Authorization'] = `Bearer ${auth}`;
  let payload = raw;
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(path, { method, headers, body: payload });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; }
  catch { throw new Error(`server returned non-JSON (HTTP ${res.status})`); }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* ---- toasts ------------------------------------------------------------- */
function toast(message, kind = '') {
  let host = $('.toast-host');
  if (!host) { host = document.createElement('div'); host.className = 'toast-host'; document.body.appendChild(host); }
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 4200);
  setTimeout(() => el.remove(), 4600);
}

/* ---- formatting --------------------------------------------------------- */
const fmtSecs = (s) => {
  const n = Number(s || 0);
  if (n < 1)  return `${Math.round(n * 1000)}ms`;
  if (n < 60) return `${n.toFixed(n < 10 ? 2 : 1)}s`;
  return `${Math.floor(n / 60)}m ${Math.round(n % 60)}s`;
};

const fmtAgo = (ts) => {
  if (!ts) return '—';
  const d = Date.now() / 1000 - Number(ts);
  if (d < 60)     return 'just now';
  if (d < 3600)   return `${Math.floor(d / 60)}m ago`;
  if (d < 86400)  return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
};

const clock = (ts, t0) => {
  const d = Math.max(0, Number(ts) - Number(t0));
  return `${String(Math.floor(d / 60)).padStart(2, '0')}:${String(Math.floor(d % 60)).padStart(2, '0')}`;
};

const OUTCOME = {
  cleared:           { label: 'ladder cleared',   cls: 'gold'  },
  out_evolved:       { label: 'out-evolved',      cls: 'bad'   },
  wrong_flag:        { label: 'wrong flag',       cls: 'bad'   },
  agent_error:       { label: 'agent error',      cls: 'warn'  },
  timeout:           { label: 'time budget hit',  cls: 'warn'  },
  evolution_stalled: { label: 'maker stalled',    cls: 'warn'  },
};
const outcomeBadge = (o) => {
  const spec = OUTCOME[o] || { label: o || 'pending', cls: '' };
  return `<span class="badge ${spec.cls}">${esc(spec.label)}</span>`;
};

const statusBadge = (status) => ({
  queued:  '<span class="badge info">queued</span>',
  running: '<span class="badge warn live">running</span>',
  done:    '<span class="badge ok">complete</span>',
  error:   '<span class="badge bad">error</span>',
}[status] || `<span class="badge">${esc(status)}</span>`);

/* ---- ladder ------------------------------------------------------------- */
/* solvedMax: deepest rung SOLVED. makerGen: where the challenge-maker stands.
   held=true draws the maker's rung in red — it stopped the agent there. */
function renderLadder(el, rungs, { solvedMax = -1, makerGen = null, held = false } = {}) {
  if (!el) return;
  el.innerHTML = (rungs || []).map((name, i) => {
    const cls = ['rung'];
    if (i === (rungs.length - 1)) cls.push('boss');
    if (i <= solvedMax) cls.push('done');
    else if (i === makerGen) cls.push(held ? 'held' : 'active');
    else if (i === rungs.length - 1) cls.push('pending');
    return `<div class="${cls.join(' ')}"><div class="g">GEN-${i}</div><div class="n">${esc(name)}</div></div>`;
  }).join('');
}

/* ---- nav ---------------------------------------------------------------- */
function mountNav(active) {
  const team = Auth.get();
  const link = (href, label) =>
    `<a href="${href}" class="${active === href ? 'on' : ''}">${label}</a>`;
  document.body.insertAdjacentHTML('afterbegin', `
    <nav class="nav">
      <a class="brand" href="/"><span class="mark">◆</span><b>AutoCTF Arena</b></a>
      <div class="links">
        ${link('/', 'Leaderboard')}${link('/practice', 'Practice')}${link('/live', 'Live')}${link('/submit', 'Enter your agent')}${link('/docs', 'Rules &amp; API')}
      </div>
      <div class="spacer"></div>
      <div class="who">${team ? `team <b>${esc(team.name)}</b>` : 'not registered'}</div>
    </nav>`);
}
