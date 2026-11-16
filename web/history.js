/* Threat History: /api/history for the chosen period, /api/ip/<address> for one address. */
import { $, esc, fmt, hideTip, showTip as placeTip } from './common.js';

(() => {
'use strict';

const short = (n) => (n >= 1e6 ? `${+(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${+(n / 1e3).toFixed(1)}k` : String(n));
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
const asDate = (day) => new Date(`${day}T00:00:00`);
const dayLabel = (day, long) => asDate(day).toLocaleDateString('en-GB', long ? { weekday: 'short', day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short' });
const dateLabel = (ts) => new Date(ts * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString('da-DK', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const cc = (code) => `<span class="cc">${esc(code || '??')}</span>`;
const isPrivate = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd]|fe80)/i.test(ip || '');
const empty = (cols, text) => `<tr><td class="empty" colspan="${cols}">${esc(text)}</td></tr>`;

/* ---------------------------------------------------------------- stars, like the live page's, a little sparser */

function drawStars() {
  const c = $('stars');
  const ctx = c.getContext('2d');
  const dpr = devicePixelRatio || 1;
  c.width = innerWidth * dpr;
  c.height = innerHeight * dpr;
  ctx.scale(dpr, dpr);
  let s = 7;
  const rnd = () => (s = (s * 16807) % 2147483647) / 2147483647;
  for (let i = 0; i < (innerWidth * innerHeight) / 3600; i++) {
    const a = 0.2 + rnd() * 0.55, r = rnd() > 0.95 ? 0.9 + rnd() : 0.25 + rnd() * 0.65, t = rnd();
    ctx.fillStyle = t < 0.08 ? `rgba(255,170,120,${a})` : t < 0.2 ? `rgba(150,190,255,${a})` : `rgba(232,236,255,${a})`;
    ctx.beginPath(); ctx.arc(rnd() * innerWidth, rnd() * innerHeight, r, 0, Math.PI * 2); ctx.fill();
  }
}
drawStars();

/* ---------------------------------------------------------------- tooltip */

const showTip = (ev, html) => placeTip(ev, html, 12);  // 12 px above the pointer here, 10 on the wall

// the keyboard's way to the same tooltips: shown at the day the arrow keys are on, and read out by screen readers
function tipAt(x, y, html) {
  showTip({ clientX: x, clientY: y }, html);
  $('say').textContent = $('tip').innerText;
}

// a finger has no "leave": its tooltip stays until a touch somewhere else, or a scroll
let touched = false;
function clearMarks() {
  hideTip();
  $('chart').querySelector('.hl')?.setAttribute('width', 0);
  clearSparks();
}
addEventListener('pointerdown', (e) => {
  touched = e.pointerType === 'touch';
  if (touched && !e.target.closest?.('#chart svg, #tAims svg[data-row]')) clearMarks();
}, true);
addEventListener('scroll', () => { if (touched) clearMarks(); }, { passive: true });

// a refresh (or a resize) draws the chart and tables anew: keyboard focus goes back to what it was on, and a
// tooltip the keyboard had open opens again
let quiet = false;  // focus put back without its tooltip
function focusKey() {
  const a = document.activeElement, tip = !$('tip').hidden;
  if (a?.matches?.('.ipbtn')) return { sel: `.ipbtn[data-ip="${CSS.escape(a.dataset.ip)}"]`, tip };
  if (a?.matches?.('#chart svg')) return { sel: '#chart svg', tip };
  if (a?.matches?.('#tAims svg[data-row]')) return { sel: `#tAims svg[aria-label="${CSS.escape(a.getAttribute('aria-label'))}"]`, tip };
  return null;
}
function refocus(key) {
  const el = key && document.querySelector(key.sel);
  if (!el) return;
  quiet = !key.tip;
  el.focus({ preventScroll: true });
  quiet = false;
}

/* ---------------------------------------------------------------- period */

let days = 7;
let keepDays = 365;
let lastSeries = [];
try { days = +localStorage.getItem('tm-history-days') || 7; } catch { /* storage blocked: default */ }

document.querySelectorAll('.range button').forEach((b) => {
  b.onclick = () => {
    days = +b.dataset.days;
    try { localStorage.setItem('tm-history-days', String(days)); } catch { /* fine without it */ }
    load();
  };
});

const pressed = (n) => document.querySelectorAll('.range button').forEach((b) => b.setAttribute('aria-pressed', String(+b.dataset.days === n)));
let loadSeq = 0;
let shownAt = 0, triedAt = 0;  // when the numbers on screen were fetched; when a load last began

async function load() {
  const seq = ++loadSeq, want = days;  // a slower earlier load (a year, say) must not draw over this one
  triedAt = Date.now();
  let d;
  try {
    const r = await fetch(`/api/history?days=${want}`);
    if (!r.ok) throw new Error(`${r.status}`);
    d = await r.json();
  } catch (e) {
    if (seq === loadSeq) $('note').textContent = `Could not load the history (${e.message}). Is the monitor running?`;
    return;
  }
  if (seq !== loadSeq) return;
  shownAt = Date.now();
  pressed(want);  // only once its numbers are on screen: after a failed load the period still shown stays pressed
  const key = focusKey();
  hideTip();  // the element under an open tooltip is about to be replaced, and its mouseleave will never come
  keepDays = d.keep_days;
  const note = d.oldest
    ? `Recording since ${dayLabel(d.oldest)} · events are kept for ${d.keep_days} days`
    : 'Nothing recorded yet';
  if ($('note').textContent !== note) $('note').textContent = note;  // a live region: read out only when it changes
  // threats are knocks, each counted once: a firewall block and the IDS alerts for the same packet are one
  const t = d.totals, threats = t.attempts;
  $('kThreats').textContent = fmt(threats);
  $('kBlock').textContent = fmt(t.block);
  $('kIds').textContent = fmt(t.flagged);
  $('kSources').textContent = fmt(t.sources);
  $('kReturning').textContent = fmt(t.returning);
  $('kBlockSub').textContent = `${pct(t.block, threats)}% of threats`;
  $('kThreatsSub').textContent = `${pct(t.listed, threats)}% from senders on a threat list`;
  $('kIdsSub').textContent = `${fmt(t.attack)} of them attacks it recognised`;
  $('kReturningSub').textContent = `${pct(t.returning, t.sources)}% of sources came back on another day`;
  lastSeries = d.series;
  chart(d.series);
  tables(d);
  aimsTable(d);
  refocus(key);
}

/* ---------------------------------------------------------------- daily chart: stacked bars, one scale */

function niceMax(v) {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map((m) => m * p).find((m) => m >= v);
}

function topRounded(x, y, w, h, r) {  // a bar whose top corners are rounded and whose base sits square
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

const labelW = (s) => s.length * 6 + 4;  // a date label's width: 10px mono is 6 px a character, plus a little air
let chartAt = -1;      // the day the arrow keys are on in the daily chart (-1: none yet)

const dayTip = (r) => `<b>${esc(dayLabel(r.day, true))}</b><br><small>${fmt(r.attempts)} threats (${fmt(r.listed)} from `
  + `senders on a threat list): ${fmt(r.block)} blocked · ${fmt(r.flagged)} flagged by the IDS `
  + `(${fmt(r.attack)} attacks)<br>`
  + `${fmt(r.sources)} sources${r.out ? ` · ${fmt(r.out)} outbound blocks` : ''}</small>`;

function chart(series) {
  const el = $('chart');
  // each day's knocks: the ones the IDS flagged (pink) on top of the rest (teal)
  series = series.map((r) => ({ ...r, plain: Math.max(0, r.attempts - r.flagged) }));
  if (!series.some((r) => r.attempts)) {
    el.innerHTML = '<p class="empty">Nothing recorded in this period yet.</p>';
    return;
  }
  const W = Math.max(300, el.clientWidth), H = 230, L = 42, R = 6, T = 10, B = 24;
  const max = niceMax(Math.max(...series.map((r) => r.attempts)));
  const n = series.length, band = (W - L - R) / n, bw = Math.max(2, Math.min(26, band * 0.7)), gap = bw > 4 ? 2 : 0;
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const step = Math.ceil(n / Math.max(3, Math.floor((W - L) / 76)));
  // a date every `step` days, and always the last day's; the regular one before it goes if the two would overlap
  const lastTick = n - 1 - ((n - 1) % step);
  const crowded = lastTick !== n - 1
    && (n - 1 - lastTick) * band < (labelW(dayLabel(series[lastTick].day)) + labelW(dayLabel(series[n - 1].day))) / 2;
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="group" tabindex="0" `
          + 'aria-label="Threats per day. The left and right arrow keys step through the days.">';
  svg += '<g class="gridlines">';
  for (const f of [0, 0.25, 0.5, 0.75, 1]) {
    const v = max * f, yy = y(v).toFixed(1);
    svg += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}"/><text x="${L - 8}" y="${yy}" dy="3" text-anchor="end">${short(v)}</text>`;
  }
  svg += '</g><rect class="hl" x="0" y="0" width="0" height="0" fill="rgba(255,255,255,0.05)" rx="3"/>';
  series.forEach((r, i) => {
    const x = L + i * band + (band - bw) / 2;
    const base = y(0);
    const hb = base - y(r.plain), hi = base - y(r.flagged);
    if (r.plain) {
      svg += hi > 0 ? `<rect x="${x.toFixed(1)}" y="${y(r.plain).toFixed(1)}" width="${bw.toFixed(1)}" height="${hb.toFixed(1)}" fill="var(--block)"/>`
                    : `<path d="${topRounded(x, y(r.plain), bw, hb, 3)}" fill="var(--block)"/>`;
    }
    if (r.flagged && hi > gap) {
      svg += `<path d="${topRounded(x, y(r.plain + r.flagged), bw, hi - (r.plain ? gap : 0), 3)}" fill="var(--ids)"/>`;
    }
    if ((i % step === 0 && !(crowded && i === lastTick)) || i === n - 1) {
      svg += `<text x="${(L + i * band + band / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">${esc(dayLabel(r.day))}</text>`;
    }
    // each day's column, named for screen readers (under the hit area, so the mouse gets no second tooltip)
    svg += `<rect x="${(L + i * band).toFixed(1)}" y="${T - 4}" width="${band.toFixed(1)}" height="${H - B - T + 4}" fill="none">`
         + `<title>${esc(dayLabel(r.day, true))}: ${fmt(r.attempts)} threats, ${fmt(r.flagged)} flagged by the IDS</title></rect>`;
  });
  svg += `<rect class="hit" x="${L}" y="0" width="${W - L - R}" height="${H - B}" fill="transparent"/></svg>`;
  el.innerHTML = svg;
  const hit = el.querySelector('.hit'), hl = el.querySelector('.hl'), sv = el.querySelector('svg');
  chartAt = Math.min(chartAt, n - 1);
  const mark = (i) => {
    hl.setAttribute('x', L + i * band); hl.setAttribute('y', T - 4);
    hl.setAttribute('width', band); hl.setAttribute('height', H - B - T + 4);
  };
  const unmark = () => { hideTip(); hl.setAttribute('width', 0); };
  const point = (ev) => {
    const box = sv.getBoundingClientRect();
    const i = Math.max(0, Math.min(n - 1, Math.floor(((ev.clientX - box.left) * (W / box.width) - L) / band)));
    mark(i);
    showTip(ev, dayTip(series[i]));
  };
  hit.addEventListener('pointermove', point);
  hit.addEventListener('pointerdown', point);
  hit.addEventListener('pointerleave', (ev) => { if (ev.pointerType !== 'touch') unmark(); });
  // the keyboard: a day at a time, its tooltip above its bar
  const key = (i) => {
    chartAt = Math.max(0, Math.min(n - 1, i));
    mark(chartAt);
    const box = sv.getBoundingClientRect(), k = box.width / W;
    tipAt(box.left + (L + (chartAt + 0.5) * band) * k, box.top + y(series[chartAt].attempts) * k, dayTip(series[chartAt]));
  };
  sv.addEventListener('focus', () => { if (!quiet && sv.matches(':focus-visible')) key(chartAt < 0 ? n - 1 : chartAt); });
  sv.addEventListener('blur', unmark);
  sv.addEventListener('keydown', (ev) => {
    const at = chartAt < 0 ? n : chartAt;
    const to = { ArrowLeft: at - 1, ArrowRight: at + 1, Home: 0, End: n - 1 }[ev.key];
    if (to !== undefined) {
      ev.preventDefault();
      key(to);
    } else if (ev.key === 'Escape') unmark();
  });
}

let resizeTimer = 0;
addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    drawStars();
    if (!lastSeries.length) return;
    const key = focusKey();
    chart(lastSeries);
    refocus(key);
  }, 150);
});

/* ---------------------------------------------------------------- what they were after, per day

   One row per kind of knock (the live page's Aims tab, day by day, from /api/history's "aims"), each with a small line
   on its own scale: the shape says whether it is rising, the numbers say how much. The threat-list share leads, as a
   percentage on a 0-100 scale. Days before the history began have no line rather than a zero; a day only partly
   recorded (today, still filling, and the first day, which began when the monitor first started) is a hollow dot apart
   from the line, and left out of "yesterday vs before": on 2 Nov, a few hours long, it made every change look huge. */

const AIM_GROUPS = ['Logins', 'Web', 'IoT & routers', 'Databases', 'VPN & VoIP', 'Windows & shares', 'DDoS amplifiers',
  'Mail', 'Factory control', 'Other services'];
const SPARK_W = 300, SPARK_H = 34, SPARK_P = 4;
const sumOf = (xs) => xs.reduce((s, x) => s + (x || 0), 0);
let aimRows = [], aimDays = [], aimPartial = [];

function spark(r, k) {
  const W = SPARK_W, H = SPARK_H, P = SPARK_P, last = r.vals.length - 1;
  const max = r.unit === '%' ? 100 : Math.max(1, ...r.vals.filter((v) => v != null));
  const x = (i) => P + (i * (W - 2 * P)) / Math.max(1, last), y = (v) => H - P - ((H - 2 * P) * v) / max;
  // the line through the whole days with data; the partly recorded ones apart
  const pts = r.vals.map((v, i) => (v != null && !aimPartial[i] ? [x(i), y(v)] : null)).filter(Boolean);
  let svg = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" data-row="${k}" tabindex="0" role="img" aria-label="${esc(r.label)} per day">`;
  if (pts.length > 1) {
    const line = pts.map(([a, b], i) => `${i ? 'L' : 'M'}${a.toFixed(1)},${b.toFixed(1)}`).join('');
    svg += `<path class="area" d="${line}L${pts[pts.length - 1][0].toFixed(1)},${H - P}L${pts[0][0].toFixed(1)},${H - P}Z"/>`
         + `<path class="line" d="${line}"/>`;
  }
  if (pts.length) svg += `<circle class="end" cx="${pts[pts.length - 1][0].toFixed(1)}" cy="${pts[pts.length - 1][1].toFixed(1)}" r="2.5"/>`;
  r.vals.forEach((v, i) => {
    if (v != null && aimPartial[i]) svg += `<circle class="today" cx="${x(i).toFixed(1)}" cy="${y(v).toFixed(1)}" r="2.5"/>`;
  });
  return `${svg}<line class="cross" x1="0" x2="0" y1="0" y2="${H}" visibility="hidden"/>`
       + `<rect class="hit" x="0" y="0" width="${W}" height="${H}" fill="transparent"/></svg>`;
}

// yesterday (the last day that is over) against the whole days before it in the period
function change(r) {
  const yi = r.vals.length - 2, y = aimPartial[yi] ? null : r.vals[yi];
  const before = r.vals.slice(0, yi).filter((v, i) => v != null && !aimPartial[i]);
  if (y == null || !before.length) return '<span class="dim">–</span>';
  const avg = sumOf(before) / before.length;
  const p = r.unit === '%' ? Math.round(y - avg) : avg ? Math.round((100 * (y - avg)) / avg) : null;
  if (p == null) return '<span class="dim">new</span>';
  if (!p) return '<span class="dim">the same</span>';
  return `<span class="${p > 0 ? 'up' : 'down'}">${p > 0 ? '▲' : '▼'} ${Math.abs(p)}${r.unit === '%' ? ' pts' : '%'}</span>`;
}

// d.aims comes a column per row, a value per day of d.series: {days, mapping, repeat, aimed: {group: [n...]},
// svcs: {group: its top 3 services}}
function aimsTable(d) {
  const a = d.aims || {}, aimed = a.aimed || {}, svcs = a.svcs || {};
  aimDays = a.days || [];
  aimPartial = aimDays.map((day, i) => i === aimDays.length - 1 || day === d.oldest);
  const has = (i) => !!d.oldest && aimDays[i] >= d.oldest;  // before the history began: no data, not zero
  const mapping = a.mapping || [], repeat = a.repeat || [];
  const all = sumOf(mapping) + sumOf(repeat) + sumOf(Object.values(aimed).map(sumOf));
  if (!all) {
    $('tAims').innerHTML = empty(4, 'Nothing in this period.');
    return;
  }
  const row = (label, sub, vals, unit) => ({ label, sub, unit, vals: vals.map((v, i) => (has(i) ? v : null)) });
  const groups = AIM_GROUPS.filter((g) => aimed[g])
    .map((g) => row(g, (svcs[g] || []).join(' · '), aimed[g]))
    .filter((r) => sumOf(r.vals) > 0);
  aimRows = [
    row('From a threat list', 'share of the day’s threats', d.series.map((r) => (r.attempts ? (100 * r.listed) / r.attempts : null)), '%'),
    row('Mapping what’s open', 'sweeps, random ports, pings', mapping),
    ...groups,
    row('The same port again and again', 'unnamed ports a few senders keep hitting', repeat),
  ];
  $('tAims').innerHTML = '<tr><th>What</th><th class="num">In the period</th><th>Per day</th><th class="num">Yesterday vs before</th></tr>'
    + aimRows.map((r, k) => {
      const tot = sumOf(r.vals);
      const amount = r.unit === '%' ? `${pct(d.totals.listed, d.totals.attempts)}%<small>of threats</small>`
        : `${fmt(tot)}<small>${tot && !pct(tot, all) ? '<1' : pct(tot, all)}% of knocks</small>`;
      return `<tr${k === 1 ? ' class="sep"' : ''}><td class="what-l"><b>${esc(r.label)}</b>${r.sub ? `<small>${esc(r.sub)}</small>` : ''}</td>`
        + `<td class="num amount">${amount}</td><td class="spark">${spark(r, k)}</td><td class="num">${change(r)}</td></tr>`;
    }).join('');
}

let crossOn = null;      // the sparkline whose crosshair shows: moving straight onto another must hide it
const sparkAt = new Map();  // a row's label -> the day the arrow keys are on in its line

// day i of a sparkline: its crosshair, and the tooltip at the pointer (ev), or above that day for the keyboard
function sparkDay(sv, i, ev) {
  if (sv !== crossOn) {
    crossOn?.querySelector('.cross').setAttribute('visibility', 'hidden');
    crossOn = sv;
  }
  const r = aimRows[+sv.dataset.row], n = r.vals.length, step = (SPARK_W - 2 * SPARK_P) / Math.max(1, n - 1);
  const cx = sv.querySelector('.cross'), xx = SPARK_P + i * step;
  cx.setAttribute('x1', xx.toFixed(1)); cx.setAttribute('x2', xx.toFixed(1)); cx.setAttribute('visibility', 'visible');
  const v = r.vals[i];
  const html = `<b>${esc(dayLabel(aimDays[i], true))}</b><br><small>${esc(r.label)}: `
    + `${v == null ? 'before the history began' : r.unit === '%' ? `${Math.round(v)}% of threats` : `${fmt(v)} knocks`}`
    + `${i === n - 1 && v != null ? ' so far' : aimPartial[i] && v != null ? ' (recording began that day)' : ''}</small>`;
  if (ev) return showTip(ev, html);
  sparkAt.set(r.label, i);
  const box = sv.getBoundingClientRect();
  tipAt(box.left + xx * (box.width / SPARK_W), box.top + 4, html);
}

function clearSparks() {
  hideTip();
  crossOn = null;
  document.querySelectorAll('#tAims .cross').forEach((c) => c.setAttribute('visibility', 'hidden'));
}

const sparkPoint = (ev) => {
  const sv = ev.target.closest('svg[data-row]');
  if (!sv) {
    crossOn?.querySelector('.cross').setAttribute('visibility', 'hidden');
    crossOn = null;
    return hideTip();
  }
  const n = aimRows[+sv.dataset.row].vals.length, box = sv.getBoundingClientRect();
  const step = (SPARK_W - 2 * SPARK_P) / Math.max(1, n - 1);
  sparkDay(sv, Math.max(0, Math.min(n - 1, Math.round(((ev.clientX - box.left) / box.width * SPARK_W - SPARK_P) / step))), ev);
};
$('tAims').addEventListener('pointermove', sparkPoint);
$('tAims').addEventListener('pointerdown', sparkPoint);
$('tAims').addEventListener('pointerleave', (ev) => { if (ev.pointerType !== 'touch') clearSparks(); });
// the keyboard: Tab to a line, the arrow keys step through its days (it starts on the last), Escape closes
const keyAt = (sv) => {
  const r = aimRows[+sv.dataset.row];
  return Math.min(sparkAt.get(r.label) ?? r.vals.length - 1, r.vals.length - 1);
};
$('tAims').addEventListener('focusin', (ev) => {
  const sv = ev.target.closest?.('svg[data-row]');
  if (sv && !quiet && sv.matches(':focus-visible')) sparkDay(sv, keyAt(sv));
});
$('tAims').addEventListener('focusout', (ev) => { if (ev.target.closest?.('svg[data-row]')) clearSparks(); });
$('tAims').addEventListener('keydown', (ev) => {
  const sv = ev.target.closest?.('svg[data-row]');
  if (!sv) return;
  const n = aimRows[+sv.dataset.row].vals.length, at = keyAt(sv);
  const to = { ArrowLeft: at - 1, ArrowRight: at + 1, Home: 0, End: n - 1 }[ev.key];
  if (to !== undefined) {
    ev.preventDefault();
    sparkDay(sv, Math.max(0, Math.min(n - 1, to)));
  } else if (ev.key === 'Escape') clearSparks();
});

/* ---------------------------------------------------------------- tables */

function tables(d) {
  $('tIps').innerHTML = '<tr><th>Address</th><th>What</th><th>Network</th><th>Country</th><th class="num">Hits</th>'
    + '<th class="num">IDS</th><th class="num">Days</th><th>First seen</th></tr>'
    + (d.top_ips.map((r) => `<tr>
        <td><button type="button" class="ipbtn" data-ip="${esc(r.ip)}">${esc(r.ip)}</button></td>
        <td>${r.what ? `<span class="what" title="${esc(r.what.text)}">${esc(r.what.key)}</span>` : ''}</td>
        <td class="dim trunc" title="${esc(r.org)}">${esc(r.org || '–')}</td>
        <td>${cc(r.cc)}</td>
        <td class="num">${fmt(r.hits)}</td><td class="num">${fmt(r.ids)}</td>
        <td class="num">${r.days > 1 ? `<span class="again" title="Seen on ${r.days} different days in this period">${r.days}</span>` : '1'}</td>
        <td class="dim">${r.first ? esc(dateLabel(r.first)) : '–'}</td></tr>`).join('') || empty(8, 'Nothing in this period.'));

  const pmax = d.top_ports[0]?.hits || 1;
  $('tPorts').innerHTML = '<tr><th>Port</th><th>Service</th><th class="num">Hits</th></tr>'
    + (d.top_ports.map((r) => `<tr><td class="mono">${esc(/^\d+$/.test(r.port) ? r.port : '–')}</td>
        <td>${esc(r.svc)}<div class="bar" style="width:${((r.hits / pmax) * 100).toFixed(1)}%"></div></td>
        <td class="num">${fmt(r.hits)}</td></tr>`).join('') || empty(3, 'Nothing in this period.'));

  const cmax = d.top_countries[0]?.hits || 1;
  $('tCountries').innerHTML = '<tr><th>Country</th><th class="num">Hits</th><th class="num">Sources</th></tr>'
    + (d.top_countries.map((r) => `<tr><td>${cc(r.cc)}${esc(r.name || r.cc)}<div class="bar" style="width:${((r.hits / cmax) * 100).toFixed(1)}%"></div></td>
        <td class="num">${fmt(r.hits)}</td><td class="num">${fmt(r.sources)}</td></tr>`).join('') || empty(3, 'Nothing in this period.'));

  $('tSigs').innerHTML = '<tr><th>Rule</th><th class="num">Alerts</th></tr>'
    + (d.top_sigs.map((r) => `<tr><td class="trunc fill" title="${esc(r.sig)}">${esc(r.sig)}</td><td class="num">${fmt(r.hits)}</td></tr>`).join('')
       || empty(2, 'No IDS alerts in this period.'));

  $('tDevices').innerHTML = '<tr><th>Device</th><th>Going to</th><th class="num">Times</th><th>Last</th></tr>'
    + (d.devices.map((r) => `<tr><td class="mono">${isPrivate(r.local) ? esc(r.local) : `<span title="${esc(r.local)}">your WAN address</span> <span class="dim">(the IDS sees it after NAT, so not which device)</span>`}</td><td class="mono">${esc(r.remote)}${r.dport != null ? ` :${esc(r.dport)}` : ''}</td>
        <td class="num">${fmt(r.n)}</td><td class="dim">${esc(dateLabel(r.last))} ${esc(clock(r.last).slice(0, 5))}</td></tr>`).join('')
       || empty(4, 'Nothing from your network was blocked or flagged going out in this period.'));
}

document.addEventListener('click', (e) => {
  const b = e.target.closest('.ipbtn');
  if (!b) return;
  lookup(b.dataset.ip, true);
  $('lookup').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
});

/* ---------------------------------------------------------------- one address */

$('lookupForm').addEventListener('submit', (e) => { e.preventDefault(); lookup($('ipInput').value.trim(), true); });

function miniChart(daily) {
  const W = 600, H = 70, n = daily.length, max = Math.max(1, ...daily.map((r) => r.hits));
  const band = W / Math.max(n, 1), bw = Math.max(2, Math.min(18, band * 0.7));
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Hits per day">${daily.map((r, i) => {
    const h = Math.max(2, (r.hits / max) * (H - 4)), x = i * band + (band - bw) / 2;
    return `<path d="${topRounded(x, H - h, bw, h, 2)}" fill="${r.ids ? 'var(--ids)' : 'var(--block)'}"><title>${esc(dayLabel(r.day, true))}: ${fmt(r.hits)} hits${r.ids ? `, ${fmt(r.ids)} IDS` : ''}</title></path>`;
  }).join('')}</svg>`;
}

let lookupSeq = 0;

// byUser: asked for here (an address selected, the form sent), so focus moves to the answer; not for one in the link
async function lookup(ip, byUser = false) {
  if (!ip) return;
  const seq = ++lookupSeq;
  $('ipInput').value = ip;
  window.history.replaceState(null, '', `#${encodeURIComponent(ip)}`);
  const box = $('ipResult');
  box.innerHTML = '<p class="empty">Looking up…</p>';
  let d, fail;
  try {
    const r = await fetch(`/api/ip/${encodeURIComponent(ip)}`);
    if (r.status === 400) fail = 'That is not an IP address. Try one like 185.220.101.1.';
    else if (!r.ok) fail = `The monitor could not answer (${r.status}). Try again in a moment.`;
    else d = await r.json();
  } catch (e) {
    fail = `The lookup failed (${e.message}). Is the monitor running?`;
  }
  if (seq !== lookupSeq) return;  // a newer lookup has started: it draws, not this one
  if (fail) {
    box.innerHTML = `<p class="empty">${esc(fail)}</p>`;
    return;
  }
  if (!d.found) {
    box.innerHTML = `<p class="empty">${esc(d.ip)} isn't in the history: it hasn't been blocked or flagged in the last ${keepDays} days.</p>`;
    return;
  }
  const where = [d.city, d.cc].filter(Boolean).join(', ');
  box.innerHTML = `
    <div class="who" tabindex="-1">${esc(d.ip)}<small>${esc([d.host, d.org, where, d.scanner && `scanner: ${d.scanner}`].filter(Boolean).join(' · '))}</small></div>
    <div class="facts">
      <div><span>First seen</span><b>${esc(dateLabel(d.first))} ${esc(clock(d.first).slice(0, 5))}</b></div>
      <div><span>Last seen</span><b>${esc(dateLabel(d.last))} ${esc(clock(d.last).slice(0, 5))}</b></div>
      <div><span>Days seen</span><b>${fmt(d.days)}</b></div>
      <div><span>Hits</span><b>${fmt(d.hits)}</b></div>
      <div><span>Flagged by the IDS</span><b>${fmt(d.ids)}</b></div>
      <div><span>What it did</span><b>${esc(d.what ? d.what.text : '–')}</b></div>
    </div>
    <div class="cols">
      <div><h3>Hits per day</h3><div class="mini">${miniChart(d.daily)}</div></div>
      <div><h3>Ports it tried</h3><table>${d.ports.map((p) => `<tr><td>${esc(p.svc)}</td><td class="mono dim">${p.dport != null ? esc(p.dport) : ''}</td><td class="num">${fmt(p.n)}</td></tr>`).join('') || empty(3, 'No port detail kept.')}</table></div>
      <div><h3>IDS rules it set off</h3><table>${d.sigs.map((s) => `<tr><td class="trunc fill" title="${esc(s.sig)}">${esc(s.sig)}</td><td class="num">${fmt(s.n)}</td></tr>`).join('') || empty(2, 'None.')}</table></div>
    </div>
    <h3 style="margin:16px 0 6px;font:600 10px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3)">Latest events</h3>
    <div class="scroll"><table>
      <tr><th>When</th><th>What</th><th>Port</th><th>Rule</th></tr>
      ${d.events.map((e) => `<tr><td class="mono dim">${esc(dateLabel(e.ts))} ${esc(clock(e.ts))}</td>
        <td class="kind-${e.kind === 'ids' ? 'ids' : 'block'}">${e.kind === 'ids' ? (e.action === 'drop' ? 'IDS drop' : e.cat === 'list' ? 'IDS: threat list' : 'IDS alert') : 'Firewall block'}${e.way === 'out' ? ' (outbound)' : ''}${e.gain != null && !(e.gain & 1) ? ' <span class="dim">(same knock)</span>' : ''}</td>
        <td>${esc(e.svc)}${e.dport != null && e.svc !== `${e.proto}/${e.dport}` ? ` <span class="mono dim">:${esc(e.dport)}</span>` : ''}</td>
        <td class="trunc dim fill" title="${esc(e.sig || '')}">${esc(e.sig || '')}${e.target ? ` · ${esc(e.target)}` : ''}</td></tr>`).join('')
        || empty(4, 'Only today\'s counts exist for this address (it was seen before history started).')}
    </table></div>`;
  if (byUser) box.querySelector('.who').focus({ preventScroll: true });
}

pressed(days);  // nothing shown yet: the stored period, as before its first load
load();
// fresh numbers while the page is in view: every minute for 7 and 30 days, every 5 minutes for 90 days and a year
// (they move slowly and cost the server more). A hidden tab fetches nothing and catches up when shown again.
const every = () => (days >= 90 ? 300000 : 60000);
setInterval(() => {
  const now = Date.now();
  if (!document.hidden && now - shownAt >= every() && now - triedAt >= every()) load();
}, 15000);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && Date.now() - shownAt >= every()) load();
});
if (location.hash.length > 1) {
  try { lookup(decodeURIComponent(location.hash.slice(1))); } catch { /* a malformed link: no lookup */ }
}
})();
