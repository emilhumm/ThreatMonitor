/* The cards round the globe: the counters, the top lists, the last hour's activity, Who's Knocking, the threat
   stream, the status pill and the clock; and which cards show. */
import { $, esc, fmt, showTip, hideTip } from '../common.js';
import { S, live, GAIN, activity, clock, again, agoText, kindOf, serverNow } from './shared.js';
import { pref, savePref } from './prefs.js';

/* ---------------------------------------------------------------- numbers */

const tweens = new Map();
function setNum(el, value) {
  let tw = tweens.get(el);
  if (!tw) tweens.set(el, (tw = { shown: 0, target: 0, raf: 0 }));
  tw.target = value;
  if (tw.raf) return;
  const step = () => {
    const d = tw.target - tw.shown;
    if (Math.abs(d) < 0.5) {
      tw.shown = tw.target;
      el.textContent = fmt(tw.shown);
      tw.raf = 0;
      return;
    }
    tw.shown += d * 0.12;
    el.textContent = fmt(tw.shown);
    tw.raf = requestAnimationFrame(step);
  };
  tw.raf = requestAnimationFrame(step);
}

// today's senders that behaved like attackers, each once: by what they did, or caught by the IDS (State._attacks)
const hostileSenders = (a) => Object.values(a.senders || {}).reduce((sum, n) => sum + n, 0);

export function renderCounters() {
  const stats = S.stats;
  setNum($('totalBig'), live.attempts);
  $('ofTotal').textContent = `of today’s ${fmt(live.attempts)} threats`;  // the rows below overlap: one knock can be both
  setNum($('blockNum'), live.blocked);
  setNum($('listNum'), live.listed);
  setNum($('idsNum'), live.flagged);
  setNum($('attackNum'), stats && stats.attacks ? stats.attacks.all : live.attack);  // by the IDS or by behaviour
  // knocks, so how many senders they came from goes in the caption: one sweeper alone can make hundreds
  const hostile = stats && stats.attacks ? hostileSenders(stats.attacks) : 0;
  $('attackSenders').textContent = hostile ? `from ${fmt(hostile)} hostile sender${hostile === 1 ? '' : 's'}`
    : 'from hostile senders';
  setNum($('uniqueBig'), live.unique);
  if (stats) setNum($('countryBig'), stats.countries);
  // today so far against yesterday by this time of day (the server counts that from the history once a minute; none
  // while the history doesn't cover all of yesterday)
  const y = stats && stats.yday;
  $('vsYday').hidden = !y;
  if (y) {
    const pct = Math.round((100 * (live.attempts - y)) / y);
    $('vsYday').innerHTML = pct === 0 ? 'the same as yesterday at this time'
      : `<b class="${pct < 0 ? 'down' : 'up'}">${pct < 0 ? '▼' : '▲'} ${Math.abs(pct)}%</b> vs yesterday at this time`;
  }
}

// what each number in Blocks · Alerts means, with today's breakdown, on hover
const CARD_TIPS = {
  blocked: () => {
    const k = (S.stats && S.stats.blocked_kinds) || {};
    const rules = (S.stats && S.stats.blocked_rules) || [];
    return `<b>${fmt(live.blocked)} knocks the firewall dropped today</b>`
      + '<p><small>Someone on the internet trying to get in: opening a connection, probing a UDP service, or a ping. '
      + 'Nothing on your network answered them.</small></p>'
      + `<p>${fmt(k.tcp || 0)} connection attempts · ${fmt(k.udp || 0)} UDP probes · ${fmt(k.ping || 0)} pings</p>`
      + (rules.length ? `<p>By rule: ${rules.map(([r, n]) => `${esc(r)} ${fmt(n)}`).join(' · ')}</p>` : '');
  },
  // a knock counts once however many lists name its sender; it goes to whichever named it first
  listed: () => {
    const by = (S.stats && S.stats.listed_by) || [];
    return `<b>${fmt(live.listed)} of today's knocks came from a sender on a threat list</b>`
      + '<p><small>Addresses known for attacking others: blocked by a firewall rule for a list (CrowdSec, Spamhaus '
      + 'DROP) or flagged by one of the IDS\'s list rules (CINS, DShield, Spamhaus).</small></p>'
      + (by.length ? `<p>${by.map(([w, n]) => `${w === 'IDS' ? 'IDS lists' : esc(w)} ${fmt(n)}`).join(' · ')}</p>` : '');
  },
  flagged: () => `<b>${fmt(live.flagged)} of today's knocks set off the IDS</b>`
    + '<p><small>Suricata watches the same traffic and flags what it knows. Mostly it knows the sender: an address on '
    + 'a threat list (CINS, DShield, Spamhaus) for attacking others.</small></p>'
    + `<p>${fmt(live.attack)} of them attacks it recognised</p>`,
  // senders that behaved like attackers: by what they did all day, or caught by the IDS; each knock once (State._attacks)
  attack: () => {
    const top = (S.stats && S.stats.attack_sigs) || [];
    const a = (S.stats && S.stats.attacks) || { all: live.attack, ids: live.attack, behaviour: {}, senders: {} };
    const b = a.behaviour, s = a.senders || {}, n = (k) => s[k] || 0;
    const idsKnocks = a.all - (b.sweep || 0) - (b.botnet || 0) - (b.brute || 0);
    const part = (count, what, knocks) => (count ? [`${fmt(count)} ${what} <small>(${fmt(knocks)} knocks)</small>`] : []);
    return `<b>${fmt(a.all)} of today's knocks came from ${fmt(hostileSenders(a))} hostile senders</b>`
      + '<p><small>Senders that behaved like attackers. Mostly they were scanning for a way in, and all of it was '
      + 'blocked at the first packet: attempts, not something that reached your network. A research scanner '
      + 'doesn\'t count.</small></p><p>'
      + [...part(n('sweep'), 'swept 6 or more of your services, looking for one to break into', b.sweep || 0),
         ...part(n('botnet'), 'went only for the ports IoT botnets use to recruit devices (Telnet, ADB, TR-069…)', b.botnet || 0),
         ...part(n('brute'), 'kept guessing passwords on one login service', b.brute || 0),
         ...part(n('ids'), 'sent traffic the IDS recognised as a scan, an exploit attempt or a protocol abused', idsKnocks)]
        .join('<br>') + '</p>'
      + (top.length ? `<p>What the IDS saw most today:<br>${top.map(([sig, k]) => `${esc(sig)} <small>(${fmt(k)})</small>`).join('<br>')}</p>` : '');
  },
};
document.querySelector('.pair').addEventListener('mousemove', (ev) => {
  const row = ev.target.closest('[data-tip]');
  if (row) showTip(ev, `<div class="tipw">${CARD_TIPS[row.dataset.tip]()}</div>`); else hideTip();
});
document.querySelector('.pair').addEventListener('mouseleave', hideTip);

/* ---------------------------------------------------------------- left: leaders */

const TABS = ['ips', 'ports', 'countries', 'aims'];
const TITLES = { ips: 'Top Sources', ports: 'Most Targeted', countries: 'Top Countries', aims: 'What They Were After' };
const LEAD_MAX = 8;  // all the server sends of each; fitRows drops what doesn't fit
let tab = 'ips';
let tabTouched = 0;
let leadHtml = '';

document.querySelectorAll('.tabs button').forEach((b) => {
  b.onclick = () => { tab = b.dataset.tab; tabTouched = Date.now(); renderLeaders(); };
});
setInterval(() => {  // on a wall nobody clicks, so the list cycles; a click holds it for a minute
  if (Date.now() - tabTouched > 60000) { tab = TABS[(TABS.indexOf(tab) + 1) % TABS.length]; renderLeaders(); }
}, 15000);

// what an address was doing (behaviour.py), as a small tag in Top Sources; the rest only in the hover text
const WHAT_TAGS = { scanner: 'scanner', sweep: 'sweep', botnet: 'botnet', brute: 'brute' };

export function renderLeaders() {
  const stats = S.stats;
  if (!stats) return;
  document.querySelectorAll('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === tab)));
  $('leadTitle').textContent = TITLES[tab];
  // one quiet line per entry and a hairline for its size against #1; the details are in the row's hover text
  const row = (label, code, n, max, detail, tag) => `
    <li title="${esc(detail)}">
      <div class="lead-row"><span class="lead-label">${esc(label)}${tag ? `<span class="what">${tag}</span>` : ''}</span>`
    + `<span class="lead-code">${esc(code)}</span><span class="lead-n">${fmt(n)}</span></div>
      <div class="lead-track"><div style="width:${((n / max) * 100).toFixed(1)}%"></div></div>
    </li>`;
  let rows = [];
  if (tab === 'ips') {
    const list = stats.top_ips.slice(0, LEAD_MAX), max = list[0]?.n || 1;
    rows = list.map((s) => row(s.ip, s.cc, s.n, max, [
      s.what && s.what.text, s.host, s.org, [s.city, s.country].filter(Boolean).join(', '), s.ports.join(', '),
      s.seen ? `also seen on ${s.seen.days} earlier day${s.seen.days === 1 ? '' : 's'}` : '', s.sig,
    ].filter(Boolean).join(' · '), s.what && WHAT_TAGS[s.what.key]));
  } else if (tab === 'ports') {
    const list = stats.top_ports.slice(0, LEAD_MAX), max = list[0]?.n || 1;
    rows = list.map((p) => row(p.svc, p.port && !p.svc.endsWith(`/${p.port}`) ? p.port : '', p.n, max,
      `${fmt(p.n)} hits${p.port ? ` on port ${p.port}` : ''}`));
  } else if (tab === 'aims') {
    rows = aimsRows(stats.aims, row);
  } else {
    const list = stats.top_countries.slice(0, LEAD_MAX), max = list[0]?.n || 1;
    rows = list.map((c) => row(c.name || c.cc, c.cc, c.n, max,
      `${c.name}: ${fmt(c.n)} hits from ${fmt(c.ips)} address${c.ips === 1 ? '' : 'es'}`));
  }
  const html = rows.length ? rows.join('') : '<li class="lead-empty">Nothing yet today</li>';
  if (html !== leadHtml) {
    $('leadList').innerHTML = leadHtml = html;
    fitRows();
  }
}

// What today's knocks were after (behaviour.aims), as one ranked list like the other tabs (a header of big numbers drew
// the eye each time the card cycled to it): mapping what's open, each kind of service with its busiest one beside it,
// and the unnamed ports a few senders keep hitting; the shares and details in each row's hover
function aimsRows(a, row) {
  if (!a) return [];
  const sum = (xs) => xs.reduce((s, n) => s + n, 0);
  const m = a.mapping, map = sum(Object.values(m)), aimed = sum(a.aimed.map((x) => x[1])), rep = sum(a.repeat.map((x) => x[1]));
  const all = map + aimed + rep;
  if (!all) return [];
  const pc = (n) => `${Math.round((100 * n) / all)}% of today's knocks`;
  const port = (svc) => { const [proto, p] = svc.split('/'); return `Port ${p}${proto === 'udp' ? ' (UDP)' : ''}`; };
  const items = [
    [map, 'Mapping what’s open', '', `${pc(map)}, aimed at nothing in particular: sweeps ${fmt(m.sweeps || 0)} · `
      + `random ports ${fmt(m.random || 0)} · pings ${fmt(m.pings || 0)}`],
    ...a.aimed.map(([g, n, svcs]) => [n, g, svcs[0] || '', `${pc(n)}, aimed at ${svcs.join(', ')}`]),
    ...a.repeat.map(([svc, n, k]) => [n, port(svc), `${fmt(k)} sender${k === 1 ? '' : 's'}`,
      `${pc(n)}: a port no known service uses, knocked on again and again by ${fmt(k)} sender${k === 1 ? '' : 's'}`]),
  ].sort((p, q) => q[0] - p[0]).slice(0, LEAD_MAX);
  return items.map(([n, label, code, detail]) => row(label, code, n, items[0][0], detail));
}

// the column runs to the foot of the page and shows as many as it has room for (up to LEAD_MAX); on a shorter screen
// a row that would be cut off drops out whole
function fitRows() {
  const items = [...$('leadList').children];
  items.forEach((li) => { li.hidden = false; });
  const bottom = $('leadList').getBoundingClientRect().bottom + 0.5;
  items.forEach((li) => { if (li.getBoundingClientRect().bottom > bottom) li.hidden = true; });
}
new ResizeObserver(fitRows).observe(document.querySelector('.col-left'));

/* ---------------------------------------------------------------- cards: which show, in the settings popup */

// cards: all six show until you untick one
const CARDS = [
  ['threats', 'Threats Detected'], ['blocks', 'Blocks · Alerts'], ['leaders', 'Top Sources'],
  ['stream', 'Threat Stream'], ['activity', 'Activity'], ['networks', 'Who’s Knocking'],
];
const cardEl = (key) => document.querySelector(`[data-card="${key}"]`);
const hiddenCards = pref('tm.hidden', new Set(), (v) => new Set(JSON.parse(v)));
function setCard(key, show) {
  if (show) hiddenCards.delete(key); else hiddenCards.add(key);
  savePref('tm.hidden', JSON.stringify([...hiddenCards]));
  applyCards();
}
function applyCards() {
  // a class per hidden card on the wall: the style sheet lets Activity fill a gap and lifts the fade from an empty edge
  const wall = document.querySelector('.wall');
  for (const [key] of CARDS) {
    cardEl(key).hidden = hiddenCards.has(key);
    wall.classList.toggle(`hide-${key}`, hiddenCards.has(key));
  }
  $('cardList').querySelectorAll('input').forEach((i) => { i.checked = !hiddenCards.has(i.value); });
  fitRows();  // with Blocks · Alerts gone, Top Sources may have room for more rows
}
$('cardList').innerHTML = CARDS.map(([key, name]) => `<label><input type="checkbox" value="${key}">${name}</label>`).join('');
$('cardList').addEventListener('change', (e) => setCard(e.target.value, e.target.checked));
applyCards();

/* ---------------------------------------------------------------- bottom: activity, one bar per minute */

const STEP = 10;      // the server counts in 10-second buckets; the bars add them up per minute
const MINUTES = 60;
const HM = { hour: '2-digit', minute: '2-digit' };
const actBars = [];
const actTicks = [];
let actFirst = 0;     // start of the leftmost minute; the rightmost bar is the minute we are in
let actMinutes = [];

(function buildActivity() {
  for (let i = 0; i < MINUTES; i++) {
    const m = document.createElement('div');
    m.className = 'm';
    m.dataset.i = i;
    actBars.push(m.appendChild(document.createElement('i')));
    $('actBars').appendChild(m);
  }
  for (let i = 0; i < 6; i++) actTicks.push($('actTicks').appendChild(document.createElement('span')));
})();

export function setActivity(a) {
  activity.buckets = new Map();
  a.cells.forEach((c, i) => { if (c[0] || c[1]) activity.buckets.set(a.start + i * a.step, c); });
  renderActivity();
}

// as the server counts them: knocks by when they started, [not flagged by the IDS, flagged]; one the IDS flags after
// its block moves over
export function bumpActivity(e) {
  const b = Math.floor((e.knock_ts || e.ts) / STEP) * STEP;
  const c = activity.buckets.get(b) || [0, 0];
  const flagged = e.gain & GAIN.flagged;
  if (!e.dup) c[flagged ? 1 : 0] += 1;
  else if (flagged && c[0] > 0) { c[0] -= 1; c[1] += 1; }
  activity.buckets.set(b, c);
}

function renderActivity() {
  actFirst = Math.floor(serverNow() / 60) * 60 - (MINUTES - 1) * 60;
  actMinutes = Array.from({ length: MINUTES }, () => [0, 0]);
  for (const [b, c] of activity.buckets) {
    const i = Math.floor((b - actFirst) / 60);
    if (i >= 0 && i < MINUTES) { actMinutes[i][0] += c[0]; actMinutes[i][1] += c[1]; }
  }
  let max = 1, total = 0;
  for (const [f, d] of actMinutes) { max = Math.max(max, f + d); total += f + d; }
  actMinutes.forEach(([f, d], i) => {
    const n = f + d;
    actBars[i].style.height = n ? `max(2px, ${((100 * n) / max).toFixed(1)}%)` : '0';
    actBars[i].style.setProperty('--p', `${n ? Math.round((100 * f) / n) : 100}%`);  // where teal (blocks) turns pink (IDS)
  });
  $('actTotal').textContent = fmt(total);
  // a time under every ten-minute mark, except right at the ends where it would hang off the card
  let k = 0;
  for (let i = 2; i < MINUTES - 2; i++) {
    const t = actFirst + i * 60;
    if (t % 600) continue;
    actTicks[k].textContent = clock(t, HM);
    actTicks[k].style.left = `${(100 * (i + 0.5)) / MINUTES}%`;
    actTicks[k++].hidden = false;
  }
  for (; k < actTicks.length; k++) actTicks[k].hidden = true;
}
setInterval(() => { if (S.stats) renderActivity(); }, 2000);

$('actBars').addEventListener('mousemove', (ev) => {
  const m = ev.target.closest('.m');
  if (!m) return hideTip();
  const t = actFirst + m.dataset.i * 60;
  const [f, d] = actMinutes[m.dataset.i] || [0, 0];
  showTip(ev, `<b>${clock(t, HM)} – ${clock(t + 60, HM)}</b><br><small>${fmt(f)} block${f === 1 ? '' : 's'} · ${fmt(d)} IDS</small>`);
});
$('actBars').addEventListener('mouseleave', hideTip);

/* ---------------------------------------------------------------- bottom: who's knocking */

// who's knocking, as two shares of the day's knocks: the companies that scan the whole internet for a living (a known
// census, not aimed at us), and addresses back from an earlier day; the details are in the hover text
let netHtml = '';
export function renderNetworks() {
  const stats = S.stats;
  const total = stats.totals.attempts;
  const scan = stats.scanners || { n: 0, names: [] };
  const share = (n, sub, who, detail) => {
    const pct = total ? Math.round((100 * n) / total) : 0;
    return `<div title="${esc(detail)}"><div class="share-big">${total ? `${pct}%` : '–'}</div>`
      + `<div class="share-bar"><i style="width:${pct}%"></i></div><div class="share-sub">${sub}<span>${esc(who)}</span></div></div>`;
  };
  const scanNames = scan.names.slice(0, 2).join(', ') + (scan.names.length > 2 ? ' …' : '');
  const html = share(scan.n, 'from research scanners', scanNames || 'none today',
    `${fmt(scan.n)} of ${fmt(total)} threats today came from companies that scan the whole internet for a living `
    + '(Censys, ONYPHE, Shodan and the like), known by their network or by their servers’ names: real, but not aimed '
    + 'at you')
    + share(stats.returning || 0, 'returning', 'seen on earlier days',
      `${fmt(stats.returning || 0)} of ${fmt(total)} threats today came from addresses already seen on an earlier day `
      + '(marked ↻ in the stream and Top Sources): mostly the same senders coming back');
  if (html === netHtml) return;
  $('netShares').innerHTML = netHtml = html;
}

/* ---------------------------------------------------------------- right: stream */

// a LAN device is named by its address; our public address (what the IDS sees after NAT) is not shown
const isLan = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd]|fe80)/i.test(ip || '');
const TAGS = {
  block: (e) => (e.way === 'out' ? 'OutboundBlock' : e.action === 'reject' ? 'FirewallReject' : 'FirewallBlock'),
  ids: (e) => (e.policy ? 'IDSInfo' : e.action === 'drop' ? 'IDSDrop' : e.cat === 'list' ? 'IDSListed' : 'IDSAlert'),
};
const MAX_ROWS = 40;
export const stream = {
  el: $('stream'),
  rows: [],
  hover: false,
  pending: [],

  reset(list) {
    this.el.innerHTML = '';
    this.rows = [];
    // what came while the pointer was over the list is in this list too (a reconnect's hello): shown once, not twice
    this.pending = [];
    $('pendingN').textContent = '0';
    list.forEach((e) => this.add(e, false));
    fitStream();
  },

  push(e) {
    if (this.hover) {
      this.pending.push(e);
      if (this.pending.length > MAX_ROWS * 4) this.pending.splice(0, this.pending.length - MAX_ROWS * 4);
      $('pendingN').textContent = fmt(this.pending.length);
      return;
    }
    this.add(e, true);
    fitStream();
  },

  add(e, animate) {
    const k = kindOf(e);
    // the IDS's alert for a packet the firewall blocked (or the other way round) is the same knock: it goes on that
    // knock's row, which then shows both
    const own = e.dup && this.rows.find((r) => r.ip === e.remote && Math.abs(e.ts - r.tsLast) <= 4);
    if (own) {
      own.el.classList.add('both');
      if (k === 'attack') own.el.classList.add('atk');
      if (e.sig && !own.el.querySelector('.sig')) {
        own.el.querySelector('.meta').insertAdjacentHTML('afterend', `<div class="sig" title="${esc(e.sig)}">${esc(e.sig)}</div>`);
      }
      return;
    }
    // repeated hits from one source within a minute fold into its row instead of flooding the list
    const row = this.rows.find((r) => r.ip === e.remote && r.k === k && e.ts - r.ts0 < 60);
    const svc = e.dport != null && e.svc !== `${e.proto}/${e.dport}` ? `${e.svc} :${e.dport}` : e.svc;
    if (row) {
      row.tsLast = e.ts;
      if (e.dup) return;  // part of a knock already on the row
      row.n += 1;
      row.svcs.add(svc);
      row.el.querySelector('.cnt').textContent = `×${fmt(row.n)}`;
      row.el.querySelector('.svc').textContent = [...row.svcs].slice(-4).join(' · ') + (row.svcs.size > 4 ? ' …' : '');
      row.el.querySelector('.time').textContent = clock(e.ts);
      if (animate) { row.el.classList.remove('bump'); void row.el.offsetWidth; row.el.classList.add('bump'); }
      return;
    }
    const li = document.createElement('li');
    li.className = k;
    if (!animate) li.style.animation = 'none';
    const g = e.geo;
    const where = g ? [g.city, g.country].filter(Boolean).join(', ') + (g.org ? ` · ${g.org}` : '') : 'location unknown';
    li.innerHTML = `
      <div class="ev"><span class="cnt"></span><span class="tag">${TAGS[e.kind](e)}</span> ${e.way === 'out' ? 'to' : 'from'} <span class="ip">${esc(e.remote)}</span></div>
      <div class="meta"><span class="time">${clock(e.ts)}</span>${e.seen ? ` ·${again(e.seen)}` : ''} · <span class="svc">${esc(svc)}</span>${e.way === 'out' ? ` · from ${isLan(e.local) ? esc(e.local) : 'your WAN'}` : ''}${e.kind === 'block' && e.gain & GAIN.listed && e.rule_name ? ` · on ${esc(e.rule_name)}'s list` : ''}</div>
      ${e.sig ? `<div class="sig" title="${esc(e.sig)}">${esc(e.sig)}</div>` : ''}
      <div class="where" title="${esc(where)}">${esc(where)}</div>`;
    this.el.prepend(li);
    if (e.dup) li.classList.add('both');
    this.rows.unshift({ ip: e.remote, k, ts0: e.ts, tsLast: e.ts, n: 1, svcs: new Set([svc]), el: li });
    while (this.rows.length > MAX_ROWS) this.rows.pop().el.remove();
  },

  flush() {
    const list = this.pending.slice(-MAX_ROWS);
    this.pending = [];
    list.forEach((e) => this.add(e, false));
    fitStream();
  },
};
// the list runs to the foot of the column; a row that would be cut off there stays out of sight until it fits
// (measured to its last line, not its spacing below; offsets ignore the slide-in animation)
function fitStream() {
  const h = stream.el.clientHeight;
  for (const li of stream.el.children) {
    const last = li.lastElementChild;
    li.style.visibility = li.offsetTop + last.offsetTop + last.offsetHeight > h ? 'hidden' : '';
  }
}
new ResizeObserver(fitStream).observe(stream.el);
stream.el.addEventListener('mouseenter', () => { stream.hover = true; $('pendingN').textContent = '0'; $('streamPause').hidden = false; });
stream.el.addEventListener('mouseleave', () => { stream.hover = false; $('streamPause').hidden = true; stream.flush(); });

/* ---------------------------------------------------------------- status + clock */

export function renderStatus() {
  const st = $('status'), feed = S.feed;
  let cls = 'wait';
  let txt = 'Connecting';
  if (S.wsState === 'down') { cls = 'down'; txt = 'Disconnected · retrying'; }
  else if (feed && feed.mode === 'demo') { cls = 'demo'; txt = 'Demo data'; }
  else if (feed) {
    const s = [...feed.senders].sort((a, b) => a.ago - b.ago)[0];
    const refused = Object.keys(feed.rejected || {});
    if (!s && refused.length) txt = `Ignoring syslog from ${refused[0]} (not allowed)`;
    else if (!s) txt = `Waiting for syslog on ${feed.port}`;
    else if (s.ago > 120) txt = `No syslog for ${agoText(s.ago)}`;
    else { cls = 'live'; txt = 'Live'; }
  }
  if (feed && !feed.geo) txt += ' · GeoIP loading';
  st.className = `status ${cls}`;
  st.lastElementChild.textContent = txt;
  st.hidden = cls === 'live';  // all well: nothing to say; the pill only shows when something needs attention

  const warnings = (S.wsState !== 'down' && feed && feed.warnings) || [];
  const box = $('warn');
  const html = warnings.map((w) => `<div>${esc(w.text)}</div>`).join('');
  if (box.innerHTML !== html) box.innerHTML = html;
  box.hidden = !warnings.length;
}

setInterval(() => {
  const now = serverNow();
  $('clockDate').textContent = new Date(now * 1000).toLocaleDateString('da-DK');
  $('clockTime').textContent = clock(now);
}, 1000);
