/* tour: now and then the camera visits what just happened */
import { $, esc, fmt } from '../common.js';
import { S, COLORS, rgba, clock, again, reduceMotion, hooks } from './shared.js';
import { globe, controls, spin, HOME_VIEW, addRing, setTouring } from './globe.js';
import { pref, savePref, radios } from './prefs.js';

// from: where the camera was when a visit began; it flies back there and the globe turns on from it
const tour = { busy: false, last: Date.now(), phase: 0, done: new Map(), cands: [], hits: new Map(), from: null };

// on or off, and how often, in the settings popup; on, once a minute, until you change it
const TOUR_TIMES = [30, 60, 120, 300];  // seconds
let tourOn = pref('tm.tour', 'on') !== 'off';
let tourEvery = +pref('tm.tourEvery', 60) || 60;
function setTour(on, every) {
  tourOn = on;
  tourEvery = TOUR_TIMES.includes(every) ? every : 60;
  savePref('tm.tour', on ? 'on' : 'off');
  savePref('tm.tourEvery', String(tourEvery));
  $('optTour').checked = on;
  $('tourEvery').querySelectorAll('input').forEach((i) => { i.checked = +i.value === tourEvery; i.disabled = !on; });
  if (!on && tour.busy) endTour(true);  // switched off during a visit: back home now
}
radios('tourEvery', TOUR_TIMES, (t) => (t < 60 ? `${t} s` : `${t / 60} min`), (v) => setTour(tourOn, +v));
$('optTour').onchange = (e) => setTour(e.target.checked, tourEvery);
setTour(tourOn, tourEvery);

export function noteForTour(e) {  // what is worth a visit: a port scan, an IDS alert, an address back from an earlier day
  if (!e.geo) return;
  const now = Date.now();
  const h = (tour.hits.get(e.remote) || []).filter((t) => now - t < 60000);
  if (!e.dup) h.push(now);  // knocks, not the IDS's second look at one
  tour.hits.set(e.remote, h);
  if (tour.hits.size > 3000) tour.hits.clear();
  let score = 0, kick = '';
  if (h.length >= 8) { score = 3; kick = 'PORT SCAN'; }
  else if (e.kind === 'ids' && e.cat === 'attack') { score = 3; kick = e.action === 'drop' ? 'IDS DROP' : 'IDS ALERT'; }
  else if (e.seen) { score = 2; kick = 'BACK AGAIN'; }
  else if (e.kind === 'ids' && e.cat === 'list') { score = 1; kick = 'ON A THREAT LIST'; }
  else return;
  tour.cands.push({ e, score, kick, t: now });
  if (tour.cands.length > 40) tour.cands.shift();
}

function pickTour() {
  const now = Date.now();
  for (const [ip, t] of tour.done) if (now - t > 600000) tour.done.delete(ip);  // visited: kept 10 minutes, see fresh
  const fresh = (ip) => now - (tour.done.get(ip) || 0) > 600000;  // not the same address twice in 10 minutes
  const c = tour.cands.filter((x) => now - x.t < 90000 && fresh(x.e.remote)).sort((a, b) => b.score - a.score || b.t - a.t)[0];
  const tops = (S.stats && S.stats.top_ips) || [];
  if (c) {
    const e = c.e, s = tops.find((x) => x.ip === e.remote);
    return { kick: c.kick, ip: e.remote, lat: e.geo.lat, lon: e.geo.lon, city: e.geo.city, country: e.geo.country,
             org: e.geo.org, n: (s && s.n) || e.ip_n || 1, ids: s ? s.ids : +(e.kind === 'ids'),
             ports: s ? s.ports : [e.svc], sig: e.sig || (s && s.sig), seen: e.seen };
  }
  const i = tops.findIndex((s) => s.lat != null && fresh(s.ip));  // nothing notable just now: a top attacker
  if (i < 0) return null;
  return { kick: `TOP ATTACKER #${i + 1}`, ...tops[i] };
}

function runTour(t) {
  const my = ++tour.phase;
  tour.busy = true;
  tour.last = Date.now();
  tour.done.set(t.ip, Date.now());
  setTouring(true);
  controls.autoRotate = false;
  clearTimeout(spin.timer);
  tour.from = globe.pointOfView();
  globe.pointOfView({ lat: t.lat - 4, lng: t.lon, altitude: 0.85 }, 2400);
  $('letterbox').classList.add('on');
  // red for an attack the IDS recognised, pink for a sender on a threat list or mostly IDS alerts, else teal
  const kind = t.kick.startsWith('IDS') ? 'attack' : t.kick === 'ON A THREAT LIST' || (t.ids && t.ids > t.n / 4) ? 'ids' : 'block';
  const color = COLORS[kind];
  setTimeout(() => {
    if (my !== tour.phase) return;
    const lower = $('lower');
    lower.className = `ov lower ${kind}`;
    lower.innerHTML = `<div class="kick"><span>${esc(t.kick)}</span><span>${esc(clock(Date.now() / 1000))}</span></div>
      <div class="big">${esc(t.ip)}</div>
      <div class="sub">${esc([t.city, t.country].filter(Boolean).join(', '))}${t.org ? ` · ${esc(t.org)}` : ''}</div>
      <div class="facts"><b>${fmt(t.n)}</b> hit${t.n === 1 ? '' : 's'} today${t.ids ? ` · <b>${fmt(t.ids)}</b> IDS` : ''}${t.ports && t.ports.length ? ` · ${esc(t.ports.slice(0, 3).join(', '))}` : ''}${again(t.seen)}</div>
      ${t.sig ? `<div class="sig">${esc(t.sig)}</div>` : ''}`;
    requestAnimationFrame(() => lower.classList.add('on'));
    addRing({ lat: t.lat, lon: t.lon, color: (k) => rgba(color, 0.9 * (1 - k)), max: 3.5, speed: 2, period: 900 }, 5600);
  }, 2300);
  setTimeout(() => { if (my === tour.phase) endTour(true); }, 8600);
}

function endTour(flyBack) {
  tour.phase += 1;
  tour.busy = false;
  setTouring(false);
  $('lower').classList.remove('on');
  $('letterbox').classList.remove('on');
  if (flyBack) {
    globe.pointOfView(tour.from || HOME_VIEW(), 2600);
    clearTimeout(spin.timer);
    spin.timer = setTimeout(() => { controls.autoRotate = spin.on; }, 2600);
  }
}

function tourCancel() { if (tour.busy) endTour(false); }  // someone took over the globe: leave the camera where they put it
hooks.tourCancel = tourCancel;

setInterval(() => {
  const now = Date.now();
  if (!tourOn || reduceMotion || !spin.on || tour.busy || document.hidden || now - spin.lastTouch < 60000
    || now - tour.last < tourEvery * 1000) return;
  const t = pickTour();
  if (t) runTour(t);
}, 3000);
