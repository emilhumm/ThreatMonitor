/* Threat Monitor's wall: one WebSocket in, a globe and panels out.
   The parts: shared.js (what the others share), shaders.js, globe.js (the globe and everything drawn on it), sky.js
   (the Fancy graphics), tour.js (the camera's visits), panels.js (the cards), prefs.js (the settings popup); and
   ../common.js, with the helpers the History page uses too. This file: the starfield behind the page, the start-up
   and the data coming in. */
import { $ } from '../common.js';
import { S, live, GAIN } from './shared.js';
import { globe, HOME_VIEW, setHome, setPoints, bumpPoint, effects, initBeams, buildShield, beamGL, shield } from './globe.js';
import { sky, buildSky } from './sky.js';
import { noteForTour } from './tour.js';
import { renderCounters, renderLeaders, setActivity, bumpActivity, renderNetworks, renderStatus, stream } from './panels.js';

/* ---------------------------------------------------------------- stars */

function drawStars() {
  const c = $('stars');
  const ctx = c.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  c.width = innerWidth * dpr;
  c.height = innerHeight * dpr;
  ctx.scale(dpr, dpr);
  let seed = 7;
  const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const n = Math.round((innerWidth * innerHeight) / 3200);
  for (let i = 0; i < n; i++) {
    const x = rnd() * innerWidth, y = rnd() * innerHeight;
    const big = rnd() > 0.94;
    const r = big ? 0.9 + rnd() * 1.1 : 0.25 + rnd() * 0.7;
    const a = 0.2 + rnd() * 0.6;
    const t = rnd();
    ctx.fillStyle = t < 0.08 ? `rgba(255,170,120,${a})` : t < 0.2 ? `rgba(150,190,255,${a})` : `rgba(232,236,255,${a})`;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();
    if (big && rnd() > 0.6) {  // a soft halo on a few bright ones, like the photo
      ctx.fillStyle = `rgba(255,190,140,${a * 0.15})`;
      ctx.beginPath();
      ctx.arc(x, y, r * 4, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}
drawStars();
addEventListener('resize', drawStars);

(function waitForGlobe(n) {  // the globe's own meshes appear over its first frames
  const ready = (shield.mesh || buildShield()) && (beamGL.mesh || initBeams()) && (!sky.on || sky.mesh || buildSky());
  if (!ready && n < 50) setTimeout(() => waitForGlobe(n + 1), 200);
})(0);

/* ---------------------------------------------------------------- data in */

// one panel that throws must not keep the others (or the status pill) from updating
function safe(fn, ...args) {
  try {
    fn(...args);
  } catch (e) {
    console.error(`ThreatMonitor: ${fn.name || 'an update'} failed`, e);
  }
}

function applyStats(s, f) {
  S.stats = s;
  S.feed = f;
  safe(() => {
    for (const k of Object.keys(GAIN)) live[k] = s.totals[k] || 0;
    live.unique = s.unique;
  });
  safe(renderCounters);
  safe(renderLeaders);
  safe(setActivity, s.activity);
  safe(renderNetworks);
  safe(renderStatus);
}

function onEvent(e) {
  if (e.policy) {  // our own network, noted by a rule (blocked going out, an external-IP lookup): an amber arc, not a threat
    if (e.geo && !document.hidden) effects(e);
    return;
  }
  stream.push(e);
  for (const [k, bit] of Object.entries(GAIN)) if (e.gain & bit) live[k] += 1;
  if (e.ip_n === 1 && !e.dup) live.unique += 1;
  noteForTour(e);
  bumpActivity(e);
  if (e.geo && (!e.dup || e.gain & GAIN.flagged)) bumpPoint(e);
  // one comet per knock, and a red one when the IDS recognises an attack in a knock the firewall already showed
  if (e.geo && (!e.dup || e.gain & GAIN.attack) && !document.hidden) effects(e);
}

let firstHello = true;
let pageBuild = null;  // the web files this page came with (hello.build); a deploy changes them
function handle(msg) {
  if (msg.now) S.serverOffset = msg.now * 1000 - Date.now();
  if (msg.t === 'hello') {
    if (pageBuild && msg.build && msg.build !== pageBuild) {  // back after a deploy: load the new page
      location.reload();
      return;
    }
    pageBuild = pageBuild || msg.build || null;
    safe(setHome, msg.home);
    if (firstHello) {
      firstHello = false;
      safe(() => globe.pointOfView(HOME_VIEW(), 0));
    }
    applyStats(msg.stats, msg.feed);
    safe(setPoints, msg.points, true, true);
    safe(() => stream.reset(msg.recent.filter((e) => !e.policy)));  // the threat stream: our own network's routine stays out
  } else if (msg.t === 'events') {
    msg.items.forEach((e) => safe(onEvent, e));
    safe(renderCounters);
  } else if (msg.t === 'stats') {
    applyStats(msg.stats, msg.feed);
  } else if (msg.t === 'points') {
    safe(setPoints, msg.items, msg.full !== false);  // a list without "full" is a whole one (a server before deltas)
  } else if (msg.t === 'home') {
    setHome(msg.home);
  }
}

// Stats come every 2 s. A connection can stay "open" with nothing coming (the server lost power, the network
// changed, this computer slept) and take many minutes to report closed, so after SILENT_MS of silence it is dropped
// and made again.
const SILENT_MS = 10000;
let retry = 1000;
function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  let heard = Date.now();
  const lost = () => {
    clearInterval(watch);
    S.wsState = 'down';
    renderStatus();
    setTimeout(connect, retry);
    retry = Math.min(retry * 2, 15000);
  };
  let checked = Date.now();
  const watch = setInterval(() => {
    // a check that comes late (the page was busy for seconds, as when it starts on a slow GPU; a hidden tab) can't
    // tell a silent connection from messages still waiting their turn: it counts as hearing, and the next one judges
    const now = Date.now(), late = now - checked > 5000;
    checked = now;
    if (late) heard = Math.max(heard, now - SILENT_MS / 2);
    if (ws.readyState !== WebSocket.OPEN || now - heard < SILENT_MS) return;
    ws.onclose = ws.onmessage = null;
    ws.close();
    lost();
  }, 2500);
  ws.onopen = () => { heard = Date.now(); S.wsState = 'open'; retry = 1000; renderStatus(); };
  ws.onmessage = (m) => { heard = Date.now(); handle(JSON.parse(m.data)); };
  ws.onclose = lost;
}
connect();
