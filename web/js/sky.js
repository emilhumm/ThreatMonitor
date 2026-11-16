/* sky: the Fancy graphics
   In place of the flat starfield painted behind the page, a sky in the globe's own scene, so the stars wheel past when
   the globe turns or the tour flies. The Milky Way lies where it really is, the edge of the atmosphere is lit by the
   real sun, the sky warms when knocks come faster than the day's normal, and an attack on the shield sends a ripple
   out through the stars. The Milky Way is painted once, on the graphics chip, when Fancy first comes on; per frame the
   sky costs one picture lookup per pixel, ~16,500 small star squares and two thin shells around the globe. */
import { $ } from '../common.js';
import { S, serverNow, COLORS, query, NARROW, reduceMotion, live, activity, hooks, linHex } from './shared.js';
import { GLOW_VS, BAKE_FS, SKY_VS, SKY_FS, STAR_VS, STAR_FS, LIMB_VS, LIMB_OUT_FS, LIMB_IN_FS } from './shaders.js';
import { globe, three, geometry, beamGL, glow, SIMPLEST, render, setRenderScale } from './globe.js';
import { pref, savePref, radios, cap } from './prefs.js';

const RAD = Math.PI / 180;
const unitAt = (lat, lon) => { const c = globe.getCoords(lat, lon, 0), l = Math.hypot(c.x, c.y, c.z); return [c.x / l, c.y / l, c.z / l]; };
const daysJ2000 = (ms) => ms / 86400000 + 2440587.5 - 2451545;  // days since noon UT on 1 January 2000
// how far the Earth has turned under the stars, in degrees. The sky is built as it stood at 0° (each star at the
// longitude of its right ascension) and turned back by this about the poles, to where it stands now.
const gmst = (ms) => (((280.46061837 + 360.98564736629 * daysJ2000(ms)) % 360) + 360) % 360;
// the sun's place among the stars, [right ascension, declination] in degrees (the Astronomical Almanac's low-precision
// formulas, good to ~0.01°)
function sunRaDec(ms) {
  const n = daysJ2000(ms);
  const g = (357.528 + 0.9856003 * n) * RAD;
  const lam = (280.460 + 0.9856474 * n + 1.915 * Math.sin(g) + 0.020 * Math.sin(2 * g)) * RAD;
  const eps = (23.439 - 0.0000004 * n) * RAD;
  return [Math.atan2(Math.cos(eps) * Math.sin(lam), Math.cos(lam)) / RAD, Math.asin(Math.sin(eps) * Math.sin(lam)) / RAD];
}
// the galaxy's own axes in the sky's frame: x towards its centre (in Sagittarius), z its north pole
function galaxyFrame() {
  const z = unitAt(27.1283, 192.8595), c = unitAt(-28.936, 266.405);
  const k = c[0] * z[0] + c[1] * z[1] + c[2] * z[2];
  const x = c.map((v, i) => v - k * z[i]), l = Math.hypot(...x);
  x.forEach((v, i) => { x[i] = v / l; });
  return { x, y: [z[1] * x[2] - z[2] * x[1], z[2] * x[0] - z[0] * x[2], z[0] * x[1] - z[1] * x[0]], z };
}

const BAKE_W = 1024, BAKE_H = 512, BAKE_STRIPS = 8;
// which parts of Fancy show, switched under Graphics in the settings popup; all on to start with. The Milky Way and
// the sun fade in and out; the Milky Way isn't painted until it is first on.
const FANCY_PARTS = [['milky', 'Milky Way'], ['sun', 'Sun'], ['warm', 'Warms when busy'], ['ripple', 'Ripples on attacks']];
const fancy = { milky: true, sun: true, warm: true, ripple: true };
const saved = pref('tm.fancy', {}, JSON.parse) || {};
for (const [k] of FANCY_PARTS) if (typeof saved[k] === 'boolean') fancy[k] = saved[k];
export const sky = { on: false, dropped: false, mesh: null, stars: null, outer: null, inner: null, limb: null, raf: 0, ts: 0,
                     warm: 0, warmTarget: 0, rippleAt: -1e9, sunAt: -1e9, bake: null, target: null, strip: 0,
                     fade: { milky: +fancy.milky, sun: +fancy.sun } };

export function buildSky() {
  const T = three(), composer = globe.postProcessingComposer();
  if (!T.ready || !T.ShaderPass || !composer.renderTarget1) return false;
  const target = sky.target = new composer.renderTarget1.constructor(BAKE_W, BAKE_H, { type: composer.renderTarget1.texture.type });
  sky.bake = new T.ShaderPass({ uniforms: {}, vertexShader: GLOW_VS, fragmentShader: BAKE_FS });
  sky.strip = 0;

  const G = galaxyFrame();
  const mat = new T.ShaderMaterial({
    uniforms: {
      tNeb: { value: target.texture }, gX: { value: G.x }, gY: { value: G.y }, gZ: { value: G.z }, sunSky: { value: [0, 0, 1] },
      res: { value: [1, 1] }, warm: { value: 0 }, edge: { value: 0 }, ripple: { value: [0, 0, 0, 0] },
      milky: { value: sky.fade.milky }, sunOn: { value: sky.fade.sun }, bgA: { value: linHex('#121a3a') }, bgB: { value: linHex('#070b18') }, hotA: { value: linHex('#2a1033') }, hotB: { value: linHex('#0e0716') },
      cBlue: { value: linHex('#24358a') }, cTeal: { value: linHex('#1f8c99') }, cViolet: { value: linHex('#7a3aa8') },
      hMag: { value: linHex('#b02a78') }, hRed: { value: linHex('#c8323e') }, ripCol: { value: linHex(COLORS.attack) }, sunCol: { value: linHex('#fff1dc') },
    },
    vertexShader: SKY_VS, fragmentShader: SKY_FS, depthTest: false, depthWrite: false, side: 2 /* both */,
  });
  sky.mesh = new T.Mesh(new T.SphereGeometry(1, 64, 32), mat);
  sky.mesh.renderOrder = -1000;
  sky.mesh.frustumCulled = false;

  // stars: an even scatter like the flat starfield's, and a dense faint crowd along the Milky Way
  let seed = 11;
  const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const gauss = () => { let u = 0; while (!u) u = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rnd()); };
  const TINT = { warm: linHex('#ffaa78'), blue: linHex('#96beff'), white: linHex('#e8ecff') };
  const pos = [], corner = [], info = [], tint = [], band = [], index = [];
  const add = (d, size, bright, twinkle, c, inBand) => {
    const base = pos.length / 3, l = Math.hypot(...d), ph = rnd() * 6.283;
    for (const [cx, cy] of [[-1, -1], [1, -1], [1, 1], [-1, 1]]) {
      pos.push(d[0] / l, d[1] / l, d[2] / l); corner.push(cx, cy); info.push(size, bright, twinkle, ph); tint.push(...c); band.push(inBand);
    }
    index.push(base, base + 1, base + 2, base, base + 2, base + 3);
  };
  for (let i = 0; i < 7500; i++) {
    const big = rnd() > 0.95, t = rnd();
    add([gauss(), gauss(), gauss()], big ? 3 + rnd() * 2.5 : 1.3 + rnd() * 1.1, big ? 0.6 + rnd() * 1.3 : 0.05 + rnd() * 0.4,
        rnd() < 0.3 ? 0.6 + rnd() * 2 : 0, t < 0.08 ? TINT.warm : t < 0.2 ? TINT.blue : TINT.white, 0);
  }
  for (let i = 0; i < 9000; i++) {
    let l;
    do { l = (rnd() * 2 - 1) * Math.PI; } while (rnd() > 0.3 + 0.7 * Math.cos(l / 2) ** 2);  // thicker towards the centre
    const b = gauss() * (rnd() < 0.7 ? 0.07 : 0.16), t = rnd();
    add([0, 1, 2].map((k) => Math.cos(b) * (Math.cos(l) * G.x[k] + Math.sin(l) * G.y[k]) + Math.sin(b) * G.z[k]),
        1.1 + rnd() * 0.8, 0.03 + rnd() * 0.22, 0, t < 0.25 ? TINT.warm : t < 0.45 ? TINT.blue : TINT.white, 1);
  }
  // band: the Milky Way's crowd, which goes with it
  const geo = geometry(T, { position: [pos, 3], corner: [corner, 2], info: [info, 4], tint: [tint, 3], band: [band, 1] }, index);
  sky.stars = new T.Mesh(geo, new T.ShaderMaterial({
    uniforms: { res: { value: [1, 1] }, dpr: { value: 1 }, time: { value: 0 }, edge: { value: 0 }, ripple: { value: [0, 0, 0, 0] },
                milky: { value: sky.fade.milky } },
    vertexShader: STAR_VS, fragmentShader: STAR_FS, depthTest: false, depthWrite: false, blending: 2 /* additive */, side: 2,
    premultipliedAlpha: true,  // added as it is (not times its alpha), with its alpha as cover (shaders.js, STAR_FS)
  }));
  sky.stars.renderOrder = -999;  // still before the globe, which hides the ones behind it
  sky.stars.frustumCulled = false;

  const R = globe.getGlobeRadius();
  sky.limb = { sunDir: { value: [0, 0, 1] }, R: { value: R }, H: { value: R * 0.028 }, cAir: { value: linHex('#8fd0ff') },
               cWarm: { value: linHex('#ffb27a') }, on: { value: sky.fade.sun } };
  const shell = (r, fs, side) => new T.Mesh(new T.SphereGeometry(r, 128, 64), new T.ShaderMaterial({
    uniforms: sky.limb, vertexShader: LIMB_VS, fragmentShader: fs, transparent: true, depthWrite: false, blending: 2, side,
    premultipliedAlpha: true,  // added as it is, with its alpha as cover (shaders.js, LIMB_OUT_FS), as the stars
  }));
  sky.outer = shell(R * 1.18, LIMB_OUT_FS, 1 /* back */);
  sky.inner = shell(R * 1.004, LIMB_IN_FS, 0 /* front */);

  globe.scene().add(sky.mesh, sky.stars, sky.outer, sky.inner);
  placeSun();
  showSky();
  return true;
}

// the sun where it is now, over the Earth and among the stars, and the sky turned to where it stands; every 10 s
function placeSun() {
  const ms = serverNow() * 1000, [ra, dec] = sunRaDec(ms), turned = gmst(ms);
  sky.sunAt = performance.now();
  sky.mesh.material.uniforms.sunSky.value = unitAt(dec, ra);
  sky.limb.sunDir.value = unitAt(dec, ra - turned);
  sky.mesh.rotation.y = sky.stars.rotation.y = -turned * RAD;
}

function showSky() {
  if (!sky.mesh) return;
  for (const m of [sky.mesh, sky.stars, sky.outer, sky.inner]) m.visible = sky.on;
  if (sky.on && !sky.raf) sky.raf = requestAnimationFrame(skyTick);
}

// one strip of the Milky Way's picture (the sky shows it filling in over the first few frames)
function bakeStrip() {
  const renderer = globe.renderer(), prev = renderer.getRenderTarget(), h = BAKE_H / BAKE_STRIPS;
  sky.target.scissor.set(0, sky.strip * h, BAKE_W, h);
  sky.target.scissorTest = true;
  sky.bake.render(renderer, sky.target, null);
  sky.target.scissorTest = false;
  renderer.setRenderTarget(prev);
  sky.strip += 1;
}

function skyTick(ts) {
  if (!sky.on) { sky.raf = 0; return; }
  if (sky.strip < BAKE_STRIPS && fancy.milky) bakeStrip();
  const dt = Math.min(0.1, Math.max(0, (ts - (sky.ts || ts)) / 1000));
  sky.ts = ts;
  for (const k of ['milky', 'sun']) sky.fade[k] += (+fancy[k] - sky.fade[k]) * (1 - Math.exp(-dt / 0.3));
  if (performance.now() - sky.sunAt > 10000) placeSun();
  sky.warm += (sky.warmTarget - sky.warm) * (1 - Math.exp(-dt / 2));
  const cv = globe.renderer().domElement, dpr = cv.width / Math.max(1, cv.clientWidth);
  let ripple = [0, 0, 0, 0];
  const age = (performance.now() - sky.rippleAt) / 1000;
  if (age < 4) {
    const s = globe.getScreenCoords(S.home.lat, S.home.lon, 0.02);
    ripple = [s.x * dpr, (cv.clientHeight - s.y) * dpr, age, 1];
  }
  const u = sky.mesh.material.uniforms, s = sky.stars.material.uniforms;
  u.res.value = s.res.value = [cv.width, cv.height];
  u.edge.value = s.edge.value = NARROW.matches ? 1 : 0;
  u.ripple.value = s.ripple.value = ripple;
  u.warm.value = sky.warm;
  u.milky.value = s.milky.value = sky.fade.milky;
  u.sunOn.value = sky.limb.on.value = sky.fade.sun;
  s.dpr.value = dpr;
  // a few stars twinkle, each at its own speed, so there is no common period: the time goes back once an hour (a jump
  // in a faint star's twinkle) so that on a wall that runs for weeks it stays small enough for a float on the chip
  s.time.value = reduceMotion ? 0 : (ts / 1000) % 3600;
  // the sunlit edge, once the globe has grown in from a dot
  sky.outer.visible = sky.inner.visible = performance.now() > 2500 && sky.fade.sun > 0.002;
  sky.raf = requestAnimationFrame(skyTick);
}

// How much busier than normal: knocks a minute over the last 5 minutes against normal, today's average so far or the
// hour before those 5 minutes, whichever is higher (so a dashboard started mid-day, or the demo, isn't measured
// against the quiet morning it never saw). Calm up to normal, fully warm at three times normal.
function skyWarmth() {
  const now = serverNow();
  let recent = 0, before = 0, first = now - 300;
  for (const [b, c] of activity.buckets) {
    if (b >= now - 300) recent += c[0] + c[1];
    else if (b >= now - 3600) { before += c[0] + c[1]; first = Math.min(first, b); }
  }
  const dayMin = (now * 1000 - new Date(now * 1000).setHours(0, 0, 0, 0)) / 60000;
  const normal = Math.max(0.5, dayMin >= 60 ? live.attempts / dayMin : 0, before / Math.max(10, (now - 300 - first) / 60));
  return Math.min(1, Math.max(0, (recent / 5 / normal - 1) / 2));
}
setInterval(() => { if (sky.on && S.stats) sky.warmTarget = fancy.warm ? skyWarmth() : 0; }, 2000);

// an attack the IDS recognised broke on the shield: one ripple through the stars, at most every 20 s
function skyRipple() {
  const t = performance.now();
  if (sky.on && fancy.ripple && !reduceMotion && !document.hidden && t - sky.rippleAt > 20000) sky.rippleAt = t;
}
hooks.ripple = skyRipple;

function setFancyPart(key, on) {
  fancy[key] = on;
  savePref('tm.fancy', JSON.stringify(fancy));
  if (!fancy.warm) sky.warmTarget = 0;      // cools back down over a few seconds
  if (!fancy.ripple) sky.rippleAt = -1e9;   // and a ripple on its way stops
}
$('fancyParts').innerHTML = FANCY_PARTS.map(([k, name]) => `<label class="opt"><span>${name}</span>`
  + `<input type="checkbox" role="switch" value="${k}"></label>`).join('');
$('fancyParts').querySelectorAll('input').forEach((i) => { i.checked = fancy[i.value]; });
$('fancyParts').addEventListener('change', (e) => setFancyPart(e.target.value, e.target.checked));

// Fancy, Simple or Simplest, in the settings popup: Simplest to start with, until this browser picks another (Simple
// with ?lite, which keeps the other two off). Simplest is Simple drawn lighter, for a tablet or a phone (globe.js,
// SIMPLEST); it is set up as the page starts, so picking it, or leaving it, reloads the page. Fancy steps down to Simple for the visit if the page runs
// slow with it (watchFrameRate below), and for this tab, reloads included, if the graphics driver was reset under it;
// picking Fancy again tries again.
const GRAPHICS = ['fancy', 'simple', 'simplest'];
let graphics = SIMPLEST ? 'simplest' : pref('tm.graphics', 'simplest') === 'fancy' ? 'fancy' : 'simple';
if (query.has('lite')) graphics = 'simple';
let gfxLost = false;
try { gfxLost = sessionStorage.getItem('tm.gfxLost') === '1'; } catch (e) { /* no storage: nothing remembered */ }
function setGraphics(key, remember) {
  const next = GRAPHICS.includes(key) ? key : 'fancy';
  if (remember && (next === 'simplest') !== SIMPLEST) {  // into or out of Simplest: the page starts again with it
    savePref('tm.graphics', next);
    try { sessionStorage.removeItem('tm.gfxLost'); } catch (e) { /* not remembered, still works */ }
    location.reload();
    return;
  }
  graphics = next;
  if (remember) {
    savePref('tm.graphics', graphics);
    try { sessionStorage.removeItem('tm.gfxLost'); } catch (e) { /* not remembered, still works */ }
  }
  $('graphics').querySelectorAll('input').forEach((i) => {
    i.checked = i.value === graphics;
    i.disabled = i.value !== 'simple' && query.has('lite');
  });
  $('graphicsNote').hidden = true;
  $('fancyParts').hidden = graphics !== 'fancy';
  sky.on = graphics === 'fancy';
  if (sky.on && !sky.mesh && beamGL.mesh) buildSky();  // else the start-up (main.js, waitForGlobe) builds it
  showSky();
}
radios('graphics', GRAPHICS, cap, (v) => setGraphics(v, true));
if (gfxLost && graphics === 'fancy') dropFancy('the graphics driver was reset while Fancy was on');
else setGraphics(graphics, false);

function dropFancy(why) {
  setGraphics('simple', false);
  $('graphicsNote').textContent = `Simple for now: ${why}`;
  $('graphicsNote').hidden = false;
  console.info(`ThreatMonitor: Simple graphics for now, ${why}; pick Fancy in the settings to try again`);
}

// The graphics driver was reset (Windows does that when one job keeps the chip busy past 2 s) or the browser took the
// chip away: the page loses its WebGL context and three.js asks for it back. With Fancy on, this tab stays Simple.
// If it never comes back (Chrome stops giving it after repeated resets: a white globe with a sad face), the page
// reloads after GFX_WAIT_MS, in Simple, at most GFX_RELOADS times an hour, so a wall nobody watches recovers.
const GFX_WAIT_MS = 15000, GFX_RELOADS = 3;
let gfxWait = 0;
function reloadForGraphics() {
  try {
    const times = JSON.parse(sessionStorage.getItem('tm.gfxReloads') || '[]').filter((t) => Date.now() - t < 3600e3);
    if (times.length >= GFX_RELOADS) {
      console.warn('ThreatMonitor: the graphics did not come back; no more reloads this hour');
      return;
    }
    sessionStorage.setItem('tm.gfxReloads', JSON.stringify([...times, Date.now()]));
  } catch (e) {
    return;  // the reloads can't be counted: better a dead globe than a page reloading forever
  }
  location.reload();
}
globe.renderer().domElement.addEventListener('webglcontextlost', () => {
  clearTimeout(gfxWait);
  gfxWait = setTimeout(reloadForGraphics, GFX_WAIT_MS);
  if (!sky.on) return;
  try { sessionStorage.setItem('tm.gfxLost', '1'); } catch (e) { /* not remembered across a reload */ }
  dropFancy('the graphics driver was reset while Fancy was on');
});
globe.renderer().domElement.addEventListener('webglcontextrestored', () => {
  clearTimeout(gfxWait);
  sky.strip = 0;  // the Milky Way's picture went with it
});

// a tablet or a weak graphics chip: if frames stay slower than ~24 a second, it is drawn lighter a step at a time: with
// Simplest first at 1x (from 1.5x, globe.js: render), with Fancy the sky first (Simple for this visit; the setting
// stays as it was), and if it's still slow, the glow. Measured in 5-second windows once start-up is over; two slow
// windows in a row are needed, so one hiccup isn't enough. Smooth three times in a row and it stops watching, but not
// with Simplest: a tablet can slow down later in a visit.
function watchFrameRate() {
  let frames = 0, t0 = 0, good = 0, slow = 0;
  const tick = (ts) => {
    if (document.hidden) { t0 = 0; frames = 0; requestAnimationFrame(tick); return; }
    if (!t0) t0 = ts;
    frames += 1;
    if (ts - t0 >= 5000) {
      const fps = (frames * 1000) / (ts - t0);
      if (fps < 24) {
        good = 0;
        if (++slow >= 2) {
          slow = 0;
          if (SIMPLEST && render.scale > 1) {
            setRenderScale(1);
            console.info(`ThreatMonitor: drawn at 1x, this screen managed ${fps.toFixed(0)} frames a second`);
          } else if (sky.on && !sky.dropped) {
            sky.dropped = true;
            dropFancy(`this screen managed ${fps.toFixed(0)} frames a second with Fancy`);
          } else if (glow.pass) {
            glow.pass.enabled = false;
            console.info(`ThreatMonitor: glow switched off at ${fps.toFixed(0)} frames/s; add ?glow to the address to keep it on`);
            return;
          }
        }
      } else {
        slow = 0;
        if (++good >= 3 && !SIMPLEST) return;  // smooth three times in a row: stop watching
      }
      t0 = ts; frames = 0;
    }
    requestAnimationFrame(tick);
  };
  setTimeout(() => requestAnimationFrame(tick), 8000);  // after the start-up work
}

if (!query.has('lite') && !query.has('glow')) watchFrameRate();
