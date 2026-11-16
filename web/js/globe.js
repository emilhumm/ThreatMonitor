/* The globe and what is drawn on it: coastlines, a beam and a pool of light per place, a comet and rings for each
   event, the shield over home, and the glow. */
import { $, esc, fmt, showTip, hideTip } from '../common.js';
import { S, serverNow, COLORS, kindOf, rgba, GAIN, agoText, query, NARROW, INSET, hooks, hexRgb, lin } from './shared.js';
import { BEAM_VS, BEAM_FS, POOL_VS, POOL_FS, GLOW_VS, BRIGHT_FS, BLUR_FS, GLOW_FS, SHIELD_VS, SHIELD_FS } from './shaders.js';
import { pref, savePref, radios, cap } from './prefs.js';

const globeEl = $('globe');
export const HOME_VIEW = () => ({ lat: Math.max(10, S.home.lat - 22), lng: S.home.lon, altitude: homeAltitude() });
// how far out the camera starts: 2.39 globe radii above the ground, as on the wall, or further out when the globe's box
// is too narrow to show it whole at that (a phone held upright, 2026-11-09): then the globe takes 85% of its width. On a
// narrow screen further still (10% further, then 8% more, then 5% back), so it shows whole with room round it.
// With ?inset (js/shared.js: Home Assistant's rail over the left edge) 15% further out on top of that:
// its column is narrower by the inset (on the wall tablet 530 px without it)
const INSET_OUT = INSET ? 0.85 : 1;
function homeAltitude() {
  const box = globeEl.getBoundingClientRect();
  if (!box.width || !box.height) return (1 + 2.39) / INSET_OUT - 1;
  const fits = Math.atan(0.85 * Math.tan((globe.camera().fov * Math.PI) / 360) * (box.width / box.height));
  const alt = Math.max(2.39, 1 / Math.sin(fits) - 1);  // the globe's edge seen at that angle from the middle
  return (1 + alt) / ((NARROW.matches ? 0.9 * 0.92 * 1.05 : 1) * INSET_OUT) - 1;
}

// "Beams on glass": a dark sphere where only coastlines glow, and a thin beam of light per source location
const BEAM_K = 0.86;                       // beam brightness, against the full brightness of the photo look
const RGB = { block: [62, 224, 208], ids: [255, 95, 210], white: [255, 255, 255] };
const mixRgb = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));
const beamHeight = (n) => Math.min(0.42, 0.045 + 0.11 * Math.log10(1 + n));
const tone = (p) => (p.n && p.ids / p.n >= 0.25 ? RGB.ids : RGB.block);   // mostly IDS alerts -> pink
const level = (p) => {                     // just hit: full white; today: normal; quiet for 30 min: dimmer
  const age = serverNow() - (p.last || 0);
  return age < 15 ? 1 : age < 1800 ? BEAM_K : BEAM_K * 0.6;
};

function pointCard(p) {
  const where = p.city ? `${esc(p.city)}, ${esc(p.country)}` : esc(p.country || p.cc);
  return `<b>${where}</b><br><small>${fmt(p.n)} hit${p.n === 1 ? '' : 's'}${p.ids ? ` · ${fmt(p.ids)} IDS` : ''}`
    + `${p.last ? ` · last ${agoText(serverNow() - p.last)} ago` : ''}</small>`;
}

// Simplest, one of the graphics in the settings (sky.js): the globe drawn lighter, for a tablet or a phone. It is set up
// as the page starts, as the drawing's edge smoothing can't be changed later: no edge smoothing, at most 1.5x the
// screen's pixels (render, below), the frame's picture in 8 bits (glow, below), and the cards' letters outlined rather
// than hazed (style.css, html.simplest). On a mid-range Android wall tablet that took Simple's 35 frames a second, with a
// stutter about once a second, to 57-60 and smooth (2026-11-07). Picking it, or leaving it, reloads the page (sky.js).
// It is what a browser starts on until Fancy or Simple is picked there.
export const SIMPLEST = !query.has('lite') && !['fancy', 'simple'].includes(pref('tm.graphics', 'simplest'));
if (SIMPLEST) document.documentElement.classList.add('simplest');

export const globe = new Globe(globeEl, { animateIn: true, rendererConfig: { antialias: !SIMPLEST } })
  .backgroundColor('rgba(0,0,0,0)')
  .showAtmosphere(true)
  .atmosphereColor('#2f5f8f')  // dim enough to stay under the glow's threshold, so it stays a soft rim
  .atmosphereAltitude(0.1)
  .polygonAltitude(0.003)
  .polygonCapColor(() => 'rgba(90, 80, 210, 0.10)')
  .polygonSideColor(() => 'rgba(0, 0, 0, 0)')
  .polygonStrokeColor(() => 'rgba(140, 200, 255, 0.5)')
  .polygonsTransitionDuration(0)
  // globe.gl's own pointer checks off: once the globe had been touched (or a mouse had been over it) they tested
  // everything drawn against the pointer 20 times a second, over 130,000 triangles and 82,000 line segments, ~7 ms each
  // time; on an iPhone a hitch every third frame until the page was reloaded (2026-11-09). Hover and tap find the
  // nearest place here instead (globeAt, nearestPlace)
  .enablePointerInteraction(false)
  .arcStartLat('sLat').arcStartLng('sLon').arcEndLat('eLat').arcEndLng('eLon')
  .arcColor('colors')
  .arcStroke('stroke')  // per arc: comets for threats, the plain dashed arc for our own network going out
  .arcDashLength('dl').arcDashGap('dg').arcDashInitialGap('dig').arcDashAnimateTime('dt')
  .arcAltitudeAutoScale(0.45)
  .arcsTransitionDuration(0)
  .ringLat('lat').ringLng('lon')
  .ringColor((r) => r.color)
  .ringMaxRadius('max').ringPropagationSpeed('speed').ringRepeatPeriod('period')
  .htmlLat('lat').htmlLng('lon').htmlAltitude('h')
  .htmlElement((d) => d.el)
  .htmlTransitionDuration(0)
  .htmlElementVisibilityModifier((el, visible) => { el.style.visibility = visible ? 'visible' : 'hidden'; });

const SEA = '#090e2a';
const mat = globe.globeMaterial();
mat.color.set(SEA);
mat.emissive.set('#0b0f36');
mat.emissiveIntensity = 0.8;
mat.shininess = 4;

/* ---------------------------------------------------------------- three.js, borrowed
   globe.gl bundles its own three.js without exposing it, so the classes are borrowed from objects the globe made: the
   post-processing ones at once, the rest once its sphere is in the scene. */

let T3 = null;
// the classes found so far; ready once all are there, and then kept (until then each call looks again)
export function three() {
  if (T3) return T3;
  const out = {};
  const comp = globe.postProcessingComposer();
  out.ShaderPass = comp.copyPass && comp.copyPass.constructor;
  out.ShaderMaterial = comp.copyPass && comp.copyPass.material.constructor;
  globe.scene().traverse((o) => {
    if (!out.Mesh && o.isMesh && o.geometry && o.geometry.type === 'SphereGeometry') {
      out.Mesh = o.constructor; out.SphereGeometry = o.geometry.constructor; out.Vector3 = o.position.constructor;
    }
  });
  if (out.SphereGeometry) {
    const probe = new out.SphereGeometry(1, 3, 2);
    out.BufferGeometry = geometryClass(probe);
    out.Attr = probe.attributes.position.constructor;
    probe.dispose();
  }
  out.ready = !!(out.Mesh && out.ShaderMaterial && out.BufferGeometry);
  if (out.ready) T3 = out;
  return out;
}

// the plain BufferGeometry class under a geometry's own (a SphereGeometry, say)
function geometryClass(g) {
  let proto = g;
  while (proto && !Object.prototype.hasOwnProperty.call(proto, 'setAttribute')) proto = Object.getPrototypeOf(proto);
  return proto.constructor;
}

// one geometry from flat arrays, {name: [numbers, numbers per vertex]}, with T's BufferGeometry and attribute classes
export function geometry(T, attrs, index) {
  const geo = new T.BufferGeometry();
  for (const [name, [values, size]] of Object.entries(attrs)) geo.setAttribute(name, new T.Attr(new Float32Array(values), size));
  if (index) geo.setIndex(index);
  return geo;
}

// two directions along the ground where n (a unit vector up from the globe's centre) meets it: what a pool spreads
// over and a beam's two strips stand along (ref: a spare vector)
function groundAxes(n, u, w, ref) {
  ref.set(0, 1, 0);
  if (Math.abs(n.y) > 0.9) ref.set(1, 0, 0);
  u.crossVectors(n, ref).normalize();
  w.crossVectors(n, u).normalize();
}

/* ---------------------------------------------------------------- land and borders */

// Country borders from Natural Earth's 1:50m map (world-atlas). The coarser 1:110m one leaves out small island
// countries, so the beams of the Seychelles or Mauritius stood in the open sea, and its rough coastlines put coastal
// cities a little offshore.
//
// An integrated graphics chip chokes on the number of separate objects drawn per frame, far more than on pixels: the
// countries' outlines, ~300 beams with halos and ~300 footprints were ~1,300 draws a frame (14-20 frames a second on
// an Intel HD 530). So beams and the pools of light under them are drawn as one object each, the outlines as two (coastlines, and the
// borders between countries). They are built straight
// from the map: the globe's own polygon layer also fills in every country's surface, which at this detail froze the
// page for ~20 s. It draws just the smallest country, long enough to lend its line style and three.js classes.
fetch('/static/vendor/countries-50m.json')
  .then((r) => r.json())
  .then((w) => {
    const obj = w.objects.countries;
    const coast = topojson.mesh(w, obj, (a, b) => a === b).coordinates;   // an edge with one country: the sea's
    const borders = topojson.mesh(w, obj, (a, b) => a !== b).coordinates;  // an edge two countries share
    const size = (f) => JSON.stringify(f.geometry.coordinates).length;
    const smallest = topojson.feature(w, obj).features.filter((f) => f.geometry).sort((a, b) => size(a) - size(b))[0];
    globe.polygonsData([smallest]);
    drawBorders(coast, borders);
    paintLand(w);
  });

// Land a shade lighter than the sea, painted once onto the globe's surface image, so it costs nothing per frame. The
// globe then takes its colour from the image alone, so the sea is painted in the sphere's own colour.
const LAND = '#1f2a6e';
function paintLand(w) {
  const W = 4096, H = 2048, cv = document.createElement('canvas');
  cv.width = W;
  cv.height = H;
  const ctx = cv.getContext('2d');
  ctx.fillStyle = SEA;
  ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = LAND;
  const land = topojson.feature(w, w.objects.land);
  for (const f of land.features || [land]) {
    for (const poly of f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates) fillLand(ctx, poly, W, H);
  }
  cv.toBlob((b) => globe.globeImageUrl(URL.createObjectURL(b)));
}

// One land shape (outline and holes, such as the Caspian, filled even-odd) on the flat world image. A few shapes cross
// the date line: Russia's far east, Wrangel Island, Fiji, and Antarctica all the way round. Drawn as they come, their
// edges jumped across the whole width and painted a band right round the globe (rings around the North Pole). So each
// ring is kept in one piece, drawn again a world-width over where it runs off an edge, and one that goes all the way
// round is closed over its pole.
function fillLand(ctx, poly, W, H) {
  const rings = poly.map((ring) => {
    const out = [];
    let shift = 0;
    for (const [lon, lat] of ring) {
      const prev = out[out.length - 1];
      if (prev && lon + shift - prev[0] > 180) shift -= 360;
      else if (prev && lon + shift - prev[0] < -180) shift += 360;
      out.push([lon + shift, lat]);
    }
    if (Math.abs(out[out.length - 1][0] - out[0][0]) > 180) {
      const pole = out.reduce((s, p) => s + p[1], 0) < 0 ? -90 : 90;
      out.push([out[out.length - 1][0], pole], [out[0][0], pole]);
    }
    return out;
  });
  let lo = Infinity, hi = -Infinity;
  for (const r of rings) for (const [lon] of r) { lo = Math.min(lo, lon); hi = Math.max(hi, lon); }
  for (const off of [0, -360, 360]) {
    if ((off < 0 && hi <= 180) || (off > 0 && lo >= -180)) continue;
    ctx.beginPath();
    for (const r of rings) r.forEach(([lon, lat], i) => ctx[i ? 'lineTo' : 'moveTo'](((lon + off + 180) / 360) * W, ((90 - lat) / 180) * H));
    ctx.fill('evenodd');
  }
}

// coastlines in the outline colour (polygonStrokeColor), borders between countries fainter, so the land's shape leads
const BORDER_OPACITY = 0.32;

function drawBorders(coast, borders) {
  let stroke = null;
  globe.scene().traverse((o) => {
    if (!stroke && o.isLineSegments && o.parent && o.parent.__globeObjType === 'polygon' && o.geometry.attributes.position) stroke = o;
  });
  if (!stroke) {  // still being built, or the page opened in a background tab: keep looking, it costs next to nothing
    setTimeout(() => drawBorders(coast, borders), 500);
    return;
  }
  // The lines go into the globe's own group, in its coordinates. On start-up the globe grows from a dot and turns into
  // place; lines put straight into the scene, at a size and angle read part-way through that, stayed small (hidden
  // inside the sphere) or turned for good, and the coastlines were missing now and then.
  let globeObj = stroke;
  while (globeObj.parent && globeObj.parent !== globe.scene()) globeObj = globeObj.parent;
  globeObj.updateWorldMatrix(true, true);
  const v = stroke.position.clone().fromBufferAttribute(stroke.geometry.attributes.position, 0).applyMatrix4(stroke.matrixWorld);
  const alt = globeObj.worldToLocal(v).length() / globe.getGlobeRadius() - 1;  // the height the globe draws its outlines at
  // the stroke's own classes: it can be here before the globe's sphere, which three() waits for
  const T = { BufferGeometry: geometryClass(stroke.geometry), Attr: stroke.geometry.attributes.position.constructor };
  const outline = (lines, opacity) => {  // all the lines as one object
    const out = [];
    const at = ([lon, lat]) => { const c = globe.getCoords(lat, lon, alt); out.push(c.x, c.y, c.z); };
    for (const line of lines) for (let i = 1; i < line.length; i++) { at(line[i - 1]); at(line[i]); }
    const m = stroke.material.clone();
    if (opacity != null) m.opacity = opacity;
    const obj = new stroke.constructor(geometry(T, { position: [out, 3] }), m);
    // never under the pointer (hover and click go by position, nearestPlace): otherwise globe.gl tests a resting mouse
    // against all ~79,000 segments 20 times a second
    obj.raycast = () => {};
    return obj;
  };
  globeObj.add(outline(coast), outline(borders, BORDER_OPACITY));
  globe.polygonsData([]);
}

/* ---------------------------------------------------------------- size, rotation, flying */

// On a wide screen the canvas is the whole page, under the cards, so a fly-in is never cut off at the centre column's
// edges; the globe is shifted from the page's middle to the column's middle (on a narrow screen the two are the same).
const GLOBE_DROP = 0.05;  // on a wide screen the globe sits this share of the page below the column's middle
function fitGlobe() {
  const box = globeEl.getBoundingClientRect(), col = globeEl.parentElement.getBoundingClientRect();
  if (!box.width || !box.height) return;
  const drop = NARROW.matches ? 0 : GLOBE_DROP * box.height;  // narrow: it has its own box
  globe.width(box.width).height(box.height).globeOffset([
    col.left + col.width / 2 - (box.left + box.width / 2),
    col.top + col.height / 2 - (box.top + box.height / 2) + drop,
  ]);
}
const fitObserver = new ResizeObserver(fitGlobe);
fitObserver.observe(globeEl);
fitObserver.observe(globeEl.parentElement);

// on a narrow screen Threats Detected and Blocks · Alerts come first, and the globe's box takes the rest of the screen
// under them (style.css): how far down the page that box starts (--globe-top), kept up as those cards change or hide,
// and how tall the screen the page has is (--view-h), measured: 100svh came out taller than an iPhone shows the
// page as a Home Screen web app, and the box's foot with its buttons ended below the screen. The smallest height seen
// at this width, so Safari's bars sliding away as the page scrolls don't resize the globe
let view = { w: 0, h: 0 };
function placeGlobeBox() {
  const top = globeEl.parentElement.getBoundingClientRect().top + scrollY;
  if (innerWidth !== view.w) view = { w: innerWidth, h: innerHeight };
  view.h = Math.min(view.h, innerHeight);
  document.documentElement.style.setProperty('--globe-top', `${Math.round(top)}px`);
  document.documentElement.style.setProperty('--view-h', `${view.h}px`);
}
const aboveObserver = new ResizeObserver(placeGlobeBox);
document.querySelectorAll('.headline, .b1').forEach((el) => aboveObserver.observe(el));
addEventListener('resize', placeGlobeBox);

// rotation: spins by itself, stops while you drag, picks up again a little after you let go. lastTouch: the last time
// someone turned or zoomed the globe; the tour leaves them alone for a while
export const controls = globe.controls();
controls.autoRotate = true;
controls.autoRotateSpeed = 0.35;
controls.enableDamping = true;
controls.dampingFactor = 0.08;
controls.minDistance = 125;
controls.maxDistance = 650;
export const spin = { on: true, timer: 0, lastTouch: 0 };
const pauseSpin = (ms) => {
  controls.autoRotate = false;
  clearTimeout(spin.timer);
  if (spin.on) spin.timer = setTimeout(() => { controls.autoRotate = spin.on; }, ms);
};
controls.addEventListener('start', () => { spin.lastTouch = Date.now(); hooks.tourCancel(); pauseSpin(1e9); });
controls.addEventListener('end', () => { spin.lastTouch = Date.now(); pauseSpin(8000); });

// how fast it turns by itself, in the settings popup
const SPIN_SPEEDS = { slow: 0.15, normal: 0.35, fast: 0.8 };
let spinSpeed = pref('tm.spinSpeed', 'normal');
function setSpinSpeed(key) {
  spinSpeed = key in SPIN_SPEEDS ? key : 'normal';
  controls.autoRotateSpeed = SPIN_SPEEDS[spinSpeed];
  savePref('tm.spinSpeed', spinSpeed);
  $('spinSpeed').querySelectorAll('input').forEach((i) => { i.checked = i.value === spinSpeed; });
}
radios('spinSpeed', Object.keys(SPIN_SPEEDS), cap, setSpinSpeed);
setSpinSpeed(spinSpeed);

$('spinBtn').onclick = () => {
  spin.on = !spin.on;
  controls.autoRotate = spin.on;
  clearTimeout(spin.timer);
  $('spinIco').setAttribute('d', spin.on ? 'M5 3h2v10H5zM9 3h2v10H9z' : 'M5 3l8 5-8 5z');
  $('spinBtn').title = $('spinBtn').ariaLabel = spin.on ? 'Pause rotation' : 'Resume rotation';
};
$('homeBtn').onclick = () => { const v = HOME_VIEW(); fly(v.lat, v.lng, v.altitude); };

export function fly(lat, lon, altitude) {
  spin.lastTouch = Date.now();
  hooks.tourCancel();
  pauseSpin(10000);
  globe.pointOfView({ lat, lng: lon, altitude }, 1200);
}

/* ---------------------------------------------------------------- places: beams and pools of light */

// places: one per location, kept as stable objects so the globe updates them instead of rebuilding them
const points = new Map();
let pointsDirty = false;
const pkey = (lat, lon) => `${lat.toFixed(1)},${lon.toFixed(1)}`;
const MAX_PLACES = 1500;  // as many as the server sends at most (state.MAX_POINTS)
const HIT_KEEP = 60;      // seconds a place just hit is kept, even where a list leaves it out or the cap would drop it
const hitLately = (p) => (p.last || 0) > serverNow() - HIT_KEEP;

// full: the whole list (hello, and at midnight when the day's counts restart): places not in it go, except, with
// keepHit, the ones hit a moment ago (a busy day has more places than the list). Otherwise only the places that
// changed, merged in. The beams are rebuilt only if something did change.
export function setPoints(list, full, keepHit = false) {
  const seen = new Set();
  let changed = false;
  for (const p of list) {
    const k = pkey(p.lat, p.lon);
    seen.add(k);
    const cur = points.get(k);
    if (!cur) points.set(k, { ...p });
    else if (Object.keys(p).some((f) => cur[f] !== p[f])) Object.assign(cur, p);
    else continue;
    changed = true;
  }
  if (full) {
    for (const [k, p] of points) {
      if (!seen.has(k) && !(keepHit && hitLately(p))) {
        points.delete(k);
        changed = true;
      }
    }
  }
  if (changed) pointsDirty = true;
}

// over the cap: the places with the fewest knocks go first, never one hit a moment ago
function capPlaces() {
  let drop = points.size - MAX_PLACES;
  if (drop <= 0) return;
  const quiet = [...points].filter(([, p]) => !hitLately(p)).sort((a, b) => a[1].n - b[1].n);
  for (const [k] of quiet) {
    if (drop-- <= 0) break;
    points.delete(k);
  }
}

export function bumpPoint(e) {
  const g = e.geo;
  const k = pkey(g.lat, g.lon);
  let p = points.get(k);
  if (!p) points.set(k, (p = { lat: g.lat, lon: g.lon, n: 0, ids: 0, cc: g.cc, city: g.city, country: g.country }));
  if (!e.dup) p.n += 1;  // knocks, and of them the ones the IDS flagged
  if (e.gain & GAIN.flagged) p.ids += 1;
  p.last = e.ts;
  pointsDirty = true;
}

// beams: every beam and halo in one mesh. A beam is two crossed strips (so it looks the same from any side) whose
// colour fades in from the ground to a near-white tip; the strips add their light to whatever is behind them.
const CORE_HALF = 0.16, HALO_HALF = 0.5;  // half-widths in globe units (the globe's radius is 100)
export const beamGL = { mesh: null, pools: null };

// pools of light: a glowing spot on the ground under every beam (a hot core and a soft halo), sized by knocks, in the
// beam's colour and white when just hit. A beam starts faint at the ground, so seen from above, without them, the
// beams looked like sticks floating over the map. All in one mesh: a flat square per place, rounded off by the shader.
const poolSize = (n) => 0.9 + 1.2 * Math.log10(1 + n);  // half-width in globe units: ~2.4° across at 300 knocks

export function initBeams() {
  const T = three();
  if (!T.ready) return false;
  const glowing = (vs, fs) => new T.ShaderMaterial({ vertexShader: vs, fragmentShader: fs,
                                                     transparent: true, depthWrite: false, blending: 2 /* additive */, side: 2 /* both */ });
  beamGL.mesh = new T.Mesh(new T.BufferGeometry(), glowing(BEAM_VS, BEAM_FS));
  beamGL.mesh.frustumCulled = false;
  beamGL.pools = new T.Mesh(new T.BufferGeometry(), glowing(POOL_VS, POOL_FS));
  beamGL.pools.frustumCulled = false;
  globe.scene().add(beamGL.mesh, beamGL.pools);
  pointsDirty = true;
  return true;
}

function drawPools(ranked) {
  if (!beamGL.pools) return;
  const T = three(), V = T.Vector3;
  const pos = [], corner = [], tint = [];
  const c = new V(), n = new V(), u = new V(), w = new V(), ref = new V();
  for (const [, p] of ranked) {
    const lvl = level(p), t = lin(lvl === 1 ? RGB.white : tone(p), 0.75 * lvl), size = poolSize(p.n);
    const g = globe.getCoords(p.lat, p.lon, 0.0025);  // just above the coastlines
    c.set(g.x, g.y, g.z);
    groundAxes(n.copy(c).normalize(), u, w, ref);
    u.multiplyScalar(size);
    w.multiplyScalar(size);
    for (const [a, b] of [[-1, -1], [1, -1], [1, 1], [-1, -1], [1, 1], [-1, 1]]) {
      pos.push(c.x + u.x * a + w.x * b, c.y + u.y * a + w.y * b, c.z + u.z * a + w.z * b);
      corner.push(a, b);
      tint.push(...t);
    }
  }
  const geo = geometry(T, { position: [pos, 3], corner: [corner, 2], tint: [tint, 4] });
  beamGL.pools.geometry.dispose();
  beamGL.pools.geometry = geo;
}

function drawBeams(ranked) {
  if (!beamGL.mesh) return;
  const T = three(), V = T.Vector3;
  const pos = [], tint = [];
  const n = new V(), u = new V(), w = new V(), s = new V(), p0 = new V(), p1 = new V(), ref = new V();
  const strip = (side, half, c0, c1) => {
    s.copy(side).multiplyScalar(half);
    const A = p0.clone().sub(s), B = p0.clone().add(s), C = p1.clone().add(s), D = p1.clone().sub(s);
    for (const [P, c] of [[A, c0], [B, c0], [C, c1], [A, c0], [C, c1], [D, c1]]) {
      pos.push(P.x, P.y, P.z);
      tint.push(c[0], c[1], c[2], c[3]);
    }
  };
  const seg = (p, alt0, alt1, half, c0, c1) => {
    const a = globe.getCoords(p.lat, p.lon, alt0), b = globe.getCoords(p.lat, p.lon, alt1);
    p0.set(a.x, a.y, a.z);
    p1.set(b.x, b.y, b.z);
    groundAxes(n.copy(p0).normalize(), u, w, ref);
    strip(u, half, c0, c1);
    strip(w, half, c0, c1);
  };
  ranked.forEach(([, p], i) => {
    const lvl = level(p), c = lvl === 1 ? RGB.white : tone(p), tip = lvl < 1 ? mixRgb(c, RGB.white, 0.55) : RGB.white;
    const h = beamHeight(p.n);
    if (i < 220) seg(p, 0.002, h, HALO_HALF, lin(c, 0.16 * lvl), lin(c, 0.08 * lvl));
    seg(p, 0.002, h * 0.5, CORE_HALF, lin(c, 0.1 * lvl), lin(c, 0.95 * lvl));
    seg(p, h * 0.5, h, CORE_HALF, lin(c, 0.95 * lvl), lin(tip, lvl));
  });
  const geo = geometry(T, { position: [pos, 3], tint: [tint, 4] });
  beamGL.mesh.geometry.dispose();
  beamGL.mesh.geometry = geo;
}

// hover and click on a place: the nearest one to the point of the globe under the pointer
function nearestPlace(lat, lng) {
  const maxDeg = 1.4 * Math.max(0.5, globe.pointOfView().altitude);  // more forgiving when zoomed out
  const k = Math.cos((lat * Math.PI) / 180);
  let best = null, bd = maxDeg;
  for (const p of points.values()) {
    let dl = Math.abs(p.lon - lng);
    if (dl > 180) dl = 360 - dl;
    const d = Math.hypot(p.lat - lat, dl * k);
    if (d < bd) { bd = d; best = p; }
  }
  return best;
}

// the point of the globe under a pointer event, as { lat, lng }, or null off the globe: one ray from the camera to the
// sphere. globe.gl's toGlobeCoords would test the ray against everything drawn, ~7 ms each time (see above)
function globeAt(ev) {
  const V = three().Vector3;
  if (!V) return null;
  const r = globeEl.getBoundingClientRect(), cam = globe.camera(), R = globe.getGlobeRadius();
  const d = new V(((ev.clientX - r.left) / r.width) * 2 - 1, -((ev.clientY - r.top) / r.height) * 2 + 1, 0.5)
    .unproject(cam).sub(cam.position).normalize();
  const o = cam.position, b = o.dot(d), disc = b * b - (o.dot(o) - R * R);
  if (disc < 0) return null;  // the ray misses the sphere
  const p = o.clone().addScaledVector(d, -b - Math.sqrt(disc));
  return globe.toGeoCoords({ x: p.x, y: p.y, z: p.z });
}

let hoverFrame = 0;
globeEl.addEventListener('mousemove', (ev) => {
  if (hoverFrame) return;
  hoverFrame = requestAnimationFrame(() => {
    hoverFrame = 0;
    const c = globeAt(ev);
    const p = c && nearestPlace(c.lat, c.lng);
    if (p) showTip(ev, pointCard(p)); else hideTip();
  });
});
globeEl.addEventListener('mouseleave', () => hideTip());

// a tap or a click on the globe flies to the nearest place; a press that moved (a drag) or a second finger (a pinch)
// is the globe being turned or zoomed, not a tap
let press = null;
globeEl.addEventListener('pointerdown', (ev) => {
  press = ev.isPrimary && ev.button === 0 ? { x: ev.clientX, y: ev.clientY, id: ev.pointerId } : null;
});
globeEl.addEventListener('pointerup', (ev) => {
  const p = press;
  press = null;
  if (!p || ev.pointerId !== p.id || Math.hypot(ev.clientX - p.x, ev.clientY - p.y) > 6) return;
  const c = globeAt(ev);
  const place = c && nearestPlace(c.lat, c.lng);
  if (place) fly(place.lat, place.lon, 1.5);
});

// faint labels with leader lines at the six busiest places (nearby places don't both get one)
let placeLabels = [];
let labelKeys = '';
function renderLabels(ranked) {
  const chosen = [];
  for (const [k, p] of ranked.slice(0, 40)) {
    if (chosen.length === 6) break;
    if (!chosen.some(([, q]) => Math.abs(q.lat - p.lat) < 9 && Math.abs(q.lon - p.lon) < 18)) chosen.push([k, p]);
  }
  const keys = chosen.map(([k]) => k).join('|');
  if (keys !== labelKeys) {
    labelKeys = keys;
    placeLabels = chosen.map(([k, p]) => {
      const el = document.createElement('div');
      el.className = 'glabel';
      el.appendChild(document.createElement('div'));
      return { k, p, el };
    });
  }
  for (const l of placeLabels) {
    Object.assign(l, { lat: l.p.lat, lon: l.p.lon, h: beamHeight(l.p.n) + 0.01 });
    l.el.firstChild.innerHTML = `<b>${esc(l.p.city || l.p.country || l.p.cc)}</b> · ${fmt(l.p.n)}`;
  }
  refreshHtml();
}

// the html layer holds the place labels and the impact tags; during a tour only the tags (the caption takes over)
let tags = [];
let touring = false;
function refreshHtml() { globe.htmlElementsData(touring || !showLabels ? tags : [...placeLabels, ...tags]); }
export function setTouring(on) {
  touring = on;
  refreshHtml();
}

// place names, in the settings popup
let showLabels = pref('tm.labels', 'on') !== 'off';
function setLabels(on) {
  showLabels = on;
  savePref('tm.labels', on ? 'on' : 'off');
  $('optLabels').checked = on;
  refreshHtml();
}
$('optLabels').onchange = (e) => setLabels(e.target.checked);
setLabels(showLabels);

function renderPlaces() {
  capPlaces();
  const ranked = [...points.entries()].sort((a, b) => b[1].n - a[1].n);
  drawBeams(ranked);
  drawPools(ranked);
  renderLabels(ranked);
}

let placeTicks = 0;
setInterval(() => {  // redraw on news, and every 6 s anyway so a beam hit a moment ago fades back from white
  if (document.hidden) return;
  if (pointsDirty || ++placeTicks % 4 === 0) {
    pointsDirty = false;
    renderPlaces();
  }
}, 1500);

/* ---------------------------------------------------------------- arcs and rings for each new event */

let arcs = [];
let rings = [];
const homeRing = { lat: S.home.lat, lon: S.home.lon, color: (t) => `rgba(255,255,255,${0.75 * (1 - t)})`, max: 4, speed: 1.6, period: 1500 };
const lastFx = new Map();

export function setHome(h) {
  if (!h) return;
  S.home = h;
  homeRing.lat = h.lat;
  homeRing.lon = h.lon;
  globe.ringsData([homeRing, ...rings]);
  placeShield();
}

function addArc(a, ms) {
  arcs.push(a);
  globe.arcsData(arcs);
  setTimeout(() => { arcs = arcs.filter((x) => x !== a); globe.arcsData(arcs); }, ms);
}

export function addRing(r, ms) {
  rings.push(r);
  globe.ringsData([homeRing, ...rings]);
  setTimeout(() => { rings = rings.filter((x) => x !== r); globe.ringsData([homeRing, ...rings]); }, ms);
}

const COMET_MS = 1400;  // a comet's flight from its source to the shield over home

export function effects(e) {
  const g = e.geo, home = S.home;
  const t = performance.now();
  const k = kindOf(e);
  if (k !== 'attack' && (lastFx.get(e.remote) || 0) > t - 1500) return;  // a port scan draws one arc, not twenty
  lastFx.set(e.remote, t);
  if (lastFx.size > 2000) lastFx.clear();
  const color = COLORS[k];

  if (arcs.length < 40) {
    if (e.way === 'out') {  // our own network going out: from home outward, and it never touches the shield
      addArc({ sLat: home.lat, sLon: home.lon, eLat: g.lat, eLon: g.lon, colors: [rgba(color, 0.1 * BEAM_K), rgba(color, BEAM_K)],
               stroke: 0.35, dl: 0.4, dg: 2, dig: 1, dt: 1300 }, 2600);
    } else {  // a threat: a comet with a white head that breaks on the shield over home
      addArc({ sLat: g.lat, sLon: g.lon, eLat: home.lat, eLon: home.lon, colors: [rgba(color, 0.05), rgba(color, 1), 'rgba(255,255,255,1)'],
               stroke: 0.75, dl: 0.07, dg: 4, dig: 1, dt: COMET_MS }, COMET_MS + 100);
      setTimeout(() => impact(e, color), COMET_MS - 20);
    }
  }
  addRing({ lat: g.lat, lon: g.lon, color: (k) => rgba(color, BEAM_K * (1 - k)), max: 2.2, speed: 2.6, period: 900 }, 1200);
}

let lastTag = 0;
function impact(e, color) {
  shieldHit(color);
  addRing({ lat: S.home.lat, lon: S.home.lon, color: (k) => rgba(color, 0.9 * (1 - k)), max: 6, speed: 9, period: 5000 }, 700);
  if (kindOf(e) === 'attack') hooks.ripple();
  const t = performance.now();
  if (t - lastTag < 1400 || document.hidden) return;  // one tag at a time, however busy it gets
  lastTag = t;
  const el = document.createElement('div');
  el.className = 'hittag';
  el.innerHTML = `<div style="background:${color}">${{ attack: 'ATTACK', ids: 'IDS' }[kindOf(e)] || 'BLOCKED'} · ${esc(e.svc)}</div>`;
  const tag = { lat: S.home.lat, lon: S.home.lon, h: 0.09, el };
  tags.push(tag);
  refreshHtml();
  setTimeout(() => { tags = tags.filter((x) => x !== tag); refreshHtml(); }, 1250);
}

/* ---------------------------------------------------------------- how sharp it is drawn */

// Device pixels per CSS pixel: globe.gl's own choice (the screen's, at most 2), or with Simplest at most 1.5, and 1 if
// it still runs slow (sky.js, watchFrameRate): on a 2x screen 44% fewer pixels a frame at 1.5, 75% fewer at 1, and the
// lines a little softer. native: globe.gl's choice, what the glow's width was set at.
export const render = { native: globe.renderer().getPixelRatio(), scale: globe.renderer().getPixelRatio() };
export function setRenderScale(pr) {
  render.scale = pr;
  globe.renderer().setPixelRatio(pr);
  globe.postProcessingComposer().setPixelRatio(pr);  // its pictures (and the glow's, setSize below) follow
}
if (SIMPLEST) setRenderScale(Math.min(render.native, 1.5));

/* ---------------------------------------------------------------- glow */

// glow: after each frame, light from the bright parts (beams, comets, coastlines) spreads into the dark around them.
// A real bloom: the bright parts are picked out at half size, blurred smoothly (a narrow glow at half size, a wide one
// at a quarter) and added onto the sharp frame. Sampling a ring of points around each pixel instead, as this did
// before, left faint offset copies of every thin line, and the globe looked out of focus.
export const glow = { pass: null };

function setupGlow() {
  const T = three();
  const composer = globe.postProcessingComposer();
  if (!T.ShaderPass || !composer.renderTarget1) return;
  const Target = composer.renderTarget1.constructor;
  const target = () => new Target(1, 1, { type: composer.renderTarget1.texture.type });
  const half = [target(), target()], quarter = [target(), target()];
  const step = (fs, uniforms) => new T.ShaderPass({ uniforms: { tDiffuse: { value: null }, ...uniforms }, vertexShader: GLOW_VS, fragmentShader: fs });
  const bright = step(BRIGHT_FS, { px: { value: [1, 1] }, threshold: { value: 0.32 } });
  const blur = step(BLUR_FS, { dir: { value: [0, 0] } });
  const add = step(GLOW_FS, { tNear: { value: null }, tFar: { value: null }, strength: { value: 1.3 } });
  add.uniforms.tNear.value = half[0].texture;  // set after: a pass copies its uniforms, and can't copy these
  add.uniforms.tFar.value = quarter[1].texture;
  // one axis, x/y in pixels of the target at the screen's own sharpness: drawn less sharp (render.scale), the steps
  // shrink with it, so the glow keeps its width on the screen
  const blurInto = (renderer, to, from, x, y) => {
    const k = render.scale / render.native;
    blur.uniforms.dir.value = [(x * k) / to.width, (y * k) / to.height];
    blur.render(renderer, to, from);
  };
  // a pass of our own for the globe's composer: the steps above, then the frame with its glow
  glow.pass = {
    enabled: true, needsSwap: true, clear: false, renderToScreen: false,
    setSize(w, h) {
      half.forEach((t) => t.setSize(Math.max(1, w >> 1), Math.max(1, h >> 1)));
      quarter.forEach((t) => t.setSize(Math.max(1, w >> 2), Math.max(1, h >> 2)));
    },
    render(renderer, writeBuffer, readBuffer) {
      bright.uniforms.px.value = [1 / readBuffer.width, 1 / readBuffer.height];
      bright.render(renderer, half[0], readBuffer);
      blurInto(renderer, half[1], half[0], 1, 0);
      blurInto(renderer, half[0], half[1], 0, 1);         // the narrow glow
      blurInto(renderer, quarter[0], half[0], 1, 0);
      blurInto(renderer, quarter[1], quarter[0], 0, 1);
      blurInto(renderer, quarter[0], quarter[1], 2, 0);
      blurInto(renderer, quarter[1], quarter[0], 0, 2);   // the wide one
      add.renderToScreen = this.renderToScreen;
      add.render(renderer, writeBuffer, readBuffer);
    },
    dispose() {
      [...half, ...quarter].forEach((t) => t.dispose());
      [bright, blur, add].forEach((p) => p.dispose());
    },
  };
  composer.addPass(glow.pass);
}

if (!query.has('lite')) setupGlow();  // ?glow keeps it on however slow the frames (sky.js, watchFrameRate)

// Simplest: the picture each frame is drawn into before the glow goes on, in 8-bit sRGB rather than three.js's half
// floats. 4 bytes a pixel instead of 8, written once and read twice a frame, and the same to the eye but for the very
// brightest spots, which stop at white. The glow's own steps, made above, stay in half floats.
if (SIMPLEST) {
  const composer = globe.postProcessingComposer(), old = composer.renderTarget1;
  composer.reset(new old.constructor(old.width, old.height, { type: 1009, colorSpace: 'srgb' }));  // UnsignedByteType
}

/* ---------------------------------------------------------------- shield */

// shield: a see-through dome over home with a glowing rim; it lights up in the colour of each threat that hits it
export const shield = { mesh: null, mat: null, V: null };

export function buildShield() {
  const T = three();
  if (!T.Mesh || !T.ShaderMaterial) return false;
  shield.V = T.Vector3;
  shield.mat = new T.ShaderMaterial({
    uniforms: { color: { value: [0.24, 0.88, 0.82] }, hit: { value: 0 }, time: { value: 0 }, dim: { value: 1 } },
    vertexShader: SHIELD_VS, fragmentShader: SHIELD_FS,
    transparent: true, depthWrite: false, blending: 2 /* additive */, side: 0 /* front */,
  });
  shield.mesh = new T.Mesh(new T.SphereGeometry(7, 48, 24, 0, Math.PI * 2, 0, Math.PI / 2), shield.mat);
  globe.scene().add(shield.mesh);
  placeShield();
  const tick = (ts) => {
    const u = shield.mat.uniforms;
    u.hit.value *= 0.93;
    // the bands come round every π seconds (time * 2 in the shader): the time goes back by a whole number of those, so
    // on a wall that runs for weeks it never grows past what a float on the graphics chip holds to the millisecond
    u.time.value = (ts / 1000) % (1000 * Math.PI);
    u.dim.value = glow.pass && glow.pass.enabled ? 0.75 : 1;  // the glow brightens it already
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  return true;
}

function placeShield() {
  if (!shield.mesh) return;
  const c = globe.getCoords(S.home.lat, S.home.lon, 0);
  shield.mesh.position.set(c.x, c.y, c.z);
  shield.mesh.quaternion.setFromUnitVectors(new shield.V(0, 1, 0), new shield.V(c.x, c.y, c.z).normalize());
}

function shieldHit(hex) {
  if (!shield.mat) return;
  shield.mat.uniforms.color.value = hexRgb(hex).map((v) => v / 255);
  shield.mat.uniforms.hit.value = 1;
}
