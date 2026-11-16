/* What the wall's modules share: home, the server's clock and its latest stats, the connection, today's counts, and
   small helpers for times, colours and kinds of event. */

export const query = new URLSearchParams(location.search);  // ?lite, ?glow, ?inset
// ?inset=<px> (0-400): the cards start that much further in from the left, for a page shown with something laid over its
// left edge: Home Assistant's rail floats over the wall's left edge there (its ?inset keeps the cards 8 px from it). The starfield and the globe still
// fill the whole screen; the globe keeps to the middle of its column (globe.js fitGlobe), which moves right by half of it,
// and starts 15% further out (globe.js homeAltitude), as that column is narrower
export const INSET = Math.max(0, Math.min(400, parseInt(query.get('inset'), 10) || 0));
if (INSET) document.documentElement.style.setProperty('--inset-left', `${INSET}px`);
export const clock = (ts, opts) => new Date(ts * 1000).toLocaleTimeString('da-DK', opts);
export const COLORS = { block: '#3ee0d0', ids: '#ff5fd2', attack: '#ff4f6d', out: '#ffb454' };
// what an event shows as: a firewall block, an IDS alert, an attack the IDS recognised (red), or our own network going out
export const kindOf = (e) => (e.way === 'out' ? 'out' : e.kind === 'ids' && e.cat === 'attack' ? 'attack' : e.kind);
export const rgba = (hex, a) => {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
};

// home: where arcs land; serverOffset: the server's clock minus the browser's, ms; stats and feed: the server's
// latest (every 2 s); wsState: the connection
export const S = { home: { lat: 56, lon: 10.2, label: 'Home' }, serverOffset: 0, stats: null, feed: null, wsState: 'connecting' };
export const serverNow = () => (Date.now() + S.serverOffset) / 1000;
// today's knocks (each counted once: a firewall block and the IDS alerts for the same packet are one), and how many
// were blocked, flagged by the IDS, by a threat list or as an attack; and different addresses
export const live = { attempts: 0, blocked: 0, flagged: 0, listed: 0, attack: 0, unique: 0 };
export const GAIN = { attempts: 1, blocked: 2, flagged: 4, listed: 8, attack: 16 };  // what an event adds to its knock (knocks.py)
// the last hour's knocks per 10 s, [not flagged by the IDS, flagged] (panels.js); the sky's warmth reads them too
export const activity = { buckets: new Map() };

// ↻ tag for an address that was also here on earlier days (from the history database)
export const again = (seen) => {
  if (!seen) return '';
  const first = new Date(seen.first * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
  return ` <span class="again" title="Also seen on ${seen.days} earlier day${seen.days === 1 ? '' : 's'}, first on ${first}">↻ ${seen.days}d</span> `;
};

export const agoText = (s) => {
  s = Math.max(0, Math.round(s));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
};

export const NARROW = matchMedia('(max-width: 1100px)');  // the globe in its own box rather than under the whole page
export const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

// calls into a module that itself imports the caller (the globe stops a tour; an attack ripples the sky): the module
// that owns each sets it
export const hooks = { tourCancel() {}, ripple() {} };

// colours, from sRGB to the linear values the shaders work in
export const hexRgb = (hex) => { const n = parseInt(hex.slice(1), 16); return [n >> 16, (n >> 8) & 255, n & 255]; };
export const srgbLin = (c) => { c /= 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
export const lin = (rgb, a) => [srgbLin(rgb[0]), srgbLin(rgb[1]), srgbLin(rgb[2]), a];
export const linHex = (hex) => hexRgb(hex).map(srgbLin);
