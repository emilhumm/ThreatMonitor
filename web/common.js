/* Helpers both pages use: the live wall (js/main.js) and the History page. */

export const $ = (id) => document.getElementById(id);
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const fmt = (n) => Math.round(n || 0).toLocaleString('en-US');

// the hover card (#tip) by the pointer, kept inside the window on both sides; gap: how far it sits above the pointer
export function showTip(ev, html, gap = 10) {
  const tip = $('tip');
  tip.innerHTML = html;
  tip.hidden = false;
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = `${Math.max(8, Math.min(innerWidth - w - 8, ev.clientX + 12))}px`;
  tip.style.top = `${Math.max(8, ev.clientY - h - gap)}px`;
}

export function hideTip() { $('tip').hidden = true; }
