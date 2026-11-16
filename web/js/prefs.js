/* The settings popup, and what it remembers in this browser, so the wall and a laptop can differ. Each setting lives
   with what it sets: Graphics in sky.js, rotation speed and place names in globe.js, the tour in tour.js, the cards in
   panels.js. */
import { $ } from '../common.js';

// a remembered setting, or fallback; without storage (private mode, blocked) every setting has its default for the visit
export function pref(key, fallback, parse = (v) => v) {
  try {
    const v = localStorage.getItem(key);
    return v == null ? fallback : parse(v);
  } catch (e) {
    return fallback;
  }
}

export function savePref(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { /* not remembered, still works */ }
}

export const cap = (s) => `${s[0].toUpperCase()}${s.slice(1)}`;

// a row of choices in the popup (.times): one radio per value, named after its box
export function radios(id, values, label, onChange) {
  $(id).innerHTML = values.map((v) => `<label><input type="radio" name="${id}" value="${v}"><span>${label(v)}</span></label>`).join('');
  $(id).addEventListener('change', (e) => onChange(e.target.value));
}

// The gear by the globe's buttons opens the settings: Fancy, Simple or Simplest graphics, rotation speed, the cinematic tour
// and how often, place names, and which cards show.
const settings = (open) => { $('settings').hidden = !open; $('settingsBtn').setAttribute('aria-expanded', String(open)); };
$('settingsBtn').onclick = (e) => { e.stopPropagation(); settings($('settings').hidden); };
$('settingsClose').onclick = () => settings(false);
document.addEventListener('click', (e) => { if (!$('settings').hidden && !$('settings').contains(e.target)) settings(false); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') settings(false); });
