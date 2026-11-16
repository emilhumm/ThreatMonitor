/* The shaders: GLSL for the graphics chip, as strings for three.js's ShaderMaterial and ShaderPass. */

// beams (globe.js): every beam and halo in one mesh, each vertex with its own colour
export const BEAM_VS = 'attribute vec4 tint; varying vec4 vTint; void main() { vTint = tint; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }';
export const BEAM_FS = `varying vec4 vTint;
void main() {
  gl_FragColor = vTint;
  #include <colorspace_fragment>
}`;

// pools of light (globe.js): a flat square per place, rounded off here
export const POOL_VS = 'attribute vec2 corner; attribute vec4 tint; varying vec2 vC; varying vec4 vTint; void main() { vC = corner; vTint = tint; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }';
export const POOL_FS = `varying vec2 vC; varying vec4 vTint;
void main() {
  float r = length(vC);
  gl_FragColor = vec4(vTint.rgb, vTint.a * (exp(-r * r * 18.0) + 0.35 * exp(-r * r * 4.0)) * (1.0 - smoothstep(0.85, 1.0, r)));
  #include <colorspace_fragment>
}`;

// the glow (globe.js), a pass after each frame
export const GLOW_VS = 'varying vec2 vUv; void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }';
// each half-size pixel takes the four full-size ones under it, each through the threshold (a thin line stays bright)
export const BRIGHT_FS = `
uniform sampler2D tDiffuse; uniform vec2 px; uniform float threshold; varying vec2 vUv;
vec3 bright(vec2 uv) { vec4 c = texture2D(tDiffuse, uv); float l = max(c.r, max(c.g, c.b)); return c.rgb * smoothstep(threshold, threshold + 0.3, l); }
void main() {
  vec2 d = px * 0.5;
  gl_FragColor = vec4((bright(vUv - d) + bright(vUv + d) + bright(vUv + vec2(d.x, -d.y)) + bright(vUv + vec2(-d.x, d.y))) * 0.25, 1.0);
}`;
// a 9-tap Gaussian along one axis in five lookups (the GPU's own filtering blends each pair of taps)
export const BLUR_FS = `
uniform sampler2D tDiffuse; uniform vec2 dir; varying vec2 vUv;
void main() {
  vec3 c = texture2D(tDiffuse, vUv).rgb * 0.2270270270;
  c += (texture2D(tDiffuse, vUv + dir * 1.3846153846).rgb + texture2D(tDiffuse, vUv - dir * 1.3846153846).rgb) * 0.3162162162;
  c += (texture2D(tDiffuse, vUv + dir * 3.2307692308).rgb + texture2D(tDiffuse, vUv - dir * 3.2307692308).rgb) * 0.0702702703;
  gl_FragColor = vec4(c, 1.0);
}`;
export const GLOW_FS = `
uniform sampler2D tDiffuse; uniform sampler2D tNear; uniform sampler2D tFar; uniform float strength; varying vec2 vUv;
void main() {
  vec4 base = texture2D(tDiffuse, vUv);
  vec3 glow = (texture2D(tNear, vUv).rgb * 0.7 + texture2D(tFar, vUv).rgb * 0.4) * strength;
  float alpha = clamp(max(base.a, max(glow.r, max(glow.g, glow.b))), 0.0, 1.0);
  gl_FragColor = vec4(base.rgb + glow, alpha);
  #include <colorspace_fragment>
  gl_FragColor.rgb += (fract(sin(dot(gl_FragCoord.xy, vec2(12.9898, 78.233))) * 43758.5453) - 0.5) / 255.0 * gl_FragColor.a;  // a touch of dither: dark gradients without bands
}`;

// the shield over home (globe.js)
export const SHIELD_VS = `varying vec3 vN; varying vec3 vV; varying float vH;
void main() { vec4 mv = modelViewMatrix * vec4(position, 1.0); vN = normalize(normalMatrix * normal); vV = normalize(-mv.xyz); vH = position.y; gl_Position = projectionMatrix * mv; }`;
export const SHIELD_FS = `uniform vec3 color; uniform float hit; uniform float time; uniform float dim; varying vec3 vN; varying vec3 vV; varying float vH;
void main() {
  float rim = pow(1.0 - abs(dot(normalize(vN), normalize(vV))), 2.0);
  float bands = 0.5 + 0.5 * sin(vH * 3.2 - time * 2.0);
  float a = (0.02 + rim * 0.32 + bands * 0.02 + hit * (0.12 + rim * 0.55)) * dim;
  gl_FragColor = vec4(color * (0.45 + hit * 1.1), a);
}`;

// The Milky Way, painted once into a picture of the whole sky in the galaxy's own coordinates (its band along the
// middle, its centre in the middle). Four fields, not colours, so the sky can recolour itself every frame for free:
// r = glowing gas, g = dark dust lanes, b = which tint, a = faint wisps over the whole sky. It is painted a strip a
// frame (skyTick, sky.js): in one go, at 2048 x 1024, it kept an Intel HD 530 busy for up to half a second, and Windows
// resets the graphics driver (the page loses its globe to a white sheet) when one job runs past 2 s.
export const BAKE_FS = `varying vec2 vUv;
float sq(float x) { return x * x; }
float hash(vec3 p) { p = fract(p * 0.3183099 + vec3(0.71, 0.113, 0.419)); p *= 17.0; return fract(p.x * p.y * p.z * (p.x + p.y + p.z)); }
float vnoise(vec3 x) {
  vec3 i = floor(x), f = fract(x); f = f * f * (3.0 - 2.0 * f);
  return mix(mix(mix(hash(i), hash(i + vec3(1.0, 0.0, 0.0)), f.x), mix(hash(i + vec3(0.0, 1.0, 0.0)), hash(i + vec3(1.0, 1.0, 0.0)), f.x), f.y),
             mix(mix(hash(i + vec3(0.0, 0.0, 1.0)), hash(i + vec3(1.0, 0.0, 1.0)), f.x), mix(hash(i + vec3(0.0, 1.0, 1.0)), hash(i + vec3(1.0, 1.0, 1.0)), f.x), f.y), f.z);
}
float fbm(vec3 p) { float s = 0.0, a = 0.5; for (int i = 0; i < 6; i++) { s += a * vnoise(p); p = p * 2.03 + vec3(1.7, 9.2, 3.1); a *= 0.5; } return s; }
void main() {
  float l = (vUv.x - 0.5) * 6.2831853, b = (vUv.y - 0.5) * 3.1415927;
  vec3 d = vec3(cos(b) * cos(l), cos(b) * sin(l), sin(b));
  vec3 q = d * 2.4;
  vec3 w = vec3(fbm(q + vec3(3.1, 0.0, 0.0)), fbm(q + vec3(0.0, 5.2, 1.3)), fbm(q + vec3(7.7, 2.1, 0.0)));
  float cloud = fbm(q * 1.7 + w * 2.2);
  float bd = degrees(b), ld = degrees(l);
  float width = 6.0 + 8.0 * fbm(d * 3.0 + 11.0);
  float c2 = sq(cos(l * 0.5));
  float band = exp(-sq(bd / width)) * (0.3 + 0.7 * c2);
  float bulge = exp(-sq(ld / 32.0) - sq(bd / 11.0));
  float dens = (band + 0.9 * bulge) * smoothstep(0.26, 0.74, cloud) * 1.6;
  float lane = exp(-sq((bd - 2.0 * sin(l * 1.7)) / 2.8)) * (0.35 + 0.65 * c2);
  float dust = lane * smoothstep(0.38, 0.62, fbm(q * 3.4 + w * 1.5 + 20.0));
  float hue = smoothstep(0.3, 0.7, fbm(q * 1.1 + w + 40.0));
  float wisp = smoothstep(0.5, 0.88, fbm(q * 1.4 + w * 2.6 + 60.0));
  gl_FragColor = vec4(dens, dust, hue, wisp);
}`;

// the sky: a sphere at infinite distance, drawn before everything else (it turns with the camera, never comes closer)
export const SKY_VS = `varying vec3 vDir;
void main() {
  vDir = position;
  vec4 p = projectionMatrix * (modelViewMatrix * vec4(position, 0.0));
  gl_Position = vec4(p.xy, p.w * 0.99999, p.w);
}`;
export const SKY_FS = `uniform sampler2D tNeb; uniform vec3 gX; uniform vec3 gY; uniform vec3 gZ; uniform vec3 sunSky; uniform vec2 res;
uniform float warm; uniform float edge; uniform vec4 ripple; uniform float milky; uniform float sunOn;
uniform vec3 bgA; uniform vec3 bgB; uniform vec3 hotA; uniform vec3 hotB;
uniform vec3 cBlue; uniform vec3 cTeal; uniform vec3 cViolet; uniform vec3 hMag; uniform vec3 hRed; uniform vec3 ripCol; uniform vec3 sunCol;
varying vec3 vDir;
float sq(float x) { return x * x; }
void main() {
  vec3 d = normalize(vDir);
  vec2 uv = gl_FragCoord.xy / res;
  float t = clamp(length((uv - vec2(0.55, 0.55)) / 0.778) / 0.62, 0.0, 1.0);  // the page's own glow, as the style sheet draws it
  vec3 col = mix(mix(bgA, hotA, warm * 0.8), mix(bgB, hotB, warm * 0.8), t);
  if (milky > 0.0) {
    float l = atan(dot(d, gY), dot(d, gX)), b = asin(clamp(dot(d, gZ), -1.0, 1.0));
    vec4 n = texture2D(tNeb, vec2(l / 6.2831853 + 0.5, b / 3.1415927 + 0.5));
    vec3 calm = mix(mix(cBlue, cTeal, n.b), cViolet, clamp(n.r - 0.7, 0.0, 1.0) * 0.6);
    vec3 nc = mix(calm, mix(hMag, hRed, n.b), warm);
    float neb = n.r * (1.0 - 0.85 * n.g);
    col += milky * (nc * (neb * (0.22 + 0.1 * warm) + n.a * (0.055 + 0.03 * warm)) + vec3(0.8, 0.82, 1.0) * sq(max(neb - 0.95, 0.0)) * 0.05);
  }
  if (sunOn > 0.0) {  // the sun, about its real size, and its glare
    float cs = max(dot(d, sunSky), 0.0);
    col += sunOn * sunCol * (pow(cs, 40000.0) * 9.0 + pow(cs, 160.0) * 0.22 + pow(cs, 14.0) * 0.022);
  }
  if (ripple.w > 0.0) {
    float dist = length((gl_FragCoord.xy - ripple.xy) / res.y), wd = 0.02 + 0.05 * ripple.z;
    col += ripCol * exp(-sq((dist - ripple.z * 0.55) / wd)) * exp(-ripple.z * 0.9) * ripple.w * 0.11;
  }
  vec2 e = min(gl_FragCoord.xy, res - gl_FragCoord.xy) / res.y;
  float a = mix(1.0, smoothstep(0.0, 0.12, min(e.x, e.y)), edge);  // a narrow screen: fade into the page at the globe's edges
  gl_FragColor = vec4(col * a, a);
  #include <colorspace_fragment>
}`;

// stars: small squares that always face the screen, a few pixels across whatever the zoom
export const STAR_VS = `attribute vec2 corner; attribute vec4 info; attribute vec3 tint; attribute float band;
uniform vec2 res; uniform float dpr; uniform float time; uniform float edge; uniform vec4 ripple; uniform float milky;
varying vec2 vC; varying vec3 vCol;
float sq(float x) { return x * x; }
void main() {
  vC = corner;
  vec4 p = projectionMatrix * (modelViewMatrix * vec4(position, 0.0));
  float a = info.y * (1.0 + 0.3 * sin(time * info.z + info.w) * step(0.001, info.z)) * mix(1.0, milky, band);
  if (p.w <= 0.0 || a < 0.002) { gl_Position = vec4(0.0, 0.0, 2.0, 1.0); vCol = vec3(0.0); return; }
  vec2 px = (p.xy / p.w * 0.5 + 0.5) * res;
  if (ripple.w > 0.0) {  // the shock front pushes the stars outward for a moment and lights them up
    vec2 dv = (px - ripple.xy) / res.y;
    float dist = length(dv), wd = 0.02 + 0.05 * ripple.z;
    float k = exp(-sq((dist - ripple.z * 0.55) / wd)) * exp(-ripple.z * 0.9) * ripple.w;
    px += dv / max(dist, 1e-4) * k * 18.0 * dpr;
    a *= 1.0 + 3.0 * k;
  }
  vec2 e = min(px, res - px) / res.y;
  a *= mix(1.0, smoothstep(0.0, 0.12, min(e.x, e.y)), edge);
  px += corner * info.x * dpr;
  gl_Position = vec4(px / res * 2.0 - 1.0, 0.99999, 1.0);
  vCol = tint * a;
}`;
export const STAR_FS = `varying vec2 vC; varying vec3 vCol;
void main() {
  float r2 = dot(vC, vC);
  float g = (exp(-r2 * 7.0) + 0.12 * exp(-r2 * 1.6)) * max(1.0 - r2, 0.0);
  gl_FragColor = vec4(vCol * g, 1.0);
  #include <colorspace_fragment>
  // light added, covering what lies behind the page only as much as it shines (sky.js: premultiplied): a whole square
  // of cover showed as a dark speck where the page's own background shows through (a phone's globe box)
  gl_FragColor.a = max(gl_FragColor.r, max(gl_FragColor.g, gl_FragColor.b));
}`;

// The sunlit edge. Outer shell: for each line of sight past the globe, how close it comes to the ground sets how much
// air it crosses (a thin layer, thinning out with height), lit where the sun is up there and brightest looking
// towards the sun. Inner shell: the same air seen over the edge of the globe itself, and the day side a shade lighter.
export const LIMB_VS = `varying vec3 vW;
void main() { vec4 w = modelMatrix * vec4(position, 1.0); vW = w.xyz; gl_Position = projectionMatrix * viewMatrix * w; }`;
export const LIMB_OUT_FS = `uniform vec3 sunDir; uniform vec3 cAir; uniform vec3 cWarm; uniform float R; uniform float H; uniform float on;
varying vec3 vW;
void main() {
  vec3 dir = normalize(vW - cameraPosition);
  vec3 q = cameraPosition + dir * max(-dot(cameraPosition, dir), 0.0);
  float h = length(q);
  float s = dot(q / h, sunDir);
  float fwd = pow(max(dot(dir, sunDir), 0.0), 5.0);
  vec3 c = mix(cWarm, cAir, smoothstep(-0.12, 0.35, s));
  gl_FragColor = vec4(c * exp(-max(h - R, 0.0) / H) * smoothstep(-0.28, 0.25, s) * (0.32 + 2.8 * fwd) * on, 1.0);
  #include <colorspace_fragment>
  // light added, covering what lies behind the page only as much as it shines (sky.js: premultiplied): full cover made
  // a dark ring round the globe where the page's own background shows through (a phone's globe box), as with the stars
  gl_FragColor.a = max(gl_FragColor.r, max(gl_FragColor.g, gl_FragColor.b));
}`;
export const LIMB_IN_FS = `uniform vec3 sunDir; uniform vec3 cAir; uniform vec3 cWarm; uniform float on;
varying vec3 vW;
void main() {
  vec3 n = normalize(vW), v = normalize(cameraPosition - vW);
  float rim = pow(1.0 - max(dot(n, v), 0.0), 5.0);
  float s = dot(n, sunDir);
  vec3 c = mix(cWarm, cAir, smoothstep(-0.05, 0.3, s));
  gl_FragColor = vec4(c * (rim * smoothstep(-0.15, 0.3, s) * 0.9 + smoothstep(-0.05, 0.35, s) * 0.006) * on, 1.0);
  #include <colorspace_fragment>
  gl_FragColor.a = max(gl_FragColor.r, max(gl_FragColor.g, gl_FragColor.b));  // as the outer shell's
}`;
