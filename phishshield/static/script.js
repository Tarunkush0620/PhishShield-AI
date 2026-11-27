/* PhishShield AI — Frontend v3 (GSAP + AOS + Lottie Edition)
    */

//  AOS Init 
document.addEventListener("DOMContentLoaded", () => {
  if (typeof AOS !== "undefined") {
    AOS.init({ duration: 600, easing: "cubic-bezier(.4,0,.2,1)", once: true, offset: 40 });
  }
  initEntryAnimation();
  initCyberBackground();
  initContainerScroll();
  initInteractiveGlobe();
  initRippleButtons();
  renderURLHistory();
  renderEmailHistory();
  fetchStats();
  fetchDashboard();
  setInterval(fetchStats, 10000);
  setInterval(fetchDashboard, 20000);
  const fastPoll = setInterval(fetchStats, 500); // fast poll first 3s
  setTimeout(() => clearInterval(fastPoll), 3000);
});

// 
// ENTRY ANIMATIONS (GSAP)
// 
function initEntryAnimation() {
  if (typeof gsap === "undefined") return;

  // Fade in the whole page
  gsap.fromTo("body", { opacity: 0 }, { opacity: 1, duration: .5, ease: "power2.out" });

  // Logo pulse
  gsap.fromTo("#logo", { opacity: 0, scale: .85 }, { opacity: 1, scale: 1, duration: .7, ease: "back.out(1.5)", delay: .1 });

  // Header stats slide down
  gsap.fromTo("#header-stats .hstat", { opacity: 0, y: -20 }, { opacity: 1, y: 0, duration: .5, stagger: .12, ease: "power2.out", delay: .3 });

  // Tab bar slide in from left
  gsap.fromTo("#tab-bar .tab-btn", { opacity: 0, x: -24 }, { opacity: 1, x: 0, duration: .45, stagger: .1, ease: "power2.out", delay: .45 });

  // How-it-works
  gsap.fromTo(".hiw-step", { opacity: 0, y: 18 }, { opacity: 1, y: 0, duration: .5, stagger: .15, ease: "power2.out", delay: .5 });
}

// 
// CYBER BACKGROUND — THREE.JS AURORA SHADER
// 
function initCyberBackground() {
  const canvas = document.getElementById("cyber-canvas");
  if (!canvas || typeof THREE === "undefined") return;

  const scene    = new THREE.Scene();
  const camera   = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  renderer.setSize(window.innerWidth, window.innerHeight);

  const material = new THREE.ShaderMaterial({
    uniforms: {
      iTime:       { value: 0 },
      iResolution: { value: new THREE.Vector2(window.innerWidth, window.innerHeight) }
    },
    vertexShader: `
      void main() {
        gl_Position = vec4(position, 1.0);
      }
    `,
    fragmentShader: `
      uniform float iTime;
      uniform vec2  iResolution;

      #define NUM_OCTAVES 3

      float rand(vec2 n) {
        return fract(sin(dot(n, vec2(12.9898, 4.1414))) * 43758.5453);
      }

      float noise(vec2 p) {
        vec2 ip = floor(p);
        vec2 u  = fract(p);
        u = u * u * (3.0 - 2.0 * u);
        float res = mix(
          mix(rand(ip),              rand(ip + vec2(1.0, 0.0)), u.x),
          mix(rand(ip + vec2(0.0,1.0)), rand(ip + vec2(1.0,1.0)), u.x), u.y
        );
        return res * res;
      }

      float fbm(vec2 x) {
        float v = 0.0;
        float a = 0.3;
        vec2  shift = vec2(100.0);
        mat2  rot   = mat2(cos(0.5), sin(0.5), -sin(0.5), cos(0.5));
        for (int i = 0; i < NUM_OCTAVES; ++i) {
          v  += a * noise(x);
          x   = rot * x * 2.0 + shift;
          a  *= 0.4;
        }
        return v;
      }

      void main() {
        vec2 shake = vec2(sin(iTime * 1.2) * 0.005, cos(iTime * 2.1) * 0.005);
        vec2 p = ((gl_FragCoord.xy + shake * iResolution.xy) - iResolution.xy * 0.5)
                 / iResolution.y * mat2(6.0, -4.0, 4.0, 6.0);
        vec2 v;
        vec4 o = vec4(0.0);

        float f = 2.0 + fbm(p + vec2(iTime * 5.0, 0.0)) * 0.5;

        for (float i = 0.0; i < 35.0; i++) {
          v = p + cos(i * i + (iTime + p.x * 0.08) * 0.025 + i * vec2(13.0, 11.0)) * 3.5
              + vec2(sin(iTime * 3.0 + i) * 0.003, cos(iTime * 3.5 - i) * 0.003);

          float tailNoise = fbm(v + vec2(iTime * 0.5, i)) * 0.3 * (1.0 - (i / 35.0));

          vec4 auroraColors = vec4(
            0.4 + 0.2 * sin(i * 0.2 + iTime * 0.4),
            0.4 + 0.2 * cos(i * 0.3 + iTime * 0.5),
            0.4 + 0.2 * sin(i * 0.4 + iTime * 0.3),
            1.0
          );

          vec4 contrib = auroraColors
            * exp(sin(i * i + iTime * 0.8))
            / length(max(v, vec2(v.x * f * 0.015, v.y * 1.5)));

          float thinness = smoothstep(0.0, 1.0, i / 35.0) * 0.6;
          o += contrib * (1.0 + tailNoise * 0.8) * thinness;
        }

        /* tone-map and darken so UI remains readable */
        o = tanh(pow(o / 100.0, vec4(1.6)));
        gl_FragColor = o * 0.45;
      }
    `
  });

  const geometry = new THREE.PlaneGeometry(2, 2);
  scene.add(new THREE.Mesh(geometry, material));

  let frameId;
  const tick = () => {
    material.uniforms.iTime.value += 0.016;
    renderer.render(scene, camera);
    frameId = requestAnimationFrame(tick);
  };
  tick();

  window.addEventListener("resize", () => {
    renderer.setSize(window.innerWidth, window.innerHeight);
    material.uniforms.iResolution.value.set(window.innerWidth, window.innerHeight);
  });

  // Pause when tab hidden to save GPU
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) cancelAnimationFrame(frameId);
    else tick();
  });
}

// 
// INTERACTIVE GLOBE — port of interactive-globe.tsx (React → vanilla Canvas 2D)
// Fibonacci sphere dots + quadratic arc connections + drag rotation + pulse markers
// 
function initInteractiveGlobe() {
  const canvas = document.getElementById("threat-globe");
  if (!canvas) return;

  // ── helpers ──────────────────────────────────────────────────────────────
  function latLngToXYZ(lat, lng, r) {
    const phi   = ((90 - lat) * Math.PI) / 180;
    const theta = ((lng + 180) * Math.PI) / 180;
    return [-(r * Math.sin(phi) * Math.cos(theta)),
              r * Math.cos(phi),
              r * Math.sin(phi) * Math.sin(theta)];
  }
  function rotY(x, y, z, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [x*c + z*s, y, -x*s + z*c];
  }
  function rotX(x, y, z, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [x, y*c - z*s, y*s + z*c];
  }
  function proj(x, y, z, cx, cy, fov) {
    const sc = fov / (fov + z);
    return [x*sc + cx, y*sc + cy, z];
  }

  // ── data (phishing threat hotspots) ──────────────────────────────────────
  const MARKERS = [
    { lat: 37.78,  lng: -122.42, label: "San Francisco" },
    { lat: 51.51,  lng:   -0.13, label: "London" },
    { lat: 35.68,  lng:  139.69, label: "Tokyo" },
    { lat: -33.87, lng:  151.21, label: "Sydney" },
    { lat:  1.35,  lng:  103.82, label: "Singapore" },
    { lat: 55.76,  lng:   37.62, label: "Moscow" },
    { lat: -23.55, lng:  -46.63, label: "São Paulo" },
    { lat: 19.43,  lng:  -99.13, label: "Mexico City" },
    { lat: 28.61,  lng:   77.21, label: "Delhi" },
    { lat: 36.19,  lng:   44.01, label: "Erbil" },
  ];
  const CONNECTIONS = [
    { from: [37.78,-122.42], to: [51.51,-0.13] },
    { from: [51.51,-0.13],   to: [35.68,139.69] },
    { from: [35.68,139.69],  to: [-33.87,151.21] },
    { from: [37.78,-122.42], to: [1.35,103.82] },
    { from: [51.51,-0.13],   to: [28.61,77.21] },
    { from: [37.78,-122.42], to: [-23.55,-46.63] },
    { from: [1.35,103.82],   to: [-33.87,151.21] },
    { from: [28.61,77.21],   to: [36.19,44.01] },
    { from: [51.51,-0.13],   to: [36.19,44.01] },
  ];

  // ── Fibonacci sphere dots ─────────────────────────────────────────────────
  const DOTS = [];
  const phi0 = (1 + Math.sqrt(5)) / 2;
  for (let i = 0; i < 1200; i++) {
    const theta = (2 * Math.PI * i) / phi0;
    const phi   = Math.acos(1 - (2 * (i + 0.5)) / 1200);
    DOTS.push([Math.cos(theta)*Math.sin(phi),
               Math.cos(phi),
               Math.sin(theta)*Math.sin(phi)]);
  }

  // ── state ─────────────────────────────────────────────────────────────────
  let rotYaw = 0.4, rotPitch = 0.3, time = 0, frame;
  let drag = { active: false, sx: 0, sy: 0, sy0: 0, sp0: 0 };

  // ── render ────────────────────────────────────────────────────────────────
  function draw() {
    const dpr = window.devicePixelRatio || 1;
    const w   = canvas.clientWidth;
    const h   = canvas.clientHeight;
    canvas.width  = w * dpr;
    canvas.height = h * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    const cx = w / 2, cy = h / 2;
    const R  = Math.min(w, h) * 0.38;
    const fov = 600;

    if (!drag.active) rotYaw += 0.002;
    time += 0.015;

    ctx.clearRect(0, 0, w, h);

    // outer glow
    const glow = ctx.createRadialGradient(cx, cy, R*0.8, cx, cy, R*1.5);
    glow.addColorStop(0, "rgba(255,255,255,.025)");
    glow.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, w, h);

    // globe outline
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI*2);
    ctx.strokeStyle = "rgba(255,255,255,.05)";
    ctx.lineWidth = 1; ctx.stroke();

    // dots
    for (const d of DOTS) {
      let [x,y,z] = [d[0]*R, d[1]*R, d[2]*R];
      [x,y,z] = rotX(x,y,z,rotPitch);
      [x,y,z] = rotY(x,y,z,rotYaw);
      if (z > 0) continue;
      const [sx,sy] = proj(x,y,z,cx,cy,fov);
      const alpha = Math.max(0.1, 1 - (z+R)/(2*R));
      ctx.beginPath();
      ctx.arc(sx, sy, 1 + alpha*0.8, 0, Math.PI*2);
      ctx.fillStyle = `rgba(200,200,200,${alpha.toFixed(2)})`;
      ctx.fill();
    }

    // arcs + traveling dots
    for (const conn of CONNECTIONS) {
      let [x1,y1,z1] = latLngToXYZ(conn.from[0], conn.from[1], R);
      let [x2,y2,z2] = latLngToXYZ(conn.to[0],   conn.to[1],   R);
      [x1,y1,z1] = rotX(x1,y1,z1,rotPitch); [x1,y1,z1] = rotY(x1,y1,z1,rotYaw);
      [x2,y2,z2] = rotX(x2,y2,z2,rotPitch); [x2,y2,z2] = rotY(x2,y2,z2,rotYaw);
      if (z1 > R*0.3 && z2 > R*0.3) continue;
      const [sx1,sy1] = proj(x1,y1,z1,cx,cy,fov);
      const [sx2,sy2] = proj(x2,y2,z2,cx,cy,fov);

      // elevated midpoint
      const mx=( x1+x2)/2, my=(y1+y2)/2, mz=(z1+z2)/2;
      const ml = Math.sqrt(mx*mx+my*my+mz*mz);
      const ah = R * 1.25;
      const [scx,scy] = proj((mx/ml)*ah,(my/ml)*ah,(mz/ml)*ah,cx,cy,fov);

      ctx.beginPath(); ctx.moveTo(sx1,sy1);
      ctx.quadraticCurveTo(scx,scy,sx2,sy2);
      ctx.strokeStyle = "rgba(200,200,200,.35)";
      ctx.lineWidth = 1.2; ctx.stroke();

      // traveling dot
      const t = (Math.sin(time*1.2 + conn.from[0]*0.1) + 1) / 2;
      const tx = (1-t)*(1-t)*sx1 + 2*(1-t)*t*scx + t*t*sx2;
      const ty = (1-t)*(1-t)*sy1 + 2*(1-t)*t*scy + t*t*sy2;
      ctx.beginPath(); ctx.arc(tx,ty,2,0,Math.PI*2);
      ctx.fillStyle = "rgba(255,255,255,1)"; ctx.fill();
    }

    // markers
    for (const m of MARKERS) {
      let [x,y,z] = latLngToXYZ(m.lat, m.lng, R);
      [x,y,z] = rotX(x,y,z,rotPitch); [x,y,z] = rotY(x,y,z,rotYaw);
      if (z > R*0.1) continue;
      const [sx,sy] = proj(x,y,z,cx,cy,fov);
      const pulse = Math.sin(time*2 + m.lat)*0.5 + 0.5;

      ctx.beginPath(); ctx.arc(sx,sy, 4+pulse*4, 0, Math.PI*2);
      ctx.strokeStyle = `rgba(220,220,220,${(0.15+pulse*0.12).toFixed(2)})`;
      ctx.lineWidth = 1; ctx.stroke();

      ctx.beginPath(); ctx.arc(sx,sy,2.5,0,Math.PI*2);
      ctx.fillStyle = "rgba(240,240,240,1)"; ctx.fill();

      if (m.label) {
        ctx.font = "10px system-ui,sans-serif";
        ctx.fillStyle = "rgba(200,200,200,.6)";
        ctx.fillText(m.label, sx+8, sy+3);
      }
    }

    frame = requestAnimationFrame(draw);
  }

  frame = requestAnimationFrame(draw);

  // ── drag interaction ──────────────────────────────────────────────────────
  canvas.addEventListener("pointerdown", e => {
    drag = { active: true, sx: e.clientX, sy: e.clientY,
             sy0: rotYaw, sp0: rotPitch };
    canvas.setPointerCapture(e.pointerId);
  });
  canvas.addEventListener("pointermove", e => {
    if (!drag.active) return;
    rotYaw   = drag.sy0 + (e.clientX - drag.sx) * 0.005;
    rotPitch = Math.max(-1, Math.min(1, drag.sp0 + (e.clientY - drag.sy) * 0.005));
  });
  canvas.addEventListener("pointerup",  () => { drag.active = false; });

  // pause when hidden
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) cancelAnimationFrame(frame);
    else { frame = requestAnimationFrame(draw); }
  });
}

// 
// CONTAINER SCROLL ANIMATION
//   rotateX: 20→0  |  scale: 1.05→1 (desktop) 0.7→0.9 (mobile)  |  titleY: 0→-100px
// 
function initContainerScroll() {
  const section = document.getElementById("scroll-hero");
  const card    = document.getElementById("scroll-card");
  const title   = document.getElementById("scroll-title");
  if (!section || !card || !title) return;

  const mobile = () => window.innerWidth <= 768;

  const update = () => {
    const viewH      = window.innerHeight;
    const sectionTop = section.getBoundingClientRect().top + window.scrollY;
    const scrolled   = window.scrollY - sectionTop;           // px scrolled past section start
    const scrollRange = section.offsetHeight - viewH;         // total scrollable range within section

    // progress: 0 when section just entered, 1 when fully scrolled through
    const progress = scrollRange > 0
      ? Math.max(0, Math.min(1, scrolled / scrollRange))
      : 0;

    const scaleFrom = mobile() ? 0.7  : 1.05;
    const scaleTo   = mobile() ? 0.9  : 1.0;

    const rotateX = (20 * (1 - progress)).toFixed(2);           // 20 → 0
    const scale   = (scaleFrom + (scaleTo - scaleFrom) * progress).toFixed(4);
    const tY      = (-100 * progress).toFixed(1);               // 0 → -100px

    card.style.transform  = `rotateX(${rotateX}deg) scale(${scale})`;
    title.style.transform = `translateY(${tY}px)`;
  };

  window.addEventListener("scroll", update, { passive: true });
  window.addEventListener("resize", update, { passive: true });
  update();
}

// 
// RIPPLE BUTTON EFFECT
// 
function initRippleButtons() {
  document.querySelectorAll(".ripple-btn").forEach(btn => {
    btn.addEventListener("click", function(e) {
      const r = document.createElement("span");
      r.className = "ripple";
      const rect = this.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      r.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - rect.left - size/2}px;top:${e.clientY - rect.top - size/2}px;`;
      this.appendChild(r);
      setTimeout(() => r.remove(), 600);
    });
  });
}

// 
// 
// SCROLL NAV — sticky tab bar scrolls to sections + highlights active
// 
const TAB_ORDER = ["url", "email", "risk", "full", "dashboard"];

// Click → smooth scroll to section
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const target = document.getElementById("tab-" + btn.dataset.tab);
    if (!target) return;
    const NAV_H = 72;
    const top = target.getBoundingClientRect().top + window.scrollY - NAV_H;
    window.scrollTo({ top, behavior: "smooth" });
  });
});

// IntersectionObserver: reveal on enter + highlight nav
const _scrollSections = document.querySelectorAll(".scroll-section");
const _sectionObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add("in-view");
      // Highlight matching nav button
      const id = entry.target.id.replace("tab-", "");
      document.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === id);
      });
    }
  });
}, { threshold: 0.12, rootMargin: "-70px 0px -35% 0px" });

_scrollSections.forEach(s => _sectionObserver.observe(s));

// 
// FULLSCREEN LOADER
// 
function showLoader() { document.getElementById("loader").classList.remove("hidden"); }
function hideLoader() { document.getElementById("loader").classList.add("hidden"); }

// 
// SKELETON SHIMMER
// 
function showSkeleton(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = `
    <div class="skel skel-title"></div>
    <div class="skel skel-bar"></div>
    <div class="skel-grid">
      <div class="skel skel-cell"></div><div class="skel skel-cell"></div>
      <div class="skel skel-cell"></div><div class="skel skel-cell"></div>
    </div>`;
  el.classList.remove("hidden");
}
function hideSkeleton(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add("hidden");
}

// 
// TOAST NOTIFICATIONS
// 
function toast(msg, type = "info") {
  const icons = { success: "", error: "", info: "ℹ", warning: "" };
  const area = document.getElementById("toast-area");
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.innerHTML = `
    <span class="toast-icon">${icons[type] || "ℹ"}</span>
    <span class="toast-msg">${escHtml(msg)}</span>
    <button class="toast-close" onclick="this.closest('.toast').remove()"></button>`;
  area.appendChild(el);
  if (typeof gsap !== "undefined") {
    gsap.fromTo(el, { opacity: 0, x: 30 }, { opacity: 1, x: 0, duration: .28, ease: "power2.out" });
  }
  setTimeout(() => {
    if (typeof gsap !== "undefined") {
      gsap.to(el, { opacity: 0, x: 30, duration: .25, ease: "power2.in", onComplete: () => el.remove() });
    } else {
      el.style.animation = "toastOut .3s ease forwards";
      setTimeout(() => el.remove(), 300);
    }
  }, 3500);
}

// 
// HTTP HELPERS
// 
async function post(endpoint, payload) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}
async function get(endpoint) {
  const res = await fetch(endpoint);
  return res.json();
}

// 
// COLOUR / THREAT HELPERS
// 
function _setRiskSourceLabel(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value || "Waiting for scan";
}

function refreshRiskSources(data) {
  const url = data?.sources?.url;
    const email = data?.sources?.email;
    _setRiskSourceLabel("risk-src-url", url ? `${(url.label || "URL").toUpperCase()} · ${Number(url.score || 0).toFixed(1)}` : _lastURLData ? `${_lastURLData.label} · ${Number((_lastURLData.threat_score_pct ?? ((_lastURLData.threat_score !== undefined ? _lastURLData.threat_score * 100 : (typeof _lastURLData.confidence_score === "number" ? (1 - _lastURLData.confidence_score) * 100 : 0))))).toFixed(1)}` : "Waiting for scan");
    _setRiskSourceLabel("risk-src-email", email ? `${email.label || "Email"} · ${Number(email.score || 0).toFixed(1)}` : _lastEmailData ? `${_lastEmailData.label} · ${Number((_lastEmailData.threat_score_pct ?? ((_lastEmailData.threat_score !== undefined ? _lastEmailData.threat_score * 100 : (typeof _lastEmailData.confidence_score === "number" ? (1 - _lastEmailData.confidence_score) * 100 : 0))))).toFixed(1)}` : "Waiting for scan");
    _setRiskSourceLabel("risk-src-full", data ? `${data.level || "Unknown"} · ${Number(data.score || 0).toFixed(1)}` : _lastRiskData ? `${_lastRiskData.level || "Unknown"} · ${Number(_lastRiskData.score || 0).toFixed(1)}` : "Waiting for scan");
}

function levelColor(level) {
  const value = String(level || "").toLowerCase();
  if (value.includes("critical") || value.includes("high")) return "#ef4444";
  if (value.includes("medium")) return "#eab308";
  if (value.includes("low") || value.includes("safe")) return "#22c55e";
  return "#22c55e";
}

async function refreshAutoRisk(silent = false) {
  const out = document.getElementById("risk-result");
  if (!out) return;

  if (!silent) showLoader();
  try {
    const data = await post("/api/risk-score", {});
    if (!silent) hideLoader();
    if (data.error) {
      showError(out, data.error);
      return;
    }
    _lastRiskData = data;
    refreshRiskSources(data);
    renderRiskPanel(out, data);
    if (!silent) {
      const icon = data.score >= 60 ? "error" : data.score >= 40 ? "warning" : "success";
      toast(`Auto risk score: ${data.score.toFixed(1)} — ${data.level} threat`, icon);
    }
  } catch (e) {
    if (!silent) hideLoader();
    showError(out, "Request failed: " + e.message);
    if (!silent) toast("Could not reach the server", "error");
  }
}

function scoreTierCls(score) {
  const value = Number(score) > 1 ? Number(score) / 100 : Number(score);
  if (value >= 0.8) return "high";
  if (value >= 0.6) return "medium";
  return "low";
}

const FEAT_RISK_WEIGHTS = {
  "Has IP address": 93,
  "Has @ symbol": 88,
  "Has tilde (~)": 82,
  "Many dots": 72,
  "High entropy": 78,
  "Suspicious length": 55,
  "No HTTPS": 60,
};

// Build feature importance bar chart HTML
function featureBarChartHTML(featureFlags) {
  const entries = Object.entries(featureFlags);
  const rows = entries.map(([k, v]) => {
    const w = FEAT_RISK_WEIGHTS[k] || 45;
    if (v) {
      return `<div class="feat-bar-row">
        <span class="feat-bar-name risk">⚠ ${k}</span>
        <div class="feat-bar-track"><div class="feat-bar-fill risk" style="width:0%" data-w="${w}"></div></div>
        <span class="feat-bar-pct" style="color:#f87171">${w}%</span>
      </div>`;
    } else {
      return `<div class="feat-bar-row">
        <span class="feat-bar-name safe">✓ ${k}</span>
        <div class="feat-bar-track"><div class="feat-bar-fill safe" style="width:4%"></div></div>
        <span class="feat-bar-pct safe">—</span>
      </div>`;
    }
  }).join("");
  return `<div class="flags-wrap" id="url-flags">
    <div class="flags-title">Feature Analysis</div>
    <div class="feat-bars">${rows}</div>
  </div>`;
}

function animateFeatureBars(container) {
  container.querySelectorAll(".feat-bar-fill.risk").forEach((el, i) => {
    const w = el.dataset.w || 50;
    setTimeout(() => {
      if (typeof gsap !== "undefined") {
        gsap.to(el, { width: w + "%", duration: 0.7, ease: "power2.out" });
      } else {
        el.style.width = w + "%";
      }
    }, i * 80);
  });
}

// ANIMATED SVG CONFIDENCE RING
// (score 0-1 drives animation; percentage shown in centre)
// 
function probRingHTML(id, score, color, label) {
  const R = 46, circ = 2 * Math.PI * R;
  const pct = Math.round(score * 100) + "%";
  return `
    <svg class="prob-ring-svg" viewBox="0 0 110 110">
      <circle class="ring-bg"   cx="55" cy="55" r="${R}"/>
      <circle class="ring-fill" id="${id}-ring"
        cx="55" cy="55" r="${R}"
        stroke="${color}"
        stroke-dasharray="${circ}"
        stroke-dashoffset="${circ}"/>
      <text class="ring-pct-text" x="55" y="51" fill="${color}" font-size="14">
        ${pct}
      </text>
      <text class="ring-label-text" x="55" y="66">${escHtml(label)}</text>
    </svg>`;
}

function animateRing(id, prob) {
  const R = 46, circ = 2 * Math.PI * R;
  const el = document.getElementById(id + "-ring");
  if (!el) return;
  if (typeof gsap !== "undefined") {
    gsap.to(el, {
      attr: { "stroke-dashoffset": circ - circ * prob },
      duration: 1.1, delay: .1,
      ease: "power2.out"
    });
  } else {
    el.style.strokeDashoffset = circ - circ * prob;
  }
}

// 
// COPY RESULT
// 
function copyResult(jsonStr) {
  navigator.clipboard.writeText(jsonStr)
    .then(() => toast("Result copied to clipboard", "success"))
    .catch(() => toast("Clipboard access denied", "error"));
}

// 
// CLEAR INPUT
// 
function clearInput(inputId, resultId, skelId) {
  const el = document.getElementById(inputId);
  if (el) { el.value = ""; el.classList.remove("input-error", "input-valid", "scanning-glow"); el.focus(); }
  if (resultId) {
    const r = document.getElementById(resultId);
    if (r && typeof gsap !== "undefined") {
      gsap.to(r, { opacity: 0, y: -8, duration: .2, onComplete: () => { r.classList.add("hidden"); r.style.cssText = ""; }});
    } else if (r) { r.classList.add("hidden"); }
  }
  if (skelId) { const s = document.getElementById(skelId); if (s) s.classList.add("hidden"); }
}

// 
// URL VALIDATION
// 
function validateURL(url) {
  return url.includes(".") || url.startsWith("http");
}

// 
// SCAN HISTORY
// 
const HISTORY_URL   = "ps_url_history";
const HISTORY_EMAIL = "ps_email_history";
const MAX_HIST = 5;

function loadHist(key) {
  try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch { return []; }
}
function saveHist(key, entry) {
  const arr = loadHist(key);
  arr.unshift(entry);
  if (arr.length > MAX_HIST) arr.length = MAX_HIST;
  localStorage.setItem(key, JSON.stringify(arr));
}
function timeNow() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function renderURLHistory() {
  const hist = loadHist(HISTORY_URL);
    const list = document.getElementById("url-history-list");
    const wrap = document.getElementById("url-history");
    if (!list || !hist.length) { if (wrap) wrap.classList.add("hidden"); return; }
    wrap.classList.remove("hidden");
    list.innerHTML = hist.map(h => {
      const conf = h.conf || "50%";
      const tierCls = h.score !== undefined ? scoreTierCls(h.score) : "low";
      const verdict = h.verdict || "Unknown";
      return `<div class="sh-item">
        <span class="conf-badge conf-${tierCls}">${conf}</span>
        <span class="sh-text">${escHtml(h.text)}</span>
        <span class="sh-verdict">${escHtml(verdict)}</span>
        <span class="sh-time">${h.time}</span>
      </div>`;
    }).join("");
}

function renderEmailHistory() {
  const hist = loadHist(HISTORY_EMAIL);
  const list = document.getElementById("email-history-list");
  const wrap = document.getElementById("email-history");
  if (!list || !hist.length) { if (wrap) wrap.classList.add("hidden"); return; }
  wrap.classList.remove("hidden");
  list.innerHTML = hist.map(h => {
    const conf    = h.conf || "50%";
    const tierCls = h.score !== undefined ? scoreTierCls(h.score) : "low";
    const verdict = h.verdict || "Unknown";
    return `<div class="sh-item">
      <span class="conf-badge conf-${tierCls}">${conf}</span>
      <span class="sh-text">${escHtml(h.text)}</span>
      <span class="sh-verdict">${escHtml(verdict)}</span>
      <span class="sh-time">${h.time}</span>
    </div>`;
  }).join("");
}

// 
// LIVE HEADER STATS WITH ANIMATED COUNTER
// 
function animateCount(el, to) {
  const from = parseInt(el.textContent) || 0;
  if (from === to) { el.textContent = to; return; }
  if (typeof gsap !== "undefined") {
    const obj = { val: from };
    gsap.to(obj, {
      val: to, duration: .8, ease: "power2.out",
      onUpdate: () => { el.textContent = Math.round(obj.val); }
    });
  } else {
    const steps = 20, diff = to - from; let i = 0;
    const t = setInterval(() => {
      i++; el.textContent = Math.round(from + diff * (i/steps));
      if (i >= steps) { el.textContent = to; clearInterval(t); }
    }, 30);
  }
}

async function fetchStats() {
  try {
    const d = await get("/api/stats");
    const map = { "stat-urls":d.urls_scanned||0, "stat-emails":d.emails_analyzed||0, "stat-threats":d.threats_detected||0 };
    Object.entries(map).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) animateCount(el, val);
    });
  } catch { /* silent */ }
}

async function fetchDashboard() {
  const panel = document.getElementById("dashboard-panel");
  if (!panel) return;

  try {
    const data = await get("/api/dashboard");
    const stats = data.stats || {};

    const counters = {
      "dash-recent-scans": stats.recent_scans || 0,
      "dash-phish-events": stats.phishing_events || 0,
      "dash-extension-alerts": stats.extension_alerts || 0,
      "dash-extension-feedback": stats.extension_feedback || 0,
    };
    Object.entries(counters).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) animateCount(el, val);
    });

    const renderList = (containerId, rows, emptyText, renderRow) => {
      const el = document.getElementById(containerId);
      if (!el) return;
      el.innerHTML = rows.length ? rows.map(renderRow).join("") : `<div class="dash-empty">${emptyText}</div>`;
    };

    renderList("dash-signals", data.top_signals || [], "No active signals yet.", item => `
      <div class="dash-list-row">
        <span>${escHtml(item.signal)}</span>
        <strong>${item.count}</strong>
      </div>`);

    const riskRows = data.risk_distribution || [];
    const riskEl = document.getElementById("dash-risk");
    if (riskEl) {
      const maxCount = Math.max(1, ...riskRows.map(item => item.count || 0));
      riskEl.innerHTML = riskRows.length ? riskRows.map(item => {
        const width = Math.max(8, ((item.count || 0) / maxCount) * 100);
        return `
          <div class="dash-risk-row">
            <div class="dash-risk-head">
              <span>${escHtml(item.level)}</span>
              <strong>${item.count}</strong>
            </div>
            <div class="dash-risk-track"><div class="dash-risk-fill" style="width:${width}%"></div></div>
          </div>`;
      }).join("") : `<div class="dash-empty">No risk history yet.</div>`;
    }

    renderList("dash-scans", data.recent_scans || [], "Run a scan to populate recent activity.", item => {
      const score = Number(item.score || 0);
      const color = score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 35 ? "#eab308" : "#22c55e";
      const signals = (item.signals || []).length ? escHtml(item.signals.slice(0, 3).join(" · ")) : "No signals";
      return `
        <div class="dash-scan-item">
          <div class="dash-scan-top">
            <div>
              <span class="dash-kind">${escHtml(item.kind || "scan")}</span>
              <div class="dash-subject">${escHtml(item.subject || "Unknown subject")}</div>
            </div>
            <span class="dash-score" style="color:${color}">${score.toFixed(1)}</span>
          </div>
          <div class="dash-scan-meta">
            <span>${escHtml(item.label || "Unknown")}</span>
            <span>${escHtml(item.confidence || "")}</span>
          </div>
          <div class="dash-scan-signals">${signals}</div>
        </div>`;
    });

    renderList("dash-alerts", data.recent_alerts || [], "No extension alerts yet.", item => `
      <div class="dash-list-row compact">
        <span>${escHtml(item.label || item.level || "Alert")}</span>
        <strong>${Number(item.score || 0).toFixed(1)}</strong>
      </div>`);

    renderList("dash-feedback", data.recent_feedback || [], "No feedback captured yet.", item => `
      <div class="dash-list-row compact">
        <span>${escHtml(item.feedback || "feedback")}</span>
        <strong>${escHtml(item.label || "")}</strong>
      </div>`);

    if ((data.stats || {}).recent_scans > 0) {
      refreshAutoRisk(true);
    }
  } catch {
    panel.dataset.error = "1";
  }
}

// 
// CRITICAL THREAT BANNER
// 
function showCriticalBanner() {
  const b = document.getElementById("threat-banner");
  if (!b) return;
  b.classList.remove("hidden");
  if (typeof gsap !== "undefined") {
    gsap.fromTo(b, { y: -60, opacity: 0 }, { y: 0, opacity: 1, duration: .4, ease: "back.out(1.4)" });
  }
  setTimeout(() => {
    if (typeof gsap !== "undefined") {
      gsap.to(b, { y: -60, opacity: 0, duration: .3, delay: 4, onComplete: () => b.classList.add("hidden") });
    } else {
      setTimeout(() => b.classList.add("hidden"), 4500);
    }
  }, 100);
}

// 
// RESULT PANEL REVEAL WITH GLOW
// 
function revealResult(el, isCritical) {
  el.classList.remove("hidden", "safe-glow", "critical-glow");
  el.classList.add(isCritical ? "critical-glow" : "safe-glow");
  if (typeof gsap !== "undefined") {
    gsap.fromTo(el, { opacity: 0, scale: .96, y: 10 }, { opacity: 1, scale: 1, y: 0, duration: .4, ease: "back.out(1.3)" });
  }
}

// 
// FLAG TAGS STAGGER
// 
function animateFlagTags(container) {
  const tags = container.querySelectorAll(".flag-tag");
  if (typeof gsap !== "undefined") {
    gsap.fromTo(tags, { opacity: 0, x: -10, scale: .9 }, { opacity: 1, x: 0, scale: 1, duration: .3, stagger: .08, ease: "power2.out" });
  } else {
    tags.forEach((t, i) => { t.style.animationDelay = `${i * 0.08}s`; });
  }
}

// 
// URL CHECKER
// 
function setURL(val) {
  document.getElementById("url-input").value = val;
  document.getElementById("url-input").classList.remove("input-error", "input-valid");
}

async function checkURL() {
  const inp = document.getElementById("url-input");
  const url = inp.value.trim();
  const out = document.getElementById("url-result");
  const animDiv = document.getElementById("url-scan-anim");
  const laser = document.getElementById("url-laser");

  if (!url) {
    inp.classList.add("input-error");
    toast("Please enter a URL to scan", "warning");
    if (typeof gsap !== "undefined") {
      gsap.to(inp, { x: -6, duration: .08, yoyo: true, repeat: 5, ease: "power1.inOut" });
    }
    return;
  }
  if (!validateURL(url)) {
    inp.classList.add("input-error");
    toast("URL doesn't look valid — check the format", "warning");
    return;
  }

  inp.classList.remove("input-error");
  inp.classList.add("input-valid", "scanning-glow");
  out.classList.add("hidden");
  hideSkeleton("url-skeleton");

  // Laser sweep
  if (laser) { laser.classList.remove("active"); void laser.offsetWidth; laser.classList.add("active"); }

  // Show scan animation
  const labels = [
    "Scanning URL structure...",
    "Checking domain entropy...",
    "Analyzing redirect chains...",
    "AI models classifying signals...",
    "Computing threat probability..."
  ];
  animDiv.classList.remove("hidden");
  let li = 0;
  const labelEl = document.getElementById("scan-label-text");
  const labelInterval = setInterval(() => {
    if (labelEl) labelEl.textContent = labels[li % labels.length];
    li++;
  }, 500);

  showSkeleton("url-skeleton");

  try {
    const data = await post("/api/check-url", { url });
    clearInterval(labelInterval);
    animDiv.classList.add("hidden");
    inp.classList.remove("scanning-glow");
    hideSkeleton("url-skeleton");

    if (data.error) { showError(out, data.error); toast("Analysis error: " + data.error, "error"); return; }

    const conf    = data.confidence || "50%";          // e.g. "87%"
    const score   = data.threat_score !== undefined ? data.threat_score : (data.confidence_score || 0.5);
    const scorePct = data.threat_score_pct !== undefined ? data.threat_score_pct : Math.round(score * 100);
    const pred    = data.prediction;
    const isPhish = pred === 1;
    const tierCls = scoreTierCls(score);
    const color   = isPhish
      ? (score >= 0.80 ? "#ef4444" : score >= 0.60 ? "#f97316" : "#eab308")
      : (score >= 0.80 ? "#22c55e" : "#06b6d4");
    const icon    = isPhish ? "⚠️" : "✅";
    const isCrit  = isPhish && score >= 0.80;

    saveHist(HISTORY_URL, { text: url, conf, score, verdict: data.label, time: timeNow() });
    renderURLHistory();
    _lastURLData = data;

    let flagsHTML = "";
    if (data.feature_flags) {
      flagsHTML = featureBarChartHTML(data.feature_flags);
    }

    let signalsHTML = "";
    if (data.threat_signals && data.threat_signals.length) {
      signalsHTML = `
        <div class="flags-wrap" id="url-signals">
          <div class="flags-title">⚡ Active Threat Signals</div>
          <div class="flags-list">
            ${data.threat_signals.map(s =>
              `<span class="flag-tag active">🔴 ${escHtml(s)}</span>`
            ).join("")}
          </div>
        </div>`;
    }

    const pdfPayload = JSON.stringify({ prediction: data.prediction, label: data.label, confidence: data.confidence, url: data.url, threat_signals: data.threat_signals });
    const copyData   = JSON.stringify(data, null, 2);
    out.innerHTML = `
      <div class="result-header" style="background:${color}18; border-bottom:1px solid ${color}30;">
        <div class="result-status">
          <span class="status-dot" style="background:${color}; box-shadow:0 0 6px ${color}88;"></span>
          <span class="result-label">${icon} ${data.label}</span>
          <span class="conf-badge conf-${tierCls}">${conf}</span>
        </div>
        <div style="display:flex;gap:6px;">
          <button class="copy-btn" onclick='copyResult(${JSON.stringify(copyData)})'>📋 Copy</button>
          <button class="pdf-btn" onclick='exportResultPDF(${JSON.stringify(pdfPayload)})'>📄 PDF</button>
        </div>
      </div>
      <div class="prob-ring-wrap">
        ${probRingHTML("url-conf", score, color, isPhish ? "Phishing risk" : "Legitimate risk")}
        <div class="prob-ring-info">
          <div class="pri-verdict">
            <span class="result-label">${icon} ${data.label}</span>
          </div>
          <div class="pri-rows">
            <div class="pr-row"><span>Verdict</span><strong style="color:${color}">${data.label}</strong></div>
            <div class="pr-row"><span>Threat score</span><strong style="color:${color}">${scorePct}%</strong></div>
            <div class="pr-row"><span>AI confidence</span><span class="conf-badge conf-${tierCls}">${conf}</span></div>
            <div class="pr-row"><span>URL Length</span><strong>${data.url_length} chars</strong></div>
          </div>
        </div>
      </div>
      <div class="detail-grid">
        <div class="detail-cell">
          <div class="d-label">URL</div>
          <div class="d-value" style="word-break:break-all;font-size:11.5px;font-family:'JetBrains Mono',monospace;">${escHtml(data.url)}</div>
        </div>
        <div class="detail-cell">
          <div class="d-label">Threat Level</div>
          <div class="d-value"><span class="conf-badge conf-${tierCls}">${conf}</span></div>
        </div>
      </div>
      ${signalsHTML}${flagsHTML}`;

    revealResult(out, isCrit);
    if (isCrit) showCriticalBanner();

    setTimeout(() => {
      animateRing("url-conf", score);
      const fw = document.getElementById("url-flags");
      if (fw) { animateFeatureBars(fw); animateFlagTags(fw); }
      const sw = document.getElementById("url-signals");
      if (sw) animateFlagTags(sw);
    }, 100);

    toast(`URL scanned — ${scorePct}% threat · ${data.label}`, isCrit ? "error" : "success");
    fetchAIExplain(data, "url-result");
    fetchStats();
    refreshAutoRisk();
  } catch (e) {
    clearInterval(labelInterval);
    animDiv.classList.add("hidden");
    inp.classList.remove("scanning-glow");
    hideSkeleton("url-skeleton");
    showError(out, "Request failed: " + e.message);
    toast("Could not reach the server", "error");
  }
}

// 
// EMAIL ANALYZER
// 
const SAMPLE_SPAM = `Congratulations! You have been selected as the WINNER of our $1,000,000 lottery prize!

To claim your reward, please click here immediately and verify your account. This offer EXPIRES in 24 hours. Act now!

No purchase required. You have won FREE money! Wire transfer available. Click below to confirm your details.`;

const SAMPLE_HAM = `Hi Sarah,

Just following up on the project proposal we discussed during Tuesday's meeting. Could you share the updated timeline and resource allocation doc by Thursday EOD?

Also, the client meeting has been rescheduled to next Monday at 2pm. Please update your calendar.

Thanks,
Michael`;

function loadSampleEmail(type) {
  document.getElementById("email-input").value = type === "spam" ? SAMPLE_SPAM : SAMPLE_HAM;
  toast(`${type === "spam" ? "Spam" : "Legitimate"} sample loaded`, "info");
}

// Lottie brain animation
let brainAnim = null;
function showBrainAnim() {
  const container = document.getElementById("email-brain-anim");
  const lottieDiv = document.getElementById("lottie-brain");
  if (!container) return;
  container.classList.remove("hidden");

  if (typeof lottie !== "undefined" && lottieDiv && !brainAnim) {
    try {
      brainAnim = lottie.loadAnimation({
        container: lottieDiv,
        renderer: "svg",
        loop: true,
        autoplay: true,
        path: "https://assets10.lottiefiles.com/packages/lf20_fcfjwiyb.json"
      });
      brainAnim.addEventListener("data_failed", () => {
        // fallback spinner
        lottieDiv.innerHTML = '<div class="brain-spinner"></div>';
      });
    } catch(e) {
      lottieDiv.innerHTML = '<div class="brain-spinner"></div>';
    }
  } else if (lottieDiv && !brainAnim) {
    lottieDiv.innerHTML = '<div class="brain-spinner"></div>';
  }
}
function hideBrainAnim() {
  const container = document.getElementById("email-brain-anim");
  if (container) {
    if (typeof gsap !== "undefined") {
      gsap.to(container, { opacity: 0, scale: .9, duration: .25, onComplete: () => {
        container.classList.add("hidden");
        container.style.cssText = "";
      }});
    } else {
      container.classList.add("hidden");
    }
  }
}

async function checkEmail() {
  const text = document.getElementById("email-input").value.trim();
  const out  = document.getElementById("email-result");
  if (!text) { toast("Please enter email text first", "warning"); return; }

  out.classList.add("hidden");
  showSkeleton("email-skeleton");
  showBrainAnim();

  try {
    const data = await post("/api/check-email", { text });
    hideBrainAnim();
    hideSkeleton("email-skeleton");
    if (data.error) { showError(out, data.error); toast("Analysis error", "error"); return; }

    const conf    = data.confidence || "50%";
    const score   = data.threat_score !== undefined ? data.threat_score : (data.confidence_score || 0.5);
    const scorePct = data.threat_score_pct !== undefined ? data.threat_score_pct : Math.round(score * 100);
    const pred    = data.prediction;
    const isSpam  = pred === 1;
    const tierCls = scoreTierCls(score);
    const color   = isSpam
      ? (score >= 0.80 ? "#ef4444" : score >= 0.60 ? "#f97316" : "#eab308")
      : (score >= 0.80 ? "#22c55e" : "#06b6d4");
    const icon    = isSpam ? "⚠️" : "✅";
    const isCrit  = isSpam && score >= 0.80;

    saveHist(HISTORY_EMAIL, { text: text.slice(0, 60), conf, score, verdict: data.label, time: timeNow() });
    renderEmailHistory();
    _lastEmailData = data;

    let tokensHTML = "";
    if (data.flagged_tokens && data.flagged_tokens.length) {
      tokensHTML = `
        <div class="flags-wrap" id="email-tokens">
          <div class="flags-title">Flagged tokens</div>
          <div class="flags-list">
            ${data.flagged_tokens.map(t =>
              `<span class="flag-tag active">🚨 ${escHtml(t)}</span>`
            ).join("")}
          </div>
        </div>`;
    }

    const copyData   = JSON.stringify(data, null, 2);
    const pdfPayload = JSON.stringify({ prediction: data.prediction, label: data.label, confidence: data.confidence, flagged_tokens: data.flagged_tokens, keyword_count: data.keyword_count });
    out.innerHTML = `
      <div class="result-header" style="background:${color}18; border-bottom:1px solid ${color}30;">
        <div class="result-status">
          <span class="status-dot" style="background:${color}; box-shadow:0 0 6px ${color}88;"></span>
          <span class="result-label">${icon} ${data.label}</span>
          <span class="conf-badge conf-${tierCls}">${conf}</span>
        </div>
        <div style="display:flex;gap:6px;">
          <button class="copy-btn" onclick='copyResult(${JSON.stringify(copyData)})'>📋 Copy</button>
          <button class="pdf-btn" onclick='exportResultPDF(${JSON.stringify(pdfPayload)})'>📄 PDF</button>
        </div>
      </div>
      <div class="prob-ring-wrap">
        ${probRingHTML("em-conf", score, color, isSpam ? "Spam risk" : "Legitimate risk")}
        <div class="prob-ring-info">
          <div class="pri-verdict">
            <span class="result-label">${icon} ${data.label}</span>
          </div>
          <div class="pri-rows">
            <div class="pr-row"><span>Verdict</span><strong style="color:${color}">${data.label}</strong></div>
            <div class="pr-row"><span>Threat score</span><strong style="color:${color}">${scorePct}%</strong></div>
            <div class="pr-row"><span>AI confidence</span><span class="conf-badge conf-${tierCls}">${conf}</span></div>
            <div class="pr-row"><span>Suspicious keywords</span><strong style="color:${data.keyword_count>0?'#f97316':'#22c55e'}">${data.keyword_count}</strong></div>
            <div class="pr-row"><span>Word count</span><strong>${data.word_count}</strong></div>
          </div>
        </div>
      </div>
      ${tokensHTML}`;

    revealResult(out, isCrit);
    if (isCrit) showCriticalBanner();

    setTimeout(() => {
      animateRing("em-conf", score);
      const tw = document.getElementById("email-tokens");
      if (tw) animateFlagTags(tw);
    }, 100);

    toast(`Email analyzed — ${scorePct}% threat · ${data.label}`, isCrit ? "error" : "success");
    fetchAIExplain(data, "email-result");
    fetchStats();
    refreshAutoRisk();
  } catch (e) {
    hideBrainAnim();
    hideSkeleton("email-skeleton");
    showError(out, "Request failed: " + e.message);
    toast("Could not reach the server", "error");
  }
}

// 
// RISK SCORE
// 
function _setRiskSourceLabel(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value || "Waiting for scan";
}

function refreshRiskSources(data) {
  const url = data?.sources?.url;
  const email = data?.sources?.email;
  _setRiskSourceLabel("risk-src-url", url ? `${(url.label || "URL").toUpperCase()} · ${Number(url.score || 0).toFixed(1)}` : _lastURLData ? `${_lastURLData.label} · ${Number((_lastURLData.threat_score_pct ?? ((_lastURLData.threat_score !== undefined ? _lastURLData.threat_score * 100 : (typeof _lastURLData.confidence_score === "number" ? (1 - _lastURLData.confidence_score) * 100 : 0))))).toFixed(1)}` : "Waiting for scan");
  _setRiskSourceLabel("risk-src-email", email ? `${email.label || "Email"} · ${Number(email.score || 0).toFixed(1)}` : _lastEmailData ? `${_lastEmailData.label} · ${Number((_lastEmailData.threat_score_pct ?? ((_lastEmailData.threat_score !== undefined ? _lastEmailData.threat_score * 100 : (typeof _lastEmailData.confidence_score === "number" ? (1 - _lastEmailData.confidence_score) * 100 : 0))))).toFixed(1)}` : "Waiting for scan");
}

async function refreshAutoRisk() {
  if (!out) return;

  showLoader();
  try {
    const data = await post("/api/risk-score", {});
    hideLoader();
    if (data.error) {
      showError(out, data.error);
      return;
    }
    _lastRiskData = data;
    refreshRiskSources(data);
    renderRiskPanel(out, data);
    const icon = data.score >= 60 ? "error" : data.score >= 40 ? "warning" : "success";
    toast(`Auto risk score: ${data.score.toFixed(1)} — ${data.level} threat`, icon);
  } catch (e) {
    hideLoader();
    showError(out, "Request failed: " + e.message);
    toast("Could not reach the server", "error");
  }
}

function renderRiskPanel(out, data) {
  const score  = data.score;
  const color  = levelColor(data.level);
  const R      = 70;
  const total  = Math.PI * R;
  const filled = (score / 100) * total;
  const dashOff = total - filled;

  let contribHTML = "";
  if (data.contributions) {
    const maxPts = 35;
    contribHTML = `
      <div class="contrib-wrap">
        <div class="contrib-title">Signal Contributions</div>
        ${Object.entries(data.contributions).map(([k, v]) => `
          <div class="contrib-row">
            <span class="contrib-name">${k.replace(/_/g," ")}</span>
            <div class="contrib-bar-bg">
              <div class="contrib-bar-fill" data-pct="${Math.min(v/maxPts*100,100).toFixed(1)}"
                   style="width:0%; background:${color};"></div>
            </div>
            <span class="contrib-pts">+${v} pts</span>
          </div>`).join("")}
      </div>`;
  }

  const sourceHTML = data.sources ? `
    <div class="risk-sources-panel">
      <div class="risk-sources-title">Auto inputs used</div>
      <div class="risk-sources-grid">
        <div><span>Mode</span><strong>${escHtml(data.mode || "auto")}</strong></div>
        <div><span>URL source</span><strong>${escHtml(data.sources.url?.kind || "unknown")}</strong></div>
        <div><span>Email source</span><strong>${escHtml(data.sources.email?.kind || "unknown")}</strong></div>
      </div>
    </div>` : "";

  const recommendationHTML = data.recommendations && data.recommendations.length ? `
    <div class="risk-recommendations">
      <div class="risk-sources-title">Recommended actions</div>
      <ul>
        ${data.recommendations.map(item => `<li>${escHtml(item)}</li>`).join("")}
      </ul>
    </div>` : "";

  const copyData = JSON.stringify(data, null, 2);
  out.innerHTML = `
    <div class="result-header" style="background:${color}18; border-bottom:1px solid ${color}30;">
      <div class="result-status">
        <span class="status-dot" style="background:${color}; box-shadow:0 0 6px ${color}88;"></span>
        <span class="result-label">Risk Score: ${score.toFixed(1)} / 100</span>
      </div>
      <button class="copy-btn" onclick='copyResult(${JSON.stringify(copyData)})'> Copy</button>
    </div>
    <div class="gauge-wrap">
      <svg class="gauge-svg" viewBox="0 0 180 95">
        <path class="gauge-bg-arc" d="M20,90 A70,70 0 0,1 160,90"
          stroke-dasharray="${total} ${total}" stroke-dashoffset="0"/>
        <path class="gauge-fill-arc" id="gauge-arc"
          d="M20,90 A70,70 0 0,1 160,90"
          stroke="${color}"
          stroke-dasharray="${total} ${total}"
          stroke-dashoffset="${total}"/>
        <text class="gauge-score-text" x="90" y="75" fill="${color}">${score.toFixed(0)}</text>
        <text class="gauge-label-text" x="90" y="91">/ 100</text>
      </svg>
      <span class="gauge-level-badge" style="background:${color}18; color:${color}; border:1px solid ${color}30;">
        ${data.level} Threat
      </span>
    </div>
    ${sourceHTML}
    ${contribHTML}`;

  out.innerHTML += recommendationHTML;

  revealResult(out, score >= 70);

  setTimeout(() => {
    const arc = document.getElementById("gauge-arc");
    if (arc) {
      if (typeof gsap !== "undefined") {
        gsap.fromTo(arc, { attr: { "stroke-dashoffset": total } }, { attr: { "stroke-dashoffset": dashOff }, duration: 1.1, ease: "power2.out" });
      } else {
        arc.style.strokeDashoffset = dashOff;
      }
    }
    document.querySelectorAll(".contrib-bar-fill[data-pct]").forEach(el => {
      if (typeof gsap !== "undefined") {
        gsap.fromTo(el, { width: "0%" }, { width: el.dataset.pct + "%", duration: .8, ease: "power2.out", delay: .1 });
      } else {
        el.style.width = el.dataset.pct + "%";
      }
    });
  }, 80);
}

// 
// FULL ANALYSIS WITH PIPELINE ANIMATION
// 
async function fullAnalysis() {
  const url   = document.getElementById("fa-url").value.trim();
  const email = document.getElementById("fa-email").value.trim();
  const out   = document.getElementById("full-result");

  if (!url && !email) {
    toast("Please enter a URL and/or email text", "warning");
    showError(out, "Please enter a URL and/or email text.");
    return;
  }

  // Show pipeline animation
  const pipeDiv = document.getElementById("pipeline-anim");
  pipeDiv.classList.remove("hidden");
  if (typeof gsap !== "undefined") {
    gsap.fromTo(pipeDiv, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: .3 });
  }

  // Animate pipeline steps sequentially
  await activatePipeStep(0, "Scanning...", "URL Model scanning...");
  await delay(600);
  await completePipeStep(0, "Done ");
  activatePipeFlow(1);
  await delay(200);
  await activatePipeStep(1, "Processing...", "Email model analyzing...");
  await delay(600);
  await completePipeStep(1, "Done ");
  activatePipeFlow(2);
  await delay(200);
  await activatePipeStep(2, "Computing...", "Risk engine scoring...");

  showLoader();
  try {
    const data = await post("/api/full-analysis", {
      url,
      email,
      domain_age_days: parseInt(document.getElementById("fa-domain-age").value) || 365,
      has_attachment : document.getElementById("fa-attachment").checked,
    });
    hideLoader();
    await completePipeStep(2, "Done ");

    setTimeout(() => {
      if (typeof gsap !== "undefined") {
        gsap.to(pipeDiv, { opacity: 0, y: -8, duration: .3, onComplete: () => { pipeDiv.classList.add("hidden"); pipeDiv.style.cssText = ""; } });
      } else {
        pipeDiv.classList.add("hidden");
      }
    }, 700);

    renderFullAnalysis(out, data);
    toast("Full analysis complete", "success");
    refreshAutoRisk();
  } catch (e) {
    hideLoader();
    pipeDiv.classList.add("hidden");
    showError(out, "Request failed: " + e.message);
    toast("Could not reach the server", "error");
  }
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function activatePipeStep(idx, status, _label) {
  const step = document.getElementById("pipe-step-" + (idx+1));
  const st   = document.getElementById("pipe-st-"   + (idx+1));
  if (!step) return Promise.resolve();
  step.classList.add("active");
  if (st) st.textContent = status;
  if (typeof gsap !== "undefined") {
    gsap.fromTo(step, { scale: 1 }, { scale: 1.05, duration: .25, ease: "back.out(1.5)" });
  }
  return Promise.resolve();
}
function completePipeStep(idx, status) {
  const step = document.getElementById("pipe-step-" + (idx+1));
  const st   = document.getElementById("pipe-st-"   + (idx+1));
  if (step) { step.classList.remove("active"); step.classList.add("done"); }
  if (st) st.textContent = status;
  return Promise.resolve();
}
function activatePipeFlow(idx) {
  const f = document.getElementById("pipe-flow-" + idx);
  if (!f) return;
  f.classList.remove("active"); void f.offsetWidth; f.classList.add("active");
}

function renderFullAnalysis(out, data) {
  const risk   = data.risk           || {};
  const urlA   = data.url_analysis   || null;
  const emA    = data.email_analysis || null;
  const rColor = levelColor(risk.level || "Safe");

  const confBadge = (conf) => {
    const c = (conf || "Low").toLowerCase();
    return `<span class="conf-badge conf-${c}">${conf || "Low"} Confidence</span>`;
  };

  let urlSection = urlA ? `<div class="analysis-section">
    <h3>🔗 URL Analysis</h3>
    <div class="analysis-row"><span class="ar-label">Verdict</span><strong style="color:${urlA.prediction===1?'#ef4444':'#22c55e'}">${urlA.label}</strong></div>
    <div class="analysis-row"><span class="ar-label">AI Confidence</span>${confBadge(urlA.confidence)}</div>
    <div class="analysis-row">
      <span class="ar-label">URL</span>
      <span style="font-size:11.5px;font-family:'JetBrains Mono',monospace;word-break:break-all;">${escHtml(urlA.url||"")}</span>
    </div>
  </div>` : "";

  let emSection = emA ? `<div class="analysis-section">
    <h3>📧 Email Analysis</h3>
    <div class="analysis-row"><span class="ar-label">Verdict</span><strong style="color:${emA.prediction===1?'#ef4444':'#22c55e'}">${emA.label}</strong></div>
    <div class="analysis-row"><span class="ar-label">AI Confidence</span>${confBadge(emA.confidence)}</div>
    <div class="analysis-row">
      <span class="ar-label">Suspicious keywords</span>
      <strong style="color:${emA.keyword_count>0?'#f97316':'#22c55e'}">${emA.keyword_count}</strong>
    </div>
  </div>` : "";

  const score    = risk.score || 0;
  const R        = 70, total = Math.PI * R;
  const dashOff  = total - (score/100) * total;
  const copyData = JSON.stringify(data, null, 2);

  out.innerHTML = `
    <div style="display:flex;justify-content:flex-end;padding:10px 18px 0;">
      <button class="copy-btn" onclick='copyResult(${JSON.stringify(copyData)})'> Copy Report</button>
    </div>
    <div class="analysis-sections">
      ${urlSection}${emSection}
      <div class="analysis-section">
        <h3> Composite Risk Score</h3>
        <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
          <svg class="gauge-svg" viewBox="0 0 180 95" style="width:140px;height:78px;">
            <path class="gauge-bg-arc" d="M20,90 A70,70 0 0,1 160,90" stroke-dasharray="${total} ${total}" stroke-dashoffset="0"/>
            <path class="gauge-fill-arc" id="fa-gauge" d="M20,90 A70,70 0 0,1 160,90" stroke="${rColor}" stroke-dasharray="${total} ${total}" stroke-dashoffset="${total}"/>
            <text class="gauge-score-text" x="90" y="75" fill="${rColor}" font-size="26">${score}</text>
            <text class="gauge-label-text" x="90" y="91">/ 100</text>
          </svg>
          <div>
            <div style="font-size:22px;font-weight:700;color:${rColor};">${risk.level || "—"}</div>
            <div style="color:var(--text-muted);font-size:13px;">Overall Threat Level</div>
          </div>
        </div>
      </div>
    </div>`;

  revealResult(out, score >= 70);
  setTimeout(() => {
    const arc = document.getElementById("fa-gauge");
    if (arc) {
      if (typeof gsap !== "undefined") {
        gsap.fromTo(arc, { attr:{"stroke-dashoffset": total} }, { attr:{"stroke-dashoffset": dashOff}, duration: 1.1, ease: "power2.out" });
      } else { arc.style.strokeDashoffset = dashOff; }
    }
  }, 80);
}

// 
// UTILITIES
// 
function showError(container, msg) {
  container.innerHTML = `<div class="error-box"> ${escHtml(msg)}</div>`;
  container.classList.remove("hidden");
}
function escHtml(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

//  Keyboard shortcuts 
document.addEventListener("DOMContentLoaded", () => {
  const urlInp = document.getElementById("url-input");
  const emInp  = document.getElementById("email-input");
  const faUrl  = document.getElementById("fa-url");
  if (urlInp) urlInp.addEventListener("keydown", e => { if (e.key === "Enter") checkURL(); });
  if (emInp)  emInp.addEventListener("keydown",  e => { if (e.ctrlKey && e.key === "Enter") checkEmail(); });
  if (faUrl)  faUrl.addEventListener("keydown",  e => { if (e.key === "Enter") fullAnalysis(); });
});

// ─────────────────────────────────────────────
// BULK URL SCANNER
// ─────────────────────────────────────────────
async function bulkScan() {
  const raw = document.getElementById("bulk-input").value.trim();
  if (!raw) { toast("Paste at least one URL", "warning"); return; }

  const urls = raw.split("\n").map(u => u.trim()).filter(Boolean);
  if (urls.length > 50) { toast("Maximum 50 URLs at once", "warning"); return; }

  const out    = document.getElementById("bulk-result");
  const prog   = document.getElementById("bulk-progress");
  const bar    = document.getElementById("bp-bar");
  const label  = document.getElementById("bp-label");
  const csvBtn = document.getElementById("bulk-csv-btn");

  out.classList.add("hidden");
  out.innerHTML = "";
  prog.classList.remove("hidden");
  bar.style.width = "0%";
  label.textContent = `Scanning ${urls.length} URL${urls.length > 1 ? "s" : ""}...`;
  csvBtn.style.display = "none";

  setTimeout(() => { bar.style.width = "55%"; }, 180);
  setTimeout(() => { bar.style.width = "80%"; }, 700);

  try {
    const data = await post("/api/bulk-scan", { urls });
    bar.style.width = "100%";
    _bulkResults = data.results;

    const t = data.threats;
    label.textContent = `Done — ${data.total} scanned · ${t} threat${t !== 1 ? "s" : ""} found`;
    renderBulkResults(data.results);
    out.classList.remove("hidden");
    csvBtn.style.display = "";
    if (t > 0) toast(`⚠ ${t} phishing URL${t > 1 ? "s" : ""} detected!`, "error");
    else toast("All URLs appear legitimate ✓", "success");
    fetchStats();
  } catch (e) {
    prog.classList.add("hidden");
    toast("Bulk scan failed: " + e.message, "error");
  }
}

function renderBulkResults(results) {
  const out     = document.getElementById("bulk-result");
  const threats = results.filter(r => r.label === "Phishing").length;
  out.innerHTML = `
    <div class="bulk-summary">
      <span class="bs-total">${results.length} URL${results.length !== 1 ? "s" : ""} scanned</span>
      <span class="bs-threats ${threats > 0 ? "bs-danger" : "bs-safe"}">${threats} threat${threats !== 1 ? "s" : ""} found</span>
    </div>
    <div class="bulk-table-wrap">
      <table class="bulk-table">
        <thead>
          <tr><th>#</th><th>URL</th><th>Verdict</th><th>Confidence</th><th>Top Signals</th></tr>
        </thead>
        <tbody>
          ${results.map((r, i) => {
            const isP  = r.label === "Phishing";
            const sc   = r.confidence_score || 0;
            const clr  = isP ? (sc >= .8 ? "#ef4444" : "#f97316") : "#22c55e";
            const sigs = (r.threat_signals && r.threat_signals.length)
              ? escHtml(r.threat_signals.slice(0, 2).join(" · "))
              : `<span style="color:#4ade80">Clean</span>`;
            const short = r.url.length > 55 ? r.url.slice(0, 55) + "…" : r.url;
            return `<tr class="bt-row ${isP ? "bt-phish" : "bt-legit"}">
              <td style="color:var(--text-muted);font-size:11px;">${i + 1}</td>
              <td class="bt-url" title="${escHtml(r.url)}">${escHtml(short)}</td>
              <td><span class="verdict-dot" style="background:${clr}"></span><strong style="color:${clr}">${escHtml(r.label)}</strong></td>
              <td><strong style="color:${clr}">${r.confidence}</strong></td>
              <td class="bt-signals">${sigs}</td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>
    </div>`;
}

function exportBulkCSV() {
  if (!_bulkResults.length) return;
  const hdr  = ["#", "URL", "Verdict", "Confidence", "Confidence Score", "Threat Signals"];
  const rows = _bulkResults.map((r, i) => [
    i + 1,
    `"${r.url.replace(/"/g, '""')}"`,
    r.label,
    r.confidence,
    r.confidence_score,
    `"${(r.threat_signals || []).join("; ").replace(/"/g, '""')}"`
  ]);
  const csv  = [hdr, ...rows].map(r => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a    = document.createElement("a");
  a.href     = URL.createObjectURL(blob);
  a.download = `phishshield-bulk-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  toast("CSV downloaded", "success");
}

// ─────────────────────────────────────────────
// PDF REPORT EXPORT  (requires jsPDF CDN)
// ─────────────────────────────────────────────
function exportResultPDF(rawData) {
  if (typeof window.jspdf === "undefined") {
    toast("PDF library loading, please try again in a moment", "warning");
    return;
  }
  const data = typeof rawData === "string" ? JSON.parse(rawData) : rawData;
  const { jsPDF } = window.jspdf;
  const doc  = new jsPDF();
  const now  = new Date().toLocaleString();
  const isP  = data.prediction === 1;
  const [r, g, b] = isP ? [239, 68, 68] : [34, 197, 94];

  // Dark background
  doc.setFillColor(10, 14, 26);
  doc.rect(0, 0, 210, 297, "F");

  // Cyan header bar
  doc.setFillColor(6, 182, 212);
  doc.rect(0, 0, 210, 13, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(9);
  doc.setFont("helvetica", "bold");
  doc.text("PHISHSHIELD AI", 10, 8.5);
  doc.setFont("helvetica", "normal");
  doc.text("Threat Analysis Report", 200, 8.5, { align: "right" });

  let y = 28;

  // Verdict heading
  doc.setTextColor(r, g, b);
  doc.setFontSize(24);
  doc.setFont("helvetica", "bold");
  doc.text(data.label.toUpperCase(), 10, y);
  y += 10;

  doc.setFontSize(12);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(200, 200, 200);
  doc.text(`Confidence: ${data.confidence}`, 10, y);
  y += 8;

  doc.setFontSize(9);
  doc.setTextColor(120, 130, 150);
  doc.text(`Generated: ${now}`, 10, y);
  y += 12;

  // Divider
  doc.setDrawColor(30, 45, 69);
  doc.setLineWidth(0.4);
  doc.line(10, y, 200, y);
  y += 10;

  // URL
  if (data.url) {
    doc.setTextColor(100, 120, 160);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text("ANALYZED URL", 10, y);
    y += 6;
    doc.setFont("helvetica", "normal");
    doc.setTextColor(200, 210, 230);
    doc.setFontSize(9.5);
    const urlLines = doc.splitTextToSize(data.url, 185);
    doc.text(urlLines, 10, y);
    y += urlLines.length * 5 + 8;
  }

  // Threat signals
  if (data.threat_signals && data.threat_signals.length) {
    doc.setTextColor(100, 120, 160);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text("ACTIVE THREAT SIGNALS", 10, y);
    y += 8;
    data.threat_signals.forEach(s => {
      doc.setFillColor(239, 68, 68);
      doc.circle(13.5, y - 1.5, 1.5, "F");
      doc.setFont("helvetica", "normal");
      doc.setTextColor(248, 113, 113);
      doc.setFontSize(10);
      doc.text(s, 18, y);
      y += 7;
    });
    y += 4;
  }

  // Flagged keywords
  if (data.flagged_tokens && data.flagged_tokens.length) {
    doc.setTextColor(100, 120, 160);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text("FLAGGED KEYWORDS", 10, y);
    y += 7;
    doc.setFont("helvetica", "normal");
    doc.setTextColor(249, 115, 22);
    doc.setFontSize(10);
    doc.text(data.flagged_tokens.join("   •   "), 10, y);
    y += 10;
  }

  // Footer
  doc.setDrawColor(30, 45, 69);
  doc.line(10, 282, 200, 282);
  doc.setTextColor(80, 90, 110);
  doc.setFontSize(8);
  doc.text("PhishShield AI  •  Powered by Machine Learning  •  For security research only", 105, 288, { align: "center" });

  doc.save(`phishshield-report-${Date.now()}.pdf`);
  toast("PDF report saved", "success");
}


/* ══════════════════════════════════════════════════════════
   AI EXPLAIN  — contextual threat narrative appended to result
══════════════════════════════════════════════════════════ */
async function fetchAIExplain(scanData, panelId) {
  const panel = document.getElementById(panelId);
  if (!panel) return;

  // Remove stale panel if re-scanning
  const old = panel.querySelector(".ai-explain-panel");
  if (old) old.remove();

  // Skeleton placeholder
  const skeleton = document.createElement("div");
  skeleton.className = "ai-explain-panel ai-explain-loading";
  skeleton.innerHTML = `
    <div class="ai-explain-header">
      <span class="ai-spark">✦</span> AI Threat Analysis
      <span class="ai-thinking">Generating…</span>
    </div>
    <div class="ai-skeleton-lines">
      <div class="ai-sk-line" style="width:94%"></div>
      <div class="ai-sk-line" style="width:80%"></div>
      <div class="ai-sk-line" style="width:87%"></div>
    </div>`;
  panel.appendChild(skeleton);

  try {
    const res = await post("/api/ai-explain", scanData);
    skeleton.remove();

    const uid     = "ait-" + Date.now();
    const explain = document.createElement("div");
    explain.className = "ai-explain-panel";
    const isThreat = scanData.label === "Phishing" || scanData.label === "Spam/Scam";
    explain.innerHTML = `
      <div class="ai-explain-header">
        <span class="ai-spark">✦</span> AI Threat Analysis
        <span class="ai-explain-badge ${isThreat ? "badge-threat" : "badge-safe"}">
          ${isThreat ? "⚠ Threat Detected" : "✓ Clean"}
        </span>
      </div>
      <p class="ai-explain-text" id="${uid}"></p>`;
    panel.appendChild(explain);

    // Typewriter effect
    const el   = explain.querySelector(`#${uid}`);
    const text = res.explanation || "";
    let i = 0;
    const iv = setInterval(() => {
      el.textContent += text[i++];
      if (i >= text.length) clearInterval(iv);
    }, text.length > 420 ? 11 : 17);
  } catch {
    skeleton.remove();
  }
}


/* ══════════════════════════════════════════════════════════
   AI CHAT WIDGET
══════════════════════════════════════════════════════════ */
let _chatOpen   = false;
let _chatInited = false;

function toggleAIChat() {
  _chatOpen = !_chatOpen;
  const panel = document.getElementById("ai-chat-panel");
  const btn   = document.getElementById("ai-chat-btn");
  const badge = document.getElementById("ai-badge");
  panel.classList.toggle("open", _chatOpen);
  btn.classList.toggle("active", _chatOpen);
  if (badge) badge.style.display = "none";

  if (_chatOpen && !_chatInited) {
    _chatInited = true;
    setTimeout(() => {
      addChatMsg("bot", "👋 Hi! I'm your AI security assistant. Ask me anything about phishing, scams, or how PhishShield works.");
      setTimeout(() => {
        const qb = document.createElement("div");
        qb.className = "chat-quick-btns";
        qb.innerHTML = `
          <button onclick="quickAsk('What is phishing?')">What is phishing?</button>
          <button onclick="quickAsk('How to stay safe online?')">Stay safe online</button>
          <button onclick="quickAsk('How does PhishShield work?')">How it works</button>`;
        const msgs = document.getElementById("ai-chat-messages");
        msgs.appendChild(qb);
        msgs.scrollTop = msgs.scrollHeight;
      }, 220);
    }, 340);
  }
  if (_chatOpen) setTimeout(() => document.getElementById("ai-chat-input")?.focus(), 380);
}

function quickAsk(q) {
  addChatMsg("user", q);
  _fetchChatResponse(q);
}

async function sendChat() {
  const inp = document.getElementById("ai-chat-input");
  const msg = inp.value.trim();
  if (!msg) return;
  inp.value = "";
  addChatMsg("user", msg);
  _fetchChatResponse(msg);
}

async function _fetchChatResponse(msg) {
  const typid = "tp-" + Date.now();
  addChatMsg("bot",
    `<span class="ai-typing-dots"><span></span><span></span><span></span></span>`,
    typid);
  try {
    const res = await post("/api/chat", { message: msg });
    document.getElementById(typid)?.remove();
    addChatMsg("bot", res.response || "I couldn't find an answer to that.");
  } catch {
    document.getElementById(typid)?.remove();
    addChatMsg("bot", "Sorry, I'm having trouble connecting. Try again in a moment.");
  }
}

function addChatMsg(role, html, id) {
  const container = document.getElementById("ai-chat-messages");
  if (!container) return;
  const div = document.createElement("div");
  div.className = `chat-msg chat-msg-${role}`;
  if (id) div.id = id;
  div.innerHTML = html;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}
