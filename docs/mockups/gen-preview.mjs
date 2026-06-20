// Generates a self-contained preview of the Spark main screen with Urbanist
// embedded as data URIs (CSP-safe — no font CDN). Mirrors gui-tauri/src/routes/+page.svelte
// exactly: VPNSwitch track 140×70 (indicator 60 + spacing 10 + padding 5), knob travel 70,
// spinner 44/stroke-8; SettingTile card with Lantern's teal elevation shadow; Lantern palette.
import { readFileSync, writeFileSync } from "node:fs";

const FONT_DIR = "../../gui-tauri/node_modules/@fontsource/urbanist/files";
const weights = [400, 500, 600, 700];
const faces = weights
  .map((w) => {
    const b64 = readFileSync(
      new URL(`${FONT_DIR}/urbanist-latin-${w}-normal.woff2`, import.meta.url),
    ).toString("base64");
    return `@font-face{font-family:'Urbanist';font-style:normal;font-weight:${w};font-display:swap;src:url(data:font/woff2;base64,${b64}) format('woff2');}`;
  })
  .join("\n");

// One device frame in a given state. state ∈ {disconnected, connecting, connected}
function frame(state) {
  const connected = state === "connected";
  const connecting = state === "connecting";
  const statusValue =
    state === "connected" ? "Connected" : state === "connecting" ? "Connecting" : "Disconnected";
  const knob = connecting
    ? `<span class="spinner"></span>`
    : `<span class="knob"></span>`;
  return `
  <div class="phone">
    <div class="app">
      <header class="appbar">
        <button class="iconbtn" aria-label="Menu"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg></button>
        <span class="wordmark">Spark</span>
      </header>
      <div class="body">
        <section class="hero">
          <button class="track ${connected ? "on" : ""}" role="switch" aria-checked="${connected}">${knob}</button>
        </section>
        <div class="card">
          <div class="tile">
            <div class="tile-head"><span class="ic">${icons.globe}</span><span class="label">VPN status</span></div>
            <div class="tile-body">
              <span class="value ${connected ? "ok" : ""}">${statusValue}${connecting ? "…" : ""}</span>
              <span class="dot ${connected ? "on" : ""} ${connecting ? "mid" : ""}"></span>
            </div>
          </div>
          <div class="divider"></div>
          <div class="tile">
            <div class="tile-head"><span class="ic">${icons.lock}</span><span class="label">Protocol</span></div>
            <div class="tile-body"><span class="value">AnyTLS</span><span class="chev">${icons.chev}</span></div>
          </div>
          <div class="divider"></div>
          <div class="tile">
            <div class="tile-head"><span class="ic">${icons.route}</span><span class="label">Routing</span></div>
            <div class="tile-body"><span class="value">Full tunnel</span><span class="chev">${icons.chev}</span></div>
          </div>
        </div>
      </div>
    </div>
    <div class="caption">${statusValue}</div>
  </div>`;
}

const icons = {
  globe: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="11" width="15" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`,
  route: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M8.5 19H14a4 4 0 0 0 0-8H10a4 4 0 0 1 0-8h5.5"/></svg>`,
  chev: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>`,
};

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Spark — Main Screen (Lantern-matched)</title>
<style>
${faces}
:root{
  --bg:#f8fafb; --surface:#ffffff; --brand:#00bdd6; --off:#616569; --knob:#ffffff;
  --text-primary:#1b1c1d; --text-secondary:#3e464e; --text-tertiary:#616569;
  --border:#edefef; --success:#00531f; --indicator-off:#dedfdf;
  --shadow:rgba(0,97,98,.098);
  --font:'Urbanist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:#e9eef0;font-family:var(--font);color:var(--text-primary);-webkit-font-smoothing:antialiased;padding:40px 24px 56px}
.head{max-width:1100px;margin:0 auto 8px}
.head h1{font-size:24px;font-weight:700;letter-spacing:-.3px;margin:0 0 4px}
.head p{margin:0;color:#56707a;font-size:14px;font-weight:500;line-height:1.5;max-width:760px}
.head code{background:#dde6e9;border-radius:4px;padding:1px 5px;font-size:12px}
.stage{max-width:1100px;margin:28px auto 0;display:flex;gap:32px;justify-content:center;flex-wrap:wrap}
.phone{display:flex;flex-direction:column;align-items:center;gap:10px}
.caption{font-size:12px;font-weight:600;color:#56707a;letter-spacing:.3px;text-transform:uppercase}
.app{width:340px;height:600px;background:var(--bg);border-radius:28px;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 18px 50px rgba(18,40,46,.22),0 2px 6px rgba(18,40,46,.12);border:1px solid rgba(0,0,0,.04)}

.appbar{height:56px;flex-shrink:0;display:flex;align-items:center;gap:6px;padding:0 10px;background:var(--bg);border-bottom:1px solid var(--border);box-shadow:0 4px 12px rgba(0,97,98,.06)}
.iconbtn{width:40px;height:40px;border:none;background:none;cursor:pointer;display:grid;place-items:center;color:var(--text-tertiary);border-radius:8px}
.wordmark{font-size:22px;font-weight:700;letter-spacing:-.2px;color:var(--text-primary)}

.body{flex:1;display:flex;flex-direction:column;padding:0 16px;min-height:0}
.hero{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px}

.track{position:relative;width:140px;height:70px;border:none;padding:0;cursor:pointer;border-radius:35px;background:var(--off);transition:background .32s ease}
.track.on{background:var(--brand)}
.knob{position:absolute;top:5px;left:5px;width:60px;height:60px;border-radius:50%;background:var(--knob);box-shadow:0 2px 8px rgba(0,0,0,.2);transition:transform .32s cubic-bezier(.4,0,.2,1)}
.track.on .knob{transform:translateX(70px)}
.spinner{position:absolute;top:13px;left:13px;width:44px;height:44px;border-radius:50%;border:8px solid rgba(255,255,255,.35);border-top-color:var(--knob);animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.card{margin:0 0 10px;background:var(--surface);border-radius:16px;box-shadow:0 4px 32px var(--shadow);overflow:hidden;flex-shrink:0}
.tile{padding:10px 16px}
.tile-head{display:flex;align-items:center;gap:8px}
.ic{width:24px;display:inline-flex;justify-content:center;color:var(--text-secondary)}
.label{font-size:14px;font-weight:400;color:var(--text-secondary)}
.tile-body{display:flex;align-items:center;padding-left:32px;margin-top:2px}
.value{flex:1;font-size:16px;font-weight:600;color:var(--text-primary)}
.value.ok{color:var(--success)}
.chev{color:var(--text-tertiary);display:inline-flex}
.dot{width:10px;height:10px;border-radius:50%;background:var(--indicator-off)}
.dot.on{background:var(--success)}
.dot.mid{background:var(--brand)}
.divider{height:1px;background:var(--border);margin:0 16px}
</style>
</head>
<body>
<div class="head">
  <h1>Spark — main screen, matched to getlantern/lantern</h1>
  <p>Rendered from the same values as <code>gui-tauri/src/routes/+page.svelte</code>, verified against the Flutter source: <code>home.dart</code>, <code>vpn_switch.dart</code> (track 140×70, knob travel 70, spinner stroke 8), <code>setting_tile.dart</code>, and the design-system tokens (Urbanist; palette blue4/gray/green8; teal elevation shadow <code>rgba(0,97,98,.098)</code>). Wordmark shows “Spark”.</p>
</div>
<div class="stage">
  ${frame("disconnected")}
  ${frame("connecting")}
  ${frame("connected")}
</div>
</body>
</html>`;

writeFileSync(new URL("./spark-lantern-screen.html", import.meta.url), html);
console.log("wrote spark-lantern-screen.html", (html.length / 1024).toFixed(0) + "KB");
