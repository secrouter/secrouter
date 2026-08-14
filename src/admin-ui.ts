/**
 * SecRouter admin console — a dependency-free single-page app served by the
 * router at GET /admin. Authenticates via OIDC Authorization Code + PKCE
 * (browser), then drives the admin-gated /admin/api/* endpoints.
 *
 * Built with the DOM API (no template literals) so the markup can live safely
 * inside this exported string. Tabs: Usage, Users & Policies, Models, Audit.
 */

export const ADMIN_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SecRouter Admin</title>
<style>
  /* "Field console" theme — warm manila paper, olive drab, oxide red. System fonts only (air-gapped). */
  :root {
    --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    /* light: warm manila "field console" */
    --bg:#e7e3d8; --panel:#f3f0e8; --panel2:#fbfaf4; --fg:#211f18; --muted:#6c6552;
    --accent:#4f6a2e; --accent-ink:#f6f3ea; --accent-soft:rgba(79,106,46,.18);
    --ok:#2f5a22; --warn:#8a5a12; --bad:#8a2b1d;
    --border:#cdc6b2; --rule:#dad4c2; --shadow:2px 2px 0 rgba(33,31,24,.06);
    --pill-bg:#e2ddcd; --pill-ok-bg:#e3ebd7; --pill-ok-bd:#b9c9a8;
    --pill-bad-bg:#f0ddd7; --pill-bad-bd:#d8b3aa; --pill-warn-bg:#efe6cf; --pill-warn-bd:#d8c69a;
    --code-bg:#e2ddcd;
  }
  /* dark: warm "night ops" — same identity, charcoal + brighter olive/terracotta */
  :root[data-theme="dark"] {
    --bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
    --accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
    --ok:#86b257; --warn:#cb9c3e; --bad:#d4634c;
    --border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
    --pill-bg:#2b2920; --pill-ok-bg:#26331c; --pill-ok-bd:#3f5230;
    --pill-bad-bg:#37201a; --pill-bad-bd:#5c2f25; --pill-warn-bg:#332a17; --pill-warn-bd:#544321;
    --code-bg:#2b2920;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
      --accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
      --ok:#86b257; --warn:#cb9c3e; --bad:#d4634c;
      --border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
      --pill-bg:#2b2920; --pill-ok-bg:#26331c; --pill-ok-bd:#3f5230;
      --pill-bad-bg:#37201a; --pill-bad-bd:#5c2f25; --pill-warn-bg:#332a17; --pill-warn-bd:#544321;
      --code-bg:#2b2920;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.55 var(--sans); background:var(--bg); color:var(--fg);
         background-image:linear-gradient(var(--rule) 1px, transparent 1px); background-size:100% 28px; background-attachment:fixed; }
  header { display:flex; align-items:center; gap:14px; padding:14px 22px; background:var(--panel);
           border-bottom:1px solid var(--border); border-top:3px solid var(--accent); }
  header h1 { font-size:15px; margin:0; font-weight:700; text-transform:uppercase; letter-spacing:.14em; }
  header .lock { color:var(--accent); }
  header .who { margin-left:auto; color:var(--muted); font:11px var(--mono); text-transform:uppercase; letter-spacing:.08em; }
  nav { display:flex; gap:2px; padding:0 18px; background:var(--panel); border-bottom:1px solid var(--border); }
  nav button { background:none; border:none; color:var(--muted); padding:11px 16px; cursor:pointer;
               border-bottom:2px solid transparent; font:11px var(--mono); text-transform:uppercase; letter-spacing:.1em; }
  nav button:hover { color:var(--fg); }
  nav button.active { color:var(--accent); border-bottom-color:var(--accent); font-weight:700; }
  main { padding:24px 22px; max-width:1080px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:2px; padding:18px; margin-bottom:16px;
          box-shadow:var(--shadow); }
  .card h3, main > h3 { margin:0 0 12px; font:11px var(--mono); font-weight:700; text-transform:uppercase; letter-spacing:.12em;
          color:var(--muted); display:flex; align-items:center; gap:8px; padding-bottom:8px; border-bottom:1px solid var(--rule); }
  main > h3 { margin-top:26px; border:none; padding:0; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin:8px 0; }
  label { color:var(--muted); font:11px var(--mono); text-transform:uppercase; letter-spacing:.06em; min-width:120px; }
  input, select { background:var(--panel2); color:var(--fg); border:1px solid var(--border); border-radius:2px; padding:6px 9px; font:13px var(--mono); }
  input:focus, select:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 2px var(--accent-soft); }
  input[type=number] { width:120px; } input[type=text] { min-width:240px; }
  input[type=checkbox] { accent-color:var(--accent); width:15px; height:15px; }
  button.btn { background:var(--accent); color:var(--accent-ink); border:1px solid var(--accent); border-radius:2px;
               padding:7px 14px; cursor:pointer; font:11px var(--mono); text-transform:uppercase; letter-spacing:.08em; }
  button.btn:hover { filter:brightness(1.08); }
  button.btn.ghost { background:var(--panel2); color:var(--fg); border-color:var(--border); }
  button.btn.danger { background:var(--bad); border-color:var(--bad); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--rule); }
  td { font:12.5px var(--mono); }
  th { color:var(--muted); font:10px var(--mono); font-weight:700; text-transform:uppercase; letter-spacing:.1em; border-bottom:1px solid var(--border); }
  tr:last-child td { border-bottom:none; }
  .bar { height:12px; background:var(--accent); border-radius:1px; }
  .pill { display:inline-block; padding:2px 7px; border-radius:2px; font:10px var(--mono); text-transform:uppercase; letter-spacing:.06em;
          background:var(--pill-bg); color:var(--muted); border:1px solid var(--border); }
  .pill.ok { color:var(--ok); border-color:var(--pill-ok-bd); background:var(--pill-ok-bg); }
  .pill.bad { color:var(--bad); border-color:var(--pill-bad-bd); background:var(--pill-bad-bg); }
  .pill.warn { color:var(--warn); border-color:var(--pill-warn-bd); background:var(--pill-warn-bg); }
  .muted { color:var(--muted); } .ro { opacity:.85; }
  .theme-toggle { padding:5px 11px; }
  .toast { position:fixed; bottom:22px; right:22px; background:var(--panel); border:1px solid var(--border);
           border-left:3px solid var(--accent); padding:11px 16px; border-radius:2px; font-size:13px; box-shadow:var(--shadow); }
  .checks { display:flex; gap:14px; flex-wrap:wrap; } .checks label { min-width:auto; display:flex; gap:5px; align-items:center; }
  .center { text-align:center; padding:70px 20px; }
  pre { font:12px var(--mono); background:var(--panel2); border:1px solid var(--rule); border-radius:2px; padding:10px; overflow:auto; }
  code { background:var(--code-bg); padding:1px 5px; border-radius:2px; font:12px var(--mono); }
  details summary { cursor:pointer; padding:6px 0; color:var(--accent); }
</style>
<script>
  /* Apply the saved theme before first paint (no flash). Default = follow OS. */
  (function(){ try { var t = localStorage.getItem('secrouter-theme'); if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t); } catch (e) {} })();
</script>
</head>
<body>
<div id="app"><div class="center muted">Loading…</div></div>
<script>
(function(){
  var TIERS = ["SIMPLE","MEDIUM","COMPLEX","REASONING"];
  // Built-in default providers baked into config.ts's DEFAULT_CONFIG. deepMerge
  // always folds these under the file config, so removing a file-defined
  // provider of the same name (POST /admin/api/endpoint/remove) writes a clean
  // file, but the built-in resurfaces after reload — with no egress rule, so
  // deny-by-default blocks it (fail-closed, not a routing/egress hole). Surfaced
  // as a card note rather than hidden.
  var BUILTIN_PROVIDERS = ["bedrock"];
  var state = { token:null, oidc:null, cfg:null };

  // ── Theme (light / dark, follows OS by default, choice persisted) ──
  function effectiveTheme(){ var a=document.documentElement.getAttribute("data-theme"); if(a==="dark"||a==="light") return a; return (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light"; }
  function setTheme(t){ document.documentElement.setAttribute("data-theme", t); try { localStorage.setItem("secrouter-theme", t); } catch(e){} var b=document.querySelector(".theme-toggle"); if(b) b.textContent = effectiveTheme()==="dark" ? "LIGHT" : "DARK"; }
  function toggleTheme(){ setTheme(effectiveTheme()==="dark" ? "light" : "dark"); }

  function el(tag, attrs, kids){
    var n = document.createElement(tag);
    if (attrs) for (var k in attrs){
      if (k==="class") n.className=attrs[k];
      else if (k==="text") n.textContent=attrs[k];
      else if (k==="html") n.innerHTML=attrs[k];
      else if (k==="onclick") n.onclick=attrs[k];
      else if (k==="onchange") n.onchange=attrs[k];
      else if (k==="value") n.value=attrs[k];
      else if (k==="checked") { if(attrs[k]) n.checked=true; }
      else if (k==="disabled") { if(attrs[k]) n.disabled=true; }
      else n.setAttribute(k, attrs[k]);
    }
    if (kids!=null) (Array.isArray(kids)?kids:[kids]).forEach(function(c){
      if (c==null) return; n.appendChild(typeof c==="string"?document.createTextNode(c):c);
    });
    return n;
  }
  function $(id){ return document.getElementById(id); }
  function toast(msg, bad){ var t=el("div",{class:"toast",text:msg}); if(bad)t.style.borderLeftColor="var(--bad)"; document.body.appendChild(t); setTimeout(function(){t.remove();},2500); }
  function usd(n){ return "$"+(Math.round((n||0)*1e4)/1e4); }
  // Render a string-or-array config field (baseUrl, allowedHost — both accept
  // a pooled/multi-host array) as a readable comma list, never an implicit
  // Array.toString(). "—" for empty/missing.
  function listText(v){ if(Array.isArray(v)) return v.length?v.join(", "):"—"; return v||"—"; }
  // Circuit-breaker state → {cls,label} pill, shared by Monitor and Models tabs.
  function healthState(s){ return ({ closed:{cls:"ok",label:"healthy"}, "half-open":{cls:"warn",label:"half-open"}, open:{cls:"bad",label:"open"} })[s] || {cls:"muted",label:s||"unknown"}; }

  // ── PKCE ──
  function b64url(buf){ return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,""); }
  function randHex(n){ var a=new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a).map(function(x){return ("0"+x.toString(16)).slice(-2);}).join(""); }
  function sha256(s){ return crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); }
  function redirectUri(){ return location.origin + location.pathname; }

  function login(){
    fetch(state.oidc.issuer.replace(/\\/$/,"")+"/.well-known/openid-configuration").then(function(r){return r.json();}).then(function(disc){
      var verifier = randHex(48);
      sessionStorage.setItem("pkce_verifier", verifier);
      sessionStorage.setItem("pkce_token_ep", disc.token_endpoint);
      sha256(verifier).then(function(hash){
        var u = new URL(disc.authorization_endpoint);
        u.searchParams.set("response_type","code");
        u.searchParams.set("client_id", state.oidc.clientId);
        u.searchParams.set("redirect_uri", redirectUri());
        u.searchParams.set("scope", state.oidc.scopes);
        u.searchParams.set("code_challenge", b64url(hash));
        u.searchParams.set("code_challenge_method","S256");
        location.href = u.toString();
      });
    });
  }
  function exchange(code){
    var verifier = sessionStorage.getItem("pkce_verifier");
    var tokenEp = sessionStorage.getItem("pkce_token_ep");
    var body = new URLSearchParams({ grant_type:"authorization_code", code:code, redirect_uri:redirectUri(), client_id:state.oidc.clientId, code_verifier:verifier });
    return fetch(tokenEp, { method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:body })
      .then(function(r){return r.json();}).then(function(j){
        if (j.access_token){ sessionStorage.setItem("access_token", j.access_token); state.token=j.access_token; }
        history.replaceState({},"",redirectUri());
      });
  }

  function api(path, opts){
    opts = opts || {}; opts.headers = opts.headers || {};
    if (state.token) opts.headers["Authorization"]="Bearer "+state.token;
    if (opts.body && typeof opts.body!=="string"){ opts.body=JSON.stringify(opts.body); opts.headers["Content-Type"]="application/json"; }
    return fetch(path, opts).then(function(r){
      if (r.status===401){ sessionStorage.removeItem("access_token"); if(state.oidc&&state.oidc.enabled) login(); throw new Error("unauthorized"); }
      return r;
    });
  }

  // ── Shell ──
  var TAB = "monitor";
  function shell(){
    var app = $("app"); app.innerHTML="";
    var head = el("header", {}, [
      el("span",{class:"lock",text:"🔒"}), el("h1",{text:"SecRouter Admin"}),
      el("span",{class:"who",text: state.token? "authenticated":"dev mode (open)"}),
      el("button",{class:"btn ghost theme-toggle",title:"Toggle light / dark",text:(effectiveTheme()==="dark"?"LIGHT":"DARK"),onclick:toggleTheme})
    ]);
    var nav = el("nav");
    [["monitor","Monitor"],["policies","Policies"],["models","Models"]].forEach(function(t){
      nav.appendChild(el("button",{class:(TAB===t[0]?"active":""),text:t[1],onclick:function(){TAB=t[0];shell();}}));
    });
    var main = el("main",{id:"main"}, el("div",{class:"muted",text:"Loading…"}));
    app.appendChild(head); app.appendChild(nav); app.appendChild(main);
    if (TAB==="monitor") renderMonitor(main);
    else if (TAB==="policies") renderUsers(main);
    else if (TAB==="models") renderModels(main);
  }

  // Monitor = Compliance + Provider health + Usage + Audit (read-only), stacked.
  function renderMonitor(main){
    main.innerHTML="";
    var compBox = el("div"); var healthBox = el("div"); var mcpBox = el("div"); var usageBox = el("div"); var auditBox = el("div");
    main.appendChild(compBox); main.appendChild(healthBox); main.appendChild(mcpBox); main.appendChild(usageBox); main.appendChild(auditBox);
    renderCompliance(compBox);
    renderHealth(healthBox);  // each renders into (and clears) its own container
    renderMcpServers(mcpBox);
    renderUsage(usageBox);
    renderAudit(auditBox);
  }

  // ── MCP tool servers: the governed tool gateway registry (Phase D) ──
  function renderMcpServers(main){
    main.innerHTML="";
    var mcp = (state.cfg&&state.cfg.mcp)||{enabled:false,servers:[]};
    if(!mcp.enabled || !(mcp.servers||[]).length) return; // gateway off / no servers → hide
    var card = el("div",{class:"card"}, el("h3",{},["MCP tool servers ", el("span",{class:"pill",text:"gateway · AC 3.1.3/3.1.5"})]));
    card.appendChild(el("div",{class:"muted",style:"font-size:12px;margin:-4px 0 10px;",text:"Registered upstream servers SecRouter brokers. Tools are deny-by-default per principal — grant them under Users → Allowed tools."}));
    (mcp.servers||[]).forEach(function(s){
      var out = el("span",{class:"muted"});
      function probe(){
        out.innerHTML=""; out.appendChild(el("span",{class:"muted",text:"probing…"}));
        api("/admin/api/mcp/probe",{method:"POST",body:{name:s.name}}).then(function(r){return r.json();}).then(function(j){
          out.innerHTML="";
          if(j.ok){ out.appendChild(el("span",{class:"pill ok",text:(j.tools||[]).length+" tools"})); if((j.tools||[]).length) out.appendChild(el("span",{class:"muted",text:" "+j.tools.join(", ")})); }
          else out.appendChild(el("span",{class:"pill bad",text:"unreachable: "+(j.error||"error")}));
        }).catch(function(){ out.innerHTML=""; out.appendChild(el("span",{class:"pill bad",text:"probe failed"})); });
      }
      card.appendChild(el("div",{class:"row"},[
        el("code",{text:s.name}), el("span",{class:"muted",text:s.url}),
        el("span",{class:"pill",text:(s.authorizedClassifications||[]).join(" / ")}),
        el("button",{class:"btn ghost",text:"Probe tools",onclick:probe}), out
      ]));
    });
    main.appendChild(card);
  }

  // ── Provider health: circuit-breaker state per upstream (Phase C / SC availability) ──
  function renderHealth(main){
    var STATE = { closed:{cls:"ok",label:"healthy"}, "half-open":{cls:"warn",label:"half-open"}, open:{cls:"bad",label:"open"} };
    function fmt(iso){ try { return new Date(iso).toLocaleTimeString(); } catch(e){ return iso; } }
    function load(){
      main.innerHTML="";
      var card = el("div",{class:"card"}, el("h3",{},["Provider health ", el("span",{class:"pill",text:"circuit breaker · SC"})]));
      api("/admin/api/health").then(function(r){return r.json();}).then(function(d){
        var r = d.resilience||{};
        card.appendChild(el("div",{class:"muted",style:"font-size:12px;margin:-4px 0 10px;",
          text:"Trips open after "+r.circuitThreshold+" consecutive failures; "+r.cooldownSec+"s cooldown before a half-open probe. "+(r.healthIntervalSec?("Active checks every "+r.healthIntervalSec+"s."):"Passive (no background checks).")}));
        var t = el("table",{}, el("tr",{},[el("th",{text:"provider"}),el("th",{text:"state"}),el("th",{text:"consec. fails"}),el("th",{text:"total fail / ok"}),el("th",{text:"last latency"}),el("th",{text:"last ok"}),el("th",{text:"last fail"})]));
        // A pooled provider (>1 endpoint) reports one row per endpoint — label
        // those "name#idx" so they're distinguishable; a single-endpoint
        // provider still shows its bare name (today's shape, unchanged).
        var rowsPerProvider = {}; (d.providers||[]).forEach(function(p){ rowsPerProvider[p.provider]=(rowsPerProvider[p.provider]||0)+1; });
        (d.providers||[]).forEach(function(p){
          var s = STATE[p.state]||{cls:"muted",label:p.state||"unknown"};
          var label = p.provider + (rowsPerProvider[p.provider]>1 ? "#"+p.endpoint : "");
          t.appendChild(el("tr",{},[
            el("td",{text:label}),
            el("td",{}, el("span",{class:"pill "+s.cls,text:s.label})),
            el("td",{text:String(p.consecutiveFailures||0)}),
            el("td",{class:"muted",text:(p.totalFailures||0)+" / "+(p.totalSuccesses||0)}),
            el("td",{class:"muted",text:(p.lastLatencyMs!=null?(p.lastLatencyMs+" ms"):"—")}),
            el("td",{class:"muted",text:(p.lastSuccess?fmt(p.lastSuccess):"—")}),
            el("td",{class:"muted",text:(p.lastFailure?fmt(p.lastFailure):"—")})
          ]));
        });
        if(!(d.providers||[]).length) t.appendChild(el("tr",{},el("td",{class:"muted",colspan:"7",text:"No providers configured."})));
        card.appendChild(t);
        card.appendChild(el("div",{class:"row"},[el("button",{class:"btn ghost",text:"Refresh",onclick:load})]));
        main.appendChild(card);
      }).catch(function(e){ card.appendChild(el("div",{class:"muted",text:"Could not load provider health: "+e.message})); main.appendChild(card); });
    }
    load();
  }

  // ── Compliance evidence: verify the audit hash chain + export an assessor bundle ──
  function renderCompliance(main){
    main.innerHTML="";
    var result = el("span",{class:"muted"});
    function verify(){
      result.innerHTML=""; result.appendChild(el("span",{class:"muted",text:"verifying…"}));
      api("/admin/api/audit/verify").then(function(r){return r.json();}).then(function(j){
        result.innerHTML="";
        result.appendChild(el("span",{class:"pill "+(j.ok?"ok":"bad"),text:(j.ok?"chain intact":"BROKEN at id "+j.brokenAtId)}));
        result.appendChild(el("span",{class:"muted",text:" "+j.checked+" events checked"}));
      }).catch(function(e){ result.innerHTML=""; result.appendChild(el("span",{class:"pill bad",text:"verify failed: "+e.message})); });
    }
    function download(){
      result.innerHTML=""; result.appendChild(el("span",{class:"muted",text:"building bundle…"}));
      api("/admin/api/evidence").then(function(r){return r.blob();}).then(function(b){
        var url=URL.createObjectURL(b);
        var a=el("a",{href:url,download:"secrouter-evidence-"+new Date().toISOString().slice(0,10)+".json"});
        document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        result.innerHTML=""; result.appendChild(el("span",{class:"pill ok",text:"evidence bundle downloaded"}));
      }).catch(function(e){ result.innerHTML=""; result.appendChild(el("span",{class:"pill bad",text:"download failed: "+e.message})); });
    }
    main.appendChild(el("div",{class:"card"}, [
      el("h3",{},["Compliance evidence ", el("span",{class:"pill",text:"CMMC · 800-171"})]),
      el("div",{class:"row"},[
        el("button",{class:"btn",text:"Verify audit chain",onclick:verify}),
        el("button",{class:"btn ghost",text:"Download evidence bundle",onclick:download}),
        result
      ]),
      el("div",{class:"muted",style:"font-size:12px;margin-top:4px;",text:"Verify the tamper-evident audit hash chain (AU 3.3.8), or export config, audit, usage, FIPS posture and a live control self-assessment as one JSON artifact for your assessor."})
    ]));
  }

  // ── Usage tab ──
  function renderUsage(main){
    var groupBy = "principal";
    function load(){
      main.innerHTML="";
      var ctrl = el("div",{class:"row"}, [
        el("label",{text:"Group by"}),
        el("select",{onchange:function(e){groupBy=e.target.value;load();}}, ["principal","model","day"].map(function(g){
          return el("option",{value:g,text:g,selected:(g===groupBy?"":null)});
        }))
      ]);
      // reflect current selection
      ctrl.querySelector("select").value = groupBy;
      main.appendChild(ctrl);
      api("/admin/api/usage?days=30&groupBy="+groupBy).then(function(r){return r.json();}).then(function(d){
        var rows = d.breakdown||[];
        var max = rows.reduce(function(m,x){return Math.max(m,x.costUsd||0);},0)||1;
        var card = el("div",{class:"card"}, el("h3",{text:"Usage — last 30 days by "+groupBy}));
        var t = el("table",{}, el("tr",{},[el("th",{text:groupBy}),el("th",{text:"requests"}),el("th",{text:"in tok"}),el("th",{text:"out tok"}),el("th",{text:"cost"}),el("th",{text:""})]));
        rows.forEach(function(x){
          var bar = el("div",{class:"bar"}); bar.style.width = Math.max(2, (x.costUsd/max)*180)+"px";
          t.appendChild(el("tr",{},[
            el("td",{text:x.key}), el("td",{text:String(x.requestCount)}),
            el("td",{text:String(x.inputTokens)}), el("td",{text:String(x.outputTokens)}),
            el("td",{text:usd(x.costUsd)}), el("td",{}, bar)
          ]));
        });
        if(!rows.length) t.appendChild(el("tr",{},el("td",{class:"muted",colspan:"6",text:"No usage recorded yet."})));
        card.appendChild(t); main.appendChild(card);
      }).catch(function(e){ main.appendChild(el("div",{class:"muted",text:"Could not load usage: "+e.message})); });
    }
    load();
  }

  // ── policy form ──
  function tierChecks(sel){
    return el("div",{class:"checks"}, TIERS.map(function(t){
      var c = el("input",{type:"checkbox",value:t}); if(sel&&sel.indexOf(t)>=0)c.checked=true;
      return el("label",{},[c,t]);
    }));
  }
  function getChecks(div){ return Array.prototype.slice.call(div.querySelectorAll("input:checked")).map(function(c){return c.value;}); }
  function num(v){ return (v===""||v==null)?undefined:Number(v); }

  function policyCard(scope, name, rule, levels, models, isNew, tools){
    rule = rule||{};
    var budgets = rule.budgets||[];
    var dayCost = (budgets.filter(function(b){return b.window==="day";})[0]||{}).maxCostUsd;
    var rpm = (budgets.filter(function(b){return b.window==="minute";})[0]||{}).maxRequests;
    var tiersDiv = tierChecks(rule.allowedTiers);
    var nameInput = el("input",{type:"text",value:name||"", placeholder:(scope==="policy.group"?"group name":"user id (sub)")});
    var maxTierSel = el("select",{}, [el("option",{value:"",text:"(none)"})].concat(TIERS.map(function(t){return el("option",{value:t,text:t});})));
    if(rule.maxTier) maxTierSel.value=rule.maxTier;
    var adminChk = el("input",{type:"checkbox"}); if(rule.admin)adminChk.checked=true;
    var onViol = el("select",{}, ["deny","downgrade"].map(function(v){return el("option",{value:v,text:v});})); if(rule.onViolation)onViol.value=rule.onViolation;
    var classSel = el("select",{}, [el("option",{value:"",text:"(default)"})].concat((levels||[]).map(function(l){return el("option",{value:l,text:l});}))); if(rule.maxClassification)classSel.value=rule.maxClassification;
    var dayCostIn = el("input",{type:"number",value:(dayCost==null?"":dayCost),placeholder:"$/day"});
    var rpmIn = el("input",{type:"number",value:(rpm==null?"":rpm),placeholder:"req/min"});
    var allowModelsDiv = el("div",{class:"checks"}, (models||[]).map(function(m){
      var c=el("input",{type:"checkbox",value:m.id}); if(rule.allowedModels&&rule.allowedModels.indexOf(m.id)>=0)c.checked=true;
      return el("label",{title:m.name},[c, m.id.split("/").pop()]);
    }));
    // MCP tool allow-list (Phase D). Default-deny: no checks ⇒ no tools for this principal.
    var toolIds = tools||[];
    var allowToolsDiv = el("div",{class:"checks"}, toolIds.map(function(t){
      var c=el("input",{type:"checkbox",value:t}); if(rule.allowedTools&&rule.allowedTools.indexOf(t)>=0)c.checked=true;
      return el("label",{title:t},[c, t]);
    }));

    function save(){
      var nm = (nameInput.value||"").trim(); if(!nm){toast("name required",true);return;}
      var b=[]; if(dayCostIn.value!=="") b.push({window:"day",maxCostUsd:Number(dayCostIn.value)});
      if(rpmIn.value!=="") b.push({window:"minute",maxRequests:Number(rpmIn.value)});
      var allowModels = getChecks(allowModelsDiv);
      var allowTools = getChecks(allowToolsDiv);
      var body = {
        allowedTiers: getChecks(tiersDiv),
        maxTier: maxTierSel.value||undefined,
        admin: adminChk.checked||undefined,
        onViolation: onViol.value||undefined,
        maxClassification: classSel.value||undefined,
        allowedModels: allowModels.length?allowModels:undefined,
        allowedTools: allowTools.length?allowTools:undefined,
        budgets: b.length?b:undefined
      };
      var seg = scope==="policy.group"?"group":"user";
      api("/admin/api/policy/"+seg+"/"+encodeURIComponent(nm),{method:"PUT",body:body}).then(function(r){
        if(r.ok){toast("Saved "+nm); loadConfig().then(function(){shell();});} else r.json().then(function(j){toast(j.error?j.error.message:"rejected",true);});
      });
    }
    function del(){
      var seg = scope==="policy.group"?"group":"user";
      api("/admin/api/policy/"+seg+"/"+encodeURIComponent(name),{method:"DELETE"}).then(function(){toast("Deleted "+name); loadConfig().then(function(){shell();});});
    }

    var rows = [
      el("div",{class:"row"},[el("label",{text:"Name"}), nameInput]),
      el("div",{class:"row"},[el("label",{text:"Allowed tiers"}), tiersDiv]),
      el("div",{class:"row"},[el("label",{text:"Max tier"}), maxTierSel, el("label",{text:"On violation"}), onViol]),
      el("div",{class:"row"},[el("label",{text:"Admin"}), adminChk, el("label",{text:"Max classification"}), classSel]),
      el("div",{class:"row"},[el("label",{text:"Daily cost cap"}), dayCostIn, el("label",{text:"Rate (rpm)"}), rpmIn]),
      el("div",{class:"row"},[el("label",{text:"Allowed models"}), allowModelsDiv]),
      toolIds.length?el("div",{class:"row"},[el("label",{text:"Allowed tools",title:"MCP tools (server/tool). Default-deny: none checked = no tools."}), allowToolsDiv]):null,
      el("div",{class:"row"},[el("button",{class:"btn",text:"Save",onclick:save}), isNew?null:el("button",{class:"btn danger",text:"Delete",onclick:del})])
    ];
    return el("div",{class:"card"}, [el("h3",{},[ (scope==="policy.group"?"Group: ":"User: "), el("code",{text:name||"(new)"}) ])].concat(rows));
  }

  // Discover MCP tools (once per session) so policy cards can offer tool chips.
  function discoverTools(){
    var servers=(state.cfg.mcp&&state.cfg.mcp.servers)||[];
    if(!servers.length){ state.knownTools=[]; return Promise.resolve(); }
    return Promise.all(servers.map(function(s){
      return api("/admin/api/mcp/probe",{method:"POST",body:{name:s.name}}).then(function(r){return r.json();}).then(function(j){return (j&&j.ok&&j.tools)||[];}).catch(function(){return [];});
    })).then(function(lists){ var all=[]; lists.forEach(function(l){l.forEach(function(t){if(all.indexOf(t)<0)all.push(t);});}); state.knownTools=all; });
  }

  function renderUsers(main){
    main.innerHTML="";
    var cfg = state.cfg; var pol = cfg.policy||{default:{},groups:{},users:{}};
    var levels = (cfg.classification&&cfg.classification.levels)||[];
    var models = cfg.knownModels||[];
    var tools = state.knownTools||[];
    var hasServers = ((cfg.mcp&&cfg.mcp.servers)||[]).length>0;
    // First visit with MCP servers configured: probe for tools, then re-render with chips.
    if(hasServers && state.knownTools===undefined){ discoverTools().then(function(){ renderUsers(main); }); }
    main.appendChild(el("div",{class:"card ro"},[el("h3",{text:"Default policy (the floor for everyone — edit in the config file)"}),
      el("pre",{class:"muted",text:JSON.stringify(pol.default||{},null,2)})]));
    main.appendChild(el("h3",{text:"Groups"}));
    Object.keys(pol.groups||{}).forEach(function(g){ main.appendChild(policyCard("policy.group",g,pol.groups[g],levels,models,false,tools)); });
    main.appendChild(el("details",{}, [el("summary",{class:"muted",text:"+ Add group"}), policyCard("policy.group","",{},levels,models,true,tools)]));
    main.appendChild(el("h3",{text:"Per-user overrides"}));
    Object.keys(pol.users||{}).forEach(function(u){ main.appendChild(policyCard("policy.user",u,pol.users[u],levels,models,false,tools)); });
    main.appendChild(el("details",{}, [el("summary",{class:"muted",text:"+ Add user override"}), policyCard("policy.user","",{},levels,models,true,tools)]));
  }

  // ── Add-endpoint wizard (writes the config FILE, then reload/restart) ──
  function buildEndpointWizard(levels){
    var wrap = el("div",{class:"card"});
    var st = {};
    var nameIn = el("input",{type:"text",placeholder:"name (e.g. onprem-vllm)"});
    var urlIn  = el("input",{type:"text",placeholder:"https://llm.internal:8000/v1"});
    var apiSel = el("select",{}, ["openai","anthropic","bedrock","azure"].map(function(a){return el("option",{value:a,text:a});}));
    // Azure deployment API needs an api-version + auth mode (shown only for azure).
    var apiVerIn = el("input",{type:"text",value:"2024-10-21",title:"Azure REST api-version",style:"width:120px;display:none"});
    var azAuthSel = el("select",{title:"Azure auth mode",style:"display:none"}, [["api-key","api-key"],["entra","entra"]].map(function(a){return el("option",{value:a[0],text:a[1]});}));
    apiSel.onchange=function(){ var az=apiSel.value==="azure"; apiVerIn.style.display=az?"":"none"; azAuthSel.style.display=az?"":"none"; };
    var authSel= el("select",{}, [["none","no auth"],["env","env var"],["token","one-time token"]].map(function(a){return el("option",{value:a[0],text:a[1]});}));
    var authVal= el("input",{type:"text",placeholder:"",style:"display:none"});
    authSel.onchange=function(){
      authVal.style.display = authSel.value==="none"?"none":"";
      authVal.type = authSel.value==="token"?"password":"text";
      authVal.placeholder = authSel.value==="env" ? "env var name (e.g. LOCAL_LLM_API_KEY)" : "token (test only — never stored)";
    };
    var modelsBox = el("div"), egressBox = el("div");

    function authFields(){
      if(authSel.value==="env")   return { authEnvKey: authVal.value.trim()||undefined };
      if(authSel.value==="token") return { authToken: authVal.value||undefined };
      return {};
    }
    function test(){
      var bu=urlIn.value.trim(); if(!bu){toast("base URL required",true);return;}
      var body={ baseUrl:bu, api:apiSel.value };
      var af=authFields(); for(var k in af) body[k]=af[k];
      modelsBox.innerHTML=""; modelsBox.appendChild(el("span",{class:"muted",text:"testing…"}));
      api("/admin/api/endpoint/probe",{method:"POST",body:body}).then(function(r){return r.json();}).then(function(res){
        modelsBox.innerHTML="";
        if(!res.ok){ modelsBox.appendChild(el("div",{class:"pill bad",text:"unreachable: "+(res.error||"error")})); return; }
        if(!(res.models && res.models.length)){
          modelsBox.appendChild(el("div",{class:"pill warn",text:"reachable, but no models listed — check the base URL (include /v1)"}));
          return;
        }
        toast("Reachable ("+(res.latencyMs||"?")+"ms) · "+res.models.length+" models");
        renderPick(res.models);
      }).catch(function(e){ modelsBox.innerHTML=""; modelsBox.appendChild(el("div",{class:"pill bad",text:"probe failed: "+e.message})); });
    }
    function renderPick(ids){
      modelsBox.innerHTML="";
      modelsBox.appendChild(el("div",{class:"pill ok",text:"reachable — select models + price them ($/Mtok, 0 = self-hosted)"}));
      st.rows = ids.map(function(id){
        var chk=el("input",{type:"checkbox",value:id}); chk.checked=true;
        var inP=el("input",{type:"number",value:"0"}); inP.style.width="80px";
        var outP=el("input",{type:"number",value:"0"}); outP.style.width="80px";
        var emb=el("input",{type:"checkbox"});
        modelsBox.appendChild(el("div",{class:"row"},[ el("label",{},[chk," "+id]),
          el("span",{class:"muted",text:"in"}),inP, el("span",{class:"muted",text:"out"}),outP,
          el("label",{title:"embedding model — served on /v1/embeddings, never routed for chat"},[emb," embedding"]) ]));
        return { id:id, chk:chk, inP:inP, outP:outP, emb:emb };
      });
      egressBox.innerHTML="";
      var host=""; try{ host=new URL(urlIn.value.trim()).host; }catch(e){}
      st.hostIn=el("input",{type:"text",value:host,placeholder:"host:port"});
      st.classDiv=el("div",{class:"checks"}, (levels||[]).map(function(l){ return el("label",{},[el("input",{type:"checkbox",value:l}),l]); }));
      st.tierDiv=el("div",{class:"checks"}, TIERS.map(function(t){ return el("label",{},[el("input",{type:"checkbox",value:t}),t]); }));
      st.result=el("div");
      egressBox.appendChild(el("div",{class:"row"},[el("label",{text:"Egress host"}),st.hostIn]));
      egressBox.appendChild(el("div",{class:"row"},[el("label",{text:"Classifications"}),st.classDiv]));
      egressBox.appendChild(el("div",{class:"row"},[el("label",{text:"Primary for tier"}),st.tierDiv]));
      egressBox.appendChild(el("div",{class:"row"},[
        el("button",{class:"btn ghost",text:"Validate",onclick:function(){submit("preview");}}),
        el("button",{class:"btn",text:"Apply to config",onclick:function(){submit("apply");}}) ]));
      egressBox.appendChild(st.result);
    }
    function buildSpec(){
      var name=nameIn.value.trim();
      var sel=(st.rows||[]).filter(function(r){return r.chk.checked;});
      var models=sel.map(function(r){ var m={ id:name+"/"+r.id, name:r.id, inputPrice:Number(r.inP.value||0), outputPrice:Number(r.outP.value||0) }; if(r.emb.checked) m.kind="embedding"; return m; });
      var chatSel=sel.filter(function(r){return !r.emb.checked;});
      var tiers={}; getChecks(st.tierDiv).forEach(function(t){ if(chatSel[0]) tiers[t]={primary:name+"/"+chatSel[0].id}; });
      var firstEmb=sel.filter(function(r){return r.emb.checked;})[0];
      var prov={ name:name, api:apiSel.value, baseUrl:urlIn.value.trim() };
      if(apiSel.value==="azure"){ prov.apiVersion=apiVerIn.value.trim()||"2024-10-21"; prov.azureAuth=azAuthSel.value; }
      if(authSel.value==="env" && authVal.value.trim()) prov.authEnvKey=authVal.value.trim();
      return { provider:prov, egress:{ allowedHost:st.hostIn.value.trim(), authorizedClassifications:getChecks(st.classDiv) },
               models:models, tiers:Object.keys(tiers).length?tiers:undefined,
               embeddingsDefault: firstEmb ? name+"/"+firstEmb.id : undefined };
    }
    function submit(mode){
      var spec=buildSpec();
      if(!spec.provider.name){toast("name required",true);return;}
      if(!spec.models.length){toast("select a model",true);return;}
      if(!spec.egress.authorizedClassifications.length){toast("pick a classification",true);return;}
      api("/admin/api/endpoint/"+(mode==="apply"?"apply":"preview"),{method:"POST",body:spec})
        .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); }).then(function(o){
        st.result.innerHTML="";
        if(mode==="preview"){
          if(o.j.valid) st.result.appendChild(el("div",{class:"pill ok",text:"valid — ready to apply"}));
          else { st.result.appendChild(el("div",{class:"pill bad",text:"invalid config"})); st.result.appendChild(el("pre",{text:(o.j.errors||[]).join("\\n")})); }
        } else if(o.ok){
          st.result.appendChild(el("div",{class:"pill ok",text:"written to "+o.j.path})); st.result.appendChild(applyBar());
        } else st.result.appendChild(el("div",{class:"pill bad",text:o.j.error?o.j.error.message:"apply failed"}));
      }).catch(function(e){ toast(e.message,true); });
    }
    function applyBar(){
      return el("div",{class:"row"},[ el("span",{class:"muted",text:"Apply it:"}),
        el("button",{class:"btn",text:"Reload (no downtime)",onclick:function(){ api("/admin/api/reload",{method:"POST"}).then(function(r){return r.json();}).then(function(){ toast("reloaded"); loadConfig().then(function(){shell();}); }).catch(function(e){toast(e.message,true);}); }}),
        el("button",{class:"btn ghost",text:"Restart",onclick:function(){ api("/admin/api/restart",{method:"POST"}).catch(function(){}); toast("restarting…"); pollHealth(0); }}) ]);
    }
    function pollHealth(n){ fetch("/health").then(function(r){ if(!r.ok) throw 0; return r.json(); }).then(function(){ toast("back up"); loadConfig().then(function(){shell();}); }).catch(function(){ if(n<30) setTimeout(function(){pollHealth(n+1);},1000); }); }

    var manualIn=el("input",{type:"text",placeholder:"deployment / model ids, comma-separated",style:"min-width:240px"});
    function enterManual(){ var ids=manualIn.value.split(",").map(function(s){return s.trim();}).filter(Boolean); if(ids.length) renderPick(ids); else toast("enter comma-separated ids",true); }

    wrap.appendChild(el("h3",{text:"Add a model endpoint"}));
    wrap.appendChild(el("div",{class:"row"},[el("label",{text:"Name"}),nameIn,el("label",{text:"API"}),apiSel,apiVerIn,azAuthSel]));
    wrap.appendChild(el("div",{class:"row"},[el("label",{text:"Base URL"}),urlIn]));
    wrap.appendChild(el("div",{class:"row"},[el("label",{text:"Auth"}),authSel,authVal,el("button",{class:"btn",text:"Test endpoint",onclick:test})]));
    wrap.appendChild(el("div",{class:"row"},[el("label",{text:"Or enter models",title:"Skip discovery — for Azure deployments or endpoints without a model list"}),manualIn,el("button",{class:"btn ghost",text:"Enter models",onclick:enterManual})]));
    wrap.appendChild(modelsBox); wrap.appendChild(egressBox);
    return wrap;
  }

  // ── Models tab ──
  // Loads live model availability (GET /admin/api/models/available — reachability,
  // model lists and circuit state per provider) before rendering, so tier routing
  // only ever offers models we can actually hit.
  function renderModels(main){
    main.innerHTML="";
    main.appendChild(el("div",{class:"muted",text:"Checking model availability…"}));
    api("/admin/api/models/available").then(function(r){return r.json();}).then(function(d){
      var avail = Array.isArray(d) ? d : [];
      renderModelsBody(main, avail, Array.isArray(d) ? null : "unexpected response");
    }).catch(function(e){ renderModelsBody(main, [], e.message); });
  }

  function renderModelsBody(main, avail, loadErr){
    main.innerHTML="";
    var cfg = state.cfg; var tiers = cfg.tiers||{};
    var levels = (cfg.classification && cfg.classification.levels) || [];
    var availByProv = {}; avail.forEach(function(a){ availByProv[a.provider]=a; });
    // Union of reachable model ids across all providers — the ONLY choices offered
    // for a tier's primary/fallback (you can't route to a model we can't hit).
    var availModels = [];
    avail.forEach(function(a){ if(a.reachable) (a.models||[]).forEach(function(m){ if(availModels.indexOf(m.id)<0) availModels.push(m.id); }); });
    if(loadErr) main.appendChild(el("div",{class:"pill bad",text:"Could not check model availability: "+loadErr+" — tier options may be stale"}));

    // ── Tier → model routing, options limited to reachable models ──
    var tierCard = el("div",{class:"card"}, el("h3",{text:"Tier → model routing (choices limited to reachable models)"}));
    TIERS.forEach(function(t){
      var tc = tiers[t]||{primary:"",fallback:[]};
      var primOptions = availModels.slice();
      var primUnreachable = !!tc.primary && primOptions.indexOf(tc.primary)<0;
      if(primUnreachable) primOptions.push(tc.primary); // keep the current pick visible; not offered as a fresh choice elsewhere
      var prim = el("select",{}, primOptions.map(function(id){
        // The current-but-unreachable primary is shown so it stays visible as the
        // selection, but disabled so it can't be re-chosen after switching away.
        var disabled = primUnreachable && id===tc.primary;
        return el("option",{value:id,text:id,disabled:disabled});
      }));
      if(tc.primary) prim.value = tc.primary;
      var primFlag = primUnreachable ? el("span",{class:"pill bad",text:"unreachable"}) : null;

      var fbChecks = el("div",{class:"checks"}, availModels.map(function(id){
        var c=el("input",{type:"checkbox",value:id}); if((tc.fallback||[]).indexOf(id)>=0) c.checked=true;
        return el("label",{},[c,id]);
      }));
      var staleFallback = (tc.fallback||[]).filter(function(id){ return availModels.indexOf(id)<0; });
      var staleFlag = staleFallback.length ? el("span",{class:"pill bad",title:"kept on save",text:staleFallback.join(", ")+" unreachable"}) : null;

      function save(){
        var fb = getChecks(fbChecks).concat(staleFallback);
        var body = { primary: prim.value, fallback: fb };
        api("/admin/api/tier/"+t,{method:"PUT",body:body}).then(function(r){
          if(r.ok){ toast("Saved "+t); loadConfig().then(function(){ renderModelsBody(main, avail, loadErr); }); }
          else r.json().then(function(j){toast(j.error?j.error.message:"rejected",true);});
        });
      }
      tierCard.appendChild(el("div",{class:"row"},[
        el("label",{text:t}), prim, primFlag,
        el("span",{class:"muted",style:"min-width:auto;",text:"fallback:"}), fbChecks, staleFlag,
        el("button",{class:"btn",text:"Save",onclick:save})
      ]));
    });
    main.appendChild(tierCard);

    // ── Configured endpoints — egress edit, current routing, health, remove ──
    main.appendChild(el("h3",{},["Configured endpoints ", el("span",{class:"pill warn",text:"egress · compliance-critical"})]));
    var egByProv = {}; (cfg.egress||[]).forEach(function(e){ egByProv[e.provider]=e; });
    var provNames = Object.keys(cfg.providers||{});
    if(!provNames.length) main.appendChild(el("div",{class:"card ro"},[el("div",{class:"muted",text:"No providers configured yet — add one below."})]));
    provNames.forEach(function(n){
      var p = cfg.providers[n]; var e = egByProv[n]||{};
      var a = availByProv[n];
      var card = el("div",{class:"card"});
      var headRow = el("div",{class:"row"},[el("strong",{text:n}), el("span",{class:"muted",text:p.api}), el("span",{class:"muted",text:listText(p.baseUrl)})]);
      if(a){
        var hs = healthState(a.health && a.health.state);
        headRow.appendChild(el("span",{class:"pill "+(a.reachable?"ok":"bad"),text:a.reachable?"reachable":"unreachable"}));
        headRow.appendChild(el("span",{class:"pill "+hs.cls,text:hs.label}));
        headRow.appendChild(el("span",{class:"muted",text:(a.models||[]).length+" models"}));
        if(a.error) headRow.appendChild(el("span",{class:"muted",text:a.error}));
      } else {
        headRow.appendChild(el("span",{class:"pill",text:"no health data"}));
      }
      if(BUILTIN_PROVIDERS.indexOf(n)>=0){
        headRow.appendChild(el("span",{class:"pill warn",title:"Baked into the server's built-in defaults — removing it here clears the file, but it resurfaces after reload with no egress rule (blocked by deny-by-default egress, not a routing hole).",text:"built-in default"}));
      }
      card.appendChild(headRow);

      // Which tier(s) currently route to this provider, with live health.
      var current = [];
      TIERS.forEach(function(t){
        var tc = tiers[t]||{};
        if(tc.primary && tc.primary.indexOf(n+"/")===0){
          var hs2 = a ? healthState(a.health && a.health.state).label : "unknown";
          current.push(t+" — current: "+tc.primary+" · "+hs2);
        }
      });
      card.appendChild(el("div",{class:"row"}, current.length ? [el("span",{class:"muted",text:current.join("   ")})] : [el("span",{class:"muted",text:"not used as a tier primary"})]));

      // Egress: admin-editable allowed host + authorized classifications.
      // POST /admin/api/endpoint/egress writes a single host string; a pooled
      // provider's multi-host rule is shown read-only above the editable field
      // so saving here can't silently collapse it to one host.
      var pooledHosts = Array.isArray(e.allowedHost) ? e.allowedHost : null;
      var hostIn = el("input",{type:"text",value: pooledHosts ? "" : (e.allowedHost||""), placeholder: pooledHosts ? "add/replace with a single host…" : "host:port"});
      var classDiv = el("div",{class:"checks"}, levels.map(function(l){
        var c=el("input",{type:"checkbox",value:l}); if((e.authorizedClassifications||[]).indexOf(l)>=0) c.checked=true;
        return el("label",{},[c,l]);
      }));
      function saveEgress(){
        var host = hostIn.value.trim(); // POST /admin/api/endpoint/egress takes a single host string (not the pooled array shape)
        if(!host){ toast("egress host required",true); return; }
        var classes = getChecks(classDiv);
        if(!classes.length){ toast("pick a classification",true); return; }
        var body = { provider:n, allowedHost: host, authorizedClassifications: classes };
        // The write lands in the config FILE (applied:false — "reload or restart to
        // apply"); GET /admin/api/config serves the still-active effective config, so
        // without an explicit reload here the edit would visually revert until the
        // wizard's Reload button is pressed. Reload before re-rendering.
        api("/admin/api/endpoint/egress",{method:"POST",body:body}).then(function(r){
          if(r.ok){
            api("/admin/api/reload",{method:"POST"})
              .then(function(){ toast("Saved egress for "+n); loadConfig().then(function(){ renderModelsBody(main, avail, loadErr); }); })
              .catch(function(e){ toast("Saved egress for "+n+" — reload failed ("+e.message+"); reload manually",true); loadConfig().then(function(){ renderModelsBody(main, avail, loadErr); }); });
          }
          else r.json().then(function(j){toast(j.error?j.error.message:"rejected",true);});
        });
      }
      if(pooledHosts) card.appendChild(el("div",{class:"row"},[el("label",{text:"Current hosts"}), el("span",{class:"muted",text:pooledHosts.join(", ")}), el("span",{class:"pill warn",text:"pooled — editor below replaces with ONE host"})]));
      card.appendChild(el("div",{class:"row"},[el("label",{text:"Egress host"}), hostIn]));
      card.appendChild(el("div",{class:"row"},[el("label",{text:"Classifications"}), classDiv, el("button",{class:"btn",text:"Save egress",onclick:saveEgress})]));

      // Remove.
      function removeEndpoint(){
        if(!confirm("Remove endpoint '"+n+"'? This clears its egress rule and any tier routing that used it.")) return;
        // Same applied:false / stale-GET situation as saveEgress above: reload
        // before refetching config so the removed provider doesn't reappear.
        api("/admin/api/endpoint/remove",{method:"POST",body:{provider:n}}).then(function(r){
          if(r.ok){
            api("/admin/api/reload",{method:"POST"})
              .then(function(){ toast("Removed "+n); loadConfig().then(function(){ renderModels(main); }); })
              .catch(function(e){ toast("Removed "+n+" — reload failed ("+e.message+"); reload manually",true); loadConfig().then(function(){ renderModels(main); }); });
          }
          else r.json().then(function(j){toast(j.error?j.error.message:"remove failed",true);});
        });
      }
      card.appendChild(el("div",{class:"row"},[el("button",{class:"btn danger",text:"Remove endpoint",onclick:removeEndpoint})]));

      main.appendChild(card);
    });

    main.appendChild(buildEndpointWizard(levels));
  }

  // ── Audit tab ──
  function renderAudit(main){
    main.innerHTML="";
    api("/admin/api/audit?limit=200").then(function(r){return r.json();}).then(function(rows){
      var card = el("div",{class:"card"}, el("h3",{text:"Recent audit events (hash-chained, newest first)"}));
      var t = el("table",{}, el("tr",{},[el("th",{text:"time"}),el("th",{text:"type"}),el("th",{text:"principal"}),el("th",{text:"model"}),el("th",{text:"outcome"}),el("th",{text:"trace"})]));
      rows.forEach(function(e){
        var cls = e.outcome==="deny"?"bad":(e.type==="anomaly"?"warn":"");
        var tid = (e.detail && e.detail.traceId) || "";
        var via = e.detail && e.detail.delegatedBy;   // on-behalf-of: the trusted UI service
        var principalCell = el("td",{text:e.principalId||"—"});
        if (via) principalCell.appendChild(el("span",{class:"muted",style:"font-size:11px;",title:"delegated by "+via,text:" · via "+via}));
        t.appendChild(el("tr",{},[
          el("td",{class:"muted",text:(e.ts||"").replace("T"," ").slice(0,19)}),
          el("td",{}, el("span",{class:"pill "+cls,text:e.type})),
          principalCell, el("td",{text:e.model||"—"}),
          el("td",{text:e.outcome||"—"}),
          el("td",{class:"muted",title:tid,text:tid?tid.slice(0,8):"—"})
        ]));
      });
      card.appendChild(t); main.appendChild(card);
    }).catch(function(e){ main.appendChild(el("div",{class:"muted",text:"Could not load audit: "+e.message})); });
  }

  // ── data + boot ──
  function loadConfig(){
    return api("/admin/api/config").then(function(r){return r.json();}).then(function(d){ state.cfg=d; return d; });
  }
  function renderLogin(){
    $("app").innerHTML="";
    $("app").appendChild(el("div",{class:"center"},[
      el("h1",{text:"SecRouter Admin"}),
      el("p",{class:"muted",text:"Sign in with your organization account to continue."}),
      el("button",{class:"btn",text:"Sign in with SSO",onclick:login})
    ]));
  }

  fetch("/admin/oidc").then(function(r){return r.json();}).then(function(oidc){
    state.oidc = oidc;
    var params = new URLSearchParams(location.search);
    var p = params.get("code") ? exchange(params.get("code")) : Promise.resolve();
    p.then(function(){
      state.token = sessionStorage.getItem("access_token");
      if (oidc.enabled && !state.token) { renderLogin(); return; }
      loadConfig().then(function(){ shell(); }).catch(function(e){
        if (oidc.enabled && !state.token) renderLogin();
        else $("app").innerHTML='<div class="center muted">'+ (e.message||"error") +'</div>';
      });
    });
  }).catch(function(){ $("app").innerHTML='<div class="center muted">Admin API unavailable.</div>'; });
})();
</script>
</body>
</html>`;
