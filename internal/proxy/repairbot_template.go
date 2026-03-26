package proxy

import (
	"html/template"
)

var repairBotFuncMap = template.FuncMap{
	"statusIcon":  statusIcon,
	"statusClass": statusClass,
	"hasPrefix":   hasPrefix,
}

var repairBotTemplate = template.Must(template.New("repairbot").Funcs(repairBotFuncMap).Parse(repairBotHTML))

// H-1: Minimal branded page for unauthenticated users hitting /repairbot
var repairBotUnauthTemplate = template.Must(template.New("repairbot-unauth").Parse(repairBotUnauthHTML))

const repairBotUnauthHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>evaOS RepairBot — Login Required</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0f;--text:#e0e0e8;--dim:#6b6b80;--accent:#00d4ff;--accent2:#7b61ff;--card:#16162a;--border:#1e1e3a;--glow:rgba(0,212,255,0.15)}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{max-width:480px;width:100%;text-align:center}
.logo{font-size:28px;font-weight:700;letter-spacing:2px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:40px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:40px 32px;box-shadow:0 0 40px var(--glow)}
.icon{font-size:48px;margin-bottom:24px}
h1{font-size:22px;font-weight:600;margin-bottom:12px}
.message{color:var(--dim);font-size:15px;line-height:1.5;margin-bottom:28px}
.btn-secondary{display:inline-block;color:var(--accent);font-size:14px;text-decoration:none;margin-top:16px;padding:8px 16px;border:1px solid var(--border);border-radius:8px;transition:all 0.2s}
.btn-secondary:hover{border-color:var(--accent);background:rgba(0,212,255,0.05)}
footer{margin-top:32px;color:var(--dim);font-size:12px;opacity:0.6}
</style>
</head>
<body>
<div class="container">
  <div class="logo">evaOS RepairBot</div>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>Login Required</h1>
    <p class="message">Please log in to access diagnostics for your Eva instance.</p>
    <a href="mailto:androiddreams@electricsheephq.com?subject=evaOS%20Support%20-%20{{.CustomerID}}" class="btn-secondary">Contact Support</a>
  </div>
  <footer>evaOS by Electric Sheep</footer>
</div>
</body>
</html>`

const repairBotHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>evaOS RepairBot — Diagnostics</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0a0f;--bg2:#12121a;--text:#e0e0e8;--dim:#6b6b80;
  --accent:#00d4ff;--accent2:#7b61ff;--danger:#ff4d6a;--success:#00e68a;--warn:#ffb347;
  --card:#16162a;--border:#1e1e3a;--glow:rgba(0,212,255,0.15);
}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh;
  padding:20px;
}
.container{max-width:680px;width:100%;margin:0 auto;}
.header{text-align:center;margin-bottom:32px;}
.logo{
  font-size:28px;font-weight:700;letter-spacing:2px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}
.subtitle{color:var(--dim);font-size:14px;margin-top:4px;}
.badge{
  display:inline-block;padding:4px 12px;border-radius:12px;
  font-size:12px;font-weight:600;margin-top:8px;
}
.badge-ok{background:rgba(0,230,138,0.15);color:var(--success);border:1px solid rgba(0,230,138,0.3);}
.badge-warning{background:rgba(255,179,71,0.15);color:var(--warn);border:1px solid rgba(255,179,71,0.3);}
.badge-critical{background:rgba(255,77,106,0.15);color:var(--danger);border:1px solid rgba(255,77,106,0.3);}
.badge-unknown{background:rgba(107,107,128,0.15);color:var(--dim);border:1px solid rgba(107,107,128,0.3);}
.card{
  background:var(--card);border:1px solid var(--border);
  border-radius:12px;padding:20px 24px;margin-bottom:16px;
  box-shadow:0 0 20px var(--glow);
}
.card-title{font-size:16px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:8px;}
.check-row{
  display:flex;align-items:flex-start;gap:12px;padding:10px 0;
  border-bottom:1px solid var(--border);
}
.check-row:last-child{border-bottom:none;}
.check-icon{font-size:18px;flex-shrink:0;width:28px;text-align:center;padding-top:2px;}
.check-body{flex:1;min-width:0;}
.check-name{font-size:13px;color:var(--dim);font-weight:500;}
.check-msg{font-size:14px;margin-top:2px;}
.check-details{
  font-size:12px;color:var(--dim);margin-top:4px;
  font-family:'SF Mono',monospace;white-space:pre-wrap;word-break:break-all;
  background:var(--bg2);border-radius:6px;padding:8px;max-height:120px;overflow-y:auto;
}
.check-suggestion{
  font-size:13px;color:var(--accent);margin-top:6px;font-style:italic;
}
.status-ok .check-msg{color:var(--success);}
.status-warning .check-msg{color:var(--warn);}
.status-critical .check-msg{color:var(--danger);}
.status-unknown .check-msg{color:var(--dim);}
.section-title{font-size:18px;font-weight:600;margin:24px 0 12px;display:flex;align-items:center;gap:8px;}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px;}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  color:#fff;border:none;border-radius:10px;padding:12px 24px;
  font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s;
  text-decoration:none;
}
.btn:hover{opacity:0.9;transform:translateY(-1px)}
.btn:disabled{opacity:0.4;cursor:not-allowed;transform:none}
.btn-outline{
  background:transparent;border:1px solid var(--border);color:var(--text);
}
.btn-outline:hover{border-color:var(--accent);background:rgba(0,212,255,0.05);}
.btn-danger{background:linear-gradient(135deg,var(--danger),#cc3355);}
.error-catalog{margin-top:16px;}
.error-item{
  display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--border);
}
.error-item:last-child{border-bottom:none;}
.error-icon{font-size:20px;flex-shrink:0;width:28px;text-align:center;}
.error-title{font-size:14px;font-weight:600;}
.error-desc{font-size:13px;color:var(--dim);margin-top:2px;}
.error-fix{font-size:13px;color:var(--accent);margin-top:4px;}
.backup-list{list-style:none;margin-top:8px;}
.backup-item{
  display:flex;justify-content:space-between;align-items:center;
  padding:8px 12px;border-radius:8px;margin-bottom:4px;
  background:var(--bg2);font-size:13px;font-family:'SF Mono',monospace;
}
.backup-item button{
  background:var(--accent2);color:#fff;border:none;border-radius:6px;
  padding:4px 12px;font-size:12px;cursor:pointer;
}
.backup-item button:disabled{opacity:0.4;cursor:not-allowed;}
.countdown{font-size:12px;color:var(--dim);margin-top:8px;}
.spinner{
  display:inline-block;width:14px;height:14px;
  border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;
  border-radius:50%;animation:spin 0.8s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}
.refresh-bar{
  display:flex;justify-content:space-between;align-items:center;
  margin-bottom:16px;color:var(--dim);font-size:12px;
}
footer{text-align:center;margin-top:32px;color:var(--dim);font-size:12px;opacity:0.6;}
.not-provisioned{text-align:center;padding:40px 20px;}
.not-provisioned .icon{font-size:48px;margin-bottom:16px;}
.not-provisioned h2{font-size:20px;margin-bottom:8px;}
.not-provisioned p{color:var(--dim);font-size:14px;}
@media(max-width:480px){
  body{padding:12px;}
  .card{padding:16px;border-radius:10px;}
  .actions{flex-direction:column;}
  .btn{width:100%;}
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">evaOS RepairBot</div>
    <div class="subtitle">Diagnostic Dashboard — {{.CustomerID}}</div>
    {{if eq .Mode "diagnostic"}}
      {{if .Report}}
        {{if eq .OverallStatus "ok"}}
          <span class="badge badge-ok">✅ All Systems OK</span>
        {{else if eq .OverallStatus "warning"}}
          <span class="badge badge-warning">⚠️ Attention Needed</span>
        {{else if eq .OverallStatus "critical"}}
          <span class="badge badge-critical">❌ Issues Detected</span>
        {{else}}
          <span class="badge badge-unknown">❓ Checking...</span>
        {{end}}
      {{end}}
    {{end}}
  </div>

  {{if eq .Mode "not_provisioned"}}
    <div class="card not-provisioned">
      <div class="icon">🛠️</div>
      <h2>Your Eva is being set up</h2>
      <p>Your instance is being provisioned. This usually takes a few minutes. Please check back shortly.</p>
      <div style="margin-top:20px">
        <a href="mailto:androiddreams@electricsheephq.com?subject=evaOS%20Support%20-%20{{.CustomerID}}" class="btn btn-outline">
          Contact Support
        </a>
      </div>
    </div>

  {{else if eq .Mode "vm_lookup_failed"}}
    <div class="card not-provisioned">
      <div class="icon">🌐</div>
      <h2>Connection Issue</h2>
      <p>We couldn't look up your instance right now. This is usually a temporary issue on our end.</p>
      <div style="margin-top:20px">
        <a href="mailto:androiddreams@electricsheephq.com?subject=evaOS%20Support%20-%20{{.CustomerID}}" class="btn btn-outline">
          Contact Support
        </a>
      </div>
    </div>

  {{else}}
    <div class="refresh-bar">
      <span id="lastUpdate">Last checked: just now</span>
      <button class="btn btn-outline" style="padding:6px 14px;font-size:12px;" onclick="refreshDiag()">↻ Refresh</button>
    </div>

    {{if .Report}}
    <!-- Diagnostic Checks -->
    <div class="card">
      <div class="card-title">🔍 System Diagnostics</div>
      {{range .Report.Checks}}
      <div class="check-row {{statusClass .Status}}">
        <div class="check-icon">{{.Icon}}</div>
        <div class="check-body">
          <div class="check-name">{{.Name}}</div>
          <div class="check-msg">{{statusIcon .Status}} {{.Message}}</div>
          {{if .Details}}<div class="check-details">{{.Details}}</div>{{end}}
          {{if .Suggestion}}<div class="check-suggestion">💡 {{.Suggestion}}</div>{{end}}
        </div>
      </div>
      {{end}}
    </div>

    <!-- Actions -->
    <div class="card">
      <div class="card-title">🛠️ Quick Actions</div>
      <div class="actions">
        <button id="restartBtn" class="btn" onclick="restartEva()">
          <span id="btnText">⚡ Restart Eva</span>
        </button>
        <a href="/vm/{{.CustomerID}}/ui/" class="btn btn-outline">🏠 Go to Eva</a>
        <a href="mailto:androiddreams@electricsheephq.com?subject=evaOS%20Support%20-%20{{.CustomerID}}" class="btn btn-outline">📧 Contact Support</a>
      </div>
      <div id="countdown" class="countdown"></div>
    </div>

    <!-- Backups -->
    {{if .HasBackups}}
    <div class="card">
      <div class="card-title">💾 Config Backups</div>
      <p style="color:var(--dim);font-size:13px;margin-bottom:12px;">
        If your Eva's settings got broken, you can restore a previous working version.
        This will restart Eva with the old settings.
      </p>
      <ul class="backup-list" id="backupList">
        {{range .Report.Backups}}
        <li class="backup-item">
          <span>{{.Filename}}</span>
          <button onclick="restoreBackup('{{.Filename}}')">Restore</button>
        </li>
        {{end}}
      </ul>
      <div id="restoreStatus" class="countdown"></div>
    </div>
    {{end}}
    {{end}}

    <!-- Error Catalog -->
    <div class="card">
      <div class="card-title">📖 Common Issues &amp; What They Mean</div>
      <p style="color:var(--dim);font-size:13px;margin-bottom:12px;">
        Here are the most common reasons your Eva might have trouble, explained in plain English.
      </p>
      <div class="error-catalog">
        {{range .CommonErrors}}
        <div class="error-item">
          <div class="error-icon">{{.Icon}}</div>
          <div>
            <div class="error-title">{{.Title}}</div>
            <div class="error-desc">{{.Description}}</div>
            <div class="error-fix">💡 {{.Suggestion}}</div>
          </div>
        </div>
        {{end}}
      </div>
    </div>
  {{end}}

  <footer>evaOS RepairBot v1 — Electric Sheep</footer>
</div>

<script>
(function(){
  var CID = "{{.CustomerID}}";
  var COOLDOWN = 120;
  var timer = null;
  var remaining = 0;

  window.restartEva = function() {
    var btn = document.getElementById("restartBtn");
    var btnText = document.getElementById("btnText");
    var cd = document.getElementById("countdown");
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    btnText.innerHTML = '<span class="spinner"></span> Restarting...';
    fetch("/vm/" + CID + "/restart", {method:"POST",headers:{"Content-Type":"application/json"}})
    .then(function(r){return r.json()})
    .then(function(data){
      if(data.status==="cooldown"){remaining=data.remaining_seconds;}
      else if(data.status==="restarting"){remaining=data.cooldown_seconds||COOLDOWN;}
      else if(data.status==="error"){
        btnText.textContent="⚡ Restart Eva";btn.disabled=false;
        cd.textContent="Restart failed: "+(data.message||"unknown error");return;
      }
      startCountdown(btn,btnText,cd);
    })
    .catch(function(){btnText.textContent="⚡ Restart Eva";btn.disabled=false;cd.textContent="Request failed";});
  };

  function startCountdown(btn,btnText,cd){
    btnText.textContent="Restarting...";
    timer=setInterval(function(){
      remaining--;
      if(remaining<=0){clearInterval(timer);btn.disabled=false;btnText.textContent="⚡ Restart Eva";cd.textContent="";return;}
      var m=Math.floor(remaining/60),s=remaining%60;
      cd.textContent="Next restart available in "+(m>0?m+"m ":"")+s+"s";
    },1000);
  }

  window.restoreBackup = function(filename) {
    var status = document.getElementById("restoreStatus");
    if(!confirm("Restore this backup? This will restart Eva with the old settings.\n\n"+filename)) return;
    status.textContent = "Restoring...";
    // Disable all restore buttons
    var btns = document.querySelectorAll(".backup-item button");
    btns.forEach(function(b){b.disabled=true;});
    fetch("/vm/"+CID+"/repairbot/restore",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({filename:filename})
    })
    .then(function(r){return r.json()})
    .then(function(data){
      if(data.status==="restoring"){
        status.textContent="✅ Restore started! Eva is restarting with the backup settings...";
        setTimeout(function(){window.location.reload();}, 30000);
      } else if(data.status==="cooldown"){
        status.textContent="Please wait "+data.remaining_seconds+"s before trying again.";
        btns.forEach(function(b){b.disabled=false;});
      } else {
        status.textContent="Error: "+(data.message||"unknown");
        btns.forEach(function(b){b.disabled=false;});
      }
    })
    .catch(function(){
      status.textContent="Request failed — check your connection";
      btns.forEach(function(b){b.disabled=false;});
    });
  };

  window.refreshDiag = function() {
    window.location.reload();
  };
})();
</script>
</body>
</html>`
