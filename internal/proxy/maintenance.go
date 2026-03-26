package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrorReason categorizes why the maintenance page is being shown.
type ErrorReason string

const (
	ReasonBackendDown    ErrorReason = "offline"      // Gateway process crashed or stopped
	ReasonNotProvisioned ErrorReason = "provisioning"  // No VM assigned yet
	ReasonStarting       ErrorReason = "starting"      // Gateway is restarting
	ReasonNetworkError   ErrorReason = "network_error" // Network/timeout issue
)

// maintenanceData is the template data for the maintenance page.
type maintenanceData struct {
	CustomerID     string
	Reason         ErrorReason
	Title          string
	Message        string
	ShowRestart    bool
	DiagnosticsURL string
}

// serveMaintenancePage renders the maintenance page for the given error scenario.
// M-5: Removed restart button — users should use /repairbot (authenticated) for self-service restart.
// M-6: Renders template to buffer first, then writes to avoid partial response on error.
func (h *Handler) serveMaintenancePage(w http.ResponseWriter, customerID string, reason ErrorReason) {
	data := maintenanceData{
		CustomerID: customerID,
		Reason:     reason,
	}

	switch reason {
	case ReasonBackendDown:
		data.Title = "Your Eva is temporarily offline"
		data.Message = "The gateway process appears to have stopped. Use the diagnostics page to check status and restart."
		data.ShowRestart = false // M-5: no restart button on unauthenticated page
		data.DiagnosticsURL = fmt.Sprintf("/vm/%s/repairbot", customerID)
	case ReasonNotProvisioned:
		data.Title = "Your Eva is being set up"
		data.Message = "Your instance is being provisioned. This usually takes a few minutes."
		data.ShowRestart = false
	case ReasonStarting:
		data.Title = "Your Eva is restarting..."
		data.Message = "Please wait while the gateway starts up. This page will automatically refresh."
		data.ShowRestart = false
	case ReasonNetworkError:
		data.Title = "Connection issue"
		data.Message = "Unable to reach your instance. This may be a temporary network issue."
		data.ShowRestart = false // M-5: no restart button on unauthenticated page
		data.DiagnosticsURL = fmt.Sprintf("/vm/%s/repairbot", customerID)
	default:
		data.Title = "Something went wrong"
		data.Message = "An unexpected error occurred."
		data.ShowRestart = false // M-5: no restart button on unauthenticated page
	}

	// M-6: Render to buffer first to avoid writing headers before knowing if template succeeds
	var buf bytes.Buffer
	if err := maintenanceTemplate.Execute(&buf, data); err != nil {
		slog.Error("failed to render maintenance page", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusServiceUnavailable)
	buf.WriteTo(w)
}

// HandleHealthCheck pings the customer VM's gateway and returns health status.
// Route: GET /vm/{customer_id}/health-check
// M-2 fix: requires session cookie or JWT auth to prevent customer_id enumeration.
func (h *Handler) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// M-2: Require auth (session cookie or JWT)
	authed := false
	if h.sessions != nil {
		if sessionToken := GetSessionCookie(r); sessionToken != "" {
			if _, err := h.sessions.ValidateSessionToken(sessionToken); err == nil {
				authed = true
			}
		}
	}
	if !authed {
		tokenStr := extractToken(r)
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := h.jwt.Validate(tokenStr); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		slog.Error("health-check: vm lookup failed", "error", err, "customer_id", customerID)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"healthy":        false,
			"gateway_status": "unknown",
		})
		return
	}
	if vm == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"healthy":        false,
			"gateway_status": "not_provisioned",
		})
		return
	}

	// Ping the gateway health endpoint
	healthURL := fmt.Sprintf("http://%s:%d/health", vm.EffectiveIP(), vm.GatewayPort)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		status := "inactive"
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			status = "timeout"
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"healthy":        false,
			"gateway_status": status,
		})
		return
	}
	defer resp.Body.Close()

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"healthy":        healthy,
		"gateway_status": "active",
	})
}

// classifyBackendError determines the ErrorReason from a proxy error.
func classifyBackendError(err error) ErrorReason {
	if err == nil {
		return ReasonBackendDown
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") {
		return ReasonBackendDown
	}
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "no route to host") {
		return ReasonNetworkError
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return ReasonNetworkError
	}
	return ReasonBackendDown
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// maintenanceTemplate is the self-contained HTML maintenance page.
var maintenanceTemplate = template.Must(template.New("maintenance").Parse(maintenanceHTML))

const maintenanceHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>evaOS — {{.Title}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0a0f;--bg2:#12121a;--text:#e0e0e8;--dim:#6b6b80;
  --accent:#00d4ff;--accent2:#7b61ff;--danger:#ff4d6a;
  --card:#16162a;--border:#1e1e3a;--glow:rgba(0,212,255,0.15);
}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh;
  display:flex;align-items:center;justify-content:center;
  padding:20px;
}
.container{
  max-width:480px;width:100%;text-align:center;
}
.logo{
  font-size:28px;font-weight:700;letter-spacing:2px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;margin-bottom:40px;
}
.card{
  background:var(--card);border:1px solid var(--border);
  border-radius:16px;padding:40px 32px;
  box-shadow:0 0 40px var(--glow);
}
.icon{
  width:64px;height:64px;margin:0 auto 24px;
  border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:28px;
}
.icon.offline{background:rgba(255,77,106,0.15);border:2px solid var(--danger)}
.icon.starting{background:rgba(0,212,255,0.15);border:2px solid var(--accent)}
.icon.provisioning{background:rgba(123,97,255,0.15);border:2px solid var(--accent2)}
.icon.network{background:rgba(255,165,0,0.15);border:2px solid #ffa500}
h1{font-size:22px;font-weight:600;margin-bottom:12px;line-height:1.3}
.message{color:var(--dim);font-size:15px;line-height:1.5;margin-bottom:28px}
.wait-time{
  color:var(--dim);font-size:13px;
  background:var(--bg2);border-radius:8px;padding:10px 16px;
  margin-bottom:24px;display:inline-block;
}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  color:#fff;border:none;border-radius:10px;padding:14px 32px;
  font-size:15px;font-weight:600;cursor:pointer;
  transition:all 0.2s;width:100%;max-width:280px;
  text-decoration:none;
}
.btn:hover{opacity:0.9;transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn:disabled{opacity:0.4;cursor:not-allowed;transform:none}
.btn-secondary{
  display:inline-block;color:var(--accent);font-size:14px;
  text-decoration:none;margin-top:16px;padding:8px 16px;
  border:1px solid var(--border);border-radius:8px;
  transition:all 0.2s;
}
.btn-secondary:hover{border-color:var(--accent);background:rgba(0,212,255,0.05)}
.countdown{
  font-size:13px;color:var(--dim);margin-top:12px;min-height:20px;
}
.spinner{
  display:inline-block;width:16px;height:16px;
  border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;
  border-radius:50%;animation:spin 0.8s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.pulsing{animation:pulse 2s ease-in-out infinite}
.status-dot{
  display:inline-block;width:8px;height:8px;border-radius:50%;
  margin-right:8px;
}
.status-dot.red{background:var(--danger)}
.status-dot.blue{background:var(--accent);animation:pulse 2s ease-in-out infinite}
.status-dot.purple{background:var(--accent2);animation:pulse 2s ease-in-out infinite}
.status-dot.orange{background:#ffa500}
footer{
  margin-top:32px;color:var(--dim);font-size:12px;opacity:0.6;
}
.hidden{display:none}
@media(max-width:480px){
  .card{padding:28px 20px;border-radius:12px}
  h1{font-size:19px}
  .btn{padding:12px 24px;font-size:14px}
}
</style>
</head>
<body>
<div class="container">
  <div class="logo">evaOS</div>
  <div class="card">
    <div class="icon {{.Reason}}">
      {{if eq (printf "%s" .Reason) "offline"}}⚡{{end}}
      {{if eq (printf "%s" .Reason) "starting"}}🔄{{end}}
      {{if eq (printf "%s" .Reason) "provisioning"}}🛠{{end}}
      {{if eq (printf "%s" .Reason) "network_error"}}🌐{{end}}
    </div>
    <h1>{{.Title}}</h1>
    <p class="message">{{.Message}}</p>

    {{if eq (printf "%s" .Reason) "starting"}}
    <div class="wait-time"><span class="status-dot blue"></span>Usually back within 30 seconds</div>
    {{end}}

    {{if .ShowRestart}}
    <div class="wait-time"><span class="status-dot red"></span>Gateway is not responding</div>
    <button id="restartBtn" class="btn" onclick="restartEva()">
      <span id="btnText">Restart Eva</span>
    </button>
    <div id="countdown" class="countdown"></div>
    {{end}}

    <div style="margin-top:20px;display:flex;flex-direction:column;gap:10px;align-items:center">
      {{if .DiagnosticsURL}}
      <a href="{{.DiagnosticsURL}}" class="btn" style="text-decoration:none">
        🔧 Open Diagnostics
      </a>
      {{end}}
      <a href="mailto:androiddreams@electricsheephq.com?subject=evaOS%20Support%20-%20{{.CustomerID}}" class="btn-secondary">
        Contact Support
      </a>
    </div>
  </div>
  <footer>evaOS by Electric Sheep<!-- v1.0.0 --></footer>
</div>

<noscript>
<style>.btn{display:none}.countdown{display:none}</style>
<p style="color:#6b6b80;font-size:13px;margin-top:16px;text-align:center">
  JavaScript is required for the restart button. Please contact support at
  androiddreams@electricsheephq.com
</p>
</noscript>

<script>
(function(){
  var CID = "{{.CustomerID}}";
  var REASON = "{{.Reason}}";
  var COOLDOWN = 120;
  var timer = null;
  var remaining = 0;
  var checkInterval = null;

  // Auto-refresh for starting state
  if (REASON === "starting") {
    setTimeout(function(){ checkHealth(); }, 5000);
    setInterval(function(){ checkHealth(); }, 10000);
  }

  window.restartEva = function() {
    var btn = document.getElementById("restartBtn");
    var btnText = document.getElementById("btnText");
    var cd = document.getElementById("countdown");
    if (!btn || btn.disabled) return;

    btn.disabled = true;
    btnText.innerHTML = '<span class="spinner"></span> Restarting...';

    fetch("/vm/" + CID + "/restart", {
      method: "POST",
      headers: {"Content-Type": "application/json"}
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
      if (data.status === "cooldown") {
        remaining = data.remaining_seconds;
      } else if (data.status === "restarting") {
        remaining = data.cooldown_seconds || COOLDOWN;
      } else if (data.status === "error") {
        btnText.textContent = "Restart Eva";
        btn.disabled = false;
        cd.textContent = "Restart failed: " + (data.message || "unknown error");
        return;
      }
      startCountdown(btn, btnText, cd);
    })
    .catch(function(err){
      btnText.textContent = "Restart Eva";
      btn.disabled = false;
      cd.textContent = "Request failed — check your connection";
    });
  };

  function startCountdown(btn, btnText, cd) {
    btnText.textContent = "Restarting...";
    // Start health checks after 15s
    setTimeout(function(){
      checkInterval = setInterval(function(){ checkHealth(); }, 5000);
    }, 15000);

    timer = setInterval(function(){
      remaining--;
      if (remaining <= 0) {
        clearInterval(timer);
        if (checkInterval) clearInterval(checkInterval);
        btn.disabled = false;
        btnText.textContent = "Restart Eva";
        cd.textContent = "";
        checkHealth();
        return;
      }
      var m = Math.floor(remaining / 60);
      var s = remaining % 60;
      cd.textContent = "Next restart available in " + (m > 0 ? m + "m " : "") + s + "s";
    }, 1000);
  }

  function checkHealth() {
    fetch("/vm/" + CID + "/health-check")
    .then(function(r){ return r.json(); })
    .then(function(data){
      if (data.healthy) {
        window.location.href = "/vm/" + CID + "/ui/";
      }
    })
    .catch(function(){});
  }
})();
</script>
</body>
</html>`
