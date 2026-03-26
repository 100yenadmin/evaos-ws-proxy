package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	defaultSSHUser    = "root"
	defaultSSHKeyPath = "/root/.ssh/id_ed25519"
	restartCooldown   = 120 * time.Second
	sshTimeout        = 10 * time.Second
	restartCommand    = "systemctl restart openclaw-gateway"
)

// RestartManager handles gateway restart requests with rate limiting.
type RestartManager struct {
	sshUser    string
	sshKeyPath string
	mu         sync.Mutex            // M-7: mutex for cooldown map
	cooldowns  map[string]time.Time  // M-7: replaced sync.Map with mutex-protected map
}

// NewRestartManager creates a new restart manager.
func NewRestartManager() *RestartManager {
	user := os.Getenv("SSH_USER")
	if user == "" {
		user = defaultSSHUser
	}
	keyPath := os.Getenv("SSH_KEY_PATH")
	if keyPath == "" {
		keyPath = defaultSSHKeyPath
	}

	// M-8: Validate SSH key path on startup
	if info, err := os.Stat(keyPath); err != nil {
		slog.Warn("SSH key file not found — SSH operations will fail until key is available",
			"path", keyPath, "error", err)
	} else {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			slog.Warn("SSH key file has overly permissive permissions — should be 0600 or 0400",
				"path", keyPath, "mode", fmt.Sprintf("%04o", mode))
		}
	}

	return &RestartManager{
		sshUser:    user,
		sshKeyPath: keyPath,
		cooldowns:  make(map[string]time.Time),
	}
}

// restartResponse is the JSON response for restart requests.
type restartResponse struct {
	Status           string `json:"status"`
	CooldownSeconds  int    `json:"cooldown_seconds,omitempty"`
	RemainingSeconds int    `json:"remaining_seconds,omitempty"`
	Message          string `json:"message,omitempty"`
}

// CheckCooldown returns the remaining cooldown seconds for a customer, or 0 if ready.
func (rm *RestartManager) CheckCooldown(customerID string) int {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if lastRestart, ok := rm.cooldowns[customerID]; ok {
		elapsed := time.Since(lastRestart)
		if elapsed < restartCooldown {
			return int((restartCooldown - elapsed).Seconds()) + 1
		}
	}
	return 0
}

// SetCooldown records a cooldown for a customer. Exported for use by restore endpoint.
func (rm *RestartManager) SetCooldown(customerID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.cooldowns[customerID] = time.Now()
}

// Restart executes a gateway restart on the customer VM via SSH.
func (rm *RestartManager) Restart(customerID, vmIP string, vmPort int) error {
	// M-2: Don't set cooldown before execution — set it after success only.

	signer, err := rm.loadSSHKey()
	if err != nil {
		return fmt.Errorf("load SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: rm.sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: buildHostKeyCallback(), // M-1: known_hosts verification
		Timeout:         sshTimeout,
	}

	addr := fmt.Sprintf("%s:22", vmIP)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(restartCommand)
	if err != nil {
		return fmt.Errorf("restart command failed: %w (output: %s)", err, string(output))
	}

	// M-2: Only set cooldown after successful restart
	rm.SetCooldown(customerID)

	slog.Info("gateway restarted via SSH",
		"customer_id", customerID,
		"vm_ip", vmIP,
		"output", string(output),
	)
	return nil
}

func (rm *RestartManager) loadSSHKey() (ssh.Signer, error) {
	key, err := os.ReadFile(rm.sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", rm.sshKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return signer, nil
}

// buildHostKeyCallback returns a known_hosts-based callback if available,
// falling back to InsecureIgnoreHostKey with a warning. (M-1 fix)
func buildHostKeyCallback() ssh.HostKeyCallback {
	home, _ := os.UserHomeDir()
	knownHostsPath := home + "/.ssh/known_hosts"

	if _, err := os.Stat(knownHostsPath); err == nil {
		cb, err := knownhosts.New(knownHostsPath)
		if err == nil {
			return cb
		}
		slog.Warn("failed to parse known_hosts, falling back to insecure",
			"path", knownHostsPath, "error", err)
	} else {
		slog.Warn("known_hosts not found, using insecure host key verification — MITM risk",
			"path", knownHostsPath)
	}

	return ssh.InsecureIgnoreHostKey()
}

// HandleRestart handles POST /vm/{customer_id}/restart requests.
func (h *Handler) HandleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// H-2: Origin check to prevent CSRF
	if !checkOrigin(r) {
		writeJSON(w, http.StatusForbidden, restartResponse{
			Status:  "error",
			Message: "invalid origin",
		})
		return
	}

	customerID := extractCustomerID(r.URL.Path)
	if customerID == "" || !customerIDPattern.MatchString(customerID) {
		http.Error(w, "invalid customer_id", http.StatusBadRequest)
		return
	}

	// H-2: Use extractTokenNoCookie to prevent CSRF via cookie-only auth
	tokenStr := extractTokenNoCookie(r)
	if tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, restartResponse{
			Status:  "error",
			Message: "unauthorized",
		})
		return
	}

	claims, err := h.jwt.Validate(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, restartResponse{
			Status:  "error",
			Message: "invalid token",
		})
		return
	}

	// Look up VM
	vm, err := h.vms.LookupByCustomerID(customerID)
	if err != nil {
		slog.Error("restart: vm lookup failed", "error", err, "customer_id", customerID)
		writeJSON(w, http.StatusInternalServerError, restartResponse{
			Status:  "error",
			Message: "internal error",
		})
		return
	}
	if vm == nil {
		writeJSON(w, http.StatusNotFound, restartResponse{
			Status:  "error",
			Message: "no VM assigned",
		})
		return
	}

	// Verify ownership (unless admin)
	if vm.UserID != claims.UserID && !h.isAdmin(claims.Email) {
		writeJSON(w, http.StatusForbidden, restartResponse{
			Status:  "error",
			Message: "forbidden",
		})
		return
	}

	// Check cooldown
	if remaining := h.restarts.CheckCooldown(customerID); remaining > 0 {
		writeJSON(w, http.StatusTooManyRequests, restartResponse{
			Status:           "cooldown",
			RemainingSeconds: remaining,
		})
		return
	}

	// Execute restart (async — return immediately, restart happens in background)
	go func() {
		if err := h.restarts.Restart(customerID, vm.EffectiveIP(), vm.GatewayPort); err != nil {
			slog.Error("restart failed",
				"customer_id", customerID,
				"error", err,
			)
		}
	}()

	writeJSON(w, http.StatusOK, restartResponse{
		Status:          "restarting",
		CooldownSeconds: int(restartCooldown.Seconds()),
	})
}

// writeJSONRestart writes a JSON restart response (used internally).
func writeJSONRestart(w http.ResponseWriter, status int, resp restartResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
