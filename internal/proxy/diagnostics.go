package proxy

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// CheckStatus represents the health status of a diagnostic check.
type CheckStatus string

const (
	StatusOK       CheckStatus = "ok"
	StatusWarning  CheckStatus = "warning"
	StatusCritical CheckStatus = "critical"
	StatusUnknown  CheckStatus = "unknown"
)

// DiagnosticCheck represents a single diagnostic check result.
type DiagnosticCheck struct {
	Name        string      `json:"name"`
	Status      CheckStatus `json:"status"`
	Message     string      `json:"message"`
	Details     string      `json:"details,omitempty"`
	Suggestion  string      `json:"suggestion,omitempty"`
	AutoFixable bool        `json:"auto_fixable"`
	Icon        string      `json:"-"`
}

// DiagnosticReport is the full diagnostic report for a customer VM.
type DiagnosticReport struct {
	CustomerID    string            `json:"customer_id"`
	Timestamp     time.Time         `json:"timestamp"`
	OverallStatus CheckStatus       `json:"overall_status"`
	Checks        []DiagnosticCheck `json:"checks"`
	GatewayUp     bool              `json:"gateway_up"`
	Backups       []BackupInfo      `json:"backups"`
	VMReachable   bool              `json:"vm_reachable"`
}

// BackupInfo represents a config backup file on the VM.
type BackupInfo struct {
	Filename string `json:"filename"`
	Size     string `json:"size,omitempty"`
}

// CommonError describes a well-known OpenClaw failure mode for the error catalog.
type CommonError struct {
	Title       string
	Description string
	Suggestion  string
	Icon        string
}

// DiagnosticsRunner runs diagnostic checks on a customer VM.
type DiagnosticsRunner interface {
	RunDiagnostics(customerID, vmIP string) (*DiagnosticReport, error)
	ListBackups(vmIP string) ([]BackupInfo, error)
	RestoreBackup(customerID, vmIP, backupFilename string) error
}

// diagnosticScript runs all checks in a single SSH session.
const diagnosticScript = `echo "---GATEWAY_STATUS---"
systemctl is-active openclaw-gateway 2>/dev/null || echo unknown
echo "---DISK_USAGE---"
df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %'
echo "---DISK_DETAIL---"
df -h / 2>/dev/null | tail -1
echo "---MEMORY---"
free -m 2>/dev/null | awk '/Mem:/{printf "%d %d %d\n", $2, $3, $7}'
echo "---UPTIME---"
uptime -s 2>/dev/null || uptime 2>/dev/null || echo unknown
echo "---CONFIG_CHECK---"
F="$HOME/.openclaw/openclaw.json"
if [ -f "$F" ]; then
  python3 -c "import json; json.load(open('$F'))" 2>&1 && echo "VALID" || echo "INVALID"
else
  echo "MISSING"
fi
echo "---RECENT_ERRORS---"
journalctl -u openclaw-gateway -p err --no-pager -n 5 --output=short 2>/dev/null || echo "no journal"
echo "---RESTART_COUNT---"
journalctl -u openclaw-gateway --since "10 min ago" 2>/dev/null | grep -c "Started" || echo "0"
echo "---SSL_CERT---"
CERT="$HOME/.openclaw/certs/cert.pem"
if [ -f "$CERT" ]; then
  openssl x509 -in "$CERT" -noout -enddate 2>/dev/null
else
  echo "no cert"
fi
echo "---BACKUPS---"
ls -1t $HOME/.openclaw/openclaw.json.backup-* 2>/dev/null || echo "none"
echo "---END---"`

// SSHDiagnostics implements DiagnosticsRunner using SSH.
type SSHDiagnostics struct {
	sshUser    string
	sshKeyPath string
}

// NewSSHDiagnostics creates a new SSH diagnostics runner using the same config as RestartManager.
func NewSSHDiagnostics(rm *RestartManager) *SSHDiagnostics {
	return &SSHDiagnostics{
		sshUser:    rm.sshUser,
		sshKeyPath: rm.sshKeyPath,
	}
}

func (d *SSHDiagnostics) sshClient(vmIP string) (*ssh.Client, error) {
	key, err := readFileFunc(d.sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", d.sshKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	config := &ssh.ClientConfig{
		User:            d.sshUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: buildHostKeyCallback(), // M-1: known_hosts verification
		Timeout:         sshTimeout,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:22", vmIP), config)
}

func (d *SSHDiagnostics) runCommand(vmIP, command string) (string, error) {
	client, err := d.sshClient(vmIP)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

// RunDiagnostics executes all diagnostic checks on a customer VM via SSH.
func (d *SSHDiagnostics) RunDiagnostics(customerID, vmIP string) (*DiagnosticReport, error) {
	report := &DiagnosticReport{
		CustomerID: customerID,
		Timestamp:  time.Now(),
		Checks:     make([]DiagnosticCheck, 0, 10),
	}

	client, err := d.sshClient(vmIP)
	if err != nil {
		report.VMReachable = false
		report.OverallStatus = StatusCritical
		report.Checks = append(report.Checks, DiagnosticCheck{
			Name:       "VM Connection",
			Status:     StatusCritical,
			Message:    "Cannot reach your VM",
			Details:    fmt.Sprintf("SSH connection to %s failed: %v", vmIP, err),
			Suggestion: "The virtual machine may be down or unreachable. Please contact support if this persists.",
			Icon:       "🖥️",
		})
		return report, nil
	}
	defer client.Close()
	report.VMReachable = true

	session, err := client.NewSession()
	if err != nil {
		report.OverallStatus = StatusCritical
		return report, fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(diagnosticScript)
	if err != nil {
		slog.Warn("diagnostic script partial failure", "error", err, "customer_id", customerID)
	}

	sections := parseDiagnosticSections(string(output))

	// 1. Gateway Status
	gwStatus := strings.TrimSpace(sections["GATEWAY_STATUS"])
	gwCheck := DiagnosticCheck{Name: "Gateway Status", Icon: "⚡"}
	switch gwStatus {
	case "active":
		gwCheck.Status = StatusOK
		gwCheck.Message = "Gateway is running"
		report.GatewayUp = true
	case "inactive", "dead":
		gwCheck.Status = StatusCritical
		gwCheck.Message = "Gateway is stopped"
		gwCheck.Suggestion = "Try restarting your Eva using the button below."
		gwCheck.AutoFixable = true
	case "failed":
		gwCheck.Status = StatusCritical
		gwCheck.Message = "Gateway has crashed"
		gwCheck.Suggestion = "The gateway crashed. Try restarting — if it keeps failing, contact support."
		gwCheck.AutoFixable = true
	default:
		gwCheck.Status = StatusUnknown
		gwCheck.Message = "Gateway status unknown"
		gwCheck.Details = gwStatus
	}
	report.Checks = append(report.Checks, gwCheck)

	// 2. Crash-loop detection
	restartCountStr := strings.TrimSpace(sections["RESTART_COUNT"])
	restartCount, _ := strconv.Atoi(restartCountStr)
	crashCheck := DiagnosticCheck{Name: "Stability", Icon: "🔄"}
	switch {
	case restartCount >= 3:
		crashCheck.Status = StatusCritical
		crashCheck.Message = fmt.Sprintf("Crash-looping: %d restarts in last 10 minutes", restartCount)
		crashCheck.Suggestion = "Eva keeps crashing after restart. This usually means a configuration issue. Please contact support."
	case restartCount >= 1:
		crashCheck.Status = StatusWarning
		crashCheck.Message = fmt.Sprintf("%d restart(s) in last 10 minutes", restartCount)
	default:
		crashCheck.Status = StatusOK
		crashCheck.Message = "Stable — no recent restarts"
	}
	report.Checks = append(report.Checks, crashCheck)

	// 3. Disk Usage
	diskPctStr := strings.TrimSpace(sections["DISK_USAGE"])
	diskDetail := strings.TrimSpace(sections["DISK_DETAIL"])
	diskPct, _ := strconv.Atoi(diskPctStr)
	diskCheck := DiagnosticCheck{Name: "Disk Space", Icon: "💾", Details: diskDetail}
	switch {
	case diskPct >= 95:
		diskCheck.Status = StatusCritical
		diskCheck.Message = fmt.Sprintf("Disk almost full: %d%% used", diskPct)
		diskCheck.Suggestion = "Your VM's disk is nearly full. This can prevent Eva from working properly. Contact support to free up space."
	case diskPct >= 80:
		diskCheck.Status = StatusWarning
		diskCheck.Message = fmt.Sprintf("Disk usage high: %d%% used", diskPct)
		diskCheck.Suggestion = "Disk usage is getting high. Consider asking support to clean up old logs."
	case diskPct > 0:
		diskCheck.Status = StatusOK
		diskCheck.Message = fmt.Sprintf("Disk usage normal: %d%% used", diskPct)
	default:
		diskCheck.Status = StatusUnknown
		diskCheck.Message = "Could not check disk usage"
	}
	report.Checks = append(report.Checks, diskCheck)

	// 4. Memory
	memLine := strings.TrimSpace(sections["MEMORY"])
	memCheck := DiagnosticCheck{Name: "Memory", Icon: "🧠"}
	memParts := strings.Fields(memLine)
	if len(memParts) >= 3 {
		total, _ := strconv.Atoi(memParts[0])
		used, _ := strconv.Atoi(memParts[1])
		available, _ := strconv.Atoi(memParts[2])
		_ = used
		memCheck.Details = fmt.Sprintf("Total: %dMB, Used: %dMB, Available: %dMB", total, used, available)
		if total > 0 {
			availPct := float64(available) / float64(total) * 100
			switch {
			case availPct < 5:
				memCheck.Status = StatusCritical
				memCheck.Message = fmt.Sprintf("Memory critically low: %dMB free of %dMB", available, total)
				memCheck.Suggestion = "Very low memory can cause Eva to crash repeatedly. Contact support — your VM may need more resources."
			case availPct < 10:
				memCheck.Status = StatusWarning
				memCheck.Message = fmt.Sprintf("Memory low: %dMB free of %dMB", available, total)
				memCheck.Suggestion = "Memory is getting tight. A restart may help free up memory temporarily."
			default:
				memCheck.Status = StatusOK
				memCheck.Message = fmt.Sprintf("Memory OK: %dMB free of %dMB", available, total)
			}
		}
	} else {
		memCheck.Status = StatusUnknown
		memCheck.Message = "Could not check memory"
	}
	report.Checks = append(report.Checks, memCheck)

	// 5. Config Validity
	configStatus := strings.TrimSpace(sections["CONFIG_CHECK"])
	configCheck := DiagnosticCheck{Name: "Configuration", Icon: "⚙️"}
	switch {
	case strings.Contains(configStatus, "VALID"):
		configCheck.Status = StatusOK
		configCheck.Message = "Configuration file is valid"
	case strings.Contains(configStatus, "INVALID"):
		configCheck.Status = StatusCritical
		configCheck.Message = "Configuration file has errors"
		configCheck.Details = configStatus
		configCheck.Suggestion = "The configuration file is malformed. Try restoring a backup below."
		configCheck.AutoFixable = true
	case strings.Contains(configStatus, "MISSING"):
		configCheck.Status = StatusCritical
		configCheck.Message = "Configuration file is missing"
		configCheck.Suggestion = "The configuration file cannot be found. Contact support."
	default:
		configCheck.Status = StatusUnknown
		configCheck.Message = "Could not validate configuration"
		configCheck.Details = configStatus
	}
	report.Checks = append(report.Checks, configCheck)

	// 6. VM Uptime
	uptimeStr := strings.TrimSpace(sections["UPTIME"])
	report.Checks = append(report.Checks, DiagnosticCheck{
		Name:    "VM Uptime",
		Status:  StatusOK,
		Message: "VM started: " + uptimeStr,
		Icon:    "⏱️",
	})

	// 7. SSL/Cert Status
	certStr := strings.TrimSpace(sections["SSL_CERT"])
	certCheck := DiagnosticCheck{Name: "SSL Certificate", Icon: "🔒"}
	if certStr == "no cert" {
		certCheck.Status = StatusOK
		certCheck.Message = "No custom SSL certificate (using default)"
	} else if strings.Contains(certStr, "notAfter=") {
		expStr := strings.TrimPrefix(certStr, "notAfter=")
		if expTime, err := parseCertDate(expStr); err == nil {
			daysLeft := int(time.Until(expTime).Hours() / 24)
			switch {
			case daysLeft < 0:
				certCheck.Status = StatusCritical
				certCheck.Message = "SSL certificate has EXPIRED"
				certCheck.Suggestion = "Your SSL certificate has expired. Secure connections may fail. Contact support."
			case daysLeft < 7:
				certCheck.Status = StatusWarning
				certCheck.Message = fmt.Sprintf("SSL certificate expires in %d days", daysLeft)
				certCheck.Suggestion = "Your SSL certificate expires very soon. Contact support to renew."
			case daysLeft < 30:
				certCheck.Status = StatusOK
				certCheck.Message = fmt.Sprintf("SSL certificate valid (%d days remaining)", daysLeft)
			default:
				certCheck.Status = StatusOK
				certCheck.Message = fmt.Sprintf("SSL certificate valid (%d days remaining)", daysLeft)
			}
		} else {
			certCheck.Status = StatusUnknown
			certCheck.Message = "Certificate expiry: " + expStr
		}
	} else {
		certCheck.Status = StatusUnknown
		certCheck.Message = "Could not check SSL certificate"
		certCheck.Details = certStr
	}
	report.Checks = append(report.Checks, certCheck)

	// 8. Recent Errors
	errorsStr := strings.TrimSpace(sections["RECENT_ERRORS"])
	errCheck := DiagnosticCheck{Name: "Recent Errors", Icon: "📋"}
	if errorsStr == "no journal" || errorsStr == "" {
		errCheck.Status = StatusOK
		errCheck.Message = "No recent error logs available"
	} else {
		var errorLines []string
		for _, line := range strings.Split(errorsStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "--") {
				errorLines = append(errorLines, line)
			}
		}
		if len(errorLines) == 0 {
			errCheck.Status = StatusOK
			errCheck.Message = "No recent errors"
		} else {
			errCheck.Status = StatusWarning
			errCheck.Message = fmt.Sprintf("%d recent error(s) in gateway logs", len(errorLines))
			// Limit details to avoid huge output
			if len(errorLines) > 5 {
				errorLines = errorLines[:5]
			}
			errCheck.Details = strings.Join(errorLines, "\n")
			errCheck.Suggestion = classifyGatewayErrors(errorLines)
		}
	}
	report.Checks = append(report.Checks, errCheck)

	// 9. Parse backups
	backupsStr := strings.TrimSpace(sections["BACKUPS"])
	if backupsStr != "none" && backupsStr != "" {
		for _, line := range strings.Split(backupsStr, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				report.Backups = append(report.Backups, BackupInfo{
					Filename: line,
				})
			}
		}
	}

	// Calculate overall status
	report.OverallStatus = StatusOK
	for _, check := range report.Checks {
		if check.Status == StatusCritical {
			report.OverallStatus = StatusCritical
			break
		}
		if check.Status == StatusWarning && report.OverallStatus != StatusCritical {
			report.OverallStatus = StatusWarning
		}
	}

	return report, nil
}

// ListBackups returns available config backups on the VM.
func (d *SSHDiagnostics) ListBackups(vmIP string) ([]BackupInfo, error) {
	output, err := d.runCommand(vmIP, `ls -lt $HOME/.openclaw/openclaw.json.backup-* 2>/dev/null || echo "none"`)
	if err != nil && !strings.Contains(output, "none") {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	output = strings.TrimSpace(output)
	if output == "none" || output == "" {
		return nil, nil
	}

	var backups []BackupInfo
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// ls -lt output: -rw-r--r-- 1 root root 1234 Mar 26 10:00 /root/.openclaw/openclaw.json.backup-xxx
		fields := strings.Fields(line)
		if len(fields) >= 9 {
			backups = append(backups, BackupInfo{
				Filename: fields[len(fields)-1],
				Size:     fields[4],
			})
		} else if strings.Contains(line, "openclaw.json.backup") {
			backups = append(backups, BackupInfo{Filename: line})
		}
	}
	return backups, nil
}

// validBackupFilename is a strict allowlist regex for backup filenames.
// Accepts full paths like /root/.openclaw/openclaw.json.backup-20260325
// or /home/user/.openclaw/openclaw.json.backup-2026-03-25_10-00-00
// H-3: Replaced fragile blocklist with strict allowlist.
var validBackupFilename = regexp.MustCompile(
	`^(/root/\.openclaw/|/home/[a-zA-Z0-9_-]+/\.openclaw/)openclaw\.json\.backup-[a-zA-Z0-9_.-]+$`,
)

// RestoreBackup restores a config backup on the VM and restarts the gateway.
func (d *SSHDiagnostics) RestoreBackup(customerID, vmIP, backupFilename string) error {
	// H-3: Strict allowlist validation — only accept well-formed backup paths
	if !validBackupFilename.MatchString(backupFilename) {
		return fmt.Errorf("invalid backup filename")
	}

	// H-3: Additional path traversal check — verify the filename resolves within the expected directory
	dir := filepath.Dir(backupFilename)
	rel, err := filepath.Rel(dir, backupFilename)
	if err != nil || strings.Contains(rel, "..") {
		return fmt.Errorf("invalid backup filename: path traversal detected")
	}

	// Backup current config, then restore, then restart
	cmd := fmt.Sprintf(
		`cp "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/openclaw.json.backup-pre-restore-$(date +%%s)" 2>/dev/null; `+
			`cp %q "$HOME/.openclaw/openclaw.json" && systemctl restart openclaw-gateway`,
		backupFilename,
	)

	output, err := d.runCommand(vmIP, cmd)
	if err != nil {
		return fmt.Errorf("restore failed: %w (output: %s)", err, output)
	}

	slog.Info("config backup restored",
		"customer_id", customerID,
		"vm_ip", vmIP,
		"backup", backupFilename,
		"output", strings.TrimSpace(output),
	)
	return nil
}

// readFileFunc is a package-level var for testing (allows mocking os.ReadFile).
var readFileFunc = os.ReadFile

// parseDiagnosticSections splits the diagnostic script output into named sections.
func parseDiagnosticSections(output string) map[string]string {
	sections := make(map[string]string)
	var currentSection string
	var buf strings.Builder

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "---") && strings.HasSuffix(line, "---") {
			name := strings.Trim(line, "-")
			if name == "END" {
				if currentSection != "" {
					sections[currentSection] = buf.String()
				}
				break
			}
			if currentSection != "" {
				sections[currentSection] = buf.String()
			}
			currentSection = name
			buf.Reset()
		} else if currentSection != "" {
			if buf.Len() > 0 {
				buf.WriteString("\n")
			}
			buf.WriteString(line)
		}
	}
	if currentSection != "" {
		sections[currentSection] = buf.String()
	}
	return sections
}

// parseCertDate parses OpenSSL's notAfter date format.
func parseCertDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	formats := []string{
		"Jan  2 15:04:05 2006 GMT",
		"Jan 2 15:04:05 2006 GMT",
		"Jan  2 15:04:05 2006 MST",
		"Jan 2 15:04:05 2006 MST",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse cert date: %s", s)
}

// classifyGatewayErrors provides human-readable suggestions based on error patterns.
func classifyGatewayErrors(errors []string) string {
	joined := strings.ToLower(strings.Join(errors, " "))
	switch {
	case strings.Contains(joined, "plugin") && (strings.Contains(joined, "failed") || strings.Contains(joined, "error") || strings.Contains(joined, "load")):
		return "A plugin may have failed to load. Try restarting, or contact support if the issue persists."
	case strings.Contains(joined, "address already in use") || strings.Contains(joined, "bind"):
		return "Another process may be using the same port. A restart usually clears this up."
	case strings.Contains(joined, "api key") || strings.Contains(joined, "unauthorized") || strings.Contains(joined, "auth"):
		return "There may be an API key or authentication issue in your configuration."
	case strings.Contains(joined, "model") && (strings.Contains(joined, "not found") || strings.Contains(joined, "unavailable")):
		return "A configured AI model may not be available. Check your model settings."
	case strings.Contains(joined, "rate limit") || strings.Contains(joined, "429"):
		return "An AI provider is rate-limiting requests. This usually resolves on its own."
	case strings.Contains(joined, "out of memory") || strings.Contains(joined, "oom"):
		return "Eva ran out of memory. Contact support — your VM may need more resources."
	case strings.Contains(joined, "disk") || strings.Contains(joined, "no space") || strings.Contains(joined, "enospc"):
		return "The VM may be running low on disk space. Contact support to clean up."
	case strings.Contains(joined, "tls") || strings.Contains(joined, "certificate") || strings.Contains(joined, "x509"):
		return "There may be an SSL/TLS certificate issue. Contact support."
	case strings.Contains(joined, "dns") || strings.Contains(joined, "resolve") || strings.Contains(joined, "lookup"):
		return "DNS resolution failed. This is usually a temporary network issue."
	default:
		return "Check the error details above, or contact support for help."
	}
}

// CommonErrors is the catalog of well-known OpenClaw failure modes shown on the repair page.
var CommonErrors = []CommonError{
	{
		Title:       "Plugin Load Failure",
		Description: "A plugin couldn't start because of a missing dependency or configuration error.",
		Suggestion:  "Try restarting Eva. If the issue persists, a configuration backup restore may help.",
		Icon:        "🧩",
	},
	{
		Title:       "Port Already In Use",
		Description: "Another process is already using the network port Eva needs.",
		Suggestion:  "Restarting usually fixes this. The old process will be stopped first.",
		Icon:        "🔌",
	},
	{
		Title:       "API Key / Auth Error",
		Description: "Eva can't connect to an AI provider because the API key is wrong or expired.",
		Suggestion:  "Check your API keys in settings. Make sure they're valid and not expired.",
		Icon:        "🔑",
	},
	{
		Title:       "Model Not Available",
		Description: "A configured AI model isn't available from the provider.",
		Suggestion:  "The model may have been renamed or discontinued. Check your model settings.",
		Icon:        "🤖",
	},
	{
		Title:       "Rate Limited by Provider",
		Description: "An AI provider is temporarily blocking requests because of too many calls.",
		Suggestion:  "This usually resolves on its own within a few minutes. Just wait.",
		Icon:        "🚦",
	},
	{
		Title:       "Out of Memory (OOM)",
		Description: "Eva used too much memory and the system stopped it to protect the VM.",
		Suggestion:  "Contact support — your VM may need more memory, or there may be a memory leak.",
		Icon:        "💥",
	},
	{
		Title:       "Disk Full",
		Description: "The VM's storage is full, so Eva can't write logs or save data.",
		Suggestion:  "Contact support to clean up old files and free disk space.",
		Icon:        "💾",
	},
	{
		Title:       "TLS Certificate Expired",
		Description: "The SSL/TLS certificate has expired, making secure connections fail.",
		Suggestion:  "Contact support to renew the certificate.",
		Icon:        "🔒",
	},
	{
		Title:       "DNS Resolution Failure",
		Description: "Eva can't look up internet addresses, so it can't reach AI providers.",
		Suggestion:  "This is usually a temporary network issue. Try again in a few minutes.",
		Icon:        "🌐",
	},
}
