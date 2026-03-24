package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// VMInfo contains the connection details for a customer's VM.
// Field names match the actual Supabase customer_vms table schema.
type VMInfo struct {
	CustomerID   string  `json:"customer_id"`
	UserID       string  `json:"user_id"`
	TailnetIP    *string `json:"tailnet_ip"`    // nullable — use PublicIP as fallback
	PublicIP     string  `json:"public_ip"`
	GatewayPort  int     `json:"openclaw_port"` // maps from openclaw_port column
	GatewayToken *string `json:"gateway_token"` // nullable until provisioned
	Status       string  `json:"status"`
}

// EffectiveIP returns the best IP to connect to: tailnet_ip if available, else public_ip.
func (v *VMInfo) EffectiveIP() string {
	if v.TailnetIP != nil && *v.TailnetIP != "" {
		return *v.TailnetIP
	}
	return v.PublicIP
}

// EffectiveToken returns the gateway token or empty string if not set.
func (v *VMInfo) EffectiveToken() string {
	if v.GatewayToken != nil {
		return *v.GatewayToken
	}
	return ""
}

type cacheEntry struct {
	vm        *VMInfo
	expiresAt time.Time
}

// SupabaseRegistry looks up VM info from Supabase PostgREST with an in-memory cache.
type SupabaseRegistry struct {
	baseURL    string
	serviceKey string
	cacheTTL   time.Duration
	client     *http.Client

	mu    sync.RWMutex
	cache map[string]*cacheEntry // keyed by customer_id
}

// NewSupabaseRegistry creates a registry backed by Supabase PostgREST.
func NewSupabaseRegistry(baseURL, serviceKey string, cacheTTL time.Duration) *SupabaseRegistry {
	return &SupabaseRegistry{
		baseURL:    baseURL,
		serviceKey: serviceKey,
		cacheTTL:   cacheTTL,
		client:     &http.Client{Timeout: 10 * time.Second},
		cache:      make(map[string]*cacheEntry),
	}
}

// LookupByCustomerID finds the active VM for a given customer_id.
// Results are cached for the configured TTL.
func (r *SupabaseRegistry) LookupByCustomerID(customerID string) (*VMInfo, error) {
	// Check cache
	r.mu.RLock()
	if entry, ok := r.cache[customerID]; ok && time.Now().Before(entry.expiresAt) {
		r.mu.RUnlock()
		return entry.vm, nil
	}
	r.mu.RUnlock()

	// Fetch from Supabase
	vm, err := r.fetchByCustomerID(customerID)
	if err != nil {
		return nil, err
	}

	// Cache positive results only — negative results use short TTL to avoid
	// poisoning during onboarding (customer row may be added seconds later)
	r.mu.Lock()
	ttl := r.cacheTTL
	if vm == nil {
		ttl = 5 * time.Second // Short negative cache
	}
	r.cache[customerID] = &cacheEntry{
		vm:        vm,
		expiresAt: time.Now().Add(ttl),
	}
	r.mu.Unlock()

	return vm, nil
}

// LookupByUserID finds the active VM for a given user_id.
func (r *SupabaseRegistry) LookupByUserID(userID string) (*VMInfo, error) {
	queryURL := fmt.Sprintf("%s/rest/v1/customer_vms?user_id=eq.%s&status=eq.active&select=*",
		r.baseURL, url.QueryEscape(userID))
	return r.doQuery(queryURL)
}

func (r *SupabaseRegistry) fetchByCustomerID(customerID string) (*VMInfo, error) {
	queryURL := fmt.Sprintf("%s/rest/v1/customer_vms?customer_id=eq.%s&status=eq.active&select=*",
		r.baseURL, url.QueryEscape(customerID))
	return r.doQuery(queryURL)
}

func (r *SupabaseRegistry) doQuery(url string) (*VMInfo, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("apikey", r.serviceKey)
	req.Header.Set("Authorization", "Bearer "+r.serviceKey)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("supabase request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("supabase returned %d: %s", resp.StatusCode, string(body))
	}

	var vms []VMInfo
	if err := json.Unmarshal(body, &vms); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if len(vms) == 0 {
		return nil, nil // No VM found — caller decides
	}

	// Default gateway port if not set
	if vms[0].GatewayPort == 0 {
		vms[0].GatewayPort = 18789
	}

	return &vms[0], nil
}
