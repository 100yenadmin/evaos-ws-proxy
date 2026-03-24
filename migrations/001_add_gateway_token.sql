-- ============================================================================
-- Migration 001: Add gateway_token to existing customer_vms table
--
-- The customer_vms table already exists with columns:
--   id, customer_id, user_id, tier, hetzner_server_id, hetzner_server_name,
--   public_ip, tailnet_ip, headscale_node_id, openclaw_port, paperclip_port,
--   region, status, health_status, last_health_check, created_at, updated_at,
--   activated_at, suspended_at, metadata
--
-- This migration adds the gateway_token column needed by the WS proxy
-- to authenticate with backend VM gateways.
-- ============================================================================

-- Add gateway token column (nullable — will be populated per-VM during provisioning)
ALTER TABLE public.customer_vms
  ADD COLUMN IF NOT EXISTS gateway_token TEXT;

-- Ensure RLS is enabled
ALTER TABLE public.customer_vms ENABLE ROW LEVEL SECURITY;

-- Users can only read their own VM info
DROP POLICY IF EXISTS "Users can view own VM" ON public.customer_vms;
CREATE POLICY "Users can view own VM" ON public.customer_vms
  FOR SELECT USING (auth.uid() = user_id);

-- Service role has full access (used by the WS proxy)
DROP POLICY IF EXISTS "Service role full access" ON public.customer_vms;
CREATE POLICY "Service role full access" ON public.customer_vms
  FOR ALL USING (true);
-- Note: service_role bypasses RLS anyway, but this policy ensures
-- the proxy's service key queries work even if RLS behavior changes.
