-- ============================================================================
-- Migration 001: Add gateway columns to existing customer_vms table
--
-- The customer_vms table already exists in Supabase with columns:
--   customer_id, user_id, tailnet_ip, status
--
-- This migration adds the columns needed by the WS proxy for backend
-- gateway connections and plan-based routing.
-- ============================================================================

-- Add gateway connection columns
ALTER TABLE public.customer_vms
  ADD COLUMN IF NOT EXISTS gateway_port INTEGER NOT NULL DEFAULT 18789,
  ADD COLUMN IF NOT EXISTS gateway_token TEXT NOT NULL DEFAULT '';

-- Add plan tier for future rate limiting / feature gating
ALTER TABLE public.customer_vms
  ADD COLUMN IF NOT EXISTS plan_tier TEXT NOT NULL DEFAULT 'go'
    CHECK (plan_tier IN ('go', 'pro', 'biz', 'admin'));

-- Add metadata JSONB for extensibility
ALTER TABLE public.customer_vms
  ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Add timestamps if they don't exist
ALTER TABLE public.customer_vms
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Indexes (idempotent — IF NOT EXISTS)
CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_vms_user_active
  ON public.customer_vms(user_id) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_customer_vms_customer_id
  ON public.customer_vms(customer_id);

CREATE INDEX IF NOT EXISTS idx_customer_vms_status
  ON public.customer_vms(status);

-- RLS (enable if not already enabled)
ALTER TABLE public.customer_vms ENABLE ROW LEVEL SECURITY;

-- Users can only read their own VM info (drop first to be idempotent)
DROP POLICY IF EXISTS "Users can view own VM" ON public.customer_vms;
CREATE POLICY "Users can view own VM" ON public.customer_vms
  FOR SELECT USING (auth.uid() = user_id);

-- Service role has full access
DROP POLICY IF EXISTS "Service role full access" ON public.customer_vms;
CREATE POLICY "Service role full access" ON public.customer_vms
  FOR ALL USING (auth.role() = 'service_role');

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS customer_vms_updated_at ON public.customer_vms;
CREATE TRIGGER customer_vms_updated_at
  BEFORE UPDATE ON public.customer_vms
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();
