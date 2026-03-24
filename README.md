# evaos-ws-proxy

WebSocket authentication proxy for Cloud evaOS. Sits between the electricsheephq.com dashboard and customer VM OpenClaw gateways.

## Architecture

```
Browser (Supabase JWT)
    │
    ▼
wss://ecs.electricsheephq.com/vm/{customer_id}/
    │
    ├── Caddy (TLS termination)
    │
    ▼
WS Auth Proxy (:8080)
    │  - Validates Supabase JWT
    │  - Looks up customer_vms in Supabase
    │  - Injects X-Forwarded-User + gateway token
    │
    ▼
ws://{tailnet_ip}:18789 (Headscale mesh → Customer VM)
    │
    ▼
OpenClaw Gateway (trusted-proxy auth mode)
```

The proxy validates the user's JWT, looks up their VM, then opens a backend WebSocket to the VM gateway via the Headscale mesh. It injects trusted-proxy headers (`X-Forwarded-User`, `X-Forwarded-Customer`) and the gateway token so the customer's OpenClaw gateway accepts the connection. All WebSocket frames (including the OpenClaw protocol handshake) are passed through transparently.

## Quick Start

```bash
# Build
go build -o ws-proxy ./cmd/proxy

# Configure
cp .env.example .env
# Edit .env with your Supabase credentials

# Run
source .env && ./ws-proxy
```

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SUPABASE_URL` | ✅ | — | Supabase project URL |
| `SUPABASE_SERVICE_KEY` | ✅ | — | Supabase service_role key (NOT anon) |
| `SUPABASE_JWT_SECRET` | ✅ | — | JWT secret from Supabase Settings → API |
| `LISTEN_ADDR` | | `:8080` | Address to listen on |
| `ADMIN_EMAILS` | | — | Comma-separated admin emails for VM override |
| `VM_CACHE_TTL` | | `60s` | How long to cache VM lookups |
| `LOG_LEVEL` | | `info` | Log level: debug, info, warn, error |
| `BACKEND_CONNECT_TIMEOUT` | | `10s` | Timeout connecting to backend VM |
| `BACKEND_RECONNECT_ATTEMPTS` | | `3` | Retry count on backend disconnect |
| `MAX_CONNECTIONS` | | `5000` | Max concurrent WebSocket connections |

## API

### `GET /vm/{customer_id}/` — WebSocket Proxy

Upgrades to WebSocket. Validates Supabase JWT, verifies the user owns the VM, then proxies to the backend gateway.

**Auth (one of):**
- `Authorization: Bearer <supabase_jwt>` header
- `?token=<supabase_jwt>` query param  
- `sb-*-auth-token` cookie (Supabase session cookie)

**Authorization:** The JWT's `sub` (user_id) must match the `user_id` in the `customer_vms` row. Admins (emails in `ADMIN_EMAILS`) bypass this check.

**Backend connection:** The proxy connects to `ws://{tailnet_ip}:{gateway_port}?token={gateway_token}` and sets:
- `X-Forwarded-User: {customer_id}` — identifies the customer to the OpenClaw gateway
- `X-Forwarded-Customer: {customer_id}` — same, for compatibility
- `X-OpenClaw-Token: {gateway_token}` — authenticates with the gateway

All WebSocket frames are proxied transparently. The OpenClaw protocol handshake (challenge → connect → hello-ok) happens end-to-end between the browser client and the gateway.

**Error codes:**
- `400` — Missing customer_id in path
- `401` — Missing or invalid JWT
- `403` — User doesn't own this VM
- `404` — No active VM for this customer_id
- `503` — Connection limit reached

### `GET /health` — Health Check

```json
{
  "status": "ok",
  "connections": 42,
  "uptime_seconds": 3600
}
```

## Database

The proxy reads from the existing `customer_vms` table in Supabase. Run the migration to add the gateway columns:

```bash
# Via Supabase SQL Editor: paste migrations/001_user_vms.sql
# Or via psql:
psql $DATABASE_URL < migrations/001_user_vms.sql
```

This adds: `gateway_port`, `gateway_token`, `plan_tier`, `metadata`, timestamps, RLS policies, and indexes.

## Frontend Integration

The electricsheephq.com dashboard connects with:

```typescript
const gatewayUrl = `wss://ecs.electricsheephq.com/vm/${customerVM.customer_id}/`;

useOpenClawChat({
  gatewayUrl,
  authMode: 'trusted-proxy',  // No explicit auth — proxy handles it
});
```

The Supabase JWT is sent automatically by the browser (via cookie or the dashboard can set the Authorization header on the upgrade request).

## Docker

```bash
docker build -t evaos-ws-proxy .

docker run -p 8080:8080 \
  -e SUPABASE_URL=https://xxx.supabase.co \
  -e SUPABASE_SERVICE_KEY=eyJ... \
  -e SUPABASE_JWT_SECRET=secret \
  evaos-ws-proxy
```

## Coolify Deployment

1. Create a new Docker Compose service in Coolify
2. Point to this repo
3. Set environment variables in Coolify UI
4. Deploy

Caddy config for `ecs.electricsheephq.com`:
```
handle /vm/* {
    reverse_proxy localhost:8080
}
```

## Testing

```bash
go test ./... -v
```

## License

Proprietary — 100Yen Org / Electric Sheep Inc.
