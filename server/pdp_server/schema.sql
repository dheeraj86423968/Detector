-- Platform database (Postgres). Telemetry (baseline entities/events) lives in a separate database
-- with one schema per endpoint so it can be purged independently.

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','analyst')), created_at TIMESTAMPTZ DEFAULT now());
-- 0.3: single sign-on accounts (auth='oidc', bound to issuer + subject; no usable password) and sign-in back-off
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_sub TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc ON users (oidc_issuer, oidc_sub) WHERE oidc_sub IS NOT NULL;

CREATE TABLE IF NOT EXISTS enroll_tokens (
  token TEXT PRIMARY KEY, name TEXT NOT NULL, created_by INT REFERENCES users(id),
  expires_at TIMESTAMPTZ NOT NULL, used_by UUID, kind TEXT NOT NULL DEFAULT 'live', dataset TEXT);
ALTER TABLE enroll_tokens ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'live';
ALTER TABLE enroll_tokens ADD COLUMN IF NOT EXISTS dataset TEXT;

CREATE TABLE IF NOT EXISTS endpoints (
  id UUID PRIMARY KEY, name TEXT NOT NULL, hostname TEXT, os TEXT, arch TEXT, agent_version TEXT,
  phase TEXT NOT NULL DEFAULT 'pending' CHECK (phase IN ('pending','baseline','training','protected','degraded','retired')),
  kind TEXT NOT NULL DEFAULT 'live' CHECK (kind IN ('live','benchmark','simulation')),
  config JSONB NOT NULL DEFAULT '{}', cert_serial TEXT, enrolled_at TIMESTAMPTZ, last_seen TIMESTAMPTZ,
  baseline_days_done INT NOT NULL DEFAULT 0, current_bundle UUID);

CREATE TABLE IF NOT EXISTS baseline_days (
  endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE, date DATE NOT NULL, events BIGINT NOT NULL DEFAULT 0,
  windows INT NOT NULL DEFAULT 0, complete BOOLEAN NOT NULL DEFAULT false, completed_at TIMESTAMPTZ, PRIMARY KEY (endpoint_id, date));
ALTER TABLE baseline_days ADD COLUMN IF NOT EXISTS windows INT NOT NULL DEFAULT 0;
ALTER TABLE baseline_days ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS upload_batches (
  endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE, batch_id TEXT NOT NULL, kind TEXT NOT NULL,
  rows INT NOT NULL, received_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY (endpoint_id, batch_id));

CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY, endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE, kind TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed','cancelled')),
  params JSONB NOT NULL DEFAULT '{}', progress JSONB NOT NULL DEFAULT '{}', error TEXT,
  created_at TIMESTAMPTZ DEFAULT now(), started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, heartbeat TIMESTAMPTZ);

CREATE TABLE IF NOT EXISTS bundles (
  id UUID PRIMARY KEY, endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE, job_id UUID REFERENCES jobs(id),
  path TEXT NOT NULL, sha256 TEXT NOT NULL, manifest JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT now());

CREATE TABLE IF NOT EXISTS windows (
  endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE, start_ns BIGINT NOT NULL, end_ns BIGINT NOT NULL,
  edges INT, nodes INT, alerts INT, max_fused REAL, max_r1 REAL, max_r2 REAL, bundle_id UUID,
  PRIMARY KEY (endpoint_id, start_ns));
CREATE INDEX IF NOT EXISTS windows_time ON windows (endpoint_id, start_ns DESC);

CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY, endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE, window_start_ns BIGINT NOT NULL,
  node_uuid TEXT NOT NULL, ntype TEXT, label TEXT, display JSONB, fused REAL, r1 REAL, r2 REAL,
  context JSONB, status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','ack','closed','true_positive','false_positive')),
  created_at TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS alerts_endpoint_time ON alerts (endpoint_id, window_start_ns DESC);

CREATE TABLE IF NOT EXISTS sim_campaigns (
  id UUID PRIMARY KEY, name TEXT NOT NULL, endpoint_id UUID REFERENCES endpoints(id), bundle_id UUID REFERENCES bundles(id),
  spec JSONB NOT NULL, seed BIGINT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
  created_at TIMESTAMPTZ DEFAULT now(), finished_at TIMESTAMPTZ);

CREATE TABLE IF NOT EXISTS sim_runs (
  id BIGSERIAL PRIMARY KEY, campaign_id UUID REFERENCES sim_campaigns(id) ON DELETE CASCADE, run_index INT NOT NULL,
  attack JSONB NOT NULL, result JSONB NOT NULL);

-- 0.2: endpoint health (last heartbeat), command acknowledgements, key/value state (alert export cursor)
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS health JSONB;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS result TEXT;
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs (state, kind, created_at);
CREATE INDEX IF NOT EXISTS alerts_window ON alerts (endpoint_id, window_start_ns);
ALTER TABLE enroll_tokens ADD COLUMN IF NOT EXISTS config JSONB;
-- 0.3: layered detection. Which layer raised an alert (novelty | rules | corroborated | learned), the rule and the
-- analyst-facing reason; all reasons for the node are kept in reasons (JSON list).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS layer TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reasons JSONB;
CREATE INDEX IF NOT EXISTS alerts_layer ON alerts (endpoint_id, layer);
