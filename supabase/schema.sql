-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Security Runs Table
CREATE TABLE IF NOT EXISTS security_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    target_url TEXT NOT NULL,
    app_id TEXT,
    started_at TIMESTAMP WITH TIME ZONE,
    ended_at TIMESTAMP WITH TIME ZONE
);

-- 2. Agent Sessions Table
CREATE TABLE IF NOT EXISTS agent_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    run_id UUID REFERENCES security_runs(id) ON DELETE CASCADE,
    agent_type TEXT NOT NULL, -- exposure, headers_tls, auth_abuse
    status TEXT NOT NULL DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    progress INTEGER DEFAULT 0,
    requests_used INTEGER DEFAULT 0,
    budget INTEGER DEFAULT 20
);

-- 3. Run Events Table (Live Console)
CREATE TABLE IF NOT EXISTS run_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    run_id UUID REFERENCES security_runs(id) ON DELETE CASCADE,
    agent_type TEXT,
    event_type TEXT NOT NULL, -- INFO, WARNING, ERROR, SUCCESS
    message TEXT NOT NULL,
    data JSONB
);

-- 4. Findings Table (Vulnerabilities)
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    run_id UUID REFERENCES security_runs(id) ON DELETE CASCADE,
    agent_type TEXT NOT NULL,
    severity TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    title TEXT NOT NULL,
    evidence TEXT,
    recommendation TEXT
);

-- Realtime Enablement
-- NOTE: You must also enable Realtime in the Supabase Dashboard for these tables!
-- Go to Database -> Replication -> Source and toggle "Insert/Update/Delete" for:
-- agent_sessions, run_events, findings

-- RLS Policies (Open for Demo - secure this for production!)
ALTER TABLE security_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Enable all for public" ON security_runs FOR ALL USING (true);

ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Enable all for public" ON agent_sessions FOR ALL USING (true);

ALTER TABLE run_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Enable all for public" ON run_events FOR ALL USING (true);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Enable all for public" ON findings FOR ALL USING (true);

-- Migrations
ALTER TABLE security_runs ADD COLUMN IF NOT EXISTS configuration JSONB;

