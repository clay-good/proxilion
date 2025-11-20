-- Proxilion MCP Security Gateway - PostgreSQL Schema
--
-- This schema stores analytics, audit logs, and threat intelligence
-- for the Proxilion MCP Security Gateway.
--
-- Usage: Automatically loaded by docker-compose.yml on first start

-- ============================================================================
-- Sessions Table - Track all active and historical sessions
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    -- Identifiers
    session_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255),

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    terminated_at TIMESTAMP,

    -- Session stats
    total_requests INTEGER NOT NULL DEFAULT 0,
    blocked_requests INTEGER NOT NULL DEFAULT 0,
    alerted_requests INTEGER NOT NULL DEFAULT 0,
    max_threat_score DECIMAL(5,2) NOT NULL DEFAULT 0.0,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    termination_reason TEXT,

    -- Indexes for fast lookups
    CONSTRAINT sessions_status_check CHECK (status IN ('active', 'terminated', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org_id ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- ============================================================================
-- Events Table - All analyzed tool calls (full audit log)
-- ============================================================================
CREATE TABLE IF NOT EXISTS events (
    -- Identifiers
    event_id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,

    -- Timestamp
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Tool call details
    tool_type VARCHAR(100) NOT NULL,
    command TEXT,
    args JSONB,
    full_tool_call JSONB NOT NULL,

    -- Analysis results
    threat_score DECIMAL(5,2) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    patterns_detected TEXT[],
    analyzer_results JSONB,

    -- Semantic analysis (if used)
    semantic_analysis_used BOOLEAN NOT NULL DEFAULT false,
    semantic_risk_boost DECIMAL(5,2),
    semantic_reasoning TEXT,

    -- Action taken
    was_blocked BOOLEAN NOT NULL DEFAULT false,
    was_alerted BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT events_decision_check CHECK (decision IN ('Allow', 'Alert', 'Block', 'Terminate'))
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_threat_score ON events(threat_score);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
CREATE INDEX IF NOT EXISTS idx_events_tool_type ON events(tool_type);
CREATE INDEX IF NOT EXISTS idx_events_blocked ON events(was_blocked);

-- ============================================================================
-- Threats Table - Only events with threat_score >= 50 (deduplicated view)
-- ============================================================================
CREATE TABLE IF NOT EXISTS threats (
    threat_id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,

    -- Timestamp
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Threat details
    threat_score DECIMAL(5,2) NOT NULL,
    threat_category VARCHAR(100),
    primary_pattern TEXT NOT NULL,
    all_patterns TEXT[],

    -- Context
    command_summary TEXT NOT NULL,
    attack_phase VARCHAR(100),

    CONSTRAINT threats_score_check CHECK (threat_score >= 50.0)
);

CREATE INDEX IF NOT EXISTS idx_threats_session_id ON threats(session_id);
CREATE INDEX IF NOT EXISTS idx_threats_user_id ON threats(user_id);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_threats_score ON threats(threat_score);
CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(threat_category);

-- ============================================================================
-- Blocks Table - Blocked requests (threat_score >= 70)
-- ============================================================================
CREATE TABLE IF NOT EXISTS blocks (
    block_id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,

    -- Timestamp
    blocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Block details
    threat_score DECIMAL(5,2) NOT NULL,
    block_reason TEXT NOT NULL,
    patterns TEXT[],

    -- Tool call that was blocked
    blocked_command TEXT NOT NULL,

    CONSTRAINT blocks_score_check CHECK (threat_score >= 70.0)
);

CREATE INDEX IF NOT EXISTS idx_blocks_session_id ON blocks(session_id);
CREATE INDEX IF NOT EXISTS idx_blocks_user_id ON blocks(user_id);
CREATE INDEX IF NOT EXISTS idx_blocks_blocked_at ON blocks(blocked_at);
CREATE INDEX IF NOT EXISTS idx_blocks_score ON blocks(threat_score);

-- ============================================================================
-- Terminations Table - Terminated sessions (threat_score >= 90)
-- ============================================================================
CREATE TABLE IF NOT EXISTS terminations (
    termination_id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255),

    -- Timestamp
    terminated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Termination details
    trigger_event_id BIGINT REFERENCES events(event_id) ON DELETE SET NULL,
    final_threat_score DECIMAL(5,2) NOT NULL,
    termination_reason TEXT NOT NULL,

    -- Session context at termination
    total_requests INTEGER NOT NULL,
    blocked_requests INTEGER NOT NULL,
    attack_phases TEXT[],

    CONSTRAINT terminations_score_check CHECK (final_threat_score >= 90.0)
);

CREATE INDEX IF NOT EXISTS idx_terminations_user_id ON terminations(user_id);
CREATE INDEX IF NOT EXISTS idx_terminations_org_id ON terminations(org_id);
CREATE INDEX IF NOT EXISTS idx_terminations_terminated_at ON terminations(terminated_at);

-- ============================================================================
-- API Usage Table - Track Claude API usage and costs
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_usage (
    usage_id BIGSERIAL PRIMARY KEY,
    event_id BIGINT REFERENCES events(event_id) ON DELETE SET NULL,
    session_id VARCHAR(255),
    user_id VARCHAR(255) NOT NULL,

    -- Timestamp
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- API details
    api_provider VARCHAR(50) NOT NULL DEFAULT 'anthropic',
    model_used VARCHAR(100) NOT NULL,
    prompt_tokens INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,

    -- Cost tracking (in USD)
    estimated_cost DECIMAL(10,6) NOT NULL,

    -- Request details
    request_type VARCHAR(50) NOT NULL DEFAULT 'semantic_analysis',
    cache_hit BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_api_usage_model ON api_usage(model_used);

-- ============================================================================
-- Statistics Views for Dashboard
-- ============================================================================

-- Daily threat statistics
CREATE OR REPLACE VIEW daily_threat_stats AS
SELECT
    DATE(timestamp) as date,
    COUNT(*) as total_requests,
    COUNT(*) FILTER (WHERE threat_score >= 50) as threats_detected,
    COUNT(*) FILTER (WHERE was_blocked) as blocked_requests,
    AVG(threat_score) as avg_threat_score,
    MAX(threat_score) as max_threat_score
FROM events
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- Hourly threat statistics (last 48 hours)
CREATE OR REPLACE VIEW hourly_threat_stats AS
SELECT
    DATE_TRUNC('hour', timestamp) as hour,
    COUNT(*) as total_requests,
    COUNT(*) FILTER (WHERE threat_score >= 50) as threats_detected,
    COUNT(*) FILTER (WHERE was_blocked) as blocked_requests,
    AVG(threat_score) as avg_threat_score
FROM events
WHERE timestamp >= NOW() - INTERVAL '48 hours'
GROUP BY DATE_TRUNC('hour', timestamp)
ORDER BY hour DESC;

-- Top threat patterns (last 7 days)
CREATE OR REPLACE VIEW top_threat_patterns AS
SELECT
    unnest(patterns_detected) as pattern,
    COUNT(*) as occurrences,
    AVG(threat_score) as avg_threat_score
FROM events
WHERE timestamp >= NOW() - INTERVAL '7 days'
  AND threat_score >= 50
GROUP BY pattern
ORDER BY occurrences DESC
LIMIT 50;

-- Most targeted users
CREATE OR REPLACE VIEW targeted_users AS
SELECT
    user_id,
    COUNT(*) as total_requests,
    COUNT(*) FILTER (WHERE threat_score >= 50) as threats_detected,
    COUNT(*) FILTER (WHERE was_blocked) as blocked_requests,
    AVG(threat_score) as avg_threat_score,
    MAX(threat_score) as max_threat_score
FROM events
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY user_id
HAVING COUNT(*) FILTER (WHERE threat_score >= 50) > 0
ORDER BY threats_detected DESC
LIMIT 100;

-- Claude API cost tracking (last 30 days)
CREATE OR REPLACE VIEW api_cost_summary AS
SELECT
    DATE(timestamp) as date,
    api_provider,
    model_used,
    COUNT(*) as total_calls,
    COUNT(*) FILTER (WHERE cache_hit) as cache_hits,
    SUM(total_tokens) as total_tokens,
    SUM(estimated_cost) as total_cost
FROM api_usage
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY DATE(timestamp), api_provider, model_used
ORDER BY date DESC, total_cost DESC;

-- ============================================================================
-- Helper Functions
-- ============================================================================

-- Function to clean up old events (retention policy)
CREATE OR REPLACE FUNCTION cleanup_old_events(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM events
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get session summary
CREATE OR REPLACE FUNCTION get_session_summary(p_session_id VARCHAR(255))
RETURNS TABLE (
    session_id VARCHAR(255),
    user_id VARCHAR(255),
    total_requests INTEGER,
    threats_detected INTEGER,
    blocked_requests INTEGER,
    max_threat_score DECIMAL(5,2),
    top_patterns TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        s.session_id,
        s.user_id,
        s.total_requests,
        s.alerted_requests as threats_detected,
        s.blocked_requests,
        s.max_threat_score,
        ARRAY(
            SELECT DISTINCT unnest(e.patterns_detected)
            FROM events e
            WHERE e.session_id = p_session_id
              AND e.threat_score >= 50
            LIMIT 10
        ) as top_patterns
    FROM sessions s
    WHERE s.session_id = p_session_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Initial Data / Comments
-- ============================================================================

COMMENT ON TABLE sessions IS 'Tracks all user sessions with statistics and status';
COMMENT ON TABLE events IS 'Complete audit log of all analyzed tool calls';
COMMENT ON TABLE threats IS 'Detected threats (score >= 50) for quick analysis';
COMMENT ON TABLE blocks IS 'Blocked requests (score >= 70) for security review';
COMMENT ON TABLE terminations IS 'Terminated sessions (score >= 90) for incident response';
COMMENT ON TABLE api_usage IS 'Claude API usage tracking for cost monitoring';

-- Grant permissions to proxilion user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO proxilion;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO proxilion;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO proxilion;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Proxilion schema created successfully!';
    RAISE NOTICE 'Tables: sessions, events, threats, blocks, terminations, api_usage';
    RAISE NOTICE 'Views: daily_threat_stats, hourly_threat_stats, top_threat_patterns, targeted_users, api_cost_summary';
    RAISE NOTICE 'Functions: cleanup_old_events(), get_session_summary()';
END $$;
