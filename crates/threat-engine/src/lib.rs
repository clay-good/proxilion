//! Threat Detection Engine
//!
//! Real-time threat analysis for MCP tool calls.

use mcp_protocol::MCPToolCall;
use serde::{Deserialize, Serialize};

pub mod analyzers;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysisResult {
    pub threat_score: f64,
    pub confidence: f64,
    pub patterns_detected: Vec<String>,
    pub analyzer_results: Vec<AnalyzerResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerResult {
    pub analyzer_name: String,
    pub threat_score: f64,
    pub patterns: Vec<String>,
    pub metadata: serde_json::Value,
}

/// Decision based on threat analysis
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Allow the operation (score < 50)
    Allow,

    /// Alert security team but allow (50 ≤ score < 70)
    Alert,

    /// Block this specific operation (70 ≤ score < 90)
    Block,

    /// Terminate the entire session (score ≥ 90)
    Terminate,
}

impl Decision {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 90.0 => Decision::Terminate,
            s if s >= 70.0 => Decision::Block,
            s if s >= 50.0 => Decision::Alert,
            _ => Decision::Allow,
        }
    }
}

/// Session statistics for session-aware analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    // For Request Rate analyzer
    pub requests_last_minute: u32,
    pub requests_last_hour: u32,
    pub total_requests: u64,
    pub request_timestamps: Vec<i64>,

    // For Session Progression analyzer
    pub attack_phases: Vec<String>,
    pub max_phase_reached: usize,
    pub phase_transitions: usize,
    pub session_age_hours: f64,
}

/// Analyze a tool call for threats using all available analyzers
pub fn analyze_tool_call(tool_call: &MCPToolCall) -> ThreatAnalysisResult {
    let mut analyzer_results = Vec::new();
    let mut all_patterns = Vec::new();

    // Run enumeration analyzer
    let enum_analyzer = analyzers::EnumerationAnalyzer::new();
    let enum_result = enum_analyzer.analyze(tool_call);
    all_patterns.extend(enum_result.patterns.clone());
    analyzer_results.push(enum_result);

    // Run credential analyzer
    let cred_analyzer = analyzers::CredentialAnalyzer::new();
    let cred_result = cred_analyzer.analyze(tool_call);
    all_patterns.extend(cred_result.patterns.clone());
    analyzer_results.push(cred_result);

    // Run exfiltration analyzer
    let exfil_analyzer = analyzers::ExfiltrationAnalyzer::new();
    let exfil_result = exfil_analyzer.analyze(tool_call);
    all_patterns.extend(exfil_result.patterns.clone());
    analyzer_results.push(exfil_result);

    // Run AI velocity analyzer
    let velocity_analyzer = analyzers::AIVelocityAnalyzer::new();
    let velocity_result = velocity_analyzer.analyze(tool_call);
    all_patterns.extend(velocity_result.patterns.clone());
    analyzer_results.push(velocity_result);

    // Run prompt engineering analyzer
    let prompt_analyzer = analyzers::PromptEngineeringAnalyzer::new();
    let prompt_result = prompt_analyzer.analyze(tool_call);
    all_patterns.extend(prompt_result.patterns.clone());
    analyzer_results.push(prompt_result);

    // Run social engineering analyzer (GTG-1002 Phase 1 detection)
    let social_analyzer = analyzers::SocialEngineeringAnalyzer::new();
    let social_result = social_analyzer.analyze(tool_call);
    all_patterns.extend(social_result.patterns.clone());
    analyzer_results.push(social_result);

    // Run callback validation analyzer (GTG-1002 Phase 3 detection)
    let callback_analyzer = analyzers::CallbackValidationAnalyzer::new();
    let callback_result = callback_analyzer.analyze(tool_call);
    all_patterns.extend(callback_result.patterns.clone());
    analyzer_results.push(callback_result);

    // Run MCP orchestration analyzer
    let mcp_analyzer = analyzers::MCPOrchestrationAnalyzer::new();
    let mcp_result = mcp_analyzer.analyze(tool_call);
    all_patterns.extend(mcp_result.patterns.clone());
    analyzer_results.push(mcp_result);

    // Run file access analyzer
    let file_analyzer = analyzers::FileAccessAnalyzer::new();
    let file_result = file_analyzer.analyze(tool_call);
    all_patterns.extend(file_result.patterns.clone());
    analyzer_results.push(file_result);

    // Run task fragmentation analyzer
    let frag_analyzer = analyzers::TaskFragmentationAnalyzer::new();
    let frag_result = frag_analyzer.analyze(tool_call);
    all_patterns.extend(frag_result.patterns.clone());
    analyzer_results.push(frag_result);

    // Run data volume analyzer
    let volume_analyzer = analyzers::DataVolumeAnalyzer::new();
    let volume_result = volume_analyzer.analyze(tool_call);
    all_patterns.extend(volume_result.patterns.clone());
    analyzer_results.push(volume_result);

    // Run privilege escalation analyzer
    let privesc_analyzer = analyzers::PrivilegeEscalationAnalyzer::new();
    let privesc_result = privesc_analyzer.analyze(tool_call);
    all_patterns.extend(privesc_result.patterns.clone());
    analyzer_results.push(privesc_result);

    // Run lateral movement analyzer
    let lateral_analyzer = analyzers::LateralMovementAnalyzer::new();
    let lateral_result = lateral_analyzer.analyze(tool_call);
    all_patterns.extend(lateral_result.patterns.clone());
    analyzer_results.push(lateral_result);

    // Run hacking tools analyzer
    let tools_analyzer = analyzers::HackingToolsAnalyzer::new();
    let tools_result = tools_analyzer.analyze(tool_call);
    all_patterns.extend(tools_result.patterns.clone());
    analyzer_results.push(tools_result);

    // Run hallucination analyzer
    let hallucination_analyzer = analyzers::HallucinationAnalyzer::new();
    let hallucination_result = hallucination_analyzer.analyze(tool_call);
    all_patterns.extend(hallucination_result.patterns.clone());
    analyzer_results.push(hallucination_result);

    // Run persistence analyzer
    let persistence_analyzer = analyzers::PersistenceAnalyzer::new();
    let persistence_result = persistence_analyzer.analyze(tool_call);
    all_patterns.extend(persistence_result.patterns.clone());
    analyzer_results.push(persistence_result);

    // Run defense evasion analyzer
    let defense_analyzer = analyzers::DefenseEvasionAnalyzer::new();
    let defense_result = defense_analyzer.analyze(tool_call);
    all_patterns.extend(defense_result.patterns.clone());
    analyzer_results.push(defense_result);

    // Run command and control analyzer
    let c2_analyzer = analyzers::CommandAndControlAnalyzer::new();
    let c2_result = c2_analyzer.analyze(tool_call);
    all_patterns.extend(c2_result.patterns.clone());
    analyzer_results.push(c2_result);

    // Run collection analyzer
    let collection_analyzer = analyzers::CollectionAnalyzer::new();
    let collection_result = collection_analyzer.analyze(tool_call);
    all_patterns.extend(collection_result.patterns.clone());
    analyzer_results.push(collection_result);

    // Run impact analyzer
    let impact_analyzer = analyzers::ImpactAnalyzer::new();
    let impact_result = impact_analyzer.analyze(tool_call);
    all_patterns.extend(impact_result.patterns.clone());
    analyzer_results.push(impact_result);

    // Run tool call analyzer (command chaining, piping to network tools, suspicious SQL)
    let tool_call_analyzer = analyzers::ToolCallAnalyzer::new();
    let tool_call_result = tool_call_analyzer.analyze(tool_call);
    all_patterns.extend(tool_call_result.patterns.clone());
    analyzer_results.push(tool_call_result);

    // Run legitimacy analyzer (does not add threat score, only adjusts)
    let legitimacy_analyzer = analyzers::LegitimacyAnalyzer::new();
    let legitimacy_result = legitimacy_analyzer.analyze(tool_call);
    all_patterns.extend(legitimacy_result.patterns.clone());
    analyzer_results.push(legitimacy_result.clone());

    // Note: Session-aware analyzers (session_progression, request_rate, ai_autonomy,
    // multi_user_correlation) are run in analyze_with_session() to leverage session state

    // Calculate aggregate threat score
    let base_threat_score = calculate_aggregate_score(&analyzer_results);

    // Apply legitimacy risk adjustment
    let risk_adjustment = legitimacy_result
        .metadata
        .get("risk_adjustment")
        .and_then(|v| v.as_f64())
        .unwrap_or(1.0);

    let threat_score = (base_threat_score * risk_adjustment).max(0.0);

    // Calculate confidence based on number of patterns detected
    let confidence = if all_patterns.len() >= 3 {
        0.95
    } else if all_patterns.len() >= 2 {
        0.85
    } else if !all_patterns.is_empty() {
        0.75
    } else {
        1.0 // High confidence in "safe" classification
    };

    ThreatAnalysisResult {
        threat_score,
        confidence,
        patterns_detected: all_patterns,
        analyzer_results,
    }
}

/// Analyze a tool call with session context for advanced detection
pub fn analyze_with_session(
    tool_call: &MCPToolCall,
    session_stats: &SessionStats,
) -> ThreatAnalysisResult {
    // First run all standard analyzers
    let mut result = analyze_tool_call(tool_call);

    // Now run session-aware analyzers
    let now = (session_stats.session_age_hours * 3_600_000.0) as i64;

    // Request Rate analyzer
    let rate_analyzer = analyzers::RequestRateAnalyzer::new();
    let rate_stats = analyzers::request_rate::RateStats {
        requests_last_minute: session_stats.requests_last_minute,
        requests_last_hour: session_stats.requests_last_hour,
        total_requests: session_stats.total_requests,
        request_timestamps: session_stats.request_timestamps.clone(),
    };
    let rate_result = rate_analyzer.analyze_with_session(tool_call, &rate_stats, now);
    result.patterns_detected.extend(rate_result.patterns.clone());
    result.analyzer_results.push(rate_result);

    // Session Progression analyzer
    let progression_analyzer = analyzers::SessionProgressionAnalyzer::new();
    let progression_stats = analyzers::session_progression::ProgressionStats {
        attack_phases: session_stats.attack_phases.clone(),
        max_phase_reached: session_stats.max_phase_reached,
        phase_transitions: session_stats.phase_transitions,
        session_age_hours: session_stats.session_age_hours,
    };
    let progression_result = progression_analyzer.analyze_with_session(tool_call, &progression_stats);
    result.patterns_detected.extend(progression_result.patterns.clone());
    result.analyzer_results.push(progression_result);

    // Recalculate threat score with session-aware results
    let base_threat_score = calculate_aggregate_score(&result.analyzer_results);

    // Apply legitimacy risk adjustment (already done in standard analysis)
    let legitimacy_result = result.analyzer_results
        .iter()
        .find(|r| r.analyzer_name == "legitimacy")
        .cloned();

    let risk_adjustment = legitimacy_result
        .and_then(|r| r.metadata.get("risk_adjustment").and_then(|v| v.as_f64()))
        .unwrap_or(1.0);

    result.threat_score = (base_threat_score * risk_adjustment).max(0.0);

    // Update confidence (more analyzers = higher confidence)
    result.confidence = if result.patterns_detected.len() >= 5 {
        0.99
    } else if result.patterns_detected.len() >= 3 {
        0.95
    } else if result.patterns_detected.len() >= 2 {
        0.85
    } else if !result.patterns_detected.is_empty() {
        0.75
    } else {
        1.0
    };

    result
}

/// Calculate aggregate threat score from multiple analyzers
/// Uses weighted max with correlation bonus for multi-vector attacks
fn calculate_aggregate_score(results: &[AnalyzerResult]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }

    // Get all non-zero scores sorted descending
    let mut scores: Vec<f64> = results
        .iter()
        .filter(|r| r.threat_score > 0.0)
        .map(|r| r.threat_score)
        .collect();

    if scores.is_empty() {
        return 0.0;
    }

    scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

    // Primary score is the maximum
    let max_score = scores[0];

    // Add diminishing contributions from other high-scoring analyzers
    // This captures multi-vector attacks more accurately
    let secondary_contribution: f64 = scores
        .iter()
        .skip(1)
        .take(3)  // Only consider top 3 secondary scores
        .enumerate()
        .map(|(i, &score)| {
            // Diminishing weights: 15%, 10%, 5%
            let weight = match i {
                0 => 0.15,
                1 => 0.10,
                2 => 0.05,
                _ => 0.0,
            };
            score * weight
        })
        .sum();

    // Correlation bonus: multiple unrelated analyzers detecting threats
    // indicates higher confidence in malicious intent
    let active_count = scores.len();
    let correlation_bonus = if active_count >= 4 {
        10.0  // 4+ analyzers triggered
    } else if active_count >= 3 {
        6.0   // 3 analyzers triggered
    } else if active_count >= 2 {
        3.0   // 2 analyzers triggered
    } else {
        0.0
    };

    (max_score + secondary_contribution + correlation_bonus).min(100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_from_score() {
        assert_eq!(Decision::from_score(0.0), Decision::Allow);
        assert_eq!(Decision::from_score(50.0), Decision::Alert);
        assert_eq!(Decision::from_score(70.0), Decision::Block);
        assert_eq!(Decision::from_score(90.0), Decision::Terminate);
    }
}
