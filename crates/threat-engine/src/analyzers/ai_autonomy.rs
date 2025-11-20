/// AI Autonomy Detection Analyzer - Detects when AI is being used as autonomous agent
///
/// This analyzer addresses GTG-1002 Gap #2: AI Orchestration Detection
///
/// The GTG-1002 attack was "80-90% autonomous AI execution" with thousands of requests
/// executed automatically. Our current analyzers can't distinguish between:
/// - Interactive human using AI as assistant (benign)
/// - AI operating autonomously as attack agent (malicious)
///
/// Detection signals for autonomous operation:
/// 1. **High velocity**: Hundreds/thousands of requests in short time
/// 2. **Systematic patterns**: Sequential scanning, methodical enumeration
/// 3. **Perfect consistency**: No typos, no pauses, no human variation
/// 4. **Parallel operations**: Multiple attack paths simultaneously
/// 5. **No conversation**: Tool calls without user prompts
/// 6. **Predetermined script**: Follows attack framework exactly
/// 7. **Error handling**: Automated retry and adaptation
/// 8. **Completionist behavior**: Exhaustive enumeration of all options
///
/// Uses both pattern analysis AND Claude API for high-confidence detection

use serde_json::json;
use crate::{AnalyzerResult, SessionStats};

#[cfg(feature = "semantic-analysis")]
use {
    reqwest::Client,
    serde::{Deserialize, Serialize},
};

/// AI autonomy analysis result
#[cfg(feature = "semantic-analysis")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutonomyAnalysisResponse {
    /// Risk score (0-100)
    risk_score: f64,
    /// Is this autonomous AI operation?
    is_autonomous: bool,
    /// Confidence (0-1)
    confidence: f64,
    /// Autonomy indicators detected
    indicators: Vec<String>,
    /// Reasoning
    reasoning: String,
}

pub struct AIAutonomyAnalyzer {
    #[cfg(feature = "semantic-analysis")]
    client: Option<Client>,
    #[cfg(feature = "semantic-analysis")]
    api_key: Option<String>,
}

impl AIAutonomyAnalyzer {
    pub fn new() -> Self {
        #[cfg(feature = "semantic-analysis")]
        {
            let api_key = std::env::var("ANTHROPIC_API_KEY").ok();
            let client = if api_key.is_some() {
                Some(Client::new())
            } else {
                None
            };

            Self {
                client,
                api_key,
            }
        }

        #[cfg(not(feature = "semantic-analysis"))]
        {
            Self {}
        }
    }

    /// Analyze session for AI autonomy patterns
    pub async fn analyze(&self, session: &SessionStats) -> AnalyzerResult {
        // First run pattern-based detection (always runs)
        let pattern_score = self.pattern_based_analysis(session);

        // If clearly autonomous by patterns, no need for semantic analysis
        if pattern_score >= 80.0 {
            return AnalyzerResult {
                analyzer_name: "ai_autonomy".to_string(),
                threat_score: pattern_score,
                patterns: self.get_pattern_descriptions(session),
                metadata: json!({
                    "detection_type": "pattern_based",
                    "autonomous": true,
                    "requests_per_minute": session.requests_last_minute,
                    "session_age_hours": session.session_age_hours
                }),
            };
        }

        // For ambiguous cases (40-80), use Claude for confirmation
        #[cfg(feature = "semantic-analysis")]
        {
            if pattern_score >= 40.0 && pattern_score < 80.0 {
                if let Some(semantic_result) = self.semantic_analysis(session).await {
                    return semantic_result;
                }
            }
        }

        // Return pattern-based result
        AnalyzerResult {
            analyzer_name: "ai_autonomy".to_string(),
            threat_score: pattern_score,
            patterns: self.get_pattern_descriptions(session),
            metadata: json!({
                "detection_type": "pattern_based",
                "autonomous": pattern_score >= 70.0,
                "requests_per_minute": session.requests_last_minute,
            }),
        }
    }

    /// Pattern-based autonomy detection (always runs, fast)
    fn pattern_based_analysis(&self, session: &SessionStats) -> f64 {
        let mut score: f64 = 0.0;

        // 1. High velocity (GTG-1002 was "thousands of requests")
        let rpm = session.requests_last_minute;
        if rpm > 100 {
            score += 40.0; // Extremely high velocity
        } else if rpm > 50 {
            score += 30.0; // Very high velocity
        } else if rpm > 20 {
            score += 20.0; // High velocity
        } else if rpm > 10 {
            score += 10.0; // Elevated velocity
        }

        // 2. Sustained high rate (not just burst)
        let rph = session.requests_last_hour;
        if rph > 1000 && rpm > 20 {
            score += 20.0; // Sustained autonomous operation
        }

        // 3. Perfect consistency (no human pauses)
        // If requests are evenly distributed, it's automated
        if rpm > 10 && session.total_requests > 100 {
            score += 15.0; // Machine-like consistency
        }

        // 4. Multiple attack phases in short time (systematic)
        if session.attack_phases.len() >= 3 && session.session_age_hours < 1.0 {
            score += 15.0; // Rapid progression through attack phases
        }

        // 5. High phase transitions (methodical attack)
        if session.phase_transitions >= 4 {
            score += 10.0; // Multiple phase changes = scripted attack
        }

        score.min(100.0)
    }

    /// Get human-readable pattern descriptions
    fn get_pattern_descriptions(&self, session: &SessionStats) -> Vec<String> {
        let mut patterns = Vec::new();

        let rpm = session.requests_last_minute;
        if rpm > 100 {
            patterns.push(format!("🚨 EXTREME VELOCITY: {} requests/min (autonomous agent)", rpm));
        } else if rpm > 50 {
            patterns.push(format!("⚠️  Very high velocity: {} requests/min (likely autonomous)", rpm));
        } else if rpm > 20 {
            patterns.push(format!("High request velocity: {} requests/min", rpm));
        }

        if session.requests_last_hour > 1000 {
            patterns.push(format!("Sustained high rate: {} requests/hour", session.requests_last_hour));
        }

        if session.attack_phases.len() >= 3 {
            patterns.push(format!("Rapid attack progression: {} phases in {:.1} hours",
                session.attack_phases.len(), session.session_age_hours));
        }

        if session.phase_transitions >= 4 {
            patterns.push("Systematic attack pattern: Multiple phase transitions".to_string());
        }

        if session.total_requests > 500 {
            patterns.push(format!("High volume session: {} total requests", session.total_requests));
        }

        if patterns.is_empty() {
            patterns.push("No autonomous operation patterns detected".to_string());
        }

        patterns
    }

    /// Semantic analysis using Claude (only for ambiguous cases)
    #[cfg(feature = "semantic-analysis")]
    async fn semantic_analysis(&self, session: &SessionStats) -> Option<AnalyzerResult> {
        if self.api_key.is_none() || self.client.is_none() {
            return None;
        }

        let client = self.client.as_ref()?;
        let api_key = self.api_key.as_ref()?;

        let prompt = format!(
            r#"You are analyzing whether an AI system is being used interactively by a human or autonomously as an attack agent.

Context from GTG-1002 Attack:
The attack was "80-90% autonomous AI execution" with thousands of automated requests. The AI operated as an autonomous agent, not an interactive assistant.

Session Statistics:
- Requests per minute: {}
- Requests per hour: {}
- Total requests: {}
- Attack phases: {:?}
- Phase transitions: {}
- Session age: {:.1} hours

Indicators of Autonomous Operation:
1. **High velocity**: >50 requests/min sustained
2. **Perfect consistency**: No human variation or pauses
3. **Systematic progression**: Methodical attack phases
4. **High volume**: Hundreds/thousands of requests
5. **No conversation breaks**: Continuous tool execution

Indicators of Interactive Use:
1. **Human rhythm**: Pauses, bursts, irregularity
2. **Conversation turns**: User prompts followed by tool calls
3. **Low velocity**: <10 requests/min
4. **Exploratory**: Random, non-systematic pattern

Analyze whether this is autonomous AI agent or interactive human use.

Respond ONLY with valid JSON:
{{
  "risk_score": <0-100>,
  "is_autonomous": <true/false>,
  "confidence": <0-1>,
  "indicators": ["indicator1", "indicator2"],
  "reasoning": "<detailed explanation>"
}}"#,
            session.requests_last_minute,
            session.requests_last_hour,
            session.total_requests,
            session.attack_phases,
            session.phase_transitions,
            session.session_age_hours
        );

        let request_body = json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [{
                "role": "user",
                "content": prompt
            }]
        });

        let response = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let response_json: serde_json::Value = response.json().await.ok()?;
        let content = response_json["content"][0]["text"].as_str()?;
        let analysis: AutonomyAnalysisResponse = serde_json::from_str(content).ok()?;

        let mut patterns = self.get_pattern_descriptions(session);
        patterns.extend(analysis.indicators.iter().map(|i| format!("AI autonomy: {}", i)));

        if analysis.is_autonomous {
            patterns.push("🤖 AUTONOMOUS AI AGENT DETECTED".to_string());
        }

        Some(AnalyzerResult {
            analyzer_name: "ai_autonomy".to_string(),
            threat_score: analysis.risk_score,
            patterns,
            metadata: json!({
                "detection_type": "semantic_enhanced",
                "is_autonomous": analysis.is_autonomous,
                "confidence": analysis.confidence,
                "reasoning": analysis.reasoning,
                "requests_per_minute": session.requests_last_minute,
            }),
        })
    }
}

impl Default for AIAutonomyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session(rpm: u32, rph: u32, total: u64, phases: usize) -> SessionStats {
        SessionStats {
            requests_last_minute: rpm,
            requests_last_hour: rph,
            total_requests: total,
            request_timestamps: vec![],
            attack_phases: vec!["recon".to_string(); phases],
            max_phase_reached: phases,
            phase_transitions: phases.saturating_sub(1),
            session_age_hours: 1.0,
        }
    }

    #[tokio::test]
    async fn test_extreme_velocity_detected() {
        let analyzer = AIAutonomyAnalyzer::new();
        let session = create_test_session(150, 2000, 2000, 5);

        let result = analyzer.analyze(&session).await;

        assert!(result.threat_score >= 70.0, "Should detect extreme velocity as high threat");
        assert!(result.patterns.iter().any(|p| p.contains("EXTREME VELOCITY")));
    }

    #[tokio::test]
    async fn test_low_velocity_safe() {
        let analyzer = AIAutonomyAnalyzer::new();
        let session = create_test_session(5, 50, 50, 1);

        let result = analyzer.analyze(&session).await;

        assert!(result.threat_score < 30.0, "Low velocity should be low threat");
    }

    #[tokio::test]
    async fn test_rapid_phase_progression() {
        let analyzer = AIAutonomyAnalyzer::new();
        // Change session_age to 0.5 hours so it passes the < 1.0 check
        let mut session = create_test_session(30, 500, 500, 4);
        session.session_age_hours = 0.5;

        let result = analyzer.analyze(&session).await;

        // 30 rpm = 20 points, 4 phases in <1 hr = 15 points, 3 transitions = 10 points = 45 total
        assert!(result.threat_score >= 40.0, "Rapid phase progression should be flagged: score={}", result.threat_score);
        assert!(result.patterns.iter().any(|p| p.contains("attack progression") || p.contains("phase")));
    }

    #[tokio::test]
    async fn test_sustained_high_rate() {
        let analyzer = AIAutonomyAnalyzer::new();
        let session = create_test_session(25, 1200, 1200, 3);

        let result = analyzer.analyze(&session).await;

        assert!(result.threat_score >= 50.0, "Sustained high rate should be detected");
        assert!(result.patterns.iter().any(|p| p.contains("Sustained high rate")));
    }
}
