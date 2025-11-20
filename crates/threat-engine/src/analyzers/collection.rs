/// Collection Detection - Detects data gathering attempts
///
/// Identifies MITRE ATT&CK T1005, T1074, T1039 (Collection) patterns:
/// - Data staging
/// - Archive creation
/// - Screenshot capture
/// - Clipboard monitoring
/// - Audio/video recording

use crate::AnalyzerResult;
use mcp_protocol::MCPToolCall;

pub struct CollectionAnalyzer {
    staging_patterns: Vec<&'static str>,
    archive_patterns: Vec<&'static str>,
    screenshot_patterns: Vec<&'static str>,
    clipboard_patterns: Vec<&'static str>,
    recording_patterns: Vec<&'static str>,
}

impl CollectionAnalyzer {
    pub fn new() -> Self {
        Self {
            staging_patterns: vec![
                "/tmp/data",
                "/tmp/exfil",
                "/tmp/archive",
                "/dev/shm/",
                "mkdir /tmp/",
                "cp -r * /tmp",
                "rsync -av",
                "staging",
            ],
            archive_patterns: vec![
                "tar -czf",
                "tar -czvf",
                "zip -r",
                "7z a",
                "rar a",
                "gzip -r",
                "tar.gz",
                "archive.zip",
                "backup.tar",
            ],
            screenshot_patterns: vec![
                "screenshot",
                "scrot",
                "import -window root",
                "screencapture",
                "xwd",
                "gnome-screenshot",
                "ImageMagick",
            ],
            clipboard_patterns: vec![
                "xclip",
                "xsel",
                "pbpaste",
                "clipboard",
                "Get-Clipboard",
                "Set-Clipboard",
            ],
            recording_patterns: vec![
                "arecord",
                "sox",
                "ffmpeg",
                "avconv",
                "streamer",
                "vlc",
                "recordmydesktop",
            ],
        }
    }

    pub fn analyze(&self, tool_call: &MCPToolCall) -> AnalyzerResult {
        let content = self.extract_content(tool_call);
        if content.is_empty() {
            return AnalyzerResult {
                analyzer_name: "collection".to_string(),
                threat_score: 0.0,
                patterns: vec![],
                metadata: serde_json::json!({}),
            };
        }

        let content_lower = content.to_lowercase();
        let mut score: f64 = 0.0;
        let mut patterns_found = Vec::new();

        // Check for data staging
        for &pattern in &self.staging_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Data staging detected: {}", pattern));
                score = score.max(80.0);
                break;
            }
        }

        // Check for archive creation (combined with staging)
        let has_archive = self.archive_patterns.iter().any(|&p| {
            content_lower.contains(&p.to_lowercase())
        });

        if has_archive {
            patterns_found.push("Archive creation detected".to_string());

            // Higher score if combined with /tmp or staging
            if content_lower.contains("/tmp") || content_lower.contains("staging") {
                score = score.max(90.0);
            } else {
                score = score.max(70.0);
            }
        }

        // Check for screenshot capture
        for &pattern in &self.screenshot_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Screenshot capture: {}", pattern));
                score = score.max(85.0);
                break;
            }
        }

        // Check for clipboard monitoring
        for &pattern in &self.clipboard_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Clipboard access: {}", pattern));
                score = score.max(75.0);
                break;
            }
        }

        // Check for recording
        for &pattern in &self.recording_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                patterns_found.push(format!("Audio/video recording: {}", pattern));
                score = score.max(88.0);
                break;
            }
        }

        AnalyzerResult {
            analyzer_name: "collection".to_string(),
            threat_score: score.min(100.0),
            patterns: patterns_found,
            metadata: serde_json::json!({
                "mitre_attack": ["T1005", "T1074", "T1039"],
                "category": "collection"
            }),
        }
    }

    fn extract_content(&self, tool_call: &MCPToolCall) -> String {
        match tool_call {
            MCPToolCall::Bash { command, args, .. } => {
                let mut content = command.clone();
                if !args.is_empty() {
                    content.push(' ');
                    content.push_str(&args.join(" "));
                }
                content
            }
            MCPToolCall::Filesystem { path, content, .. } => {
                let mut result = path.clone();
                if let Some(bytes) = content {
                    if let Ok(text) = String::from_utf8(bytes.clone()) {
                        result.push(' ');
                        result.push_str(&text);
                    }
                }
                result
            }
            MCPToolCall::Network { url, .. } => url.clone(),
            MCPToolCall::Database { query, .. } => query.clone(),
            MCPToolCall::Unknown { params, .. } => {
                serde_json::to_string(params).unwrap_or_default()
            }
        }
    }
}

impl Default for CollectionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_and_staging() {
        let analyzer = CollectionAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "tar -czf /tmp/data.tar.gz /home/user/documents".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 85.0);
    }

    #[test]
    fn test_screenshot() {
        let analyzer = CollectionAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "scrot screenshot.png".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert!(result.threat_score > 80.0);
    }

    #[test]
    fn test_safe_operations() {
        let analyzer = CollectionAnalyzer::new();
        let tool_call = MCPToolCall::Bash { args: vec![], env: std::collections::HashMap::new(),
            command: "ls -la".to_string(),
        };

        let result = analyzer.analyze(&tool_call);
        assert_eq!(result.threat_score, 0.0);
    }
}
