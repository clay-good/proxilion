//! Threat Analyzers
//!
//! Individual analyzers that detect specific attack patterns.

pub mod enumeration;
pub mod credential;
pub mod exfiltration;
pub mod ai_velocity;
pub mod prompt_engineering;
pub mod semantic;
pub mod social_engineering;
pub mod callback_validation;
pub mod mcp_orchestration;
pub mod file_access;
pub mod task_fragmentation;
pub mod data_volume;
pub mod privilege_escalation;
pub mod lateral_movement;
pub mod hacking_tools;
pub mod legitimacy;
pub mod hallucination;
pub mod request_rate;
pub mod session_progression;
pub mod multi_user_correlation;
pub mod conversation_context;

// GTG-1002 Gap Closers (Conversation-aware, Orchestration detection)
pub mod conversation_analysis;
pub mod ai_autonomy;
pub mod multi_target_orchestration;

// Additional MITRE ATT&CK Coverage
pub mod persistence;
pub mod defense_evasion;
pub mod collection;
pub mod command_and_control;
pub mod impact;
pub mod tool_call;

pub use enumeration::EnumerationAnalyzer;
pub use credential::CredentialAnalyzer;
pub use exfiltration::ExfiltrationAnalyzer;
pub use ai_velocity::AIVelocityAnalyzer;
pub use prompt_engineering::PromptEngineeringAnalyzer;
pub use semantic::SemanticAnalyzer;
pub use social_engineering::SocialEngineeringAnalyzer;
pub use callback_validation::CallbackValidationAnalyzer;
pub use mcp_orchestration::MCPOrchestrationAnalyzer;
pub use file_access::FileAccessAnalyzer;
pub use task_fragmentation::TaskFragmentationAnalyzer;
pub use data_volume::DataVolumeAnalyzer;
pub use privilege_escalation::PrivilegeEscalationAnalyzer;
pub use lateral_movement::LateralMovementAnalyzer;
pub use hacking_tools::HackingToolsAnalyzer;
pub use legitimacy::LegitimacyAnalyzer;
pub use hallucination::HallucinationAnalyzer;
pub use request_rate::RequestRateAnalyzer;
pub use session_progression::SessionProgressionAnalyzer;
pub use multi_user_correlation::MultiUserCorrelationAnalyzer;
pub use conversation_context::ConversationContextAnalyzer;

// GTG-1002 Gap Closers
pub use conversation_analysis::ConversationAnalyzer;
pub use ai_autonomy::AIAutonomyAnalyzer;
pub use multi_target_orchestration::MultiTargetOrchestrationAnalyzer;

// Additional MITRE ATT&CK Coverage
pub use persistence::PersistenceAnalyzer;
pub use defense_evasion::DefenseEvasionAnalyzer;
pub use collection::CollectionAnalyzer;
pub use command_and_control::CommandAndControlAnalyzer;
pub use impact::ImpactAnalyzer;
pub use tool_call::ToolCallAnalyzer;
