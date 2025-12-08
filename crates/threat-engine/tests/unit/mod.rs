//! Unit Test Suite for Proxilion Threat Engine
//!
//! This module contains comprehensive unit tests for all analyzers.
//! Tests cover:
//! - Known malicious patterns (should detect)
//! - Safe patterns (should not detect)
//! - Edge cases (boundary conditions)
//! - Unicode handling
//! - Empty/null input handling

pub mod test_utils;
pub mod enumeration_tests;
pub mod collection_tests;
pub mod command_and_control_tests;
