#!/usr/bin/env rust-script
//! Proxilion Semantic Analysis Cost Calculator
//!
//! Estimates monthly costs for Claude API-based semantic analysis.
//!
//! Usage:
//!   cargo run --manifest-path tools/Cargo.toml -- [OPTIONS]
//!
//! Or compile and run:
//!   rustc tools/cost-calculator.rs -o cost-calculator
//!   ./cost-calculator --requests 100000 --ambiguous-rate 0.3

use std::env;

/// Claude Sonnet 4 pricing (as of 2025)
const SONNET_INPUT_PRICE_PER_MTK: f64 = 3.00;   // $3.00 per million input tokens
const SONNET_OUTPUT_PRICE_PER_MTK: f64 = 15.00; // $15.00 per million output tokens
const CACHED_INPUT_PRICE_PER_MTK: f64 = 0.30;   // $0.30 per million cached input tokens

/// Estimated token counts per semantic analysis request
const SYSTEM_PROMPT_TOKENS: u64 = 250;      // Cached after first request
const AVG_USER_PROMPT_TOKENS: u64 = 150;    // Tool call description + context
const AVG_OUTPUT_TOKENS: u64 = 200;         // JSON response with reasoning

/// Cache hit rate for system prompt (very high - same prompt every time)
const SYSTEM_PROMPT_CACHE_HIT_RATE: f64 = 0.95;

/// Default result cache hit rate (similar commands get cached results)
#[allow(dead_code)]
const DEFAULT_RESULT_CACHE_HIT_RATE: f64 = 0.40;

#[derive(Debug)]
struct CostEstimate {
    monthly_requests: u64,
    ambiguous_rate: f64,
    result_cache_hit_rate: f64,

    // Calculated
    semantic_analysis_requests: u64,
    actual_api_calls: u64,

    // Token usage
    input_tokens_regular: u64,
    input_tokens_cached: u64,
    output_tokens: u64,

    // Costs
    input_cost: f64,
    cached_cost: f64,
    output_cost: f64,
    total_monthly_cost: f64,
    cost_per_request: f64,
}

fn calculate_costs(
    monthly_requests: u64,
    ambiguous_rate: f64,
    result_cache_hit_rate: f64,
) -> CostEstimate {
    // Only ambiguous requests (score 40-80) trigger semantic analysis
    let semantic_analysis_requests = (monthly_requests as f64 * ambiguous_rate) as u64;

    // Result cache reduces actual API calls
    let actual_api_calls = (semantic_analysis_requests as f64 * (1.0 - result_cache_hit_rate)) as u64;

    // Token calculations
    // System prompt: mostly cached after first request
    let cached_system_tokens = (actual_api_calls as f64 * SYSTEM_PROMPT_TOKENS as f64 * SYSTEM_PROMPT_CACHE_HIT_RATE) as u64;
    let uncached_system_tokens = (actual_api_calls as f64 * SYSTEM_PROMPT_TOKENS as f64 * (1.0 - SYSTEM_PROMPT_CACHE_HIT_RATE)) as u64;

    // User prompt: never cached (unique per request)
    let user_tokens = actual_api_calls * AVG_USER_PROMPT_TOKENS;

    // Total input tokens
    let input_tokens_regular = uncached_system_tokens + user_tokens;
    let input_tokens_cached = cached_system_tokens;

    // Output tokens
    let output_tokens = actual_api_calls * AVG_OUTPUT_TOKENS;

    // Cost calculations
    let input_cost = (input_tokens_regular as f64 / 1_000_000.0) * SONNET_INPUT_PRICE_PER_MTK;
    let cached_cost = (input_tokens_cached as f64 / 1_000_000.0) * CACHED_INPUT_PRICE_PER_MTK;
    let output_cost = (output_tokens as f64 / 1_000_000.0) * SONNET_OUTPUT_PRICE_PER_MTK;

    let total_monthly_cost = input_cost + cached_cost + output_cost;
    let cost_per_request = if monthly_requests > 0 {
        total_monthly_cost / monthly_requests as f64
    } else {
        0.0
    };

    CostEstimate {
        monthly_requests,
        ambiguous_rate,
        result_cache_hit_rate,
        semantic_analysis_requests,
        actual_api_calls,
        input_tokens_regular,
        input_tokens_cached,
        output_tokens,
        input_cost,
        cached_cost,
        output_cost,
        total_monthly_cost,
        cost_per_request,
    }
}

fn print_estimate(estimate: &CostEstimate) {
    println!("═══════════════════════════════════════════════════════════════");
    println!("         PROXILION SEMANTIC ANALYSIS COST ESTIMATE");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("INPUT PARAMETERS");
    println!("─────────────────────────────────────────────────────────────────");
    println!("  Monthly requests:        {:>12}", format_number(estimate.monthly_requests));
    println!("  Ambiguous rate:          {:>12.1}%", estimate.ambiguous_rate * 100.0);
    println!("  Result cache hit rate:   {:>12.1}%", estimate.result_cache_hit_rate * 100.0);
    println!();
    println!("REQUEST FLOW");
    println!("─────────────────────────────────────────────────────────────────");
    println!("  Total requests:          {:>12}", format_number(estimate.monthly_requests));
    println!("  -> Ambiguous (40-80):    {:>12} (triggers semantic analysis)", format_number(estimate.semantic_analysis_requests));
    println!("  -> Cache misses:         {:>12} (actual API calls)", format_number(estimate.actual_api_calls));
    println!();
    println!("TOKEN USAGE");
    println!("─────────────────────────────────────────────────────────────────");
    println!("  Input tokens (regular):  {:>12}", format_number(estimate.input_tokens_regular));
    println!("  Input tokens (cached):   {:>12}", format_number(estimate.input_tokens_cached));
    println!("  Output tokens:           {:>12}", format_number(estimate.output_tokens));
    println!();
    println!("COST BREAKDOWN");
    println!("─────────────────────────────────────────────────────────────────");
    println!("  Input cost:              {:>12}", format_currency(estimate.input_cost));
    println!("  Cached input cost:       {:>12}", format_currency(estimate.cached_cost));
    println!("  Output cost:             {:>12}", format_currency(estimate.output_cost));
    println!("  ─────────────────────────────────────");
    println!("  TOTAL MONTHLY COST:      {:>12}", format_currency(estimate.total_monthly_cost));
    println!("  Cost per request:        {:>12}", format_currency_precise(estimate.cost_per_request));
    println!();
    println!("═══════════════════════════════════════════════════════════════");
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_currency(amount: f64) -> String {
    format!("${:.2}", amount)
}

fn format_currency_precise(amount: f64) -> String {
    if amount < 0.01 {
        format!("${:.6}", amount)
    } else {
        format!("${:.4}", amount)
    }
}

fn print_usage() {
    println!("Proxilion Semantic Analysis Cost Calculator");
    println!();
    println!("USAGE:");
    println!("  cost-calculator [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  -r, --requests <NUM>      Monthly request volume (default: 100000)");
    println!("  -a, --ambiguous <RATE>    Rate of ambiguous requests 0.0-1.0 (default: 0.30)");
    println!("  -c, --cache <RATE>        Result cache hit rate 0.0-1.0 (default: 0.40)");
    println!("  -h, --help                Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("  cost-calculator --requests 50000");
    println!("  cost-calculator -r 1000000 -a 0.25 -c 0.50");
    println!();
    println!("NOTES:");
    println!("  - Ambiguous requests are those with pattern scores between 40-80");
    println!("  - Only ambiguous requests trigger semantic analysis");
    println!("  - Result caching reduces API calls for similar commands");
    println!("  - Pricing based on Claude Sonnet 4 rates (2025)");
}

fn print_comparison_table() {
    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("              COST COMPARISON BY REQUEST VOLUME");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Assumptions: 30% ambiguous rate, 40% result cache hit rate");
    println!();
    println!("┌──────────────┬──────────────┬──────────────┬──────────────┐");
    println!("│   Requests   │  API Calls   │ Monthly Cost │  Per Request │");
    println!("├──────────────┼──────────────┼──────────────┼──────────────┤");

    let volumes = [10_000u64, 50_000, 100_000, 500_000, 1_000_000];
    for volume in volumes {
        let estimate = calculate_costs(volume, 0.30, 0.40);
        println!(
            "│ {:>12} │ {:>12} │ {:>12} │ {:>12} │",
            format_number(volume),
            format_number(estimate.actual_api_calls),
            format_currency(estimate.total_monthly_cost),
            format_currency_precise(estimate.cost_per_request)
        );
    }

    println!("└──────────────┴──────────────┴──────────────┴──────────────┘");
    println!();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut requests: u64 = 100_000;
    let mut ambiguous_rate: f64 = 0.30;
    let mut cache_rate: f64 = 0.40;
    let mut show_comparison = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                return;
            }
            "-r" | "--requests" => {
                i += 1;
                if i < args.len() {
                    requests = args[i].parse().unwrap_or(100_000);
                }
            }
            "-a" | "--ambiguous" => {
                i += 1;
                if i < args.len() {
                    ambiguous_rate = args[i].parse().unwrap_or(0.30);
                }
            }
            "-c" | "--cache" => {
                i += 1;
                if i < args.len() {
                    cache_rate = args[i].parse().unwrap_or(0.40);
                }
            }
            "--compare" => {
                show_comparison = true;
            }
            _ => {}
        }
        i += 1;
    }

    let estimate = calculate_costs(requests, ambiguous_rate, cache_rate);
    print_estimate(&estimate);

    if show_comparison {
        print_comparison_table();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_requests() {
        let estimate = calculate_costs(0, 0.30, 0.40);
        assert_eq!(estimate.total_monthly_cost, 0.0);
    }

    #[test]
    fn test_no_ambiguous_requests() {
        let estimate = calculate_costs(100_000, 0.0, 0.40);
        assert_eq!(estimate.semantic_analysis_requests, 0);
        assert_eq!(estimate.actual_api_calls, 0);
        assert_eq!(estimate.total_monthly_cost, 0.0);
    }

    #[test]
    fn test_full_cache_hit() {
        let estimate = calculate_costs(100_000, 0.30, 1.0);
        assert_eq!(estimate.actual_api_calls, 0);
        assert_eq!(estimate.total_monthly_cost, 0.0);
    }

    #[test]
    fn test_typical_scenario() {
        let estimate = calculate_costs(100_000, 0.30, 0.40);
        // 100k requests * 30% ambiguous = 30k semantic requests
        assert_eq!(estimate.semantic_analysis_requests, 30_000);
        // 30k * 60% cache miss = 18k API calls
        assert_eq!(estimate.actual_api_calls, 18_000);
        // Cost should be reasonable (less than $100/month for this volume)
        assert!(estimate.total_monthly_cost < 100.0);
        assert!(estimate.total_monthly_cost > 0.0);
    }
}
