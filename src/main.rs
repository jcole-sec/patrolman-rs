mod args;
mod config;
mod cti_enrichment;
mod display;
mod huntevil;
mod process;
mod types;

use anyhow::{bail, Result};
use chrono::Local;
use colored::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use args::Args;
use config::Config;
use cti_enrichment::run_cti_lookups;
use display::{
    display_banner, display_phase, display_results, display_summary, display_threats,
    write_json_output, write_tsv_output, PhaseStatus,
};
use huntevil::run_huntevil_checks;
use process::get_process_list;
use types::ProcessData;

fn calculate_risk_score(p: &ProcessData) -> u8 {
    let mut score = 0u8;

    if !p.hunt_flags.is_empty() {
        score = score.saturating_add((p.hunt_flags.len() as u8).saturating_mul(10).min(30));
    }

    let has_malware = (p.hash_cti_malware != "-" && !p.hash_cti_malware.is_empty())
        || (p.rip_cti_malware != "-" && !p.rip_cti_malware.is_empty())
        || (p.hash_mb_file_type != "-" && !p.hash_mb_file_type.is_empty());
    if has_malware {
        score = score.saturating_add(40);
    }

    let has_cti_confidence = (p.hash_cti_confidence != "-" && !p.hash_cti_confidence.is_empty())
        || (p.rip_cti_confidence != "-" && !p.rip_cti_confidence.is_empty());
    if has_cti_confidence {
        score = score.saturating_add(20);
    }

    if p.rip_type.as_ref() == "PUBLIC" {
        score = score.saturating_add(10);
    }

    score.min(100)
}

async fn execute_scan(args: &Args, config: &Config) -> Result<Vec<ProcessData>> {
    // Phase 1: Process enumeration
    display_phase("Networked process enumeration", PhaseStatus::Starting);
    let process_list = get_process_list(args.test).await?;
    display_phase(
        "Networked process enumeration",
        PhaseStatus::Complete(process_list.len()),
    );

    // Phase 2: Hunt Evil detection
    display_phase(
        "Process anomaly detection (Hunt Evil)",
        PhaseStatus::Starting,
    );
    let huntevil_list = run_huntevil_checks(process_list);
    let flagged_count = huntevil_list
        .iter()
        .filter(|p| !p.hunt_flags.is_empty())
        .count();
    display_phase(
        "Process anomaly detection",
        PhaseStatus::Complete(flagged_count),
    );

    // Track metrics for summary
    let processes_with_hashes = huntevil_list.iter().filter(|p| p.phash != "-").count();
    let processes_with_public_ips = huntevil_list
        .iter()
        .filter(|p| p.rip != "-" && p.rip != "0.0.0.0")
        .count();

    // Phase 3: CTI enrichment
    let enriched_list = if config.threatfox_api_key.is_some() {
        display_phase(
            "Cyber Threat Intelligence enrichment",
            PhaseStatus::Starting,
        );
        let result = run_cti_lookups(huntevil_list, config).await?;
        let threat_count = result
            .iter()
            .filter(|p| {
                (p.hash_cti_malware != "-" && !p.hash_cti_malware.is_empty())
                    || (p.hash_mb_file_type != "-" && !p.hash_mb_file_type.is_empty())
                    || (p.rip_cti_malware != "-" && !p.rip_cti_malware.is_empty())
            })
            .count();
        display_phase(
            "CTI enrichment (ThreatFox + MalwareBazaar + RIPE)",
            PhaseStatus::Complete(threat_count),
        );
        result
    } else {
        display_phase("CTI enrichment", PhaseStatus::Skipped("No API key"));
        huntevil_list
    };

    // Calculate deduplication savings (estimate unique hashes and IPs)
    let unique_hashes = enriched_list
        .iter()
        .filter(|p| p.phash != "-")
        .map(|p| p.phash.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let unique_ips = enriched_list
        .iter()
        .filter(|p| p.rip != "-" && p.rip != "0.0.0.0")
        .map(|p| p.rip.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let dedup_savings = (processes_with_hashes.saturating_sub(unique_hashes))
        + (processes_with_public_ips.saturating_sub(unique_ips));

    // Filter to public IPs only if requested and assign risk score
    let mut final_list: Vec<ProcessData> = if args.public {
        enriched_list
            .into_iter()
            .filter(|p| p.rip_type.as_ref() == "PUBLIC")
            .collect()
    } else {
        enriched_list
    };

    for pdata in &mut final_list {
        pdata.risk_score = calculate_risk_score(pdata);
    }

    // Generate output filename with hostname and timestamp
    let hostname = hostname::get()
        .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
        .to_string_lossy()
        .to_string();
    let timestamp = Local::now().format("%Y%m%d.%H%M%S");
    let base_filename = format!("patrolman_{}_{}", hostname, timestamp);

    // Display summary dashboard before output
    if args.display {
        display_summary(
            &final_list,
            &hostname,
            unique_hashes,
            unique_ips,
            dedup_savings,
        );
        display_threats(&final_list);
        display_results(&final_list)?;
    }

    // Write output based on flags with enhanced export banner
    let mut exports = Vec::new();

    if args.json {
        let json_path = PathBuf::from(format!("{}.json", base_filename));
        write_json_output(&final_list, &json_path)?;
        exports.push(("JSON", json_path.display().to_string(), final_list.len()));
    }

    if args.tsv {
        let tsv_path = PathBuf::from(format!("{}.tsv", base_filename));
        write_tsv_output(&final_list, &tsv_path)?;
        exports.push(("TSV", tsv_path.display().to_string(), final_list.len()));
    }

    // Display export banner
    if !exports.is_empty() {
        println!("\n{}", "[✓] Results exported:".green().bold());
        for (format, path, count) in exports {
            let icon = match format {
                "JSON" => "📄",
                "TSV" => "📊",
                _ => "📁",
            };
            println!(
                "    {} {}: {} ({} processes)",
                icon,
                format,
                path.bright_white(),
                count
            );
        }
    }

    Ok(final_list)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command-line arguments
    let args = Args::parse_args();

    // Configure debug logging if requested
    if args.debug {
        log::set_max_level(log::LevelFilter::Debug);
    }

    // Load configuration
    let config = Config::load("patrolman.conf")?;

    // Secret hygiene checks (warn by default, optional strict failure mode)
    if config.insecure_config_key_detected {
        if let Some(message) = &config.secret_hygiene_message {
            eprintln!("{} {}", "[!]".bright_red().bold(), message.bright_red());
            eprintln!(
                "{}",
                "    Recommendation: set THREATFOX_API_KEY in your environment and replace patrolman.conf key with a placeholder."
                    .bright_black()
            );
        }

        let strict_secret_hygiene = std::env::var("PATROLMAN_STRICT_SECRET_HYGIENE")
            .map(|v| {
                let normalized = v.trim().to_ascii_lowercase();
                matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);

        if strict_secret_hygiene {
            bail!("Strict secret hygiene check failed due to repo-local API key in patrolman.conf");
        }
    }

    // Display banner
    display_banner();

    let start_time = Instant::now();
    let max_duration = if args.duration > 0 {
        Some(Duration::from_secs(args.duration * 60))
    } else {
        None
    };

    let mut run_number = 1u64;
    loop {
        if args.interval > 0 {
            println!("\n{} {}", "[Run]".bright_cyan().bold(), run_number);
        }

        let _ = execute_scan(&args, &config).await?;

        if args.interval == 0 {
            break;
        }

        if let Some(limit) = max_duration {
            if start_time.elapsed() >= limit {
                println!("{}", "[✓] Continuous mode duration reached. Exiting.".green());
                break;
            }
        }

        println!(
            "{}",
            format!(
                "[i] Waiting {}s before next scan. Press Ctrl+C to stop.",
                args.interval
            )
            .bright_black()
        );

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("{}", "[✓] Shutdown signal received. Exiting continuous mode.".yellow());
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(args.interval)) => {}
        }

        run_number += 1;
    }

    Ok(())
}
