mod args;
mod config;
mod cti_enrichment;
mod display;
mod huntevil;
mod process;
mod types;

use anyhow::Result;
use chrono::Local;
use colored::*;
use std::path::PathBuf;

use args::Args;
use config::Config;
use cti_enrichment::run_cti_lookups;
use display::{display_banner, display_phase, display_results, display_summary, display_threats, write_json_output, write_tsv_output, PhaseStatus};
use huntevil::run_huntevil_checks;
use process::get_process_list;
use types::ProcessData;

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

    // Display banner
    display_banner();

    // Phase 1: Process enumeration
    display_phase("Networked process enumeration", PhaseStatus::Starting);
    let process_list = get_process_list(args.test).await?;
    display_phase("Networked process enumeration", PhaseStatus::Complete(process_list.len()));

    // Phase 2: Hunt Evil detection
    display_phase("Process anomaly detection (Hunt Evil)", PhaseStatus::Starting);
    let huntevil_list = run_huntevil_checks(process_list);
    let flagged_count = huntevil_list.iter().filter(|p| !p.hunt_flags.is_empty()).count();
    display_phase("Process anomaly detection", PhaseStatus::Complete(flagged_count));

    // Track metrics for summary
    let processes_with_hashes = huntevil_list.iter().filter(|p| p.phash != "-").count();
    let processes_with_public_ips = huntevil_list
        .iter()
        .filter(|p| p.rip != "-" && p.rip != "0.0.0.0")
        .count();

    // Phase 3: CTI enrichment
    let enriched_list = if config.threatfox_api_key.is_some() {
        display_phase("Cyber Threat Intelligence enrichment", PhaseStatus::Starting);
        let result = run_cti_lookups(huntevil_list, &config).await?;
        let threat_count = result
            .iter()
            .filter(|p| {
                (p.hash_cti_malware != "-" && !p.hash_cti_malware.is_empty())
                    || (p.hash_mb_file_type != "-" && !p.hash_mb_file_type.is_empty())
                    || (p.rip_cti_malware != "-" && !p.rip_cti_malware.is_empty())
            })
            .count();
        display_phase("CTI enrichment (ThreatFox + MalwareBazaar + RIPE)", PhaseStatus::Complete(threat_count));
        result
    } else {
        display_phase("CTI enrichment", PhaseStatus::Skipped("No API key"));
        huntevil_list
    };

    // Calculate deduplication savings (estimate unique hashes and IPs)
    let unique_hashes = enriched_list.iter()
        .filter(|p| p.phash != "-")
        .map(|p| p.phash.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let unique_ips = enriched_list.iter()
        .filter(|p| p.rip != "-" && p.rip != "0.0.0.0")
        .map(|p| p.rip.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let dedup_savings = (processes_with_hashes.saturating_sub(unique_hashes)) + 
                        (processes_with_public_ips.saturating_sub(unique_ips));

    // Filter to public IPs only if requested
    let final_list: Vec<ProcessData> = if args.public {
        enriched_list
            .into_iter()
            .filter(|p| p.rip_type.as_ref() == "PUBLIC")
            .collect()
    } else {
        enriched_list
    };

    // Generate output filename with hostname and timestamp
    let hostname = hostname::get()
        .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
        .to_string_lossy()
        .to_string();
    let timestamp = Local::now().format("%Y%m%d.%H%M");
    let base_filename = format!("patrolman_{}_{}", hostname, timestamp);

    // Display summary dashboard before output
    if args.display {
        display_summary(&final_list, &hostname, unique_hashes, unique_ips, dedup_savings);
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
            println!("    {} {}: {} ({} processes)", icon, format, path.bright_white(), count);
        }
    }

    Ok(())
}
