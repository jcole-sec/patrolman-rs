use anyhow::Result;
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::types::ProcessData;

/// Display application banner
pub fn display_banner() {
    let banner = r#"
    ____        __             __                     
   / __ \____ _/ /__________  / /___ ___  ____ _____  
  / /_/ / __ `/ __/ ___/ __ \/ / __ `__ \/ __ `/ __ \ 
 / ____/ /_/ / /_/ /  / /_/ / / / / / / / /_/ / / / / 
/_/    \__,_/\__/_/   \____/_/_/ /_/ /_/\__,_/_/ /_/  
"#;
    println!("{}", banner.bright_cyan());
    println!(
        "{}",
        "    🛡️  Windows Security Analysis Tool v0.2.0"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "    Hunt Evil • CTI Enrichment • Network Forensics\n"
            .bright_black()
    );
}

/// Display a phase indicator with spinner-style prefix
pub fn display_phase(phase: &str, status: PhaseStatus) {
    match status {
        PhaseStatus::Starting => {
            println!(
                "{} {}",
                "▶".bright_cyan().bold(),
                phase.cyan()
            );
        }
        PhaseStatus::Complete(count) => {
            println!(
                "{} {} {}",
                "✓".bright_green().bold(),
                phase.green(),
                format!("({} items)", count).bright_black()
            );
        }
        PhaseStatus::Skipped(reason) => {
            println!(
                "{} {} {}",
                "⊘".bright_yellow(),
                phase.yellow(),
                format!("[{}]", reason).bright_black()
            );
        }
    }
}

pub enum PhaseStatus {
    Starting,
    Complete(usize),
    Skipped(&'static str),
}

/// Display summary dashboard with key metrics
pub fn display_summary(
    process_list: &[ProcessData],
    hostname: &str,
    unique_hashes: usize,
    unique_ips: usize,
    dedup_savings: usize,
) {
    use colored::Colorize;

    let total_processes = process_list.len();
    let flagged_count = process_list
        .iter()
        .filter(|p| !p.hunt_flags.is_empty())
        .count();
    let public_ips = process_list
        .iter()
        .filter(|p| p.rip_type.as_ref() == "PUBLIC")
        .count();
    let threat_count = process_list
        .iter()
        .filter(|p| {
            (p.hash_cti_malware != "-" && !p.hash_cti_malware.is_empty())
                || (p.hash_mb_signature != "-" && !p.hash_mb_signature.is_empty())
                || (p.rip_cti_malware != "-" && !p.rip_cti_malware.is_empty())
        })
        .count();
    let mb_hits = process_list
        .iter()
        .filter(|p| p.hash_mb_file_type != "-" && !p.hash_mb_file_type.is_empty())
        .count();

    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .bright_blue()
    );
    println!(
        "{}{}{}",
        "║".bright_blue(),
        "                           📊 SCAN SUMMARY                                    ".bright_white().bold(),
        "║".bright_blue()
    );
    println!(
        "{}",
        "╠══════════════════════════════════════════════════════════════════════════════╣"
            .bright_blue()
    );

    // System info
    let time_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!(
        "{} 🖥️  {:<20} ⏱️  {:<36} {}",
        "║".bright_blue(),
        hostname.bright_white(),
        time_str.bright_white(),
        "║".bright_blue()
    );

    println!(
        "{}",
        "╠══════════════════════════════════════════════════════════════════════════════╣"
            .bright_blue()
    );

    // Metrics row 1
    let process_str = format!("{}", total_processes);
    let flags_str = format!("{}", flagged_count);
    let flags_colored = if flagged_count > 0 {
        flags_str.bright_yellow().bold().to_string()
    } else {
        flags_str.bright_green().to_string()
    };
    println!(
        "{} 📋 Processes: {:<12} 🚩 Hunt Evil Flags: {:<21} {}",
        "║".bright_blue(),
        process_str.bright_white(),
        flags_colored,
        "║".bright_blue()
    );

    // Metrics row 2
    let public_str = format!("{}", public_ips);
    let hash_str = format!("{}", unique_hashes);
    println!(
        "{} 🌐 Public IPs: {:<11} 🔐 Unique Hashes: {:<23} {}",
        "║".bright_blue(),
        public_str.bright_white(),
        hash_str.bright_white(),
        "║".bright_blue()
    );

    // Metrics row 3 - Threat intelligence
    let threat_str = format!("{}", threat_count);
    let threat_colored = if threat_count > 0 {
        threat_str.bright_red().bold().to_string()
    } else {
        threat_str.bright_green().to_string()
    };
    let mb_str = format!("{}", mb_hits);
    println!(
        "{} ☠️  Threat Hits: {:<10} 🦠 MalwareBazaar: {:<23} {}",
        "║".bright_blue(),
        threat_colored,
        mb_str.bright_white(),
        "║".bright_blue()
    );

    // Deduplication savings
    let dedup_str = format!("{} API calls saved", dedup_savings);
    let ip_str = format!("{} unique", unique_ips);
    println!(
        "{} ⚡ Dedup Savings: {:<8} 🔍 IP Lookups: {:<25} {}",
        "║".bright_blue(),
        dedup_str.bright_cyan(),
        ip_str.bright_white(),
        "║".bright_blue()
    );

    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .bright_blue()
    );
    println!();
}

/// Display threat detections in a highlighted panel
pub fn display_threats(process_list: &[ProcessData]) {
    use colored::Colorize;

    let threats: Vec<&ProcessData> = process_list
        .iter()
        .filter(|p| {
            !p.hunt_flags.is_empty()
                || (p.hash_cti_malware != "-" && !p.hash_cti_malware.is_empty())
                || (p.hash_mb_signature != "-" && !p.hash_mb_signature.is_empty())
                || (p.rip_cti_malware != "-" && !p.rip_cti_malware.is_empty())
        })
        .collect();

    if threats.is_empty() {
        println!(
            "{}",
            "  ✅ No threats or anomalies detected".bright_green().bold()
        );
        return;
    }

    println!(
        "{}",
        "┌─────────────────────────────────── ⚠️  DETECTIONS ───────────────────────────────────┐"
            .bright_red()
    );

    for pdata in &threats {
        let pid_str = format!("PID {}", pdata.pid);
        println!(
            "│ {} {} ({})",
            "►".bright_red(),
            pdata.pname.bright_white().bold(),
            pid_str.bright_black()
        );

        // Show hunt evil flags
        if !pdata.hunt_flags.is_empty() {
            for flag in &pdata.hunt_flags {
                println!(
                    "│   {} {}",
                    "🚩".to_string(),
                    flag.yellow()
                );
            }
        }

        // Show ThreatFox hits
        if pdata.hash_cti_malware != "-" && !pdata.hash_cti_malware.is_empty() {
            println!(
                "│   {} ThreatFox: {} ({})",
                "☠️".to_string(),
                pdata.hash_cti_malware.bright_red().bold(),
                pdata.hash_cti_threat_type.bright_black()
            );
        }

        // Show MalwareBazaar hits
        if pdata.hash_mb_file_type != "-" && !pdata.hash_mb_file_type.is_empty() {
            let sig = if pdata.hash_mb_signature != "-" {
                &pdata.hash_mb_signature
            } else {
                "Unknown"
            };
            println!(
                "│   {} MalwareBazaar: {} [{}] tags: {}",
                "🦠".to_string(),
                sig.bright_magenta().bold(),
                pdata.hash_mb_file_type.bright_white(),
                pdata.hash_mb_tags.bright_black()
            );
        }

        // Show remote IP threat intel
        if pdata.rip_cti_malware != "-" && !pdata.rip_cti_malware.is_empty() {
            println!(
                "│   {} Remote IP {}: {} ({})",
                "🌐".to_string(),
                pdata.rip.bright_white(),
                pdata.rip_cti_malware.bright_red().bold(),
                pdata.rip_country.bright_black()
            );
        }

        // Show path for suspicious processes
        if pdata.ppath != "-" && !pdata.ppath.is_empty() {
            println!("│   📂 {}", pdata.ppath.bright_black());
        }

        println!("│");
    }

    println!(
        "{}",
        "└──────────────────────────────────────────────────────────────────────────────────────┘"
            .bright_red()
    );
    println!();
}

/// Display results in a formatted table with color-coded threat levels
pub fn display_results(process_list: &[ProcessData]) -> Result<()> {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    
    // Get terminal width and set table to fit
    let term_width = terminal_size::terminal_size()
        .map(|(w, _)| w.0 as u16)
        .unwrap_or(120);
    
    table.set_width(term_width);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    
    // Header
    table.set_header(vec![
        Cell::new("PID").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("Process").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("User").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("Local IP:Port").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("Remote IP:Port").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("Flags").fg(Color::Cyan).add_attribute(Attribute::Bold),
    ]);

    // Rows with color coding based on threat level
    for pdata in process_list {
        // Truncate flags if too long
        let flags_str = if pdata.hunt_flags.is_empty() {
            "-".to_string()
        } else {
            let full_flags = pdata.hunt_flags.join(", ");
            if full_flags.len() > 50 {
                format!("{}...", &full_flags[..47])
            } else {
                full_flags
            }
        };

        let lip_port = format!("{}:{}", pdata.lip, pdata.lport);
        let rip_port = format!("{}:{}", pdata.rip, pdata.rport);

        // Determine threat level for color coding
        let has_malware = (pdata.hash_cti_malware != "-" && pdata.hash_cti_malware != "") ||
                          (pdata.rip_cti_malware != "-" && pdata.rip_cti_malware != "");
        let has_threat = (pdata.hash_cti_confidence != "-" && pdata.hash_cti_confidence != "") ||
                         (pdata.rip_cti_confidence != "-" && pdata.rip_cti_confidence != "");
        let has_flags = !pdata.hunt_flags.is_empty();

        // Color code rows: RED for malware, YELLOW for flags, default for clean
        let row_color = if has_malware {
            Some(Color::Red)
        } else if has_threat || has_flags {
            Some(Color::Yellow)
        } else {
            None
        };

        let mut row = vec![
            Cell::new(pdata.pid.to_string()),
            Cell::new(&pdata.pname),
            Cell::new(&pdata.puser),
            Cell::new(lip_port),
            Cell::new(rip_port),
            Cell::new(flags_str),
        ];

        // Apply color to all cells in row if threat detected
        if let Some(color) = row_color {
            row = row.into_iter().map(|cell| cell.fg(color)).collect();
        }

        table.add_row(row);
    }

    println!("{}", table);
    Ok(())
}

/// Write JSON output
pub fn write_json_output<P: AsRef<Path>>(
    process_list: &[ProcessData],
    path: P,
) -> Result<()> {
    let json = serde_json::to_string_pretty(process_list)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Write TSV output
pub fn write_tsv_output<P: AsRef<Path>>(
    process_list: &[ProcessData],
    path: P,
) -> Result<()> {
    let mut file = File::create(path)?;

    // Header
    writeln!(
        file,
        "{}",
        [
            "pid", "pname", "ppid", "ppid_name", "ppath", "puser", "cmdline", "phash",
            "lip", "lport", "rip", "rport", "protocol", "lip_type", "rip_type",
            "hunt_flags", "hash_cti_confidence", "hash_cti_threat_type", "hash_cti_malware",
            "rip_cidr", "rip_netname", "rip_country", "rip_cti_confidence",
            "rip_cti_threat_type", "rip_cti_malware"
        ]
        .join("\t")
    )?;

    // Data rows
    for pdata in process_list {
        let flags = pdata.hunt_flags.join("|");
        writeln!(
            file,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            pdata.pid, pdata.pname, pdata.ppid, pdata.ppid_name, pdata.ppath,
            pdata.puser, pdata.cmdline, pdata.phash, pdata.lip, pdata.lport,
            pdata.rip, pdata.rport, pdata.protocol, pdata.lip_type, pdata.rip_type,
            flags, pdata.hash_cti_confidence, pdata.hash_cti_threat_type,
            pdata.hash_cti_malware, pdata.rip_cidr, pdata.rip_netname,
            pdata.rip_country, pdata.rip_cti_confidence, pdata.rip_cti_threat_type,
            pdata.rip_cti_malware
        )?;
    }

    Ok(())
}
