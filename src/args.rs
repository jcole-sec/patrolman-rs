use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "patrolman",
    version = "2.1.0",
    about = "Windows security analysis tool for networked processes with malware detection",
    long_about = None
)]
pub struct Args {
    /// Enable JSON output (default: true)
    #[arg(long, default_value_t = true)]
    pub json: bool,

    /// Enable TSV (tab-separated) output
    #[arg(long, default_value_t = false)]
    pub tsv: bool,

    /// Enable console display output
    #[arg(short = 'd', long, default_value_t = false)]
    pub display: bool,

    /// Filter results to public IP addresses only
    #[arg(short = 'p', long, default_value_t = false)]
    pub public: bool,

    /// Enable debug logging
    #[arg(long, default_value_t = false)]
    pub debug: bool,

    /// Insert synthetic test data for validation
    #[arg(long, default_value_t = false)]
    pub test: bool,
}

impl Args {
    pub fn parse_args() -> Self {
        Args::parse()
    }
}
