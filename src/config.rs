use anyhow::Result;
use configparser::ini::Ini;
use log::{debug, warn};
use std::env;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub threatfox_api_key: Option<String>,
    pub api_request_delay: f64,
    pub api_max_retries: u32,
    pub api_retry_backoff: f64,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut config = Config::default();

        // Try to load from config file
        if path.as_ref().exists() {
            let mut ini = Ini::new();
            let loaded_config = ini.load(path.as_ref().to_str().unwrap());
            
            if loaded_config.is_err() {
                warn!("Failed to load config file: {}", path.as_ref().display());
                return Ok(config);
            }

            // Load API key from config file
            if let Some(key) = ini.get("default", "threatfox_api_key") {
                let cleaned_key = key.trim().trim_matches('"').to_string();
                if !cleaned_key.is_empty() {
                    config.threatfox_api_key = Some(cleaned_key);
                }
            }

            // Load rate limiting settings
            if let Some(delay) = ini.get("default", "api_request_delay") {
                if let Ok(val) = delay.parse::<f64>() {
                    config.api_request_delay = val;
                }
            }

            if let Some(retries) = ini.get("default", "api_max_retries") {
                if let Ok(val) = retries.parse::<u32>() {
                    config.api_max_retries = val;
                }
            }

            if let Some(backoff) = ini.get("default", "api_retry_backoff") {
                if let Ok(val) = backoff.parse::<f64>() {
                    config.api_retry_backoff = val;
                }
            }

            debug!("Config file loaded: {}", path.as_ref().display());
        } else {
            debug!("Config file not found: {}", path.as_ref().display());
        }

        // Environment variable takes precedence over config file
        if let Ok(env_key) = env::var("THREATFOX_API_KEY") {
            config.threatfox_api_key = Some(env_key);
        }

        // Log configuration status
        if config.threatfox_api_key.is_some() {
            debug!("abuse.ch API key configured - ThreatFox and MalwareBazaar enrichment enabled");
        } else {
            warn!("abuse.ch API key not configured - running in limited mode (RIPE lookups only)");
        }

        debug!(
            "API rate limiting: delay={}s, retries={}, backoff={}",
            config.api_request_delay, config.api_max_retries, config.api_retry_backoff
        );

        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threatfox_api_key: None,
            api_request_delay: 0.1,
            api_max_retries: 3,
            api_retry_backoff: 2.0,
        }
    }
}
