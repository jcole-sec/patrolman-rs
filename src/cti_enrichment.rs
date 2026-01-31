use anyhow::Result;
use log::{debug, error, warn};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::Config;
use crate::process::get_ip_type;
use crate::types::{ProcessData, BLANK};

const THREATFOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";
const MALWAREBAZAAR_URL: &str = "https://mb-api.abuse.ch/api/v1/";
const RIPE_URL_TEMPLATE: &str = "https://stat.ripe.net/data/whois/data.json?resource=";

#[derive(Debug, Deserialize)]
struct ThreatFoxResponse {
    #[allow(dead_code)]
    query_status: Option<String>,
    data: Option<Vec<ThreatFoxData>>,
}

#[derive(Debug, Deserialize)]
struct ThreatFoxData {
    confidence_level: Option<u32>,
    threat_type: Option<String>,
    malware_printable: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MalwareBazaarResponse {
    #[allow(dead_code)]
    query_status: Option<String>,
    data: Option<Vec<MalwareBazaarData>>,
}

#[derive(Debug, Deserialize)]
struct MalwareBazaarData {
    signature: Option<String>,
    file_type: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RipeResponse {
    data: Option<RipeData>,
}

#[derive(Debug, Deserialize)]
struct RipeData {
    records: Option<Vec<Vec<RipeRecord>>>,
}

#[derive(Debug, Deserialize)]
struct RipeRecord {
    key: String,
    value: String,
}

/// Run CTI lookups for all processes with deduplication and parallel batching
pub async fn run_cti_lookups(
    process_list: Vec<ProcessData>,
    config: &Config,
) -> Result<Vec<ProcessData>> {
    let client = Arc::new(
        Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(20)
            .build()?,
    );

    // Step 1: Collect unique hashes and IPs that need lookup
    let mut unique_hashes = HashSet::new();
    let mut unique_ips = HashSet::new();

    for pdata in &process_list {
        // Collect unique hashes
        if pdata.phash != BLANK && config.threatfox_api_key.is_some() {
            unique_hashes.insert(pdata.phash.clone());
        }
        
        // Collect unique public IPs
        if pdata.rip != BLANK && get_ip_type(&pdata.rip) == "PUBLIC" {
            unique_ips.insert(pdata.rip.clone());
        }
    }

    let total_processes = process_list.len();
    let unique_hash_count = unique_hashes.len();
    let unique_ip_count = unique_ips.len();
    
    debug!("Deduplication: {} processes → {} unique hashes, {} unique IPs", 
          total_processes, unique_hash_count, unique_ip_count);

    // Step 2: Perform deduplicated lookups - run ThreatFox and MalwareBazaar concurrently
    let (hash_cache, mb_cache, (ripe_cache, ip_cache)) = tokio::join!(
        lookup_unique_hashes(
            &client,
            unique_hashes.clone(),
            config.threatfox_api_key.as_deref(),
            config.api_request_delay,
        ),
        lookup_unique_hashes_malwarebazaar(
            &client,
            unique_hashes.clone(),
            config.threatfox_api_key.as_deref(),
            config.api_request_delay,
        ),
        lookup_unique_ips(
            &client,
            unique_ips,
            config.threatfox_api_key.as_deref(),
            config.api_request_delay,
        )
    );

    // Step 3: Apply cached results to all processes
    let enriched_list: Vec<ProcessData> = process_list
        .into_iter()
        .map(|mut pdata| {
            // Apply ThreatFox hash data from cache
            if pdata.phash != BLANK {
                if let Some(hash_data) = hash_cache.get(&pdata.phash) {
                    pdata.hash_cti_confidence = hash_data.0.clone();
                    pdata.hash_cti_threat_type = hash_data.1.clone();
                    pdata.hash_cti_malware = hash_data.2.clone();
                }
                
                // Apply MalwareBazaar hash data from cache
                if let Some(mb_data) = mb_cache.get(&pdata.phash) {
                    pdata.hash_mb_signature = mb_data.0.clone();
                    pdata.hash_mb_tags = mb_data.1.clone();
                    pdata.hash_mb_file_type = mb_data.2.clone();
                }
            }

            // Apply IP data from cache
            if pdata.rip != BLANK && get_ip_type(&pdata.rip) == "PUBLIC" {
                if let Some(ripe_data) = ripe_cache.get(&pdata.rip) {
                    pdata.rip_cidr = ripe_data.0.clone();
                    pdata.rip_netname = ripe_data.1.clone();
                    pdata.rip_country = ripe_data.2.clone();
                }
                
                if let Some(ip_data) = ip_cache.get(&pdata.rip) {
                    pdata.rip_cti_confidence = ip_data.0.clone();
                    pdata.rip_cti_threat_type = ip_data.1.clone();
                    pdata.rip_cti_malware = ip_data.2.clone();
                }
            }

            pdata
        })
        .collect();

    Ok(enriched_list)
}

/// Lookup unique hashes in parallel batches
async fn lookup_unique_hashes(
    client: &Client,
    hashes: HashSet<String>,
    api_key: Option<&str>,
    delay: f64,
) -> HashMap<String, (String, String, String)> {
    let mut cache = HashMap::new();
    
    if hashes.is_empty() || api_key.is_none() {
        return cache;
    }

    let api_key = api_key.unwrap();
    let batch_size = 10;
    let delay_duration = Duration::from_secs_f64(delay);

    let hash_vec: Vec<String> = hashes.into_iter().collect();
    
    for batch in hash_vec.chunks(batch_size) {
        let tasks: Vec<_> = batch
            .iter()
            .map(|hash| {
                let hash = hash.clone();
                let api_key = api_key.to_string();
                async move {
                    let result = threatfox_hash_lookup(client, &hash, &api_key).await;
                    (hash, result)
                }
            })
            .collect();

        let results = futures::future::join_all(tasks).await;
        
        for (hash, result) in results {
            match result {
                Ok(data) => {
                    cache.insert(
                        hash,
                        (
                            data.confidence_level.map(|c| c.to_string()).unwrap_or_else(|| BLANK.to_string()),
                            data.threat_type.unwrap_or_else(|| BLANK.to_string()),
                            data.malware_printable.unwrap_or_else(|| BLANK.to_string()),
                        ),
                    );
                }
                Err(e) => {
                    error!("Hash lookup failed for {}: {}", hash, e);
                }
            }
        }
        
        sleep(delay_duration).await;
    }

    cache
}

/// Lookup unique IPs in parallel batches (RIPE + ThreatFox)
async fn lookup_unique_ips(
    client: &Client,
    ips: HashSet<String>,
    api_key: Option<&str>,
    delay: f64,
) -> (HashMap<String, (String, String, String)>, HashMap<String, (String, String, String)>) {
    let mut ripe_cache = HashMap::new();
    let mut ip_cache = HashMap::new();
    
    if ips.is_empty() {
        return (ripe_cache, ip_cache);
    }

    let batch_size = 10;
    let delay_duration = Duration::from_secs_f64(delay);
    let ip_vec: Vec<String> = ips.into_iter().collect();
    
    for batch in ip_vec.chunks(batch_size) {
        let tasks: Vec<_> = batch
            .iter()
            .map(|ip| {
                let ip = ip.clone();
                let api_key_clone = api_key.map(|s| s.to_string());
                async move {
                    let ripe_result = ripe_lookup(client, &ip).await;
                    
                    let ip_result = if let Some(key) = api_key_clone {
                        threatfox_ip_lookup(client, &ip, &key).await
                    } else {
                        Ok(ThreatFoxData {
                            confidence_level: None,
                            threat_type: None,
                            malware_printable: None,
                        })
                    };
                    
                    (ip, ripe_result, ip_result)
                }
            })
            .collect();

        let results = futures::future::join_all(tasks).await;
        
        for (ip, ripe_result, ip_result) in results {
            // Process RIPE data
            match ripe_result {
                Ok(ripe_data) => {
                    let cidr = ripe_data
                        .get("CIDR")
                        .or_else(|| ripe_data.get("inetnum"))
                        .cloned()
                        .unwrap_or_else(|| BLANK.to_string());
                    let netname = ripe_data
                        .get("netname")
                        .or_else(|| ripe_data.get("NetName"))
                        .cloned()
                        .unwrap_or_else(|| BLANK.to_string());
                    let country = ripe_data
                        .get("country")
                        .or_else(|| ripe_data.get("Country"))
                        .cloned()
                        .unwrap_or_else(|| BLANK.to_string());
                    
                    ripe_cache.insert(ip.clone(), (cidr, netname, country));
                }
                Err(e) => {
                    error!("RIPE lookup failed for {}: {}", ip, e);
                }
            }
            
            // Process ThreatFox IP data
            match ip_result {
                Ok(data) => {
                    ip_cache.insert(
                        ip,
                        (
                            data.confidence_level.map(|c| c.to_string()).unwrap_or_else(|| BLANK.to_string()),
                            data.threat_type.unwrap_or_else(|| BLANK.to_string()),
                            data.malware_printable.unwrap_or_else(|| BLANK.to_string()),
                        ),
                    );
                }
                Err(e) => {
                    error!("ThreatFox IP lookup failed for {}: {}", ip, e);
                }
            }
        }
        
        sleep(delay_duration).await;
    }

    (ripe_cache, ip_cache)
}

/// Perform ThreatFox hash lookup
async fn threatfox_hash_lookup(
    client: &Client,
    hash: &str,
    api_key: &str,
) -> Result<ThreatFoxData> {
    let body = json!({
        "query": "search_hash",
        "hash": hash
    });

    let response = match client
        .post(THREATFOX_URL)
        .header("Content-Type", "application/json")
        .header("Auth-Key", api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(_) => {
            // Network error - return empty data
            return Ok(ThreatFoxData {
                confidence_level: None,
                threat_type: None,
                malware_printable: None,
            });
        }
    };

    if response.status() != StatusCode::OK {
        warn!("ThreatFox hash request failed: {}", response.status());
        return Ok(ThreatFoxData {
            confidence_level: None,
            threat_type: None,
            malware_printable: None,
        });
    }

    // Handle response - ThreatFox may return no_result status without data field
    match response.json::<ThreatFoxResponse>().await {
        Ok(threat_response) => {
            Ok(threat_response.data
                .and_then(|mut v| v.pop())
                .unwrap_or(ThreatFoxData {
                    confidence_level: None,
                    threat_type: None,
                    malware_printable: None,
                }))
        }
        Err(_) => {
            // API returned unexpected format (likely no_result)
            Ok(ThreatFoxData {
                confidence_level: None,
                threat_type: None,
                malware_printable: None,
            })
        }
    }
}

/// Lookup unique hashes in MalwareBazaar
async fn lookup_unique_hashes_malwarebazaar(
    client: &Client,
    hashes: HashSet<String>,
    api_key: Option<&str>,
    delay: f64,
) -> HashMap<String, (String, String, String)> {
    let mut cache = HashMap::new();
    
    if hashes.is_empty() || api_key.is_none() {
        return cache;
    }

    let api_key = api_key.unwrap();
    let batch_size = 10;
    let delay_duration = Duration::from_secs_f64(delay);
    let hash_vec: Vec<String> = hashes.into_iter().collect();
    
    for batch in hash_vec.chunks(batch_size) {
        let tasks: Vec<_> = batch
            .iter()
            .map(|hash| {
                let hash = hash.clone();
                let api_key = api_key.to_string();
                async move {
                    let result = malwarebazaar_hash_lookup(client, &hash, &api_key).await;
                    (hash, result)
                }
            })
            .collect();

        let results = futures::future::join_all(tasks).await;
        
        for (hash, result) in results {
            match result {
                Ok(data) => {
                    cache.insert(
                        hash,
                        (
                            data.signature.unwrap_or_else(|| BLANK.to_string()),
                            data.tags.map(|t| t.join(", ")).unwrap_or_else(|| BLANK.to_string()),
                            data.file_type.unwrap_or_else(|| BLANK.to_string()),
                        ),
                    );
                }
                Err(e) => {
                    // Silently skip errors for MalwareBazaar lookups
                    log::debug!("MalwareBazaar lookup failed for {}: {}", hash, e);
                }
            }
        }
        
        sleep(delay_duration).await;
    }

    cache
}

/// Perform MalwareBazaar hash lookup
async fn malwarebazaar_hash_lookup(
    client: &Client,
    hash: &str,
    api_key: &str,
) -> Result<MalwareBazaarData> {
    // MalwareBazaar uses form-urlencoded data, not JSON
    let params = [
        ("query", "get_info"),
        ("hash", hash),
    ];

    let response = match client
        .post(MALWAREBAZAAR_URL)
        .header("Auth-Key", api_key)
        .form(&params)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(_) => {
            // Network error - return empty data
            return Ok(MalwareBazaarData {
                signature: None,
                file_type: None,
                tags: None,
            });
        }
    };

    if response.status() != StatusCode::OK {
        return Ok(MalwareBazaarData {
            signature: None,
            file_type: None,
            tags: None,
        });
    }

    // Handle response - MalwareBazaar may return no_result status
    match response.json::<MalwareBazaarResponse>().await {
        Ok(mb_response) => {
            Ok(mb_response.data
                .and_then(|mut v| v.pop())
                .unwrap_or(MalwareBazaarData {
                    signature: None,
                    file_type: None,
                    tags: None,
                }))
        }
        Err(_) => {
            // API returned unexpected format
            Ok(MalwareBazaarData {
                signature: None,
                file_type: None,
                tags: None,
            })
        }
    }
}

/// Perform ThreatFox IP lookup
async fn threatfox_ip_lookup(
    client: &Client,
    ip: &str,
    api_key: &str,
) -> Result<ThreatFoxData> {
    let body = json!({
        "query": "search_ioc",
        "search_term": ip
    });

    let response = match client
        .post(THREATFOX_URL)
        .header("Content-Type", "application/json")
        .header("Auth-Key", api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(_) => {
            // Network error - return empty data
            return Ok(ThreatFoxData {
                confidence_level: None,
                threat_type: None,
                malware_printable: None,
            });
        }
    };

    if response.status() != StatusCode::OK {
        warn!("ThreatFox IP request failed: {}", response.status());
        return Ok(ThreatFoxData {
            confidence_level: None,
            threat_type: None,
            malware_printable: None,
        });
    }

    // Handle response - ThreatFox may return no_result status without data field
    match response.json::<ThreatFoxResponse>().await {
        Ok(threat_response) => {
            Ok(threat_response.data
                .and_then(|mut v| v.pop())
                .unwrap_or(ThreatFoxData {
                    confidence_level: None,
                    threat_type: None,
                    malware_printable: None,
                }))
        }
        Err(_) => {
            // API returned unexpected format (likely no_result)
            Ok(ThreatFoxData {
                confidence_level: None,
                threat_type: None,
                malware_printable: None,
            })
        }
    }
}

/// Perform RIPE lookup
async fn ripe_lookup(client: &Client, ip: &str) -> Result<HashMap<String, String>> {
    let url = format!("{}{}", RIPE_URL_TEMPLATE, ip);
    
    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(_) => {
            // Network error - return empty data
            return Ok(HashMap::new());
        }
    };
    
    if response.status() != StatusCode::OK {
        return Ok(HashMap::new());
    }

    let ripe_response = match response.json::<RipeResponse>().await {
        Ok(resp) => resp,
        Err(_) => {
            // JSON decoding error - return empty data
            return Ok(HashMap::new());
        }
    };
    
    let mut result = HashMap::new();

    if let Some(data) = ripe_response.data {
        if let Some(records) = data.records {
            for record_set in records {
                for record in record_set {
                    result.insert(record.key, record.value);
                }
            }
        }
    }

    Ok(result)
}
