use serde::{Deserialize, Serialize};
use std::sync::Arc;

lazy_static::lazy_static! {
    pub static ref INTERNED_BLANK: Arc<str> = Arc::from("-");
    pub static ref INTERNED_TCP: Arc<str> = Arc::from("TCP");
    pub static ref INTERNED_UDP: Arc<str> = Arc::from("UDP");
    pub static ref INTERNED_PUBLIC: Arc<str> = Arc::from("PUBLIC");
    pub static ref INTERNED_PRIVATE: Arc<str> = Arc::from("PRIVATE");
    pub static ref INTERNED_LOOPBACK: Arc<str> = Arc::from("LOOPBACK");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessData {
    pub pid: u32,
    pub pname: String,
    pub ppid: u32,
    pub ppid_name: String,
    pub ppath: String,
    pub puser: String,
    pub cmdline: String,
    pub phash: String,
    
    // Network information - using Arc<str> for common values
    pub lip: String,
    pub lport: u16,
    pub rip: String,
    pub rport: u16,
    #[serde(serialize_with = "serialize_arc_str")]
    #[serde(deserialize_with = "deserialize_arc_str")]
    pub protocol: Arc<str>,
    #[serde(serialize_with = "serialize_arc_str")]
    #[serde(deserialize_with = "deserialize_arc_str")]
    pub lip_type: Arc<str>,
    #[serde(serialize_with = "serialize_arc_str")]
    #[serde(deserialize_with = "deserialize_arc_str")]
    pub rip_type: Arc<str>,
    
    // Hunt Evil flags
    pub hunt_flags: Vec<String>,
    
    // CTI enrichment - ThreatFox Hash
    pub hash_cti_confidence: String,
    pub hash_cti_threat_type: String,
    pub hash_cti_malware: String,
    
    // CTI enrichment - MalwareBazaar Hash
    pub hash_mb_signature: String,
    pub hash_mb_tags: String,
    pub hash_mb_file_type: String,
    
    // CTI enrichment - Remote IP
    pub rip_cidr: String,
    pub rip_netname: String,
    pub rip_country: String,
    pub rip_cti_confidence: String,
    pub rip_cti_threat_type: String,
    pub rip_cti_malware: String,
}

// Serialization helpers for Arc<str>
fn serialize_arc_str<S>(value: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value)
}

fn deserialize_arc_str<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Arc::from(s.as_str()))
}

impl Default for ProcessData {
    fn default() -> Self {
        Self {
            pid: 0,
            pname: BLANK.to_string(),
            ppid: 0,
            ppid_name: BLANK.to_string(),
            ppath: BLANK.to_string(),
            puser: BLANK.to_string(),
            cmdline: BLANK.to_string(),
            phash: BLANK.to_string(),
            lip: BLANK.to_string(),
            lport: 0,
            rip: BLANK.to_string(),
            rport: 0,
            protocol: INTERNED_TCP.clone(),
            lip_type: INTERNED_BLANK.clone(),
            rip_type: INTERNED_BLANK.clone(),
            hunt_flags: Vec::new(),
            hash_cti_confidence: BLANK.to_string(),
            hash_cti_threat_type: BLANK.to_string(),
            hash_cti_malware: BLANK.to_string(),
            hash_mb_signature: BLANK.to_string(),
            hash_mb_tags: BLANK.to_string(),
            hash_mb_file_type: BLANK.to_string(),
            rip_cidr: BLANK.to_string(),
            rip_netname: BLANK.to_string(),
            rip_country: BLANK.to_string(),
            rip_cti_confidence: BLANK.to_string(),
            rip_cti_threat_type: BLANK.to_string(),
            rip_cti_malware: BLANK.to_string(),
        }
    }
}

pub const BLANK: &str = "-";
