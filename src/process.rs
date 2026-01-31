use anyhow::Result;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use sysinfo::System;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::ProcessStatus::{
    K32GetProcessImageFileNameW,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::types::{ProcessData, BLANK, INTERNED_TCP, INTERNED_UDP};

/// Get IP address type (PUBLIC, PRIVATE, LOOPBACK, etc.)
pub fn get_ip_type(ip: &str) -> String {
    if ip == BLANK || ip.is_empty() {
        return BLANK.to_string();
    }

    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() {
                    "LOOPBACK".to_string()
                } else if ipv4.is_private() {
                    "PRIVATE".to_string()
                } else if ipv4.is_link_local() {
                    "LINK_LOCAL".to_string()
                } else if ipv4.is_multicast() {
                    "MULTICAST".to_string()
                } else {
                    "PUBLIC".to_string()
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() {
                    "LOOPBACK".to_string()
                } else if ipv6.is_multicast() {
                    "MULTICAST".to_string()
                } else {
                    "IPV6".to_string()
                }
            }
        }
    } else {
        BLANK.to_string()
    }
}

/// Calculate SHA256 hash of a file
pub fn calculate_sha256<P: AsRef<Path>>(path: P) -> Result<String> {
    let contents = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Convert Windows IN_ADDR to string IP address
fn in_addr_to_string(addr: &IN_ADDR) -> String {
    unsafe {
        let bytes = addr.S_un.S_addr.to_ne_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Convert port from network byte order to host byte order
fn ntohs(port: u16) -> u16 {
    u16::from_be(port)
}

/// Get TCP connections for all processes using Windows API
fn get_tcp_connections() -> Result<HashMap<u32, Vec<(String, u16, String, u16)>>> {
    let mut connections: HashMap<u32, Vec<(String, u16, String, u16)>> = HashMap::new();
    
    unsafe {
        // First call to get the required buffer size
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size == 0 {
            return Ok(connections);
        }

        // Allocate buffer and get the actual table
        let mut buffer = vec![0u8; size as usize];
        let result = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if result != NO_ERROR.0 {
            return Ok(connections);
        }

        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let entries = std::slice::from_raw_parts(
            &table.table[0] as *const MIB_TCPROW_OWNER_PID,
            table.dwNumEntries as usize,
        );

        for entry in entries {
            let pid = entry.dwOwningPid;
            let local_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: entry.dwLocalAddr,
                },
            };
            let remote_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: entry.dwRemoteAddr,
                },
            };
            
            let lip = in_addr_to_string(&local_addr);
            let lport = ntohs(entry.dwLocalPort as u16);
            let rip = in_addr_to_string(&remote_addr);
            let rport = ntohs(entry.dwRemotePort as u16);

            connections
                .entry(pid)
                .or_insert_with(Vec::new)
                .push((lip, lport, rip, rport));
        }
    }

    Ok(connections)
}

/// Get UDP connections for all processes using Windows API
fn get_udp_connections() -> Result<HashMap<u32, Vec<(String, u16, String, u16)>>> {
    let mut connections: HashMap<u32, Vec<(String, u16, String, u16)>> = HashMap::new();
    
    unsafe {
        // First call to get the required buffer size
        let mut size: u32 = 0;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if size == 0 {
            return Ok(connections);
        }

        // Allocate buffer and get the actual table
        let mut buffer = vec![0u8; size as usize];
        let result = GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if result != NO_ERROR.0 {
            return Ok(connections);
        }

        let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let entries = std::slice::from_raw_parts(
            &table.table[0] as *const MIB_UDPROW_OWNER_PID,
            table.dwNumEntries as usize,
        );

        for entry in entries {
            let pid = entry.dwOwningPid;
            let local_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: entry.dwLocalAddr,
                },
            };
            
            let lip = in_addr_to_string(&local_addr);
            let lport = ntohs(entry.dwLocalPort as u16);
            let rip = "0.0.0.0".to_string(); // UDP has no remote address in listening state
            let rport = 0;

            connections
                .entry(pid)
                .or_insert_with(Vec::new)
                .push((lip, lport, rip, rport));
        }
    }

    Ok(connections)
}

/// Get the process name from PID using Windows API
fn get_process_name_by_pid(pid: u32) -> String {
    if pid == 0 {
        return BLANK.to_string();
    }

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return BLANK.to_string(),
        };

        let mut buffer = vec![0u16; 1024];
        let result = K32GetProcessImageFileNameW(handle, &mut buffer);
        let _ = CloseHandle(handle);

        if result == 0 {
            return BLANK.to_string();
        }

        let path = String::from_utf16_lossy(&buffer[..result as usize]);
        
        // Extract just the filename from the full path
        if let Some(filename) = path.split('\\').last() {
            filename.to_string()
        } else {
            path
        }
    }
}

/// Get the user associated with a process using Windows API
fn get_process_user(pid: u32) -> String {
    if pid == 0 {
        return BLANK.to_string();
    }

    unsafe {
        // Try to open process with TOKEN_QUERY rights
        let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => {
                // Try with limited information if full access fails
                match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    Ok(h) => h,
                    Err(_) => return BLANK.to_string(),
                }
            }
        };

        let mut token_handle = HANDLE::default();
        if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
            let _ = CloseHandle(process_handle);
            return BLANK.to_string();
        }

        // Get token user information
        let mut return_length: u32 = 0;
        let _ = GetTokenInformation(
            token_handle,
            TokenUser,
            None,
            0,
            &mut return_length,
        );

        if return_length == 0 {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return BLANK.to_string();
        }

        let mut buffer = vec![0u8; return_length as usize];
        if GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
        .is_err()
        {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return BLANK.to_string();
        }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        // Convert SID to string using Windows API
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        let mut sid_string = PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut sid_string).is_ok() {
            let sid_str = sid_string.to_string().unwrap_or_else(|_| BLANK.to_string());
            
            // Try to resolve SID to account name
            use windows::Win32::Security::LookupAccountSidW;
            let mut name_size = 0u32;
            let mut domain_size = 0u32;
            let mut sid_type = windows::Win32::Security::SidTypeUser;
            
            let _ = LookupAccountSidW(
                None,
                sid,
                PWSTR::null(),
                &mut name_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_type,
            );

            if name_size > 0 && domain_size > 0 {
                let mut name = vec![0u16; name_size as usize];
                let mut domain = vec![0u16; domain_size as usize];
                
                if LookupAccountSidW(
                    None,
                    sid,
                    PWSTR::from_raw(name.as_mut_ptr()),
                    &mut name_size,
                    PWSTR::from_raw(domain.as_mut_ptr()),
                    &mut domain_size,
                    &mut sid_type,
                )
                .is_ok()
                {
                    let domain_str = String::from_utf16_lossy(&domain[..domain_size as usize - 1]);
                    let name_str = String::from_utf16_lossy(&name[..name_size as usize - 1]);
                    
                    let _ = CloseHandle(token_handle);
                    let _ = CloseHandle(process_handle);
                    
                    return format!("{}\\{}", domain_str, name_str);
                }
            }
            
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return sid_str;
        }

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);
        BLANK.to_string()
    }
}

/// Get process list with network connections
pub async fn get_process_list(include_test_data: bool) -> Result<Vec<ProcessData>> {
    let mut system = System::new_all();
    system.refresh_all();

    let process_count = system.processes().len();
    
    // Pre-allocate with capacity for better performance
    let mut process_list = Vec::with_capacity(process_count * 5); // Multiple entries per process for each connection
    let mut pid_to_name: HashMap<u32, String> = HashMap::with_capacity(process_count);
    
    for (pid, process) in system.processes() {
        pid_to_name.insert(pid.as_u32(), process.name().to_string_lossy().to_string());
    }

    // Get all TCP and UDP connections using Windows API
    let tcp_connections = get_tcp_connections().unwrap_or_default();
    let udp_connections = get_udp_connections().unwrap_or_default();

    // Collect unique executable paths for parallel hashing
    let unique_paths: HashSet<PathBuf> = system.processes()
        .values()
        .filter_map(|p| p.exe().map(|e| e.to_path_buf()))
        .collect();

    // Parallel file hashing using rayon (I/O-bound, benefits from parallelism)
    let hash_cache: HashMap<PathBuf, String> = unique_paths
        .into_par_iter()
        .filter_map(|path| {
            calculate_sha256(&path)
                .ok()
                .map(|hash| (path, hash))
        })
        .collect();
    
    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        
        // Get process attributes
        let pname = process.name().to_string_lossy().to_string();
        let ppath = process.exe()
            .and_then(|p| p.to_str())
            .unwrap_or(BLANK)
            .to_string();
        
        // Use Windows API for more accurate user information
        let puser = get_process_user(pid_u32);
        
        let cmdline = process.cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        
        let parent_pid = process.parent()
            .map(|p| p.as_u32())
            .unwrap_or(0);
        
        // Use Windows API for accurate parent process name
        let ppid_name = get_process_name_by_pid(parent_pid);
        
        // Lookup hash from pre-computed cache (parallel hashing)
        let phash = if ppath != BLANK && !ppath.is_empty() {
            hash_cache
                .get(Path::new(&ppath))
                .cloned()
                .unwrap_or_else(|| BLANK.to_string())
        } else {
            BLANK.to_string()
        };

        // Process TCP connections
        if let Some(connections) = tcp_connections.get(&pid_u32) {
            for (lip, lport, rip, rport) in connections {
                let lip_type_str = get_ip_type(lip);
                let rip_type_str = get_ip_type(rip);
                
                let pdata = ProcessData {
                    pid: pid_u32,
                    pname: pname.clone(),
                    ppid: parent_pid,
                    ppid_name: ppid_name.clone(),
                    ppath: ppath.clone(),
                    puser: puser.clone(),
                    cmdline: cmdline.clone(),
                    phash: phash.clone(),
                    lip: lip.clone(),
                    lport: *lport,
                    rip: rip.clone(),
                    rport: *rport,
                    protocol: INTERNED_TCP.clone(),
                    lip_type: std::sync::Arc::from(lip_type_str.as_str()),
                    rip_type: std::sync::Arc::from(rip_type_str.as_str()),
                    ..Default::default()
                };

                process_list.push(pdata);
            }
        }

        // Process UDP connections
        if let Some(connections) = udp_connections.get(&pid_u32) {
            for (lip, lport, rip, rport) in connections {
                let lip_type_str = get_ip_type(lip);
                let rip_type_str = get_ip_type(rip);
                
                let pdata = ProcessData {
                    pid: pid_u32,
                    pname: pname.clone(),
                    ppid: parent_pid,
                    ppid_name: ppid_name.clone(),
                    ppath: ppath.clone(),
                    puser: puser.clone(),
                    cmdline: cmdline.clone(),
                    phash: phash.clone(),
                    lip: lip.clone(),
                    lport: *lport,
                    rip: rip.clone(),
                    rport: *rport,
                    protocol: INTERNED_UDP.clone(),
                    lip_type: std::sync::Arc::from(lip_type_str.as_str()),
                    rip_type: std::sync::Arc::from(rip_type_str.as_str()),
                    ..Default::default()
                };

                process_list.push(pdata);
            }
        }
    }

    // Add test data if requested
    if include_test_data {
        process_list.extend(get_test_data());
    }

    Ok(process_list)
}

/// Generate synthetic test data for validation
fn get_test_data() -> Vec<ProcessData> {
    vec![
        ProcessData {
            pid: 9999,
            pname: "system.exe".to_string(),
            ppid: 9998,
            ppid_name: "malsploit.exe".to_string(),
            ppath: "c:\\temp\\system.exe".to_string(),
            puser: "NT AUTHORITY\\SYSTEM".to_string(),
            cmdline: "system.exe".to_string(),
            phash: "bad_hash_1".to_string(),
            lip: "192.168.1.100".to_string(),
            lport: 443,
            rip: "1.2.3.4".to_string(),
            rport: 80,
            protocol: INTERNED_TCP.clone(),
            lip_type: std::sync::Arc::from("PRIVATE"),
            rip_type: std::sync::Arc::from("PUBLIC"),
            hunt_flags: vec![
                "System process should not have a path".to_string(),
                "System process should not have a parent process".to_string(),
            ],
            ..Default::default()
        },
        ProcessData {
            pid: 9997,
            pname: "dropper.exe".to_string(),
            ppid: 9996,
            ppid_name: "cmd.exe".to_string(),
            ppath: "c:\\temp\\dropper.exe".to_string(),
            puser: "NT AUTHORITY\\SYSTEM".to_string(),
            cmdline: "dropper.exe --install".to_string(),
            phash: "01b28477d034ad53c65c600e1cbe705efbaf34d512636afef3f20f288e003075".to_string(),
            lip: "192.168.1.100".to_string(),
            lport: 8080,
            rip: "5.6.7.8".to_string(),
            rport: 443,
            protocol: INTERNED_TCP.clone(),
            lip_type: std::sync::Arc::from("PRIVATE"),
            rip_type: std::sync::Arc::from("PUBLIC"),
            hunt_flags: vec![
                "Services process should have WinInit as parent".to_string(),
            ],
            ..Default::default()
        },
        ProcessData {
            pid: 9995,
            pname: "services.exe".to_string(),
            ppid: 9994,
            ppid_name: "wininit.exe".to_string(),
            ppath: "c:\\windows\\system32\\services.exe".to_string(),
            puser: "dropper.exe".to_string(),
            cmdline: "services.exe".to_string(),
            phash: "bad_hash_3".to_string(),
            lip: "192.168.1.100".to_string(),
            lport: 135,
            rip: "9.10.11.12".to_string(),
            rport: 443,
            protocol: INTERNED_TCP.clone(),
            lip_type: std::sync::Arc::from("PRIVATE"),
            rip_type: std::sync::Arc::from("PUBLIC"),
            hunt_flags: vec![
                "Services should be running as the local system user".to_string(),
            ],
            ..Default::default()
        },
    ]
}
