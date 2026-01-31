use crate::types::{ProcessData, BLANK};
use rayon::prelude::*;
use std::borrow::Cow;

// Static flag messages to avoid repeated allocations
mod flags {
    // System process flags
    pub const SYSTEM_HAS_PATH: &str = "System process should not have a path";
    pub const SYSTEM_HAS_PARENT: &str = "System process should not have a parent (PPID should be 0)";
    
    // SMSS flags
    pub const SMSS_WRONG_PATH: &str = "SMSS should run from System32";
    pub const SMSS_WRONG_PARENT: &str = "SMSS parent should be System";
    pub const SMSS_WRONG_USER: &str = "SMSS should run as NT AUTHORITY\\SYSTEM";
    
    // CSRSS flags
    pub const CSRSS_WRONG_PATH: &str = "CSRSS should run from System32";
    pub const CSRSS_WRONG_USER: &str = "CSRSS should run as NT AUTHORITY\\SYSTEM";
    pub const CSRSS_HAS_PARENT: &str = "CSRSS parent should not be visible (smss.exe exits)";
    
    // WinInit flags
    pub const WININIT_WRONG_PATH: &str = "WinInit should run from System32";
    pub const WININIT_WRONG_USER: &str = "WinInit should run as NT AUTHORITY\\SYSTEM";
    pub const WININIT_HAS_PARENT: &str = "WinInit parent should not be visible (smss.exe exits)";
    
    // Services flags
    pub const SERVICES_WRONG_PATH: &str = "Services should run from System32";
    pub const SERVICES_WRONG_PARENT: &str = "Services parent should be WinInit";
    pub const SERVICES_WRONG_USER: &str = "Services should run as NT AUTHORITY\\SYSTEM";
    
    // LSASS flags
    pub const LSASS_WRONG_PATH: &str = "LSASS should run from System32";
    pub const LSASS_WRONG_PARENT: &str = "LSASS parent should be WinInit";
    pub const LSASS_WRONG_USER: &str = "LSASS should run as NT AUTHORITY\\SYSTEM";
    
    // LSAISO flags
    pub const LSAISO_WRONG_PATH: &str = "LSAISO should run from System32";
    pub const LSAISO_WRONG_PARENT: &str = "LSAISO parent should be WinInit";
    pub const LSAISO_WRONG_USER: &str = "LSAISO should run as NT AUTHORITY\\SYSTEM";
    
    // SvcHost flags
    pub const SVCHOST_WRONG_PATH: &str = "SvcHost should run from System32";
    pub const SVCHOST_WRONG_PARENT: &str = "SvcHost parent should be Services";
    pub const SVCHOST_NO_K_PARAM: &str = "SvcHost should have -k parameter in command line";
    
    // Explorer flags
    pub const EXPLORER_WRONG_PATH: &str = "Explorer should run from Windows directory (not System32)";
    pub const EXPLORER_WRONG_USER: &str = "Explorer should not run as SYSTEM";
    
    // WinLogon flags
    pub const WINLOGON_WRONG_PATH: &str = "WinLogon should run from System32";
    pub const WINLOGON_WRONG_USER: &str = "WinLogon should run as NT AUTHORITY\\SYSTEM";
    pub const WINLOGON_HAS_PARENT: &str = "WinLogon parent should not be visible (smss.exe exits)";
    
    // RuntimeBroker flags
    pub const RUNTIMEBROKER_WRONG_PATH: &str = "RuntimeBroker should run from System32";
    pub const RUNTIMEBROKER_WRONG_PARENT: &str = "RuntimeBroker parent should be svchost.exe";
    pub const RUNTIMEBROKER_WRONG_USER: &str = "RuntimeBroker should not run as SYSTEM";
    
    // TaskHostW flags
    pub const TASKHOSTW_WRONG_PATH: &str = "TaskHostW should run from System32";
    pub const TASKHOSTW_WRONG_PARENT: &str = "TaskHostW parent should be svchost.exe";
}

/// Pre-computed lowercase strings for efficient comparison
struct ProcessContext<'a> {
    pdata: &'a ProcessData,
    path_lower: Cow<'a, str>,
    pname_lower: Cow<'a, str>,
    ppid_name_lower: Cow<'a, str>,
}

impl<'a> ProcessContext<'a> {
    #[inline]
    fn new(pdata: &'a ProcessData) -> Self {
        Self {
            pdata,
            path_lower: Cow::Owned(pdata.ppath.to_lowercase()),
            pname_lower: Cow::Owned(pdata.pname.to_lowercase()),
            ppid_name_lower: Cow::Owned(pdata.ppid_name.to_lowercase()),
        }
    }
    
    #[inline]
    fn path_contains(&self, needle: &str) -> bool {
        self.path_lower.contains(needle)
    }
    
    #[inline]
    fn is_system_user(&self) -> bool {
        self.pdata.puser == "NT AUTHORITY\\SYSTEM"
    }
    
    #[inline]
    fn parent_is(&self, name: &str) -> bool {
        self.ppid_name_lower == name
    }
}

/// Run Hunt Evil checks on all processes using parallel iteration
pub fn run_huntevil_checks(process_list: Vec<ProcessData>) -> Vec<ProcessData> {
    process_list
        .into_par_iter()
        .map(|mut pdata| {
            pdata.hunt_flags = check_process(&pdata);
            pdata
        })
        .collect()
}

/// Check a single process for anomalies
fn check_process(pdata: &ProcessData) -> Vec<String> {
    let ctx = ProcessContext::new(pdata);
    
    match ctx.pname_lower.as_ref() {
        "system" => check_system_process(&ctx),
        "smss.exe" => check_smss_process(&ctx),
        "csrss.exe" => check_csrss_process(&ctx),
        "wininit.exe" => check_wininit_process(&ctx),
        "services.exe" => check_services_process(&ctx),
        "lsass.exe" => check_lsass_process(&ctx),
        "lsaiso.exe" => check_lsaiso_process(&ctx),
        "svchost.exe" => check_svchost_process(&ctx),
        "explorer.exe" => check_explorer_process(&ctx),
        "winlogon.exe" => check_winlogon_process(&ctx),
        "runtimebroker.exe" => check_runtimebroker_process(&ctx),
        "taskhostw.exe" => check_taskhostw_process(&ctx),
        _ => Vec::new(),
    }
}

/// Helper to push a static flag - avoids allocation
#[inline]
fn push_flag(flags: &mut Vec<String>, flag: &'static str) {
    flags.push(flag.to_string());
}

/// Check System process (PID 4)
/// - Should have no path (kernel process)
/// - Should have no parent (PPID 0)
fn check_system_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(2);
    
    if ctx.pdata.ppath != BLANK && ctx.pdata.ppath != "-" && !ctx.pdata.ppath.is_empty() {
        push_flag(&mut flags, flags::SYSTEM_HAS_PATH);
    }
    
    if ctx.pdata.ppid != 0 {
        push_flag(&mut flags, flags::SYSTEM_HAS_PARENT);
    }
    
    flags
}

/// Check smss.exe (Session Manager)
/// - Path: %SystemRoot%\System32\smss.exe
/// - Parent: System
/// - User: NT AUTHORITY\SYSTEM
fn check_smss_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::SMSS_WRONG_PATH);
    }
    
    if !ctx.parent_is("system") {
        push_flag(&mut flags, flags::SMSS_WRONG_PARENT);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::SMSS_WRONG_USER);
    }
    
    flags
}

/// Check csrss.exe (Client/Server Runtime Subsystem)
/// - Path: %SystemRoot%\System32\csrss.exe
/// - Parent: Should appear as orphan (smss.exe exits after creating it)
/// - User: NT AUTHORITY\SYSTEM
fn check_csrss_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::CSRSS_WRONG_PATH);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::CSRSS_WRONG_USER);
    }
    
    // Parent should not be visible (smss.exe exits)
    // Allow blank/dash or smss.exe (if captured before exit)
    let parent = ctx.ppid_name_lower.as_ref();
    if !parent.is_empty() && parent != "-" && parent != "smss.exe" {
        push_flag(&mut flags, flags::CSRSS_HAS_PARENT);
    }
    
    flags
}

/// Check wininit.exe (Windows Initialization)
/// - Path: %SystemRoot%\System32\wininit.exe
/// - Parent: Should appear as orphan (smss.exe exits after creating it)
/// - User: NT AUTHORITY\SYSTEM
/// - Instances: One
fn check_wininit_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::WININIT_WRONG_PATH);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::WININIT_WRONG_USER);
    }
    
    // Parent should not be visible (smss.exe exits)
    let parent = ctx.ppid_name_lower.as_ref();
    if !parent.is_empty() && parent != "-" && parent != "smss.exe" {
        push_flag(&mut flags, flags::WININIT_HAS_PARENT);
    }
    
    flags
}

/// Check services.exe (Service Control Manager)
/// - Path: %SystemRoot%\System32\services.exe
/// - Parent: wininit.exe
/// - User: NT AUTHORITY\SYSTEM
/// - Instances: One
fn check_services_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::SERVICES_WRONG_PATH);
    }
    
    if !ctx.parent_is("wininit.exe") {
        push_flag(&mut flags, flags::SERVICES_WRONG_PARENT);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::SERVICES_WRONG_USER);
    }
    
    flags
}

/// Check lsass.exe (Local Security Authority Subsystem Service)
/// - Path: %SystemRoot%\System32\lsass.exe
/// - Parent: wininit.exe
/// - User: NT AUTHORITY\SYSTEM
/// - Instances: One (CRITICAL - multiple instances is highly suspicious)
fn check_lsass_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::LSASS_WRONG_PATH);
    }
    
    if !ctx.parent_is("wininit.exe") {
        push_flag(&mut flags, flags::LSASS_WRONG_PARENT);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::LSASS_WRONG_USER);
    }
    
    flags
}

/// Check lsaiso.exe (LSA Isolated - Credential Guard)
/// - Path: %SystemRoot%\System32\lsaiso.exe
/// - Parent: wininit.exe
/// - User: NT AUTHORITY\SYSTEM
/// - Instances: Zero or One (only present with Credential Guard enabled)
fn check_lsaiso_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::LSAISO_WRONG_PATH);
    }
    
    if !ctx.parent_is("wininit.exe") {
        push_flag(&mut flags, flags::LSAISO_WRONG_PARENT);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::LSAISO_WRONG_USER);
    }
    
    flags
}

/// Check svchost.exe (Service Host)
/// - Path: %SystemRoot%\System32\svchost.exe
/// - Parent: services.exe
/// - User: Varies (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, or user)
/// - Command line should contain -k parameter
fn check_svchost_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::SVCHOST_WRONG_PATH);
    }
    
    if !ctx.parent_is("services.exe") {
        push_flag(&mut flags, flags::SVCHOST_WRONG_PARENT);
    }
    
    // Check for -k parameter in command line
    let cmdline_lower = ctx.pdata.cmdline.to_lowercase();
    if !cmdline_lower.contains("-k") && !cmdline_lower.contains("/k") {
        push_flag(&mut flags, flags::SVCHOST_NO_K_PARAM);
    }
    
    flags
}

/// Check explorer.exe (Windows Explorer)
/// - Path: %SystemRoot%\explorer.exe (NOT System32!)
/// - Parent: userinit.exe (which exits, so appears as orphan)
/// - User: Logged-on user (should NOT be SYSTEM)
fn check_explorer_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(2);
    
    // Explorer should be in Windows directory, NOT System32
    if !ctx.path_contains("\\windows\\") || ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::EXPLORER_WRONG_PATH);
    }
    
    // Explorer should not run as SYSTEM
    if ctx.is_system_user() {
        push_flag(&mut flags, flags::EXPLORER_WRONG_USER);
    }
    
    flags
}

/// Check winlogon.exe (Windows Logon)
/// - Path: %SystemRoot%\System32\winlogon.exe
/// - Parent: Should appear as orphan (smss.exe exits)
/// - User: NT AUTHORITY\SYSTEM
fn check_winlogon_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::WINLOGON_WRONG_PATH);
    }
    
    if !ctx.is_system_user() {
        push_flag(&mut flags, flags::WINLOGON_WRONG_USER);
    }
    
    // Parent should not be visible (smss.exe exits)
    let parent = ctx.ppid_name_lower.as_ref();
    if !parent.is_empty() && parent != "-" && parent != "smss.exe" {
        push_flag(&mut flags, flags::WINLOGON_HAS_PARENT);
    }
    
    flags
}

/// Check RuntimeBroker.exe (Runtime Broker for UWP apps)
/// - Path: %SystemRoot%\System32\RuntimeBroker.exe
/// - Parent: svchost.exe
/// - User: Logged-on user (should NOT be SYSTEM)
fn check_runtimebroker_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(3);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::RUNTIMEBROKER_WRONG_PATH);
    }
    
    if !ctx.parent_is("svchost.exe") {
        push_flag(&mut flags, flags::RUNTIMEBROKER_WRONG_PARENT);
    }
    
    // RuntimeBroker typically runs as logged-on user, not SYSTEM
    if ctx.is_system_user() {
        push_flag(&mut flags, flags::RUNTIMEBROKER_WRONG_USER);
    }
    
    flags
}

/// Check taskhostw.exe (Task Host Window)
/// - Path: %SystemRoot%\System32\taskhostw.exe
/// - Parent: svchost.exe
/// - User: Varies (can be user or service accounts)
fn check_taskhostw_process(ctx: &ProcessContext) -> Vec<String> {
    let mut flags = Vec::with_capacity(2);
    
    if !ctx.path_contains("\\system32\\") {
        push_flag(&mut flags, flags::TASKHOSTW_WRONG_PATH);
    }
    
    if !ctx.parent_is("svchost.exe") {
        push_flag(&mut flags, flags::TASKHOSTW_WRONG_PARENT);
    }
    
    flags
}
