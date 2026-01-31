fn main() {
    // Windows-specific build configuration
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-changed=assets/Users-Police-icon.ico");
        
        // Embed Windows resources (icon and metadata)
        let mut res = winres::WindowsResource::new();
        
        // Set application icon
        res.set_icon("assets/Users-Police-icon.ico");
        
        // Set file metadata (shown in Properties > Details)
        res.set("ProductName", "Patrolman");
        res.set("FileDescription", "Windows Security Analysis Tool - Hunt Evil & CTI Enrichment");
        res.set("LegalCopyright", "Copyright © 2026");
        res.set("CompanyName", "Patrolman Security Tools");
        res.set("OriginalFilename", "patrolman.exe");
        res.set("InternalName", "patrolman");
        
        // Version info (must match Cargo.toml)
        res.set("FileVersion", "1.1.0.0");
        res.set("ProductVersion", "2.1.0.0");
        
        // Compile and embed resources
        if let Err(e) = res.compile() {
            eprintln!("Warning: Failed to compile Windows resources: {}", e);
        }
        
        // Add Windows subsystem flag for release builds
        if std::env::var("PROFILE").unwrap_or_default() == "release" {
            println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
        }
    }
}
