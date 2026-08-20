// polyglot/rust/emulator_avd_spoof_detector.rs
//! Android AVD (Android Virtual Device) Spoof Detection Module
//! 
//! Detects whether a running process is executing inside or spoofing an
//! Android emulator environment using multi-layered analysis: file artifacts,
//! system properties, process signatures, memory hints, and network patterns.
//! 
//! Returns a scored verdict with detailed evidence for RASP-style posture checking.

use std::process::{Command, Stdio};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Detection result containing the confidence score and categorized evidence.
#[derive(Debug, Clone)]
pub struct SpoofResult {
    pub is_emulator: bool,
    pub confidence_score: u8, // 0-100
    pub categories_detected: Vec<String>,
    pub raw_evidence: Vec<(String, String)>, // (category, detail)
}

impl SpoofResult {
    /// Creates a new result with the given data.
    pub fn new(
        is_emulator: bool,
        confidence_score: u8,
        categories_detected: Vec<String>,
        raw_evidence: Vec<(String, String)>,
    ) -> Self {
        Self {
            is_emulator,
            confidence_score,
            categories_detected,
            raw_evidence,
        }
    }

    /// Returns a human-readable verdict string.
    pub fn verdict(&self) -> &str {
        if self.confidence_score >= 80 {
            "HIGH: Likely running in emulator or AVD spoof"
        } else if self.confidence_score >= 50 {
            "MEDIUM: Some emulator indicators present"
        } else if self.confidence_score > 0 {
            "LOW: Minor emulator hints detected"
        } else {
            "CLEAN: No significant AVD artifacts found"
        }
    }

    /// Returns a JSON-serializable representation.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Core detector implementation with all sub-checks.
pub struct EmulatorSpoofDetector;

impl EmulatorSpoofDetector {
    /// Runs the complete AVD spoof detection suite.
    pub fn detect() -> SpoofResult {
        let mut evidence: Vec<(String, String)> = Vec::new();
        let mut categories_detected: Vec<String> = Vec::new();
        
        // Run all sub-checks and collect results
        if Self::check_file_artifacts(&mut evidence) {
            categories_detected.push("FILE_ARTIFACTS".to_string());
        }
        
        if Self::check_system_properties(&mut evidence) {
            categories_detected.push("SYSTEM_PROPERTIES".to_string());
        }
        
        if Self::check_process_signatures(&mut evidence) {
            categories_detected.push("PROCESS_SIGNATURES".to_string());
        }
        
        if Self::check_memory_procfs(&mut evidence) {
            categories_detected.push("MEMORY_PROCFS".to_string());
        }
        
        if Self::check_network_patterns(&mut evidence) {
            categories_detected.push("NETWORK_PATTERNS".to_string());
        }
        
        // Calculate confidence score based on number and strength of indicators
        let max_categories = 5;
        let category_bonus: u8 = (categories_detected.len() as f32 / max_categories as f32) * 40.0;
        
        let evidence_strength = Self::calculate_evidence_strength(&evidence);
        let score = (category_bonus + evidence_strength).clamp(0, 100) as u8;
        
        SpoofResult::new(
            score >= 50,
            score,
            categories_detected,
            evidence,
        )
    }

    /// Check for known AVD file artifacts.
    fn check_file_artifacts(evidence: &mut Vec<(String, String)>) -> bool {
        let mut found = false;
        
        // Common AVD temporary files
        let avd_paths = [
            "/data/local/tmp/android.sndservice",
            "/data/local/tmp/avd.tmp",
            "/data/data/com.google.android.gms/.../emulator",
            "/system/etc/permissions/com.android.vending.xml",
        ];
        
        for path in &avd_paths {
            if let Ok(content) = fs::read_to_string(path) {
                evidence.push(("FILE_CONTENT".to_string(), format!("Found content in: {}", path)));
                found = true;
            } else if fs::metadata(path).is_ok() {
                evidence.push(("FILE_EXISTS".to_string(), format!("File exists: {}", path)));
                found = true;
            }
        }
        
        // Check for emulator-specific permissions
        let perm_path = "/system/etc/permissions/com.android.vending.xml";
        if let Ok(perm) = fs::read_to_string(perm_path) {
            if perm.contains("emulator") || perm.contains("avd") {
                evidence.push(("PERMISSION_HINT".to_string(), "AVD-specific permissions found"));
                found = true;
            }
        }
        
        found
    }

    /// Check system properties for emulator signatures.
    fn check_system_properties(evidence: &mut Vec<(String, String)>) -> bool {
        let mut found = false;
        
        // Get ro.product.model - emulators often have distinctive models
        if let Ok(model) = Self::get_prop("ro.product.model") {
            let model_lower = model.to_lowercase();
            
            if model_lower.contains("sdk built for") || 
               model_lower.contains("android sdk") ||
               model_lower.contains("goldfish") ||
               model_lower.contains("grouper") ||
               model_lower.contains("shamu") ||
               model_lower.contains("hammerhead") {
                evidence.push(("PRODUCT_MODEL".to_string(), format!("Suspicious model: {}", model)));
                found = true;
            }
        }
        
        // Check ro.build.fingerprint for emulator strings
        if let Ok(fingerprint) = Self::get_prop("ro.build.fingerprint") {
            let fp_lower = fingerprint.to_lowercase();
            
            if fp_lower.contains("sdk built for") || 
               fp_lower.contains("android sdk") ||
               fp_lower.contains("emulator") {
                evidence.push(("BUILD_FINGERPRINT".to_string(), format!("Suspicious fingerprint: {}", fingerprint)));
                found = true;
            }
        }
        
        // Check ro.hardware - goldfish is a strong indicator
        if let Ok(hardware) = Self::get_prop("ro.hardware") {
            if hardware == "goldfish" || 
               hardware == "grouper" || 
               hardware == "shamu" ||
               hardware == "hammerhead" {
                evidence.push(("HARDWARE".to_string(), format!("Emulator-like hardware: {}", hardware)));
                found = true;
            }
        }
        
        // Check ro.bootloader - emulators often have generic bootloaders
        if let Ok(bootloader) = Self::get_prop("ro.bootloader") {
            if bootloader.is_empty() || 
               bootloader == "unknown" ||
               bootloader.contains("sdk") {
                evidence.push(("BOOTLOADER".to_string(), format!("Generic bootloader: '{}'", bootloader)));
                found = true;
            }
        }
        
        found
    }

    /// Check process signatures and running processes.
    fn check_process_signatures(evidence: &mut Vec<(String, String)>) -> bool {
        let mut found = false;
        
        // Check for emulator processes in /proc
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                
                // Skip non-numeric process IDs
                let pid_str: String = match path.file_name().and_then(|n| n.to_str()) {
                    Some(s) if s.parse::<u32>().is_ok() => s.to_string(),
                    _ => continue,
                };
                
                // Check cmdline for emulator processes
                if let Ok(cmdline) = fs::read_to_string(path.join("cmdline")) {
                    let cmdline_lower = cmdline.to_lowercase();
                    
                    if cmdline_lower.contains("emulator") || 
                       cmdline_lower.contains("qemu-system-arm") ||
                       cmdline_lower.contains("adb") && cmdline_lower.contains("-s") {
                        evidence.push(("CMDLINE".to_string(), format!("Emulator process detected: {}", cmdline)));
                        found = true;
                    }
                }
                
                // Check status for emulator hints
                if let Ok(status) = fs::read_to_string(path.join("status")) {
                    if status.contains("Emulator:") || 
                       status.contains("qemu") ||
                       status.contains("android-sdk") {
                        evidence.push(("STATUS".to_string(), "Emulator hint found in /proc/status"));
                        found = true;
                    }
                }
            }
        }
        
        // Check for running emulator processes via ps (fallback)
        if let Ok(output) = Command::new("ps").arg("-A").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            if stdout.contains("emulator") || 
               stdout.contains("qemu-system-arm") ||
               stdout.contains("Android SDK built for") {
                evidence.push(("PS_OUTPUT".to_string(), "Running emulator processes detected"));
                found = true;
            }
        }
        
        found
    }

    /// Check memory and procfs hints.
    fn check_memory_procfs(evidence: &mut Vec<(String, String)>) -> bool {
        let mut found = false;
        
        // Check /proc/self/status for emulator-specific flags
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            // Look for specific hints in status
            if status.contains("Emulator:") || 
               status.contains("qemu") ||
               status.contains("android-sdk") {
                evidence.push(("PROC_SELF_STATUS".to_string(), "Emulator flag found"));
                found = true;
            }
            
            // Check for unusual memory layout hints (less common but possible)
            if let Ok(mem_info) = fs::read_to_string("/proc/meminfo") {
                // Emulators sometimes have different memory allocation patterns
                if mem_info.contains("Android SDK") || 
                   mem_info.contains("Emulator Memory") {
                    evidence.push(("MEMINFO".to_string(), "SDK-specific memory hints"));
                    found = true;
                }
            }
        }
        
        // Check for /data/local/tmp artifacts (common AVD temp location)
        if let Ok(tmp_dir) = fs::read_dir("/data/local/tmp") {
            for entry in tmp_dir.flatten() {
                let name = match entry.file_name().to_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                
                // Common AVD temp files
                if name.contains("android.sndservice") || 
                   name.contains("avd.tmp") ||
                   name.contains("sdk") {
                    evidence.push(("TMP_FILE".to_string(), format!("AVD temp file: {}", name)));
                    found = true;
                }
            }
        }
        
        found
    }

    /// Check network patterns for AVD-specific behavior.
    fn check_network_patterns(evidence: &mut Vec<(String, String)>) -> bool {
        let mut found = false;
        
        // Check for Google Play Services emulator connections
        if let Ok(output) = Command::new("netstat").arg("-tlnp").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // AVD apps often connect to specific Google services with different patterns
            if stdout.contains("google.com") && 
               stdout.contains(":443") &&
               !stdout.contains("com.google.android.gms") {
                evidence.push(("NETWORK".to_string(), "Google service connection pattern detected"));
                found = true;
            }
        }
        
        // Check for user-agent headers from AVD apps (via curl if available)
        if let Ok(curl_output) = Command::new("curl").arg("-sI").arg("http://www.google.com").output() {
            let header = String::from_utf8_lossy(&curl_output.stdout);
            
            // Look for SDK-specific user-agents
            if header.contains("Android SDK") || 
               header.contains("Emulator") ||
               header.contains("AVD") {
                evidence.push(("USER_AGENT".to_string(), "SDK-specific user-agent detected"));
                found = true;
            }
        }
        
        found
    }

    /// Calculate overall evidence strength (0-40) based on detail richness.
    fn calculate_evidence_strength(evidence: &[(String, String)]) -> u8 {
        let mut strength = 0u8;
        
        // Base score from number of evidence items
        strength += (evidence.len() as f32 / 10.0) * 5.0;
        
        // Bonus for specific high-confidence indicators
        if evidence.iter().any(|(cat, _)| cat == "PRODUCT_MODEL" || 
                                          cat == "HARDWARE") {
            strength += 8.0;
        }
        
        if evidence.iter().any(|(cat, _)| cat == "CMDLINE" || 
                                          cat == "STATUS") {
            strength += 7.0;
        }
        
        // Bonus for file artifacts
        if evidence.iter().any(|(cat, _)| cat == "FILE_CONTENT" || 
                                          cat == "PERMISSION_HINT") {
            strength += 5.0;
        }
        
        (strength).min(40) as u8
    }

    /// Helper to read a system property safely.
    fn get_prop(name: &str) -> Result<String, std::io::Error> {
        Command::new("getprop")
            .arg(name)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    /// Helper to read a system property via /proc (fallback for older Android).
    fn get_prop_fallback(name: &str) -> Result<String, std::io::Error> {
        let path = format!("/sys/devices/system/cpu/{}", name);
        
        // Try different fallback paths for common properties
        let fallback_paths = [
            format!("/proc/self/dropbox/{}", name),
            format!("/data/local/tmp/{}", name),
        ];
        
        for p in &fallback_paths {
            if let Ok(content) = fs::read_to_string(p) {
                return Ok(content.trim().to_string());
            }
        }
        
        // Last resort: try reading from /proc directly
        if let Ok(cmdline) = Self::get_prop(name) {
            return Ok(cmdline);
        }
        
        Err(std::io::Error::new(0, "Fallback failed"))
    }

    /// Returns a detailed debug string for logging.
    pub fn debug_string(&self) -> String {
        let mut buf = format!(
            "AVD Spoof Detection Result:\n  Is Emulator: {}\n  Confidence: {}%\n  Categories: {:?}\n",
            self.is_emulator,
            self.confidence_score,
            self.categories_detected
        );
        
        for (cat, detail) in &self.raw_evidence {
            buf.push_str(&format!("    [{},]: {}\n", cat, detail));
        }
        
        buf
    }
}

/// Convenience function for quick checks.
pub fn quick_check() -> SpoofResult {
    EmulatorSpoofDetector::detect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_verdict_high_confidence() {
        let result = SpoofResult::new(true, 90, vec!["SYSTEM_PROPERTIES".to_string()], 
            vec![("PRODUCT_MODEL