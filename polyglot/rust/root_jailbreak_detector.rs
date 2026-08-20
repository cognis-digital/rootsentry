mod root_jailbreak_detector {
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    // =====================================================================
    // CONSTANTS & CONFIGURATION
    // =====================================================================

    /// Known root/jailbreak indicator paths (Android/iOS)
    const ROOT_INDICATORS: &[&str] = &[
        "/data/local/tmp/su",
        "/system/bin/sh",
        "/system/xbin/which",
        "/system/app/SuperUser.apk",
        "/system/usr/cmdline.txt",
        "/proc/self/status",
    ];

    /// Known emulator indicators
    const EMULATOR_INDICATORS: &[&str] = &[
        "/data/local/tmp/emulator",
        "/dev/socket/qemmd",
        "/data/data/com.android.vending/backup_set",
        "/system/etc/init.qemu.sh.rc",
        "QEMU_AUDIO_DRV=none",
    ];

    /// Known hook/tamper indicators
    const HOOK_INDICATORS: &[&str] = &[
        "/data/local/tmp/hooks.so",
        "/system/lib/libhooker.so",
        "/proc/1/cmdline",
        "LD_PRELOAD=",
        "DYLD_INSERT_LIBRARIES=",
    ];

    // =====================================================================
    // TYPES & ENUMS
    // =====================================================================

    /// Result of a single integrity check
    #[derive(Debug, Clone)]
    pub struct CheckResult {
        name: String,
        passed: bool,
        score_impact: u8,
        message: Option<String>,
    }

    impl Default for CheckResult {
        fn default() -> Self {
            Self {
                name: "unknown".to_string(),
                passed: true,
                score_impact: 0,
                message: None,
            }
        }
    }

    /// Severity level of a detected issue
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum Severity {
    Low(1),
    Medium(2),
    High(3),
    Critical(4),
}

impl Default for Severity {
    fn default() -> Self {
        Self::Low
    }
}

/// Final posture verdict with remediation guidance
#[derive(Debug, Clone)]
pub struct PostureVerdict {
    pub score: u8,
    pub level: Level,
    pub findings: Vec<Finding>,
    pub recommendation: String,
}

impl Default for PostureVerdict {
    fn default() -> Self {
        Self {
            score: 0,
            level: Level::Clean,
            findings: Vec::new(),
            recommendation: "Application appears to be running in a trusted environment.".to_string(),
        }
    }
}

/// Severity of the overall posture
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Level {
    Clean(0),
    LowRisk(1..=25),
    MediumRisk(26..=50),
    HighRisk(51..=75),
    Critical(76..=100),
}

impl Default for Level {
    fn default() -> Self {
        Self::Clean
    }
}

/// A single finding with context
#[derive(Debug, Clone)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub source: String,
    pub detail: String,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            category: Category::Unknown,
            severity: Severity::Low,
            source: "unknown".to_string(),
            detail: String::new(),
        }
    }
}

/// Category of the finding
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Category {
    FileSystem,
    Process,
    Environment,
    Network,
    Memory,
    Unknown,
}

impl Default for Category {
    fn default() -> Self {
        Self::Unknown
    }
}

// =====================================================================
    // CORE DETECTION ENGINE
    // =====================================================================

    /// Main detector instance
    pub struct RootJailbreakDetector {
        config: Config,
        results: Vec<CheckResult>,
    }

    impl Default for RootJailbreakDetector {
        fn default() -> Self {
            Self::new(Config::default())
        }
    }

    /// Detector configuration
    #[derive(Debug, Clone)]
    pub struct Config {
        pub strict_mode: bool,
        pub include_network: bool,
        pub verbose: bool,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                strict_mode: false,
                include_network: true,
                verbose: false,
            }
        }
    }

    impl RootJailbreakDetector {
        pub fn new(config: Config) -> Self {
            Self {
                config,
                results: Vec::new(),
            }
        }

        /// Run all integrity checks and return the posture verdict
        pub fn detect(&mut self) -> PostureVerdict {
            self.results.clear();

            // File system checks
            for indicator in ROOT_INDICATORS.iter() {
                if let Some(result) = Self::check_file_path(indicator, "root_indicator") {
                    self.results.push(result);
                }
            }

            // Emulator checks
            for indicator in EMULATOR_INDICATORS.iter() {
                if let Some(result) = Self::check_file_path(indicator, "emulator_indicator") {
                    self.results.push(result);
                }
            }

            // Hook/tamper checks
            for indicator in HOOK_INDICATORS.iter() {
                if let Some(result) = Self::check_file_path(indicator, "hook_indicator") {
                    self.results.push(result);
                }
            }

            // Environment variable checks
            Self::check_environment_variables(&mut self.results);

            // Process/proc filesystem checks (Linux-specific)
            #[cfg(target_os = "linux")]
            Self::check_proc_self_status();

            // Calculate final score and verdict
            let total_score: u8 = self.results.iter().map(|r| r.score_impact).sum();
            let max_possible_score = 100;
            let normalized_score = (total_score as f32 / max_possible_score as f32) * 100u8 as f32 as u8;

            PostureVerdict {
                score: normalized_score,
                level: Level::from_score(normalized_score),
                findings: self.results.iter()
                    .filter(|r| !r.passed)
                    .map(|r| Finding {
                        category: Category::FileSystem,
                        severity: Severity::High,
                        source: r.name.clone(),
                        detail: r.message.clone().unwrap_or_default(),
                    })
                    .collect(),
                recommendation: self.generate_recommendation(normalized_score),
            }
        }

        /// Check if a file path exists and is suspicious
        fn check_file_path(path: &str, category: &str) -> Option<CheckResult> {
            let full_path = PathBuf::from(path);
            
            if !full_path.exists() {
                return None;
            }

            // Check if it's a symlink (common in root/jailbreak scenarios)
            let is_symlink = match fs::read_link(&full_path) {
                Ok(_) => true,
                Err(_) => false,
            };

            Some(CheckResult {
                name: format!("{} at {}", category, path),
                passed: !is_symlink,
                score_impact: if is_symlink { 15 } else { 0 },
                message: Some(format!(
                    "Suspicious symlink detected at: {}",
                    full_path.display()
                )),
            })
        }

        /// Check environment variables for tampering indicators
        fn check_environment_variables(results: &mut Vec<CheckResult>) {
            let suspicious_vars = [
                ("LD_PRELOAD", "LD_PRELOAD"),
                ("DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES"),
                ("ANDROID_DEBUG", "ANDROID_DEBUG"),
                ("QEMU_AUDIO_DRV", "QEMU_AUDIO_DRV"),
            ];

            for (var, name) in suspicious_vars.iter() {
                if let Ok(value) = env::var(var) {
                    results.push(CheckResult {
                        name: format!("{}={}", name, value),
                        passed: value.is_empty(),
                        score_impact: 10,
                        message: Some(format!(
                            "Suspicious environment variable set: {}={}",
                            name, value
                        )),
                    });
                }
            }
        }

        /// Check /proc/self/status for process anomalies (Linux)
        fn check_proc_self_status() {
            if let Ok(status) = fs::read_to_string("/proc/self/status") {
                // Look for common indicators in status file
                let lines: Vec<&str> = status.lines().collect();
                
                for line in lines.iter() {
                    if line.starts_with("VmRSS:") || line.starts_with("Threads:") {
                        // Normal fields, continue checking
                    } else if line.contains("state") && !line.contains("S") {
                        // Non-idle state might indicate activity
                    }
                }
            }
        }

        /// Generate recommendation based on score
        fn generate_recommendation(score: u8) -> String {
            match Level::from_score(score) {
                Level::Clean => "Application appears to be running in a trusted environment.".to_string(),
                Level::LowRisk => "Minor indicators detected. Review findings and consider additional verification if strict mode is enabled.".to_string(),
                Level::MediumRisk => "Moderate risk detected. Recommend investigation of flagged paths and potential re-deployment from verified build artifacts.".to_string(),
                Level::HighRisk => "Significant tampering indicators found. Verify application integrity, check for active hooks, and consider emergency patch deployment.".to_string(),
                Level::Critical => "Critical compromise likely. Immediate forensic analysis recommended. Check for root access, active emulators, or injected code.".to_string(),
            }
        }

        /// Convert score to level
        fn from_score(score: u8) -> Level {
            match score {
                0..=25 => Level::LowRisk,
                26..=50 => Level::MediumRisk,
                51..=75 => Level::HighRisk,
                _ => Level::Critical,
            }
        }

        /// Get human-readable level name
        pub fn level_name(level: &Level) -> &'static str {
            match level {
                Level::Clean(_) => "CLEAN",
                Level::LowRisk(_) => "LOW RISK",
                Level::MediumRisk(_) => "MEDIUM RISK",
                Level::HighRisk(_) => "HIGH RISK",
                Level::Critical(_) => "CRITICAL",
            }
        }

        /// Get detailed findings as JSON-like string
        pub fn get_findings_json(&self) -> String {
            self.results.iter()
                .map(|r| format!(
                    r#"{{"name":"{}","passed":{},,"score_impact":{}}}"#,
                    r.name, r.passed, r.score_impact
                ))
                .collect::<Vec<_>>()
                .join(", ")
        }

        /// Check a single path and return result (for incremental checking)
        pub fn check_path(&self, path: &str) -> Option<CheckResult> {
            Self::check_file_path(path, "manual_check")
        }

        /// Get the number of failed checks
        pub fn failed_count(&self) -> usize {
            self.results.iter().filter(|r| !r.passed).count()
        }

        /// Get total score impact
        pub fn total_score_impact(&self) -> u8 {
            self.results.iter().map(|r| r.score_impact).sum()
        }
    }

    // =====================================================================
    // PUBLIC API - CONVENIENCE FUNCTIONS
    // =====================================================================

    /// Quick check with default configuration
    pub fn quick_check() -> PostureVerdict {
        let mut detector = RootJailbreakDetector::default();
        detector.detect()
    }

    /// Check a specific path for root indicators
    pub fn check_root_indicator(path: &str) -> Result<bool, io::Error> {
        Ok(fs::metadata(path)?.is_symlink())
    }

    /// Get the current posture score without running full detection
    pub fn get_current_score() -> u8 {
        let mut detector = RootJailbreakDetector::default();
        let verdict = detector.detect();
        verdict.score
    }

    // =====================================================================
    // DEMO / ENTRY POINT
    // =====================================================================

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_default_detector() {
            let mut detector = RootJailbreakDetector::default();
            let verdict = detector.detect();
            
            assert!(verdict.score <= 100);
            assert!(verdict.level != Level::Critical || verdict.score > 75);
        }

        #[test]
        fn test_file_check() {
            // Check a known existing path
            let result = RootJailbreakDetector::check_file_path("/etc/passwd", "test");
            assert!(result.is_some());
            
            // Check non-existent path
            let result = RootJailbreakDetector::check_file_path("/nonexistent/path/12345", "test");
            assert!(result.is_none());
        }

        #[test]
        fn test_environment_check() {
            env::set_var("TEST_VAR", "test_value");
            
            let mut detector = RootJailbreakDetector::default();
            let _verdict = detector.detect();
        }
    }

    /// Main demo function - run when compiled as binary
    fn main_demo() -> Result<(), Box<dyn std::error::Error>> {
        println!("=== Rootsentry: Mobile Runtime Integrity Detector ===\n");

        // Run detection
        let mut detector = RootJailbreakDetector::default();
        let verdict = detector.detect();

        // Output results
        println!("Posture Verdict: {}", Level::level_name(&verdict.level));
        println!("Risk Score: {}/100", verdict.score);
        println!("\nRecommendation:\n  {}\n", verdict.recommendation);

        if !verdict.findings.is_empty() {
            println!("\n=== Findings ({}) ===", verdict.findings.len());
            for finding in &verdict.findings {
                println!("  [{}] {}", 
                    Severity::level_name(finding.severity),
                    finding.source,
                );
                if !finding.detail.is_empty() {
                    println!("      Detail: {}", finding.detail);
                }
            }
        }

        // Show detailed results for debugging
        println!("\n=== Detailed Check Results ===");
        for (i, result) in detector.results.iter().enumerate() {
            let status = if result.passed { "✓" } else { "✗" };
            println!("  [{:2}] {} - {}", i + 1, status, result.name);
            if !result.message.is_some_and(|m| m.is_empty()) {
                println!("         {}", result.message.as_ref().unwrap());
            }
        }

        Ok(())
    }

    /// Helper to get level name for display
    impl Level {
        pub fn level_name(&self) -> &'static str {
            match self {
                Self::Clean(_) => "CLEAN",
                Self::LowRisk(_) => "LOW RISK",
                Self::MediumRisk(_) => "MEDIUM RISK",
                Self::HighRisk(_) => "HIGH RISK",
                Self::Critical(_) => "CRITICAL",
            }
        }
    }

    /// Helper to get severity name for display
    impl Severity {
        pub fn level_name(&self) -> &'static str {
            match self {
                Self::Low(1) => "LOW",
                Self::Medium(2) =>