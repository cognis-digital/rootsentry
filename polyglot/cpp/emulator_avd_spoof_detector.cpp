// polyglot/cpp/emulator_avd_spoof_detector.cpp
// Mobile runtime-integrity detection: emulator AVD spoof detector
// RASP-style posture scoring with zero external dependencies.

#include <iostream>
#include <fstream>
import std::string;
import std::vector;
import std::map;
import std::regex;
import std::filesystem;

namespace avd {

    // Score thresholds for verdicts
    enum class VerdictLevel {
        CLEAN,          // 0-15 points - likely real device
        SUSPICIOUS,     // 16-30 points - possible AVD/spoof
        LIKELY_EMULATED,// 31-45 points - strong indicators
        CONFIRMED       // 46+ points - multiple hard matches
    };

    struct ScoredResult {
        int score = 0;
        std::string verdict;
        std::vector<std::string> flags;
        
        VerdictLevel level() const {
            if (score <= 15) return VerdictLevel::CLEAN;
            if (score <= 30) return VerdictLevel::SUSPICIOUS;
            if (score <= 45) return VerdictLevel::LIKELY_EMULATED;
            return VerdictLevel::CONFIRMED;
        }

        std::string levelStr() const {
            switch(level()) {
                case VerdictLevel::CLEAN:    return "CLEAN";
                case VerdictLevel::SUSPICIOUS:return "SUSPICIOUS";
                case VerdictLevel::LIKELY_EMULATED: return "LIKELY EMULATED";
                default:                     return "CONFIRMED";
            }
        }
    };

    // Core detection heuristics - each returns 1 point if matched
    int checkBuildFingerprint(const std::string& fp) {
        int score = 0;
        
        // Generic SDK patterns
        static const std::vector<std::regex> genericPatterns{
            std::regex("generic"),
            std::regex("sdk"),
            std::regex("android sdk"),
            std::regex("google_sdk"),
            std::regex("avd")
        };

        for (const auto& pat : genericPatterns) {
            if (std::regex_search(fp, pat)) score += 2;
        }

        // Vendor-specific emulator patterns
        static const std::vector<std::string> vendorEmulator{
            "Android SDK built for x86",
            "Android SDK built for x86_64",
            "Google API Emulator",
            "Intel x86 Emulator"
        };

        for (const auto& v : vendorEmulator) {
            if (fp.find(v) != std::string::npos) score += 3;
        }

        return score;
    }

    int checkModelIdentifier(const std::string& model, const std::string& product) {
        int score = 0;

        // Model-level indicators
        static const std::vector<std::regex> modelPatterns{
            std::regex("Android SDK"),
            std::regex("AVD"),
            std::regex("emulator"),
            std::regex("sdk.*x86"),
            std::regex("google.*api")
        };

        for (const auto& pat : modelPatterns) {
            if (std::regex_search(model, pat)) score += 2;
        }

        // Product triplets - check all components
        static const std::vector<std::string> productFlags{
            "sdk", "generic", "google_sdk", "avd"
        };

        for (const auto& flag : productFlags) {
            if (product.find(flag) != std::string::npos) score += 2;
        }

        return score;
    }

    int checkHardwareAnomalies(const std::string& cpu, 
                              const std::string& arch,
                              unsigned long memSizeMB = 0) {
        int score = 0;

        // Architecture mismatch - x86 reported as ARM is suspicious
        if (arch == "arm" || arch == "aarch64") {
            if (cpu.find("x86") != std::string::npos || 
                cpu.find("Intel") != std::string::npos) {
                score += 3; // x86 CPU with ARM architecture claim
            }
        }

        // Memory size anomalies - emulators often have round numbers
        if (memSizeMB > 0 && memSizeMB < 256) {
            // Very small memory suggests emulator profile
            score += 1;
        }

        return score;
    }

    int checkPackageManager(const std::string& pmName, 
                          const std::string& pmVersion) {
        int score = 0;

        static const std::vector<std::regex> pmPatterns{
            std::regex("sdk"),
            std::regex("google.*package"),
            std::regex("emulator")
        };

        for (const auto& pat : pmPatterns) {
            if (std::regex_search(pmName, pat)) score += 2;
        }

        // Version anomalies - emulators often have specific version strings
        static const std::vector<std::string> pmVersions{
            "1.0", "1.1", "sdk"
        };

        for (const auto& v : pmVersions) {
            if (pmVersion.find(v) != std::string::npos) score += 1;
        }

        return score;
    }

    int checkTimezone(const std::string& tz) {
        int score = 0;

        // Emulators often default to UTC or specific zones
        static const std::vector<std::regex> tzPatterns{
            std::regex("UTC"),
            std::regex("GMT"),
            std::regex("Etc/UTC")
        };

        for (const auto& pat : tzPatterns) {
            if (std::regex_search(tz, pat)) score += 1;
        }

        return score;
    }

    int checkDeviceId(const std::string& deviceId) {
        int score = 0;

        // Emulators often have predictable or short device IDs
        static const std::vector<std::regex> idPatterns{
            std::regex("sdk"),
            std::regex("emulator"),
            std::regex("android.*sdk")
        };

        for (const auto& pat : idPatterns) {
            if (std::regex_search(deviceId, pat)) score += 2;
        }

        // Short or repeated IDs are suspicious
        if (deviceId.length() < 8 || 
            deviceId.find("android-") == 0) {
            score += 1;
        }

        return score;
    }

    int checkAppSignature(const std::string& signature,
                         const std::string& certFingerprint) {
        int score = 0;

        // Emulator apps often have specific signatures
        static const std::vector<std::regex> sigPatterns{
            std::regex("sdk"),
            std::regex("google.*api")
        };

        for (const auto& pat : sigPatterns) {
            if (std::regex_search(signature, pat)) score += 2;
        }

        // Certificate fingerprint patterns
        static const std::vector<std::string> certFlags{
            "sdk", "google"
        };

        for (const auto& flag : certFlags) {
            if (certFingerprint.find(flag) != std::string::npos) score += 1;
        }

        return score;
    }

    // Main detection function - aggregates all heuristics
    ScoredResult analyzeDevicePosture(
        const std::map<std::string, std::string>& deviceInfo,
        unsigned long memSizeMB = 0
    ) {
        int totalScore = 0;
        std::vector<std::string> flags;

        // Build fingerprint check (highest weight)
        auto fpScore = checkBuildFingerprint(deviceInfo["build.fingerprint"]);
        if (fpScore > 0) {
            totalScore += fpScore;
            flags.push_back("BUILD_FINGERPRINT");
        }

        // Model identifier check
        auto modelScore = checkModelIdentifier(
            deviceInfo["model"], 
            deviceInfo["product"]
        );
        if (modelScore > 0) {
            totalScore += modelScore;
            flags.push_back("MODEL_IDENTIFIER");
        }

        // Hardware anomalies
        auto hwScore = checkHardwareAnomalies(
            deviceInfo["cpu"],
            deviceInfo["architecture"],
            memSizeMB
        );
        if (hwScore > 0) {
            totalScore += hwScore;
            flags.push_back("HARDWARE_ANOMALY");
        }

        // Package manager check
        auto pmScore = checkPackageManager(
            deviceInfo["package.manager.name"],
            deviceInfo["package.manager.version"]
        );
        if (pmScore > 0) {
            totalScore += pmScore;
            flags.push_back("PACKAGE_MANAGER");
        }

        // Timezone check
        auto tzScore = checkTimezone(deviceInfo["timezone"]);
        if (tzScore > 0) {
            totalScore += tzScore;
            flags.push_back("TIMEZONE");
        }

        // Device ID check
        auto idScore = checkDeviceId(deviceInfo["device.id"]);
        if (idScore > 0) {
            totalScore += idScore;
            flags.push_back("DEVICE_ID");
        }

        // App signature check
        auto sigScore = checkAppSignature(
            deviceInfo["app.signature"],
            deviceInfo["cert.fingerprint"]
        );
        if (sigScore > 0) {
            totalScore += sigScore;
            flags.push_back("APP_SIGNATURE");
        }

        // Apply multiplier for multiple hard matches
        int hardMatches = 0;
        if (totalScore >= 25) hardMatches++;
        if (totalScore >= 35) hardMatches++;
        if (hardMatches > 0) totalScore += hardMatches * 5;

        ScoredResult result;
        result.score = totalScore;
        result.flags = flags;

        return result;
    }

} // namespace avd

// ============================================================================
// Demo / Entry Point
// ============================================================================

int main() {
    std::cout << "=== AVD Spoof Detector Demo ===\n\n";

    // Sample 1: Real device (simulated)
    std::map<std::string, std::string> realDevice{
        {"build.fingerprint", "Samsung/GT-I9500/I9500XXU2APB/OPR6.0.170726.AJE4:user/release-keys"},
        {"model", "SM-G900F"},
        {"product", "lte"},
        {"cpu", "ARMv8-a"},
        {"architecture", "arm64-v8a"},
        {"package.manager.name", "com.android.packageinstaller"},
        {"package.manager.version", "1.2.3"},
        {"timezone", "America/New_York"},
        {"device.id", "ABC123XYZ789"},
        {"app.signature", "SHA: a1b2c3d4e5f6..."},
        {"cert.fingerprint", "Google Play Services"}
    };

    auto realResult = avd::analyzeDevicePosture(realDevice, 4096);
    std::cout << "[REAL DEVICE]\n";
    std::cout << "  Score: " << realResult.score << "/50\n";
    std::cout << "  Verdict: " << realResult.levelStr() << "\n";
    if (!realResult.flags.empty()) {
        std::cout << "  Flags: ";
        for (size_t i = 0; i < realResult.flags.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << realResult.flags[i];
        }
        std::cout << "\n";
    } else {
        std::cout << "  Flags: none\n";
    }

    // Sample 2: Android SDK built for x86 (classic emulator)
    std::map<std::string, std::string> classicEmulator{
        {"build.fingerprint", "Android SDK built for x86/SDK/SDK30RQ.1A.457921/user/release-keys"},
        {"model", "Android SDK"},
        {"product", "sdk"},
        {"cpu", "Intel(R) Core(TM)"},
        {"architecture", "x86_64"},
        {"package.manager.name", "com.android.sdk.packageinstaller"},
        {"package.manager.version", "1.0"},
        {"timezone", "UTC"},
        {"device.id", "android-sdk-30"},
        {"app.signature", "SHA: google_sdk_api..."},
        {"cert.fingerprint", "Google SDK"}
    };

    auto classicResult = avd::analyzeDevicePosture(classicEmulator, 256);
    std::cout << "\n[CLASSIC EMULATOR]\n";
    std::cout << "  Score: " << classicResult.score << "/50\n";
    std::cout << "  Verdict: " << classicResult.levelStr() << "\n";
    if (!classicResult.flags.empty()) {
        std::cout << "  Flags: ";
        for (size_t i = 0; i < classicResult.flags.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << classicResult.flags[i];
        }
        std::cout << "\n";
    } else {
        std::cout << "  Flags: none\n";
    }

    // Sample 3: AVD with spoofed ARM architecture (tricky case)
    std::map<std::string, std::string> spoofedEmulator{
        {"build.fingerprint", "generic/generic/29/user/release-keys"},
        {"model", "AVD"},
        {"product", "google_sdk"},
        {"cpu", "ARMv8-a (spoofed)"},
        {"architecture", "arm64-v8a"},
        {"package.manager.name", "com.android.sdk.packageinstaller"},
        {"package.manager.version", "1.0"},
        {"timezone", "Etc/UTC"},
        {"device.id", "android-29-generic"},
        {"app.signature", "SHA: google_api..."},
        {"cert.fingerprint", "Google API"}
    };

    auto spoofedResult = avd::analyzeDevicePosture(spoofedEmulator, 512);
    std::cout << "\n[SPOOFED EMULATOR (ARM spoof)]\n";
    std::cout << "  Score: " << spoofedResult.score << "/50\n";
    std::cout << "  Verdict: " << spoofedResult.levelStr() << "\n";
    if (!spoofedResult.flags.empty()) {
        std::cout << "  Flags: ";
        for (size_t i = 0; i < spoofedResult.flags.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << spoofedResult.flags[i];
        }
        std::cout << "\n";
    } else {
        std::cout << "  Flags: none\n";
    }

    // Sample 4: Jailed/Rooted device (different indicators)
    std::map<std::string, std::string> jailedDevice{
        {"build.fingerprint", "OnePlus/NE5213/OPR6.0.170726.AJE4:user/release-keys"},
        {"model", "NE5213"},
        {"product", "oneplus"},
        {"cpu", "ARMv8-a"},
        {"architecture", "arm64-v8a"},
        {"package.manager.name", "com.android.packageinstaller"},
        {"package.manager.version", "1.2.3"},
        {"timezone", "America/Los_Angeles"},
        {"device.id", "JAIL001XYZ999"},
        {"app.signature", "SHA: a1b2c3d4e5f6..."},
        {"cert.fingerprint", "Google Play Services"}
    };

    auto jailedResult = avd::analyzeDevicePosture(jailedDevice, 8192);
    std::cout << "\n[JAILED DEVICE]\n";
    std::cout << "  Score: " << jailedResult.score << "/50\n";
    std::cout << "  Verdict: " << jailedResult.levelStr() << "\n";