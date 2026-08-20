// polyglot/cpp/root_jailbreak_detector.cpp
// Mobile runtime-integrity detection: root/jailbreak/emulator/hook/tamper indicators
// with a scored posture verdict (RASP-style, zero deps)

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <memory>

namespace rootsentry {

// ============================================================================
// Configuration & Constants
// ============================================================================

struct Config {
    // Scoring thresholds (0-100)
    static const int SCORE_CRITICAL = 85;
    static const int SCORE_HIGH     = 60;
    static const int SCORE_MEDIUM  = 40;
    
    // File paths to check
    static const std::vector<std::string> ROOT_INDICATORS {
        "/system/bin/su",
        "/data/local/tmp/.android_root_access",
        "/data/local/tmp/.android_root",
        "/data/local/tmp/.root_access",
        "/data/local/tmp/.su",
        "/data/local/tmp/adb_shell.sh",
    };
    
    static const std::vector<std::string> JAILBREAK_INDICATORS {
        "/var/lib/dpkg/status.d/jailbreak",
        "/var/lib/apt/lists/*jailbreak*",
        "/Library/Preferences/com.apple.mobile.*",
        "/private/var/mobile/Library/Preferences/com.apple.mobile.*",
    };
    
    static const std::vector<std::string> EMULATOR_INDICATORS {
        "/dev/socket/qemmd",
        "/sys/class/android_devices/",
        "ANDROID_EMULATOR",
        "QEMU",
    };
};

// ============================================================================
// Data Structures
// ============================================================================

struct DetectionResult {
    int total_score = 0;
    std::map<std::string, int> category_scores; // root, jailbreak, emulator, hook
    
    struct Indicator {
        std::string name;
        std::string path_or_value;
        bool found;
        std::string details;
    };
    
    std::vector<Indicator> indicators_found;
    std::string verdict;
    std::string timestamp;
};

// ============================================================================
// Utility Functions
// ============================================================================

inline std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

inline bool file_exists(const std::string& path) {
    struct stat st;
    return (stat(path.c_str(), &st) == 0);
}

inline bool is_executable(const std::string& path) {
    if (!file_exists(path)) return false;
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IXUSR);
}

inline bool is_binary_file(const std::string& path, size_t max_size = 4096) {
    if (!file_exists(path)) return false;
    
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    
    unsigned char header[256];
    size_t bytes_read = fread(header, 1, std::min(max_size, static_cast<size_t>(sizeof(header))), f);
    fclose(f);
    
    // Check for ELF magic
    if (bytes_read >= 4 && header[0] == 0x7f && header[1] == 'E' && 
        header[2] == 'L' && header[3] == 'F') {
        return true;
    }
    
    // Check for Mach-O magic
    if (bytes_read >= 4) {
        uint32_t magic = *reinterpret_cast<uint32_t*>(header);
        if ((magic & 0xFFFF) == 0xCAFEBABE || 
            (magic & 0xFFFF) == 0xFEEDFACE ||
            (magic & 0xFFFF) == 0xFEEDFACF) {
            return true;
        }
    }
    
    // Check for PE magic
    if (bytes_read >= 4 && header[0] == 'M' && header[1] == 'Z') {
        return true;
    }
    
    return false;
}

inline std::string read_file_content(const std::string& path, size_t max_size = 8192) {
    if (!file_exists(path)) return "";
    
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return "";
    
    char buffer[max_size];
    size_t bytes_read = fread(buffer, 1, max_size - 1, f);
    fclose(f);
    
    std::string result;
    for (size_t i = 0; i < bytes_read && i < max_size - 1; ++i) {
        if (!std::isspace(static_cast<unsigned char>(buffer[i]))) {
            result += buffer[i];
        }
    }
    
    return result;
}

inline std::string get_proc_maps() {
    static const std::string MAPS_PATH = "/proc/self/maps";
    if (!file_exists(MAPS_PATH)) return "";
    
    FILE* f = fopen(MAPS_PATH.c_str(), "r");
    if (!f) return "";
    
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        // Extract library names from maps
        std::string lib_name;
        size_t start = line.find('[');
        size_t end = line.find(']');
        
        if (start != std::string::npos && end > start) {
            lib_name = line.substr(start + 1, end - start - 1);
            
            // Clean up path
            size_t slash_pos = lib_name.rfind('/');
            if (slash_pos != std::string::npos) {
                lib_name = lib_name.substr(slash_pos + 1);
            }
        }
        
        if (!lib_name.empty()) {
            return line; // Return first non-empty map line for quick check
        }
    }
    
    fclose(f);
    return "";
}

inline std::string get_env_var(const char* name) {
    const char* val = getenv(name);
    return val ? val : "";
}

// ============================================================================
// Detection Modules
// ============================================================================

struct RootCheckResult {
    int score; // 0-25
    std::vector<Indicator> indicators;
};

RootCheckResult check_root() {
    RootCheckResult result{0, {}};
    
    // Check for su binary
    if (file_exists("/system/bin/su") && is_executable("/system/bin/su")) {
        Indicator ind{"su_binary", "/system/bin/su", true, "Found executable su in system path"};
        result.indicators.push_back(ind);
        result.score += 10;
    } else if (file_exists("/system/bin/su")) {
        Indicator ind{"su_file", "/system/bin/su", true, "Found non-executable su file"};
        result.indicators.push_back(ind);
        result.score += 5;
    }
    
    // Check common root access files
    for (const auto& path : Config::ROOT_INDICATORS) {
        if (file_exists(path)) {
            Indicator ind{"root_indicator", path, true, "Found potential root indicator file"};
            result.indicators.push_back(ind);
            result.score += 8;
            
            // Check if it's executable
            if (is_executable(path)) {
                ind.details = "Executable";
            } else {
                std::string content = read_file_content(path, 256);
                if (!content.empty()) {
                    ind.details = "Content: " + trim(content.substr(0, 100));
                }
            }
        }
    }
    
    // Check effective UID (root access)
    uid_t euid = geteuid();
    if (euid == 0 && result.score < 5) {
        Indicator ind{"effective_uid", "geteuid()", true, "Running with effective UID 0"};
        result.indicators.push_back(ind);
        result.score += 15;
    } else if (result.score == 0) {
        // No other indicators found but running as root
        Indicator ind{"effective_uid", "geteuid()", true, "Running with effective UID 0"};
        result.indicators.push_back(ind);
        result.score += 15;
    }
    
    return result;
}

struct JailbreakCheckResult {
    int score; // 0-25
    std::vector<Indicator> indicators;
};

JailbreakCheckResult check_jailbreak() {
    JailbreakCheckResult result{0, {}};
    
    // Check for common jailbreak paths on iOS
    std::string home = get_env_var("HOME");
    if (!home.empty()) {
        std::vector<std::string> ios_paths = {
            "/var/lib/dpkg/status.d/jailbreak",
            "/private/var/mobile/Library/Preferences/com.apple.mobile.*",
        };
        
        for (const auto& path : ios_paths) {
            if (file_exists(path)) {
                Indicator ind{"ios_jailbreak_path", path, true, "Found iOS jailbreak indicator"};
                result.indicators.push_back(ind);
                result.score += 10;
                
                std::string content = read_file_content(path, 256);
                if (!content.empty()) {
                    ind.details = trim(content.substr(0, 100));
                }
            }
        }
    }
    
    // Check for Cydia/Sileo indicators
    if (file_exists("/var/lib/cydia") || file_exists("/Library/Cydia")) {
        Indicator ind{"cydia", "/var/lib/cydia or /Library/Cydia", true, "Found Cydia installation"};
        result.indicators.push_back(ind);
        result.score += 12;
    }
    
    // Check for Sileo
    if (file_exists("/var/sileo") || file_exists("/Library/Sileo")) {
        Indicator ind{"sileo", "/var/sileo or /Library/Sileo", true, "Found Sileo installation"};
        result.indicators.push_back(ind);
        result.score += 10;
    }
    
    // Check for common jailbreak env vars
    std::vector<std::string> jb_env_vars = {
        "CYDIA",
        "SILEO",
        "THEOS",
        "JAILBROKEN",
    };
    
    for (const auto& var : jb_env_vars) {
        std::string val = get_env_var(var.c_str());
        if (!val.empty()) {
            Indicator ind{"jailbreak_env", var, true, "Environment variable set: " + var};
            result.indicators.push_back(ind);
            result.score += 5;
        }
    }
    
    return result;
}

struct EmulatorCheckResult {
    int score; // 0-25
    std::vector<Indicator> indicators;
};

EmulatorCheckResult check_emulator() {
    EmulatorCheckResult result{0, {}};
    
    // Check for QEMU emulator socket
    if (file_exists("/dev/socket/qemmd")) {
        Indicator ind{"qemu_socket", "/dev/socket/qemmd", true, "Found QEMU emulator socket"};
        result.indicators.push_back(ind);
        result.score += 15;
    }
    
    // Check for Android emulator indicators
    if (file_exists("/sys/class/android_devices/")) {
        Indicator ind{"android_devices", "/sys/class/android_devices/", true, "Found Android devices directory"};
        result.indicators.push_back(ind);
        result.score += 5;
    }
    
    // Check environment variables
    std::vector<std::string> emulator_env_vars = {
        "ANDROID_EMULATOR",
        "QEMU",
        "EMULATOR",
        "ANDROID_SDK_ROOT",
    };
    
    for (const auto& var : emulator_env_vars) {
        std::string val = get_env_var(var.c_str());
        if (!val.empty()) {
            Indicator ind{"emulator_env", var, true, "Environment variable set: " + var};
            result.indicators.push_back(ind);
            result.score += 5;
            
            // Check for QEMU-specific env
            if (var == "QEMU" || var == "ANDROID_EMULATOR") {
                result.score += 10;
            }
        }
    }
    
    // Check /proc/cpuinfo for emulator hints
    if (file_exists("/proc/cpuinfo")) {
        std::string content = read_file_content("/proc/cpuinfo", 4096);
        
        // Look for common emulator CPU signatures
        std::vector<std::string> cpu_hints = {
            "QEMU User",
            "Android Emulator",
            "x86_64",
            "Intel(R) Core(TM)",
        };
        
        for (const auto& hint : cpu_hints) {
            if (content.find(hint) != std::string::npos) {
                Indicator ind{"cpu_signature", "/proc/cpuinfo", true, "Found emulator CPU signature: " + hint};
                result.indicators.push_back(ind);
                result.score += 8;
            }
        }
    }
    
    return result;
}

struct HookCheckResult {
    int score; // 0-25
    std::vector<Indicator> indicators;
};

HookCheckResult check_hook() {
    HookCheckResult result{0, {}};
    
    // Check for LD_PRELOAD environment variable
    std::string ld_preload = get_env_var("LD_PRELOAD");
    if (!ld_preload.empty()) {
        Indicator ind{"ld_preload", "LD_PRELOAD", true, "LD_PRELOAD set: " + ld_preload};
        result.indicators.push_back(ind);
        result.score += 15;
        
        // Check if the preload library exists and is executable
        if (file_exists(ld_preload)) {
            Indicator sub_ind{"ld_preload_file", ld_preload, true, "LD_PRELOAD file exists"};
            result.indicators.push_back(sub_ind);
            result.score += 5;
        }
    }
    
    // Check for common hook libraries in memory maps
    std::string maps = get_proc_maps();
    if (!maps.empty()) {
        std::vector<std::string> hook_libs = {
            "libhooker",
            "libinjector",
            "libfrida",
            "libgdbserver",
            "liblldb",
            "libdlopen_hook",
        };
        
        for (const auto& lib : hook_libs) {
            if (maps.find(lib) != std::string::npos) {
                Indicator ind{"hook_library", lib, true, "Found potential hook library in memory: " + lib};
                result.indicators.push_back(ind);
                result.score += 8;
            }
        }
    }
    
    // Check for common hook paths
    std::vector<std::string> hook_paths = {
        "/data/local/tmp/libhooker.so",
        "/data/local/tmp/libinjector.so",
        "/data/local/tmp/libfrida-agent.so",
        "/system/lib64/libhooker.so",
    };
    
    for (const auto& path : hook_paths) {
        if (file_exists(path)) {
            Indicator ind{"hook_path", path, true, "Found potential hook library: " + path};
            result.indicators.push_back(ind);
            result.score += 10;
            
            // Check if it's a shared object
            if (is_binary_file(path)) {
                std::string content = read_file_content(path, 256);
                if (!content.empty()) {
                    ind.details = "ELF/Mach-O binary";
                }
            }
        }
    }
    
    // Check for ptrace activity (debugger attachment)