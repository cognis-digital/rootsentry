package polyglot.java;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Mobile runtime-integrity detection for RASP-style posture analysis.
 * Detects: root, jailbreak, emulator, hook libraries, and tampering indicators.
 * Returns a scored risk verdict (0-100) with category breakdown.
 */
public class RootJailbreakDetector {

    private static final int ROOT_BASE_SCORE = 40;
    private static final int JAILBREAK_BASE_SCORE = 35;
    private static final int EMULATOR_BASE_SCORE = 25;
    private static final int HOOK_BASE_SCORE = 30;
    private static final int ENV_VAR_BASE_SCORE = 15;

    // Root indicators
    private static final Set<String> ROOT_PATHS = new HashSet<>(Arrays.asList(
            "/system/bin/su",
            "/data/local/tmp/su",
            "/data/local/root/su",
            "/sbin/su",
            "/system/xbin/su"
    ));

    // Jailbreak indicators (iOS)
    private static final Set<String> JAILBREAK_PATHS = new HashSet<>(Arrays.asList(
            "/var/lib/apt/lists/*",
            "/private/var/containers/Data/Library/Preferences/com.apple.mobile.*",
            "/data/data/com.android.shell/"
    ));

    // Emulator indicators
    private static final Set<String> EMULATOR_PATHS = new HashSet<>(Arrays.asList(
            "/data/local/emulator",
            ".android-emulator/",
            "/.emu/",
            "/.android/adb_shell/",
            "/system/etc/init/android_emulator.rc"
    ));

    // Hook library indicators
    private static final Set<String> HOOK_PATHS = new HashSet<>(Arrays.asList(
            "libxposed.so",
            "libfrida-agent.dylib",
            "liblldb.so",
            "libhooker.so",
            "libinjector.so"
    ));

    // Suspicious environment variables
    private static final Set<String> SUSPICIOUS_ENV = new HashSet<>(Arrays.asList(
            "ANDROID_EMULATOR",
            "XPOSED_ENABLED",
            "FRIDA_AGENT_PATH",
            "LLDB_DEBUGGER",
            "ROOTED"
    ));

    public static class PostureResult {
        private final int riskScore;
        private final String verdict;
        private final Map<String, Integer> categoryScores;
        private final List<String> detectedIndicators;

        public PostureResult(int riskScore, String verdict, 
                           Map<String, Integer> categoryScores, 
                           List<String> detectedIndicators) {
            this.riskScore = riskScore;
            this.verdict = verdict;
            this.categoryScores = categoryScores;
            this.detectedIndicators = detectedIndicators;
        }

        public int getRiskScore() { return riskScore; }
        public String getVerdict() { return verdict; }
        public Map<String, Integer> getCategoryScores() { return categoryScores; }
        public List<String> getDetectedIndicators() { return detectedIndicators; }

        @Override
        public String toString() {
            return "PostureResult{" +
                    "riskScore=" + riskScore +
                    ", verdict='" + verdict + '\'' +
                    ", categories=" + categoryScores +
                    ", indicators=" + detectedIndicators +
                    '}';
        }
    }

    /**
     * Main detection entry point. Returns a scored posture result.
     */
    public static PostureResult detect() {
        Map<String, Integer> categoryScores = new HashMap<>();
        List<String> allIndicators = new ArrayList<>();

        // Check root indicators
        if (checkRoot()) {
            categoryScores.put("ROOT", ROOT_BASE_SCORE);
            allIndicators.add("root_binary_found");
        }

        // Check jailbreak indicators
        if (checkJailbreak()) {
            categoryScores.put("JAILBREAK", JAILBREAK_BASE_SCORE);
            allIndicators.add("jailbreak_indicator");
        }

        // Check emulator indicators
        if (checkEmulator()) {
            categoryScores.put("EMULATOR", EMULATOR_BASE_SCORE);
            allIndicators.add("emulator_environment");
        }

        // Check hook libraries
        if (checkHookLibraries()) {
            categoryScores.put("HOOK_LIBRARY", HOOK_BASE_SCORE);
            allIndicators.add("hook_library_detected");
        }

        // Check environment variables
        if (checkEnvironmentVariables()) {
            categoryScores.put("ENV_VAR", ENV_VAR_BASE_SCORE);
            allIndicators.add("suspicious_env_var");
        }

        // Calculate total risk score with saturation at 100
        int totalScore = Math.min(100, 
                categoryScores.values().stream()
                        .mapToInt(Integer::intValue)
                        .sum());

        String verdict;
        if (totalScore >= 80) {
            verdict = "HIGH_RISK";
        } else if (totalScore >= 50) {
            verdict = "MEDIUM_RISK";
        } else if (totalScore > 0) {
            verdict = "LOW_RISK";
        } else {
            verdict = "CLEAN";
        }

        return new PostureResult(totalScore, verdict, categoryScores, allIndicators);
    }

    /**
     * Check for root indicators in the filesystem.
     */
    private static boolean checkRoot() {
        try {
            // Check for su binary existence
            File[] rootCandidates = ROOT_PATHS.stream().map(File::new).filter(f -> f.exists()).toArray(File[]::new);
            if (rootCandidates.length > 0) {
                return true;
            }

            // Alternative: check /proc/self/status for UID 0
            try (BufferedReader reader = new BufferedReader(
                    new FileReader("/proc/self/status"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("Uid:") && 
                        line.split(":")[1].trim().equals("0")) {
                        return true;
                    }
                }
            }

        } catch (IOException e) {
            // Log but don't fail - might be running in restricted environment
        }

        return false;
    }

    /**
     * Check for jailbreak indicators.
     */
    private static boolean checkJailbreak() {
        try {
            File[] candidates = JAILBREAK_PATHS.stream().map(File::new).filter(f -> f.exists()).toArray(File[]::new);
            if (candidates.length > 0) {
                return true;
            }

            // Check for common jailbreak app signatures in /data
            File dataDir = new File("/data");
            if (dataDir.exists() && dataDir.isDirectory()) {
                try (BufferedReader reader = new BufferedReader(
                        new FileReader(new File(dataDir, "app_process"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        // Check for Cydia/Sileo indicators
                        if (line.contains("Cydia") || line.contains("Sileo")) {
                            return true;
                        }
                    }
                } catch (IOException ignored) {}
            }

        } catch (Exception e) {
            // Graceful degradation
        }

        return false;
    }

    /**
     * Check for emulator indicators.
     */
    private static boolean checkEmulator() {
        try {
            File[] candidates = EMULATOR_PATHS.stream().map(File::new).filter(f -> f.exists()).toArray(File[]::new);
            if (candidates.length > 0) {
                return true;
            }

            // Check environment variable
            String emulatorEnv = System.getenv("ANDROID_EMULATOR");
            if (emulatorEnv != null && !emulatorEnv.isEmpty()) {
                return true;
            }

            // Check for emulator-specific process names via /proc
            try (BufferedReader reader = new BufferedReader(
                    new FileReader("/proc/self/status"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("Name:") && 
                        (line.contains("emulator") || line.contains("qemu"))) {
                        return true;
                    }
                }
            }

        } catch (IOException e) {
            // Graceful degradation
        }

        return false;
    }

    /**
     * Check for hook library indicators in memory and filesystem.
     */
    private static boolean checkHookLibraries() {
        try {
            // Check filesystem first
            File[] candidates = HOOK_PATHS.stream().map(File::new).filter(f -> f.exists()).toArray(File[]::new);
            if (candidates.length > 0) {
                return true;
            }

            // Try to detect loaded hook libraries via reflection
            try {
                Field field = Runtime.class.getDeclaredField("loadedLibraryNames");
                field.setAccessible(true);
                
                Object obj = field.get(null);
                if (obj instanceof String[]) {
                    String[] libs = (String[]) obj;
                    for (String lib : libs) {
                        if (lib.toLowerCase().contains("xposed") || 
                            lib.toLowerCase().contains("frida") ||
                            lib.toLowerCase().contains("lldb")) {
                            return true;
                        }
                    }
                }

            } catch (Exception ignored) {}

        } catch (Exception e) {
            // Graceful degradation
        }

        return false;
    }

    /**
     * Check for suspicious environment variables.
     */
    private static boolean checkEnvironmentVariables() {
        try {
            for (String env : SUSPICIOUS_ENV) {
                String value = System.getenv(env);
                if (value != null && !value.isEmpty()) {
                    return true;
                }
            }

            // Also check for common tamper indicators in command line args
            String[] args = Runtime.getRuntime().getRuntimeMXBean().getName();
            for (String arg : args) {
                if (arg.toLowerCase().contains("frida") || 
                    arg.toLowerCase().contains("lldb")) {
                    return true;
                }
            }

        } catch (Exception e) {
            // Graceful degradation
        }

        return false;
    }

    /**
     * Main demo entry point. Run this to see the detector in action.
     */
    public static void main(String[] args) {
        System.out.println("=== ROOTSENTRY: Runtime Integrity Detector ===\n");
        
        PostureResult result = detect();
        
        System.out.println("Risk Score: " + result.getRiskScore() + "/100");
        System.out.println("Verdict: " + result.getVerdict());
        System.out.println("\nCategory Breakdown:");
        for (Map.Entry<String, Integer> entry : result.getCategoryScores().entrySet()) {
            System.out.printf("  %-20s: %d\n", entry.getKey(), entry.getValue());
        }
        
        if (!result.getDetectedIndicators().isEmpty()) {
            System.out.println("\nDetected Indicators:");
            for (String indicator : result.getDetectedIndicators()) {
                System.out.println("  - " + indicator);
            }
        } else {
            System.out.println("\nNo indicators detected.");
        }

        // Exit with appropriate code based on risk level
        int exitCode = switch (result.getRiskScore()) {
            case >= 80 -> 2;   // HIGH_RISK
            case >= 50 -> 1;   // MEDIUM_RISK
            default -> 0;      // CLEAN or LOW_RISK
        };

        System.out.println("\nExit Code: " + exitCode);
    }
}