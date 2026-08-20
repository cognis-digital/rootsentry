package polyglot.java;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Emulator AVD Spoof Detector - Detects Android Virtual Device (AVD) environments.
 * 
 * Checks multiple vectors: build props, env vars, file artifacts, processes, network interfaces.
 * Returns a confidence score and detailed findings.
 */
public final class EmulatorAVDSpoofDetector {

    private static final int EMULATOR_SCORE_THRESHOLD = 3;
    
    /**
     * Main detection entry point.
     * @return DetectionResult with score, verdict, and findings
     */
    public static DetectionResult detect() {
        return detect(System.getenv());
    }

    /**
     * Detect using provided environment map (useful for unit tests).
     */
    public static DetectionResult detect(Map<String, String> env) {
        List<Finding> findings = new ArrayList<>();
        
        // 1. Build Properties Analysis
        findings.addAll(checkBuildProperties(env));
        
        // 2. Environment Variable Analysis
        findings.addAll(checkEnvironmentVariables(env));
        
        // 3. File System Artifacts (if running on Android)
        findings.addAll(checkFileArtifacts());
        
        // 4. Process Detection
        findings.addAll(checkProcesses());
        
        // 5. Network Interface Analysis
        findings.addAll(checkNetworkInterfaces());
        
        // 6. Sensor/Device Pattern Analysis
        findings.addAll(checkSensorPatterns(env));
        
        int score = calculateScore(findings);
        return new DetectionResult(score, findings);
    }

    /**
     * Calculate confidence score based on findings.
     */
    private static int calculateScore(List<Finding> findings) {
        int score = 0;
        for (Finding f : findings) {
            if (!f.isSoft()) {
                score += f.getWeight();
            }
        }
        return Math.min(score, 10); // Cap at 10
    }

    /**
     * Determine verdict from score.
     */
    private static String getVerdict(int score) {
        if (score >= EMULATOR_SCORE_THRESHOLD) {
            return "LIKELY_EMULATOR";
        } else if (score > 0) {
            return "POSSIBLE_EMULATOR";
        }
        return "REAL_DEVICE";
    }

    /**
     * Check Android build properties for emulator signatures.
     */
    private static List<Finding> checkBuildProperties(Map<String, String> env) {
        List<Finding> findings = new ArrayList<>();
        
        // Common emulator product model patterns
        Set<String> emulatorModels = Set.of(
            "Android SDK Built-in",
            "Android SDK Phone",
            "emulator-5554",
            "sdk_phone_x86",
            "Generic Android TV"
        );
        
        String model = env.get("ro.product.model");
        if (model != null && emulatorModels.contains(model)) {
            findings.add(new Finding(
                "EMULATOR_MODEL_SIGNATURE",
                "Product model matches known AVD template: " + model,
                5, false));
        }
        
        // Check for SDK-specific build props
        String sdkVersion = env.get("ro.build.version.sdk");
        if (sdkVersion != null) {
            int sdkInt;
            try {
                sdkInt = Integer.parseInt(sdkVersion);
                // AVD often has specific SDK patterns or "release" strings
                if (sdkInt < 21 || sdkInt > 35) {
                    findings.add(new Finding(
                        "UNUSUAL_SDK_RANGE",
                        "SDK version outside typical range: " + sdkVersion,
                        2, true));
                }
            } catch (NumberFormatException e) {
                // Non-numeric SDK - might be emulator-specific string
                if (!sdkVersion.contains("release")) {
                    findings.add(new Finding(
                        "UNUSUAL_SDK_FORMAT",
                        "Non-standard SDK format: " + sdkVersion,
                        2, true));
                }
            }
        }
        
        // Check for emulator-specific build fingerprint patterns
        String fingerprint = env.get("ro.build.fingerprint");
        if (fingerprint != null) {
            if (fingerprint.contains("_emulator") || 
                fingerprint.contains("/emulator/") ||
                fingerprint.contains("sdk_phone")) {
                findings.add(new Finding(
                    "EMULATOR_FINGERPRINT",
                    "Fingerprint contains emulator marker: " + fingerprint,
                    4, false));
            }
        }
        
        // Check for Android SDK specific props
        String sdkPath = env.get("ro.sdk.path");
        if (sdkPath != null && sdkPath.contains("AndroidSdk")) {
            findings.add(new Finding(
                "SDK_PATH_ARTIFACT",
                "SDK path suggests AVD: " + sdkPath,
                2, true));
        }
        
        return findings;
    }

    /**
     * Check environment variables for emulator indicators.
     */
    private static List<Finding> checkEnvironmentVariables(Map<String, String> env) {
        List<Finding> findings = new ArrayList<>();
        
        // Android-specific emulator env vars
        Set<String> emulatorEnvVars = Set.of(
            "ANDROID_SERIAL",
            "ANDROID_VNDK_ROOT",
            "ANDROID_HOME",
            "ANDROID_SDK_ROOT",
            "ANDROID_NDK_ROOT"
        );
        
        for (String key : emulatorEnvVars) {
            String value = env.get(key);
            if (value != null && !value.isEmpty()) {
                findings.add(new Finding(
                    "EMULATOR_ENV_VAR_" + key,
                    "Environment variable present: " + key + "=" + value,
                    2, true));
            }
        }
        
        // Check for QEMU-specific env vars (common in AVD)
        if (env.containsKey("QEMU_AUDIO_DRV") || 
            env.containsKey("SDL_AUDIODRIVER")) {
            findings.add(new Finding(
                "QEMU_AUDIO_DRIVER",
                "QEMU/SDL audio driver detected: " + env.get("QEMU_AUDIO_DRV"),
                3, false));
        }
        
        // Check for virtual device specific vars
        if (env.containsKey("ANDROID_VNDK_ROOT")) {
            findings.add(new Finding(
                "VNDK_ARTIFACT",
                "Android VNDK root set: " + env.get("ANDROID_VNDK_ROOT"),
                3, false));
        }
        
        return findings;
    }

    /**
     * Check for file system artifacts indicating AVD.
     */
    private static List<Finding> checkFileArtifacts() {
        List<Finding> findings = new ArrayList<>();
        
        // Common emulator artifact paths (relative to root)
        Set<String> artifactPaths = Set.of(
            "data/local/tmp/AndroidSdcard",
            "data/data/com.android.vndk.current.service/",
            "system/etc/vintf/manifest.xml"
        );
        
        for (String path : artifactPaths) {
            Path fullPath;
            
            // Try multiple base paths
            String[] bases = {"/", System.getProperty("user.dir")};
            for (String base : bases) {
                fullPath = new File(base + path).getAbsoluteFile();
                if (fullPath.exists()) {
                    findings.add(new Finding(
                        "FILE_ARTIFACT_FOUND",
                        "Emulator artifact found: " + fullPath.getAbsolutePath(),
                        3, false));
                }
            }
        }
        
        // Check for AVD-specific files in common locations
        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            File qemuPidFile = new File("/proc/self/status");
            if (qemuPidFile.exists()) {
                try (BufferedReader reader = Files.newBufferedReader(qemuPidFile.toPath())) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.startsWith("Name:") && 
                            (line.contains("qemu") || line.contains("emulator"))) {
                            findings.add(new Finding(
                                "QEMU_PROCESS_NAME",
                                "Process appears to be QEMU/Emulator: " + line,
                                4, false));
                        }
                    }
                } catch (IOException e) {
                    // Ignore read errors
                }
            }
        }
        
        return findings;
    }

    /**
     * Check running processes for emulator indicators.
     */
    private static List<Finding> checkProcesses() {
        List<Finding> findings = new ArrayList<>();
        
        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            try {
                // Read /proc/self/status to check process name
                File selfStatus = new File("/proc/self/status");
                if (selfStatus.exists()) {
                    try (BufferedReader reader = Files.newBufferedReader(
                            selfStatus.toPath())) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("Name:") && 
                                (line.contains("qemu") || line.contains("emulator"))) {
                                findings.add(new Finding(
                                    "PROCESS_NAME_SIGNATURE",
                                    "Process name indicates emulator: " + line,
                                    4, false));
                            } else if (line.startsWith("VmRSS:") && 
                                       Long.parseLong(line.split(":")[1]) > 500 * 1024) {
                                // Large memory footprint - common in emulators
                                findings.add(new Finding(
                                    "HIGH_MEMORY_FOOTPRINT",
                                    "Process has large memory: " + line,
                                    2, true));
                            }
                        }
                    }
                }
            } catch (IOException e) {
                // Ignore read errors
            }
        }
        
        return findings;
    }

    /**
     * Check network interfaces for emulator patterns.
     */
    private static List<Finding> checkNetworkInterfaces() {
        List<Finding> findings = new ArrayList<>();
        
        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            try {
                // Read /proc/net/dev to check for virtual interfaces
                File netDevFile = new File("/proc/net/dev");
                if (netDevFile.exists()) {
                    try (BufferedReader reader = Files.newBufferedReader(
                            netDevFile.toPath())) {
                        String line;
                        boolean foundHeader = false;
                        
                        while ((line = reader.readLine()) != null) {
                            // Skip header lines
                            if (!foundHeader && !line.isEmpty() && 
                                !line.contains("Inter") && !line.contains("lo")) {
                                foundHeader = true;
                            }
                            
                            if (foundHeader && line.contains(":")) {
                                String[] parts = line.split(":");
                                String ifaceName = parts[0].trim();
                                
                                // Check for virtual interface patterns
                                if (ifaceName.toLowerCase().contains("veth") ||
                                    ifaceName.toLowerCase().contains("virbr") ||
                                    ifaceName.toLowerCase().contains("docker")) {
                                    
                                    findings.add(new Finding(
                                        "VIRTUAL_NETWORK_INTERFACE",
                                        "Virtual network interface detected: " + ifaceName,
                                        2, true));
                                }
                                
                                // Check for emulator-specific patterns
                                if (ifaceName.contains("emulator") || 
                                    ifaceName.contains("avd")) {
                                    findings.add(new Finding(
                                        "EMULATOR_NETWORK_INTERFACE",
                                        "Emulator network interface: " + ifaceName,
                                        3, false));
                                }
                            }
                        }
                    }
                }
            } catch (IOException e) {
                // Ignore read errors
            }
        }
        
        return findings;
    }

    /**
     * Check for sensor/data patterns that differ between real devices and emulators.
     */
    private static List<Finding> checkSensorPatterns(Map<String, String> env) {
        List<Finding> findings = new ArrayList<>();
        
        // Emulator sensors often have specific characteristics
        if (env.containsKey("ro.hardware.sensors")) {
            String sensorHardware = env.get("ro.hardware.sensors");
            
            // Common emulator sensor hardware strings
            Set<String> emulatorSensors = Set.of(
                "emulator",
                "sdk_phone",
                "generic"
            );
            
            if (sensorHardware.toLowerCase().contains("emulator") ||
                sensorHardware.toLowerCase().contains("sdk")) {
                findings.add(new Finding(
                    "EMULATOR_SENSOR_HARDWARE",
                    "Sensor hardware indicates emulator: " + sensorHardware,
                    3, false));
            }
        }
        
        // Check for simulated gyroscope/accelerometer patterns
        if (env.containsKey("ro.hardware.gyro")) {
            String gyro = env.get("ro.hardware.gyro");
            
            // Emulator often has "simulated" or similar markers
            if (gyro.toLowerCase().contains("simulated") ||
                gyro.toLowerCase().contains("emulated")) {
                findings.add(new Finding(
                    "SIMULATED_GYROSCOPE",
                    "Simulated gyroscope detected: " + gyro,
                    3, false));
            }
        }
        
        return findings;
    }

    /**
     * Result of detection.
     */
    public static class DetectionResult {
        private final int score;
        private final List<Finding> findings;
        private String verdict;
        
        public DetectionResult(int score, List<Finding> findings) {
            this.score = score;
            this.findings = findings;
            this.verdict = getVerdict(score);
        }

        public int getScore() {
            return score;
        }

        public String getVerdict() {
            return verdict;
        }

        public List<Finding> getFindings() {
            return Collections.unmodifiableList(findings);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("DetectionResult{score=").append(score)
              .append(", verdict='").append(verdict).append('\'')
              .append(", findingsCount=").append(findings.size()).append('}');
            
            if (!findings.isEmpty()) {
                sb.append("\n  Details:");
                for (Finding f : findings) {
                    sb.append("\n    - ").append(f);
                }
            }
            
            return sb.toString();
        }
    }

    /**
     * Individual finding with metadata.
     */
    public static class Finding {
        private final String type;
        private final String description;
        private final int weight;
        private final boolean isSoft; // Soft findings are less definitive
        
        public Finding(String type, String description, int weight, boolean isSoft) {
            this.type = type;
            this.description = description;
            this.weight = weight;
            this.isSoft = isSoft;
        }

        public String getType() {
            return type;
        }

        public String getDescription() {
            return description;
        }

        public int getWeight() {
            return weight;
        }

        public boolean isSoft() {
            return isSoft;
        }

        @Override
        public String toString() {
            return "  [" + (isSoft ? "[soft]" : "") + 
                   "] type=" + type + ", desc='" + description + "'";
        }
    }

    // ============================================================================
    // Runnable Demo / Main Entry Point
    // ============================================================================
    
    public static void main(String[] args) {
        System.out.println("=== AVD Spoof Detector ===\n");
        
        DetectionResult result = detect();
        
        System.out.println("Score: " + result.getScore() + "/10");
        System.out.println("Verdict: " + result.getVerdict());
        System.out.println("\nFindings (" + result.getFindings().size() + "):");
        
        if (result.getFindings().isEmpty()) {
            System.out.println("  [none]");
        } else {
            for (Finding f : result.getFindings()) {
                System.out.println(f);
            }
        }
        
        // Quick summary recommendation
        System.out.println("\n=== Summary ===");
        switch (result.getVerdict()) {
            case "LIKELY_EMULATOR":
                System.out.println("Device is likely running in an Android emulator.");
                break;
            case "POSSIBLE_EMULATOR":
                System.out.println("Some indicators suggest emulation, but confidence is moderate.");
                break;
            default:
                System.out.println("No strong evidence of emulation detected.");
                break;
        }