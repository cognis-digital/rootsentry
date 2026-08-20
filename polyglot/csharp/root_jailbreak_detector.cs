using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace rootsentry
{
    /// <summary>
    /// Mobile runtime integrity detection with scored posture verdict.
    /// Detects root, jailbreak, emulator, hook, and tamper indicators.
    /// </summary>
    public static class RootJailbreakDetector
    {
        private const int MaxScore = 100;

        // Known root/jailbreak library signatures (partial names)
        private static readonly HashSet<string> RootLibSignatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "libroot", "libjailbreak", "libsu", "supersu", "magisk", 
            "zygote64_32", "zygote64_arm64_v8a", "arm64-v8a", "x86_64"
        };

        // Known emulator process names and env vars
        private static readonly HashSet<string> EmulatorProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "com.android.emulator", "bluestacks", "nox", "mokee", 
            "genymotion", "android_studio_emu", "vysor"
        };

        // Common jailbreak environment variables
        private static readonly HashSet<string> JailbreakEnvVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ANDROID_ROOT", "JAILBREAK_MODE", "CYDIA_HOME", 
            "DEBIAN_FRONTEND", "TERM_PROGRAM"
        };

        // Hooking library signatures
        private static readonly HashSet<string> HookLibSignatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "frida", "xposed", "lsposed", "cydia", "sileo", 
            "theos", "substrate", "hooker"
        };

        // Known tamper indicators (file paths that should exist in clean installs)
        private static readonly HashSet<string> SystemBinaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "/system/bin/sh", "/system/bin/zygote64", 
            "/data/local/tmp/frida-server-14.x.x"
        };

        public class PostureResult
        {
            public int Score { get; }
            public string Verdict { get; }
            public List<CheckDetail> Details { get; }
            
            public PostureResult(int score, string verdict, List<CheckDetail> details)
            {
                Score = score;
                Verdict = verdict;
                Details = details ?? new List<CheckDetail>();
            }

            public override string ToString() => $"{Verdict} (Score: {Score}/{MaxScore})";
        }

        /// <summary>
        /// Detailed result of a single integrity check.
        /// </summary>
        public class CheckDetail
        {
            public string Name { get; }
            public bool Passed { get; }
            public int PointsLost { get; }
            public string Message { get; }

            public CheckDetail(string name, bool passed, int pointsLost = 0, string message = null)
            {
                Name = name;
                Passed = passed;
                PointsLost = pointsLost;
                Message = message;
            }
        }

        /// <summary>
        /// Main entry point for integrity detection.
        /// </summary>
        public static PostureResult Detect()
        {
            var details = new List<CheckDetail>();
            int totalPointsLost = 0;

            // Step 1: Process and Assembly Integrity Checks
            details.AddRange(CheckProcessIntegrity());

            // Step 2: Environment Variable Analysis
            details.AddRange(CheckEnvironmentVariables());

            // Step 3: File System and Binary Verification
            details.AddRange(CheckFileSystemIntegrity());

            // Step 4: Memory/Loaded Library Analysis
            details.AddRange(CheckMemoryAndLibraries());

            // Calculate final score
            int totalPoints = MaxScore;
            totalPointsLost = details.Sum(d => d.PointsLost);
            int finalScore = Math.Max(0, totalPoints - totalPointsLost);

            string verdict;
            if (finalScore >= 90)
                verdict = "Clean";
            else if (finalScore >= 75)
                verdict = "Minor Suspicion";
            else if (finalScore >= 50)
                verdict = "Moderate Risk";
            else if (finalScore >= 25)
                verdict = "High Risk";
            else
                verdict = "Critical Compromise";

            return new PostureResult(finalScore, verdict, details);
        }

        /// <summary>
        /// Check process name, command line, and assembly location.
        /// </summary>
        private static IEnumerable<CheckDetail> CheckProcessIntegrity()
        {
            var details = new List<CheckDetail>();

            // Check current process name
            string processName = Process.GetCurrentProcess().ProcessName;
            
            if (EmulatorProcessNames.Contains(processName))
            {
                details.Add(new CheckDetail(
                    "Process Name", false, 15, 
                    $"Detected emulator-like process: {processName}"));
            }

            // Check command line arguments for suspicious flags
            string commandLine = Process.GetCurrentProcess().CommandLine;
            
            if (commandLine.Contains("-debug") || commandLine.Contains("--debug"))
            {
                details.Add(new CheckDetail(
                    "Debug Flags", false, 5, 
                    "Found debug flag in command line"));
            }

            // Check assembly location for tampering signs
            string assemblyLocation = Assembly.GetExecutingAssembly().Location;
            
            if (assemblyLocation.Contains("temp") || 
                assemblyLocation.Contains("cache") ||
                assemblyLocation.Contains("data"))
            {
                details.Add(new CheckDetail(
                    "Assembly Location", false, 10, 
                    $"Assembly in non-standard location: {assemblyLocation}"));
            }

            return details;
        }

        /// <summary>
        /// Analyze environment variables for jailbreak/emulator indicators.
        /// </summary>
        private static IEnumerable<CheckDetail> CheckEnvironmentVariables()
        {
            var details = new List<CheckDetail>();

            // Get all environment variables
            var envVars = Environment.GetEnvironmentVariables();

            foreach (var kvp in envVars)
            {
                string name = kvp.Key;
                
                if (JailbreakEnvVars.Contains(name))
                {
                    details.Add(new CheckDetail(
                        $"Env Var: {name}", false, 10, 
                        $"Found jailbreak indicator: {name}"));
                }

                // Check for emulator-specific env vars
                if (name.StartsWith("EMULATOR") || name.Contains("_EMU_"))
                {
                    details.Add(new CheckDetail(
                        $"Emulator Env Var", false, 8, 
                        $"Found emulator env var: {name}"));
                }

                // Check for common tamper indicators
                if (name == "USER" && !kvp.Value.ToString().Contains("root"))
                {
                    details.Add(new CheckDetail(
                        "User Context", true, 0, 
                        $"Running as user: {kvp.Value}"));
                }
            }

            return details;
        }

        /// <summary>
        /// Verify file system integrity and check for modified binaries.
        /// </summary>
        private static IEnumerable<CheckDetail> CheckFileSystemIntegrity()
        {
            var details = new List<CheckDetail>();

            // Check for root/jailbreak files in common locations
            string[] rootIndicators = {
                "/data/local/tmp/frida-server",
                "/data/data/com.termux/files/usr/bin/root",
                "/system/etc/init/android_root_init.sh"
            };

            foreach (var indicator in rootIndicators)
            {
                if (!string.IsNullOrEmpty(indicator) && 
                    File.Exists(indicator))
                {
                    details.Add(new CheckDetail(
                        $"Root Indicator: {indicator}", false, 12, 
                        $"Found potential root file at: {indicator}"));
                }
            }

            // Check for modified system binaries (if accessible)
            try
            {
                string[] systemBins = { "/system/bin/sh", "/system/bin/zygote64" };
                
                foreach (var bin in systemBins)
                {
                    if (!string.IsNullOrEmpty(bin))
                    {
                        if (File.Exists(bin))
                        {
                            // Check file size for anomalies
                            long fileSize = new FileInfo(bin).Length;
                            
                            // Typical sizes vary, but extremely large files are suspicious
                            if (fileSize > 50 * 1024 * 1024) // 50MB threshold
                            {
                                details.Add(new CheckDetail(
                                    $"Binary Size: {bin}", false, 8, 
                                    $"Unusually large binary file: {fileSize} bytes"));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Expected in many mobile environments where /system is read-only
                details.Add(new CheckDetail(
                    "System Binary Access", true, 0, 
                    $"Limited system access: {ex.Message}"));
            }

            return details;
        }

        /// <summary>
        /// Analyze loaded libraries and memory for hooking indicators.
        /// </summary>
        private static IEnumerable<CheckDetail> CheckMemoryAndLibraries()
        {
            var details = new List<CheckDetail>();

            // Get all loaded assemblies (DLLs)
            var loadedAssemblies = AppDomain.CurrentDomain.GetAssemblies();

            foreach (var assembly in loadedAssemblies)
            {
                string name = assembly.GetName().Name;
                
                if (RootLibSignatures.Contains(name))
                {
                    details.Add(new CheckDetail(
                        $"Loaded Library: {name}", false, 15, 
                        $"Found root/jailbreak library: {name}"));
                }

                if (HookLibSignatures.Contains(name))
                {
                    details.Add(new CheckDetail(
                        $"Hooking Library: {name}", false, 20, 
                        $"Found hooking library: {name}"));
                }

                // Check for suspicious assembly locations
                string location = assembly.Location;
                
                if (location != null && 
                    (location.Contains("temp") || 
                     location.Contains("/data/data/") && !location.Contains(".apk")))
                {
                    details.Add(new CheckDetail(
                        $"Assembly Location: {name}", false, 5, 
                        $"Loaded from non-standard path: {location}"));
                }
            }

            // Check for Frida server specifically (common hooking tool)
            try
            {
                string fridaPath = "/data/local/tmp/frida-server-14.x.x";
                
                if (!string.IsNullOrEmpty(fridaPath))
                {
                    if (File.Exists(fridaPath))
                    {
                        details.Add(new CheckDetail(
                            "Frida Server", false, 25, 
                            $"Found Frida server at: {fridaPath}"));
                    }
                }
            }
            catch
            {
                // Expected in many environments
            }

            return details;
        }

        /// <summary>
        /// Get a human-readable interpretation of the score.
        /// </summary>
        public static string InterpretScore(int score)
        {
            switch (score)
            {
                case >= 90:
                    return "Runtime appears clean and trustworthy.";
                case >= 75:
                    return "Minor indicators present, likely safe but worth noting.";
                case >= 50:
                    return "Moderate risk detected. Review details for context.";
                case >= 25:
                    return "High probability of runtime modification or emulation.";
                default:
                    return "Strong indicators of root/jailbreak/emulator environment.";
            }
        }

        /// <summary>
        /// Main demo/entry point. Run this to test the detector.
        /// </summary>
        public static void Main(string[] args)
        {
            Console.WriteLine("=== rootsentry: Mobile Runtime Integrity Detector ===\n");

            // Run detection
            var result = Detect();

            // Display results
            Console.WriteLine($"Verdict: {result.Verdict}");
            Console.WriteLine($"Score:   {result.Score}/{MaxScore}\n");
            
            if (string.IsNullOrEmpty(result.Interpretation()))
                Console.WriteLine(InterpretScore(result.Score));
            else
                Console.WriteLine(result.Interpretation());

            Console.WriteLine("\n--- Detailed Findings ---\n");

            // Sort by points lost (worst first)
            var sortedDetails = result.Details.OrderByDescending(d => d.PointsLost).ToList();

            foreach (var detail in sortedDetails)
            {
                string status = detail.Passed ? "[PASS]" : "[FAIL]";
                Console.WriteLine($"{status} | {detail.Name,-35}");
                
                if (!detail.Passed)
                {
                    Console.WriteLine($"       Points lost: {detail.PointsLost}");
                    if (!string.IsNullOrEmpty(detail.Message))
                        Console.WriteLine($"       Details: {detail.Message}");
                }
            }

            // Summary
            int failedCount = result.Details.Count(d => !d.Passed);
            Console.WriteLine($"\n--- Summary ---");
            Console.WriteLine($"Total checks:  {result.Details.Count}");
            Console.WriteLine($"Passed:        {result.Details.Count(d => d.Passed)}");
            Console.WriteLine($"Failed:        {failedCount}");
            Console.WriteLine($"Score impact:  -{result.Details.Sum(d => d.PointsLost)}/{MaxScore} points");

            // Exit with appropriate code
            Environment.Exit(result.Score < 50 ? 1 : 0);
        }

        /// <summary>
        /// Get human-readable interpretation of the result.
        /// </summary>
        public string Interpretation() => InterpretScore(Score);
    }
}