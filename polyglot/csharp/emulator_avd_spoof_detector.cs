using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace rootsentry
{
    /// <summary>
    /// Android AVD (Android Virtual Device) Spoof Detector.
    /// Analyzes system properties to detect emulator/runtime environments.
    /// </summary>
    public static class EmulatorAvdSpoofDetector
    {
        private const string BuildClass = "android.os.Build";

        // Known emulator manufacturer signatures
        private static readonly HashSet<string> EmulatorManufacturers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Google",           // Android Studio AVD, Genymotion sometimes
            "BlueStacks",       // BlueStacks emulator
            "Nox",              // Nox App Player
            "LDPlayer",         // LDPlayer
            "Genymotion",       // Genymotion
            "VMware",           // VMware Android Studio
            "Intel",            // Intel x86 emulation
            "Morphis",          // Morphis
            "Panda",            // Panda Player
            "Memu",             // Memu Player
            "TianYu",           // TianYu Player
            "YiSo",             // YiSo Player
            "Hypium",           // Hypium
            "Kode",             // Kode
            "Appetize",         // Appetize.io
            "BrowserStack",     // BrowserStack
            "SauceLabs",        // Sauce Labs
            "Perfecto",         // Perfecto
            "FirebaseTestLab"   // Firebase Test Lab
        };

        // Known emulator model signatures (partial matches)
        private static readonly HashSet<string> EmulatorModels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Android SDK Built-in Phone",
            "Android SDK Built-in Tablet",
            "Google Pixel 4",      // Often used as default AVD template
            "Pixel 3",
            "Pixel 2",
            "Nexus 5",
            "Nexus 6",
            "Nexus 7",
            "Nexus 10",
            "Nexus S",
            "Nexus 4",
            "Nexus 9",
            "Nexus 5X",
            "Nexus 6P",
            "Pixel 3a",
            "Pixel 3a XL",
            "Pixel 4a",
            "Pixel 4a (5G)",
            "Pixel 5",
            "Pixel 6",
            "Pixel 7",
            "Pixel 8"
        };

        // Hardware identifiers that suggest emulation
        private static readonly HashSet<string> EmulatorHardware = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "goldfish",
            "grouper",
            "hammerhead",
            "shamu",
            "sdk_phone_x86",
            "sdk_tablet_x86",
            "vbox86p"
        };

        // Real device hardware that should reduce score
        private static readonly HashSet<string> RealDeviceHardware = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "qcom",
            "snapdragon",
            "exynos",
            "mediatek",
            "kirin",
            "apple",
            "samsung"
        };

        /// <summary>
        /// Detects if the current runtime is likely running on an emulator.
        /// </summary>
        public static (int score, string verdict, List<string> details) Analyze()
        {
            var details = new List<string>();
            int score = 0;

            // Check manufacturer
            var manufacturer = GetManufacturer();
            if (!string.IsNullOrEmpty(manufacturer))
            {
                bool isEmulatorManuf = EmulatorManufacturers.Contains(manufacturer);
                
                if (isEmulatorManuf)
                {
                    score += 35;
                    details.Add($"[HIGH] Manufacturer '{manufacturer}' matches known emulator");
                }
                else if (RealDeviceHardware.Any(h => manufacturer.Contains(h)))
                {
                    score -= 10;
                    details.Add($"[LOW] Manufacturer '{manufacturer}' suggests real device");
                }

                // Check model name
                var model = GetModel();
                if (!string.IsNullOrEmpty(model))
                {
                    bool isEmulatorModel = EmulatorModels.Any(m => model.Contains(m));
                    
                    if (isEmulatorModel)
                    {
                        score += 25;
                        details.Add($"[HIGH] Model '{model}' matches known AVD template");
                    }

                    // Check hardware identifier
                    var hardware = GetHardware();
                    if (!string.IsNullOrEmpty(hardware))
                    {
                        bool isEmulatorHw = EmulatorHardware.Any(h => hardware.Contains(h, StringComparison.OrdinalIgnoreCase));
                        
                        if (isEmulatorHw)
                        {
                            score += 30;
                            details.Add($"[HIGH] Hardware '{hardware}' suggests x86 emulation");
                        }

                        bool isRealHw = RealDeviceHardware.Any(h => hardware.Contains(h, StringComparison.OrdinalIgnoreCase));
                        
                        if (isRealHw)
                        {
                            score -= 15;
                            details.Add($"[LOW] Hardware '{hardware}' suggests ARM device");
                        }
                    }

                    // Check build fingerprint for AVD patterns
                    var fingerprint = GetFingerprint();
                    if (!string.IsNullOrEmpty(fingerprint))
                    {
                        bool isAvdPattern = fingerprint.Contains("sdk") || 
                                           fingerprint.Contains("avd") ||
                                           fingerprint.Contains("emulator");
                        
                        if (isAvdPattern)
                        {
                            score += 20;
                            details.Add($"[MEDIUM] Fingerprint '{fingerprint}' contains AVD pattern");
                        }

                        // Check for common AVD version patterns
                        bool isCommonAvdVersion = fingerprint.Contains("sdk built-in") ||
                                                  fingerprint.Contains("google sdk built-in");
                        
                        if (isCommonAvdVersion)
                        {
                            score += 25;
                            details.Add($"[HIGH] Fingerprint matches common AVD template: '{fingerprint}'");
                        }
                    }

                    // Check for x86-specific properties that indicate emulator
                    var props = GetBuildProperties();
                    
                    if (props.ContainsKey("ro.product.cpu.abi") && 
                        props["ro.product.cpu.abi"].Contains("x86"))
                    {
                        score += 20;
                        details.Add($"[MEDIUM] CPU ABI is x86, common in AVDs");
                    }

                    // Check for emulator-specific boot properties
                    if (props.ContainsKey("ro.bootloader") && 
                        props["ro.bootloader"].Contains("sdk"))
                    {
                        score += 15;
                        details.Add($"[MEDIUM] Bootloader contains 'sdk' pattern");
                    }

                    // Check sensor data patterns (emulators often have default values)
                    if (props.ContainsKey("ro.hardware.sensors") && 
                        props["ro.hardware.sensors"].Contains("default"))
                    {
                        score += 10;
                        details.Add($"[LOW] Sensors report 'default' configuration");
                    }

                    // Check for virtual display indicators
                    var display = GetDisplayInfo();
                    if (!string.IsNullOrEmpty(display) && 
                        (display.Contains("virtual") || display.Contains("emulator")))
                    {
                        score += 15;
                        details.Add($"[MEDIUM] Display info suggests virtual environment");
                    }

                    // Check for common AVD release patterns
                    var release = GetRelease();
                    if (!string.IsNullOrEmpty(release))
                    {
                        bool isCommonAvdRelease = release.Contains("sdk built-in") ||
                                                   release.Contains("google sdk built-in");
                        
                        if (isCommonAvdRelease)
                        {
                            score += 10;
                            details.Add($"[LOW] Release version matches common AVD template");
                        }
                    }

                    // Check for emulator-specific environment variables
                    var env = GetEnvironment();
                    
                    if (!string.IsNullOrEmpty(env) && 
                        (env.Contains("ANDROID_EMULATOR") || 
                         env.Contains("AVD_HOME") ||
                         env.Contains("EMULATOR")))
                    {
                        score += 20;
                        details.Add($"[MEDIUM] Environment variables suggest AVD runtime");
                    }

                    // Check for known emulator process signatures
                    if (props.ContainsKey("ro.debuggable") && 
                        props["ro.debuggable"] == "1" &&
                        props.ContainsKey("ro.build.type"))
                    {
                        var buildType = props["ro.build.type"];
                        if (buildType.Contains("userdebug") || buildType.Contains("eng"))
                        {
                            // Debug builds are common in AVDs but also real devices
                            score += 5;
                            details.Add($"[LOW] Debuggable build type detected");
                        }
                    }

                    // Check for virtual memory patterns
                    var memInfo = GetMemoryInfo();
                    if (!string.IsNullOrEmpty(memInfo) && 
                        memInfo.Contains("virtual"))
                    {
                        score += 10;
                        details.Add($"[LOW] Memory info suggests virtual environment");
                    }

                    // Check for known AVD-specific properties
                    var avdProps = new Dictionary<string, string>
                    {
                        ["ro.build.id"] = props.ContainsKey("ro.build.id") ? props["ro.build.id"] : "",
                        ["ro.product.device"] = props.ContainsKey("ro.product.device") ? props["ro.product.device"] : ""
                    };

                    if (avdProps["ro.build.id"].Contains("sdk"))
                    {
                        score += 15;
                        details.Add($"[MEDIUM] Build ID contains 'sdk' pattern");
                    }

                    // Check for emulator-specific vendor strings
                    var vendor = GetVendor();
                    if (!string.IsNullOrEmpty(vendor) && 
                        (vendor.Contains("google") || vendor.Contains("android sdk")))
                    {
                        score += 10;
                        details.Add($"[LOW] Vendor string suggests AVD environment");
                    }

                    // Check for known emulator-specific release patterns
                    var sdkVersion = GetSdkVersion();
                    if (!string.IsNullOrEmpty(sdkVersion) && 
                        (sdkVersion.Contains("sdk built-in") || 
                         sdkVersion.Contains("google sdk built-in")))
                    {
                        score += 15;
                        details.Add($"[MEDIUM] SDK version matches AVD template");
                    }

                    // Check for virtualization-specific properties
                    var virtProps = new Dictionary<string, string>
                    {
                        ["ro.virtualization"] = props.ContainsKey("ro.virtualization") ? props["ro.virtualization"] : "",
                        ["ro.boot.vboot"] = props.ContainsKey("ro.boot.vboot") ? props["ro.boot.vboot"] : ""
                    };

                    if (!string.IsNullOrEmpty(virtProps["ro.virtualization"]) && 
                        virtProps["ro.virtualization"].Contains("emulator"))
                    {
                        score += 20;
                        details.Add($"[MEDIUM] Virtualization property indicates emulator");
                    }

                    // Check for known AVD-specific hardware properties
                    var hwProps = new Dictionary<string, string>
                    {
                        ["ro.hardware"] = props.ContainsKey("ro.hardware") ? props["ro.hardware"] : "",
                        ["ro.board.platform"] = props.ContainsKey("ro.board.platform") ? props["ro.board.platform"] : ""
                    };

                    if (!string.IsNullOrEmpty(hwProps["ro.hardware"]) && 
                        hwProps["ro.hardware"].Contains("sdk"))
                    {
                        score += 15;
                        details.Add($"[MEDIUM] Hardware property contains 'sdk' pattern");
                    }

                    // Check for emulator-specific bootloader properties
                    var bootProps = new Dictionary<string, string>
                    {
                        ["ro.bootloader"] = props.ContainsKey("ro.bootloader") ? props["ro.bootloader"] : "",
                        ["ro.boot.serialno"] = props.ContainsKey("ro.boot.serialno") ? props["ro.boot.serialno"] : ""
                    };

                    if (!string.IsNullOrEmpty(bootProps["ro.bootloader"]) && 
                        bootProps["ro.bootloader"].Contains("sdk"))
                    {
                        score += 10;
                        details.Add($"[LOW] Bootloader contains 'sdk' pattern");
                    }

                    // Check for emulator-specific network properties
                    var netProps = new Dictionary<string, string>
                    {
                        ["ro.nettype"] = props.ContainsKey("ro.nettype") ? props["ro.nettype"] : "",
                        ["ro.wifi.supplicant"] = props.ContainsKey("ro.wifi.supplicant") ? props["ro.wifi.supplicant"] : ""
                    };

                    if (!string.IsNullOrEmpty(netProps["ro.nettype"]) && 
                        netProps["ro.nettype"].Contains("wifi"))
                    {
                        // WiFi properties are common but not definitive
                        score += 5;
                        details.Add($"[LOW] Network property detected");
                    }

                    // Check for emulator-specific power properties
                    var powerProps = new Dictionary<string, string>
                    {
                        ["ro.power"] = props.ContainsKey("ro.power") ? props["ro.power"] : "",
                        ["ro.battery"] = props.ContainsKey("ro.battery") ? props["ro.battery"] : ""
                    };

                    if (!string.IsNullOrEmpty(powerProps["ro.power"]) && 
                        powerProps["ro.power"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"[LOW] Power property suggests default configuration");
                    }

                    // Check for emulator-specific audio properties
                    var audioProps = new Dictionary<string, string>
                    {
                        ["ro.audio"] = props.ContainsKey("ro.audio") ? props["ro.audio"] : "",
                        ["ro.sound"] = props.ContainsKey("ro.sound") ? props["ro.sound"] : ""
                    };

                    if (!string.IsNullOrEmpty(audioProps["ro.audio"]) && 
                        audioProps["ro.audio"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"[LOW] Audio property suggests default configuration");
                    }

                    // Check for emulator-specific camera properties
                    var cameraProps = new Dictionary<string, string>
                    {
                        ["ro.camera"] = props.ContainsKey("ro.camera") ? props["ro.camera"] : "",
                        ["ro.sensor"] = props.ContainsKey("ro.sensor") ? props["ro.sensor"] : ""
                    };

                    if (!string.IsNullOrEmpty(cameraProps["ro.camera"]) && 
                        cameraProps["ro.camera"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"[LOW] Camera property suggests default configuration");
                    }

                    // Check for emulator-specific location properties
                    var locProps = new Dictionary<string, string>
                    {
                        ["ro.location"] = props.ContainsKey("ro.location") ? props["ro.location"] : "",
                        ["ro.geolocation"] = props.ContainsKey("ro.geolocation") ? props["ro.geolocation"] : ""
                    };

                    if (!string.IsNullOrEmpty(locProps["ro.location"]) && 
                        locProps["ro.location"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"[LOW] Location property suggests default configuration");
                    }

                    // Check for emulator-specific touch properties
                    var touchProps = new Dictionary<string, string>
                    {
                        ["ro.touch"] = props.ContainsKey("ro.touch") ? props["ro.touch"] : "",
                        ["ro.input"] = props.ContainsKey("ro.input") ? props["ro.input"] : ""
                    };

                    if (!string.IsNullOrEmpty(touchProps["ro.touch"]) && 
                        touchProps["ro.touch"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"[LOW] Touch property suggests default configuration");
                    }

                    // Check for emulator-specific gesture properties
                    var gestureProps = new Dictionary<string, string>
                    {
                        ["ro.gesture"] = props.ContainsKey("ro.gesture") ? props["ro.gesture"] : "",
                        ["ro.swipe"] = props.ContainsKey("ro.swipe") ? props["ro.swipe"] : ""
                    };

                    if (!string.IsNullOrEmpty(gestureProps["ro.gesture"]) && 
                        gestureProps["ro.gesture"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"[LOW] Gesture property suggests default configuration");
                    }

                    // Check for emulator-specific proximity properties
                    var proxProps = new Dictionary<string, string>
                    {
                        ["ro.proximity"] = props.ContainsKey("ro.proximity") ? props["ro.proximity"] : "",
                        ["ro.nearfield"] = props.ContainsKey("ro.nearfield") ? props["ro.nearfield"] : ""
                    };

                    if (!string.IsNullOrEmpty(proxProps["ro.proximity"]) && 
                        proxProps["ro.proximity"].Contains("default"))
                    {
                        score += 5;
                        details.Add($"