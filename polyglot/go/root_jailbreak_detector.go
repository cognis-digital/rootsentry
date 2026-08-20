package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Detector holds state for the integrity check
type Detector struct {
	score    int
	details   []string
	mu        sync.Mutex
}

func NewDetector() *Detector {
	return &Detector{score: 0, details: make([]string, 0)}
}

// addScore increments score and logs detail if verbose
func (d *Detector) addScore(points int, msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.score += points
	if len(d.details) < 100 {
		d.details = append(d.details, msg)
	}
}

// getVerdict returns the posture based on score
func (d *Detector) getVerdict(score int) string {
	switch {
	case score <= 19:
		return "CLEAN"
	case score <= 49:
		return "SUSPICIOUS"
	default:
		return "COMPROMISED"
	}
}

// getScoredResult returns formatted output
func (d *Detector) getScoredResult() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ROOTSENTRY v1.0 - Runtime Integrity Report\n"))
	sb.WriteString(strings.Repeat("=", 40) + "\n")
	sb.WriteString(fmt.Sprintf("Posture: %s (Score: %d/100)\n", d.getVerdict(d.score), d.score))
	
	if len(d.details) > 0 {
		sb.WriteString("\nFindings:\n")
		for _, f := range d.details {
			sb.WriteString(fmt.Sprintf("  • %s\n", f))
		}
	}
	
	return sb.String()
}

// checkAndroidRoot checks for Android root indicators
func (d *Detector) checkAndroidRoot() {
	details := []string{}
	
	// Check for su binary in common locations
	suPaths := []string{
		"/system/bin/su",
		"/system/xbin/su",
		"/data/local/tmp/su",
		"/data/local/bin/su",
		"/sbin/su",
	}
	
	for _, path := range suPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			d.addScore(10, fmt.Sprintf("Found su binary at %s", path))
			break
		}
	}
	
	// Check system properties via getprop simulation
	propsToCheck := map[string]string{
		"ro.rootdir":           "/data/local/tmp",
		"ro.debuggable":        "true",
		"persist.sys.usb.config": "adb,debug",
	}
	
	for key, expected := range propsToCheck {
		if val, err := exec.Command("getprop", key).Output(); err == nil {
			valStr := strings.TrimSpace(string(val))
			if valStr == expected || (key == "ro.debuggable" && valStr == "true") {
				d.addScore(5, fmt.Sprintf("Property %s matches suspicious value: %s", key, valStr))
			}
		}
	}
	
	// Check mount points for jailbreak mounts
	mountPoints := []string{
		"/data/local/tmp",
		"/mnt/shell_subdir",
		"/data/data/com.android.shell/dropbox",
	}
	
	for _, mp := range mountPoints {
		if info, err := os.Stat(mp); err == nil && !info.IsDir() {
			d.addScore(5, fmt.Sprintf("Found suspicious mount point: %s", mp))
		} else if err == nil && info.IsDir() {
			d.addScore(3, fmt.Sprintf("Directory at %s exists (may indicate root)", mp))
		}
	}
	
	// Check for busybox which is often present in rooted devices
	if _, err := os.Stat("/system/bin/busybox"); err == nil {
		d.addScore(2, "Found busybox - common in rooted Android")
	}
}

// checkIOSJailbreak checks for iOS jailbreak indicators
func (d *Detector) checkIOSJailbreak() {
	details := []string{}
	
	// Check for common jailbreak binaries
	jbBinaries := []string{
		"/var/lib/cydia",
		"/usr/bin/sileo",
		"/Applications/Sileo.app/Contents/MacOS/Sileo",
		"/Library/Application Support/Cydia",
	}
	
	for _, path := range jbBinaries {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			d.addScore(15, fmt.Sprintf("Found jailbreak indicator at %s", path))
		}
	}
	
	// Check for Cydia/Sileo presence via file checks
	cydiaPaths := []string{
		"/var/lib/cydia/installed_packages.db",
		"/Library/Application Support/Cydia/packages.db",
	}
	
	for _, path := range cydiaPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			d.addScore(10, fmt.Sprintf("Found Cydia database at %s", path))
		}
	}
	
	// Check for SpringBoard modifications (jailbreak often modifies SB)
	if _, err := os.Stat("/var/mobile/Library/Preferences/com.apple.SpringBoard.plist"); err == nil {
		d.addScore(3, "SpringBoard preferences found - may indicate jailbreak")
	}
	
	// Check for common jailbreak tweak paths
	tweakPaths := []string{
		"/var/tweaks",
		"/Library/MobileSubstrate/DynamicLibraries/",
	}
	
	for _, path := range tweakPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			d.addScore(8, fmt.Sprintf("Found tweak directory at %s", path))
		}
	}
}

// checkEmulator detects emulator indicators
func (d *Detector) checkEmulator() {
	details := []string{}
	
	// Check for emulator-specific properties
	emulatorProps := map[string]string{
		"ro.product.model":       "Generic",
		"ro.product.manufacturer": "Google Inc.",
	}
	
	for key, expected := range emulatorProps {
		if val, err := exec.Command("getprop", key).Output(); err == nil {
			valStr := strings.TrimSpace(string(val))
			if valStr == expected {
				d.addScore(10, fmt.Sprintf("Emulator-like property: %s=%s", key, valStr))
			}
		}
	}
	
	// Check for emulator-specific mount points
	emulatorMounts := []string{
		"/data/local/tmp/emulator",
		"/sdcard/Android/data/com.android.emulator",
	}
	
	for _, mp := range emulatorMounts {
		if info, err := os.Stat(mp); err == nil && !info.IsDir() {
			d.addScore(8, fmt.Sprintf("Found emulator indicator at %s", mp))
		}
	}
	
	// Check for common emulator process names
	emulatorProcs := []string{
		"emulator-5554",
		"com.android.emulator",
		"Android Emulator",
	}
	
	for _, proc := range emulatorProcs {
		if cmd := exec.Command("ps", "A"); err == nil {
			out, _ := cmd.Output()
			if strings.Contains(string(out), proc) {
				d.addScore(12, fmt.Sprintf("Emulator process detected: %s", proc))
				break
			}
		}
	}
	
	// Check for emulator-specific memory patterns (approximate check)
	if info, err := os.Stat("/proc/self/status"); err == nil {
		file, _ := os.Open("/proc/self/status")
		defer file.Close()
		
		scanner := new(strings.Reader)
		scanner.Reset(file)
		
		for line := scanner.ReadString('\n'); len(line) > 0; line = scanner.ReadString('\n') {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "VmSize" {
				vmSize, _ := strconv.ParseInt(parts[1], 10, 64)
				// Emulators often have very large virtual memory allocations
				if vmSize > 5*1024*1024*1024 && parts[0] == "VmSize" {
					d.addScore(5, fmt.Sprintf("Large VmSize detected: %.2f GB", float64(vmSize)/(1024*1024*1024)))
				}
			}
		}
	}
}

// checkHookTamper detects hooking and tampering indicators
func (d *Detector) checkHookTamper() {
	details := []string{}
	
	// Check for Frida/Xposed/LLHook signatures in process list
	hookProcs := []string{
		"frida-server",
		"xposed",
		"llhook",
		"zygote32", // Often modified in hooked environments
	}
	
	for _, proc := range hookProcs {
		if cmd := exec.Command("ps", "A"); err == nil {
			out, _ := cmd.Output()
			if strings.Contains(string(out), proc) {
				d.addScore(15, fmt.Sprintf("Hook-related process detected: %s", proc))
			}
		}
	}
	
	// Check for common hook libraries in memory (via /proc/meminfo patterns)
	if info, err := os.Stat("/proc/self/maps"); err == nil {
		file, _ := os.Open("/proc/self/maps")
		defer file.Close()
		
		scanner := new(strings.Reader)
		scanner.Reset(file)
		
		hookLibs := []string{
			"libfrida-",
			"libxposed",
			"libllhook",
			"libhooker",
		}
		
		for line := scanner.ReadString('\n'); len(line) > 0; line = scanner.ReadString('\n') {
			if strings.Contains(line, "r-xp") || strings.Contains(line, "r--p") {
				for _, lib := range hookLibs {
					if strings.Contains(line, lib) {
						d.addScore(12, fmt.Sprintf("Potential hook library in memory: %s", lib))
					}
				}
			}
		}
	}
	
	// Check for modified system binaries (hash comparison would be ideal)
	modifiedBinaries := []string{
		"/system/bin/sh",
		"/system/bin/zygote",
		"/system/lib/libc.so",
	}
	
	for _, bin := range modifiedBinaries {
		if info, err := os.Stat(bin); err == nil && !info.IsDir() {
			// Check if binary is writable (suspicious for system binaries)
			if perm := info.Mode().Perm(); perm&0200 != 0 { // Writable by owner
				d.addScore(10, fmt.Sprintf("System binary %s is writable", bin))
			}
		}
	}
	
	// Check for debugger attached (gdbserver, xcode debug)
	debuggers := []string{
		"gdbserver",
		"xcrun simctl",
		"lldb-server",
	}
	
	for _, dbg := range debuggers {
		if cmd := exec.Command("ps", "A"); err == nil {
			out, _ := cmd.Output()
			if strings.Contains(string(out), dbg) {
				d.addScore(8, fmt.Sprintf("Debugger indicator found: %s", dbg))
			}
		}
	}
	
	// Check for common tamper detection bypass indicators
	tamperIndicators := []string{
		"ro.debuggable=1",
		"persist.sys.usb.config=adb,debug",
	}
	
	for _, indicator := range tamperIndicators {
		if val, err := exec.Command("getprop", strings.Split(indicator, "=")[0]).Output(); err == nil {
			valStr := strings.TrimSpace(string(val))
			if valStr == strings.Split(indicator, "=")[1] || (indicator == "ro.debuggable=1" && valStr == "true") {
				d.addScore(5, fmt.Sprintf("Tamper indicator: %s", indicator))
			}
		}
	}
}

// checkEnvironment checks environment variables and basic state
func (d *Detector) checkEnvironment() {
	details := []string{}
	
	// Check for common environment indicators
	envVars := map[string]string{
		"ANDROID_ROOT":          "1",
		"ANDROID_SHELL_PATH":    "/data/local/shell",
	}
	
	for key, expected := range envVars {
		if val := os.Getenv(key); val == expected {
			d.addScore(5, fmt.Sprintf("Environment variable %s=%s matches indicator", key, val))
		}
	}
	
	// Check for common jailbreak/emulator environment patterns
	jailbreakEnv := []string{
		"JB_ENV=1",
		"EMULATOR=true",
	}
	
	for _, env := range jailbreakEnv {
		if val, ok := os.LookupEnv(env); ok && (val == "1" || val == "true") {
			d.addScore(8, fmt.Sprintf("Environment pattern detected: %s=%s", env, val))
		}
	}
	
	// Check process list for suspicious patterns
	if cmd := exec.Command("ps", "-A"); err == nil {
		out, _ := cmd.Output()
		
		suspiciousPatterns := []string{
			"frida-",
			"xposed",
			"llhook",
			"z32", // Short for zygote32
		}
		
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(string(out), pattern) {
				d.addScore(7, fmt.Sprintf("Suspicious process pattern: %s", pattern))
			}
		}
	}
	
	// Check for common jailbreak tweak paths in environment
	tweakPaths := []string{
		"/var/tweaks/",
		"/Library/MobileSubstrate/DynamicLibraries/",
	}
	
	for _, path := range tweakPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			d.addScore(6, fmt.Sprintf("Tweak directory found: %s", path))
		}
	}
}

// checkMemoryPatterns checks for memory-based indicators
func (d *Detector) checkMemoryPatterns() {
	details := []string{}
	
	// Check /proc/self/status for suspicious patterns
	if info, err := os.Stat("/proc/self/status"); err == nil {
		file, _ := os.Open("/proc/self/status")
		defer file.Close()
		
		scanner := new(strings.Reader)
		scanner.Reset(file)
		
		for line := scanner.ReadString('\n'); len(line) > 0; line = scanner.ReadString('\n') {
			parts := strings.Fields(line)
			
			// Check for high memory usage (common in emulators/hooked apps)
			if len(parts) >= 2 && parts[0] == "VmSize" {
				vmSize, _ := strconv.ParseInt(parts[1], 10, 64)
				vmRSS, _ := strconv.ParseInt(parts[3], 10, 64)
				
				// Very high VmSize/RSS ratio can indicate emulation
				if vmSize > 0 && vmRSS/vmSize < 0.5 {
					d.addScore(4, fmt.Sprintf("High memory overhead: %.2f%%", float64(vmRSS)/float64(vmSize)*100))
				}
			}
			
			// Check for