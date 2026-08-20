package emulator_avd_spoof_detector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// EmulatorModel represents known AVD model signatures
type EmulatorModel struct {
	Name       string
	Pattern    *regexp.Regexp
	Score      int // Base score contribution (0-30)
	Description string
}

var emulatorModels = []EmulatorModel{
	{"Android SDK built for x86", regexp.MustCompile(`.*x86.*`), 25, "Classic AVD x86"},
	{"Generic", regexp.MustCompile(`.*Generic.*`), 20, "Generic AVD template"},
	{"Pixel Emulator", regexp.MustCompile(`.*Pixel.*Emulator.*`), 24, "Google Pixel emulator"},
	{"Nexus Emulator", regexp.MustCompile(`.*Nexus.*Emulator.*`), 23, "Nexus emulator variant"},
	{"Shamu", regexp.MustCompile(`.*shamu.*`), 18, "Pixel XL emulator codename"},
	{"Rex", regexp.MustCompile(`.*rex.*`), 17, "Pixel emulator codename"},
	{"Tuna", regexp.MustCompile(`.*tuna.*`), 16, "Pixel 2 emulator codename"},
	{"Blue", regexp.MustCompile(`.*blue.*`), 15, "Pixel 3 emulator codename"},
	{"Bluejay", regexp.MustCompile(`.*bluejay.*`), 14, "Pixel 3 XL emulator codename"},
}

// HardwareProfile represents expected hardware for real devices vs emulators
type HardwareProfile struct {
	ModelName     string
	Cores         int
	MemoryMB      int64
	IsEmulator    bool
	Score         int
	Description   string
}

var knownEmulatorHardware = []HardwareProfile{
	{"Android SDK built for x86", 4, 2048, true, 25, "Classic x86 AVD"},
	{"Generic", 4, 1024, true, 20, "Generic AVD profile"},
	{"Pixel Emulator", 8, 4096, true, 24, "Google Pixel emulator"},
}

// Detector holds state for a single detection run
type Detector struct {
	modelName     string
	buildFingerprints []string
	hardware       HardwareProfile
	score         int
	verdict       Verdict
	reasons       []string
}

// Verdict represents the final determination
type Verdict struct {
	Score        int    // 0-100, higher = more likely emulator
	Level        string // "CLEAN", "SUSPICIOUS", "LIKELY", "CONFIRMED"
	Confidence   float64 // 0.0-1.0
}

// Level constants for readability
const (
	VerdictClean    VerdictLevel = "CLEAN"
	VerdictSuspicious VerdictLevel = "SUSPICIOUS"
	VerdictLikely   VerdictLevel = "LIKELY"
	VerdictConfirmed VerdictLevel = "CONFIRMED"
)

// Level thresholds
var levelThresholds = []struct {
	Score    int
	Level    VerdictLevel
	Confidence float64
}{
	{0, VerdictClean, 1.0},
	{25, VerdictSuspicious, 0.75},
	{50, VerdictLikely, 0.50},
	{75, VerdictConfirmed, 0.25},
}

// Detect runs the full analysis and returns a Verdict
func (d *Detector) Detect() Verdict {
	d.score = 0
	d.reasons = make([]string, 0)

	// Check model name against known emulator patterns
	d.checkModelName()

	// Check hardware profile
	d.checkHardwareProfile()

	// Check build fingerprints
	d.checkBuildFingerprints()

	// Calculate confidence and determine level
	d.calculateConfidence()

	return d.verdict
}

func (d *Detector) checkModelName() {
	for _, model := range emulatorModels {
		if model.Pattern.MatchString(d.modelName) {
			d.score += model.Score
			d.reasons = append(d.reasons, fmt.Sprintf("Model name matches '%s' pattern", model.Name))
		}
	}

	if d.score == 0 && !strings.Contains(strings.ToLower(d.modelName), "emulator") {
		d.reasons = append(d.reasons, "Model name does not match known emulator patterns")
	}
}

func (d *Detector) checkHardwareProfile() {
	for _, profile := range knownEmulatorHardware {
		if d.hardware.ModelName == profile.ModelName && d.hardware.IsEmulator {
			d.score += profile.Score
			d.reasons = append(d.reasons, fmt.Sprintf("Hardware matches '%s' emulator profile", profile.Description))
		}
	}

	// Check for suspiciously clean hardware (too many cores for typical phone)
	if d.hardware.Cores > 8 && !strings.Contains(strings.ToLower(d.modelName), "x86") {
		d.score += 10
		d.reasons = append(d.reasons, "High core count suggests x86 emulator or high-end device")
	}

	// Check for suspiciously low memory (common in emulators)
	if d.hardware.MemoryMB < 512 && !strings.Contains(strings.ToLower(d.modelName), "x86") {
		d.score += 8
		d.reasons = append(d.reasons, "Low memory profile common in AVDs")
	}
}

func (d *Detector) checkBuildFingerprints() {
	emulatorProps := map[string]int{
		"ro.product.model":           15,
		"ro.build.fingerprint":       12,
		"ro.bootloader.id":           10,
		"ro.hardware":                8,
	}

	for _, fp := range d.buildFingerprints {
		for prop, score := range emulatorProps {
			if strings.Contains(fp, prop) {
				d.score += score
				d.reasons = append(d.reasons, fmt.Sprintf("Build fingerprint contains '%s' indicator", prop))
			}
		}

		// Check for specific AVD fingerprint patterns
		avdPatterns := []string{
			"Android SDK built for x86",
			"com.android.emulator",
			"androidsdk/",
			"emulator-",
		}

		for _, pattern := range avdPatterns {
			if strings.Contains(fp, pattern) {
				d.score += 10
				d.reasons = append(d.reasons, fmt.Sprintf("Build fingerprint contains AVD indicator: '%s'", pattern))
			}
		}
	}

	if len(d.buildFingerprints) == 0 {
		d.reasons = append(d.reasons, "No build fingerprints available for analysis")
	}
}

func (d *Detector) calculateConfidence() {
	maxScore := 100
	if d.score > maxScore {
		d.score = maxScore
	}

	// Map score to level and confidence
	for _, threshold := range levelThresholds {
		if d.score >= threshold.Score {
			d.level = threshold.Level
			d.confidence = threshold.Confidence
			break
		}
	}

	// Adjust confidence based on number of reasons found
	reasonCount := len(d.reasons)
	if reasonCount > 3 {
		d.confidence += 0.15
	} else if reasonCount == 0 {
		d.confidence -= 0.20
	}

	if d.confidence > 1.0 {
		d.confidence = 1.0
	}
}

// NewDetector creates a new detector with the given hardware profile
func NewDetector(modelName string, cores int, memoryMB int64) *Detector {
	return &Detector{
		modelName: modelName,
		hardware: HardwareProfile{
			ModelName:  modelName,
			Cores:      cores,
			MemoryMB:   memoryMB,
			IsEmulator: false, // Will be set by checkHardwareProfile
		},
	}
}

// DetectFromProps analyzes build properties from a map
func (d *Detector) DetectFromProps(props map[string]string) Verdict {
	d.buildFingerprints = make([]string, 0)

	for key, value := range props {
		if !strings.Contains(key, "ro.") {
			continue // Skip non-RO properties
		}

		// Include relevant RO properties
		relevantProps := []string{
			"product.model",
			"build.fingerprint",
			"bootloader.id",
			"hardware",
			"device.product.name",
			"ro.build.version.release",
		}

		for _, rp := range relevantProps {
			if strings.Contains(key, rp) {
				d.buildFingerprints = append(d.buildFingerprints, fmt.Sprintf("%s=%s", key, value))
			}
		}

		// Also include the full property string for pattern matching
		d.buildFingerprints = append(d.buildFingerprints, value)
	}

	return d.Detect()
}

// DetectFromEnv analyzes environment variables (useful when running in containerized environments)
func (d *Detector) DetectFromEnv(env map[string]string) Verdict {
	d.buildFingerprints = make([]string, 0)

	for key, value := range env {
		if strings.Contains(strings.ToLower(key), "android") ||
			strings.Contains(strings.ToLower(key), "sdk") ||
			strings.Contains(strings.ToLower(key), "emulator") {
			d.buildFingerprints = append(d.buildFingerprints, fmt.Sprintf("%s=%s", key, value))
		}

		if strings.Contains(value, "android") ||
			strings.Contains(value, "sdk") ||
			strings.Contains(value, "emulator") {
			d.buildFingerprints = append(d.buildFingerprints, value)
		}
	}

	return d.Detect()
}

// DetectFromPath analyzes a file path (useful for /proc/self/cmdline or similar)
func (d *Detector) DetectFromPath(path string) Verdict {
	d.buildFingerprints = make([]string, 0)

	if path == "" {
		return d.Detect()
	}

	content, err := os.ReadFile(path)
	if err != nil {
		d.reasons = append(d.reasons, fmt.Sprintf("Failed to read file: %v", err))
		return d.Detect()
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || !strings.Contains(strings.ToLower(line), "android") &&
			!strings.Contains(strings.ToLower(line), "emulator") {
			continue
		}

		d.buildFingerprints = append(d.buildFingerprints, line)
	}

	return d.Detect()
}

// DetectFromStream analyzes a reader (useful for /proc/self/cmdline or similar streams)
func (d *Detector) DetectFromStream(r *bufio.Reader) Verdict {
	d.buildFingerprints = make([]string, 0)

	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			lines := strings.Split(string(buf[:n]), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if len(line) == 0 || !strings.Contains(strings.ToLower(line), "android") &&
					!strings.Contains(strings.ToLower(line), "emulator") {
					continue
				}

				d.buildFingerprints = append(d.buildFingerprints, line)
			}
		}
		if err != nil || n == 0 {
			break
		}
	}

	return d.Detect()
}

// DetectFromReader wraps a reader for convenience
func (d *Detector) DetectFromReader(r io.Reader) Verdict {
	reader := bufio.NewReader(r)
	return d.DetectFromStream(reader)
}

// GetReport returns a human-readable report of the detection
func (d *Detector) GetReport() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== AVD SPOOF DETECTION REPORT ===\n\n"))
	sb.WriteString(fmt.Sprintf("Model Name: %s\n", d.modelName))
	sb.WriteString(fmt.Sprintf("Hardware Profile:\n  Cores: %d\n  Memory: %d MB\n\n", d.hardware.Cores, d.hardware.MemoryMB))

	if len(d.buildFingerprints) > 0 {
		sb.WriteString(fmt.Sprintf("Build Fingerprints Analyzed (%d):\n", len(d.buildFingerprints)))
		for i, fp := range d.buildFingerprints[:min(10, len(d.buildFingerprints))] {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, fp))
		}
		if len(d.buildFingerprints) > 10 {
			sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(d.buildFingerprints)-10))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Score: %d/100\n", d.score))
	sb.WriteString(fmt.Sprintf("Level: %s\n", d.level))
	sb.WriteString(fmt.Sprintf("Confidence: %.2f\n\n", d.confidence))

	if len(d.reasons) > 0 {
		sb.WriteString("Reasons:\n")
		for i, reason := range d.reasons[:min(10, len(d.reasons))] {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, reason))
		}
		if len(d.reasons) > 10 {
			sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(d.reasons)-10))
		}
	}

	return sb.String()
}

// DetectFromReader is a convenience function that wraps the detector lifecycle
func DetectFromReader(r io.Reader) Verdict {
	d := NewDetector("", 4, 2048) // Default values
	return d.DetectFromStream(bufio.NewReader(r))
}

// DetectFromProps is a convenience function for build properties
func DetectFromProps(props map[string]string) Verdict {
	d := NewDetector("", 4, 2048)
	return d.DetectFromProps(props)
}

// DetectFromEnv is a convenience function for environment variables
func DetectFromEnv(env map[string]string) Verdict {
	d := NewDetector("", 4, 2048)
	return d.DetectFromEnv(env)
}

// DetectFromFile is a convenience function for file paths
func DetectFromFile(path string) (Verdict, error) {
	if path == "" {
		path = "/proc/self/cmdline"
	}

	d := NewDetector("", 4, 2048)
	reader, err := os.Open(path)
	if err != nil {
		return d.Detect(), fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	return d.DetectFromReader(reader), nil
}

// DetectFromStdin is a convenience function for stdin input
func DetectFromStdin() Verdict {
	d := NewDetector("", 4, 2048)
	return d.DetectFromStream(bufio.NewReader(os.Stdin))
}

// RunDemo runs a self-test with various inputs and prints results
func RunDemo() {
	fmt.Println("=== ROOTSENTRY: AVD SPOOF DETECTOR DEMO ===\n")

	// Test 1: Real device-like profile
	fmt.Println("--- Test 1: Real Device Profile ---")
	d1 := NewDetector("Pixel 6 Pro", 8, 4096)
	d1.buildFingerprints = []string{
		"ro.product.model=Pixel 6 Pro",
		"ro.build.fingerprint=google/pixel6/pro:12/SP1A.210812.023/X51S:user/release-keys",
	}
	v1 := d1.Detect()
	fmt.Printf("Score: %d, Level: %s, Confidence: %.2f\n\n", v1.Score, v1.Level, v1.Confidence)

	// Test 2: Classic AVD x86
	fmt.Println("--- Test 2: Classic AVD x86 ---")
	d2 := NewDetector("Android SDK built for x86", 4, 2048)
	d2.buildFingerprints = []string{
		"ro.product.model=Android SDK built for x86",
		"ro.build.fingerprint=com.android.emulator/Android SDK built for x86/12.0.0:user/release-keys",
	}
	v2 := d2.Detect()
	fmt.Printf("Score: %d, Level: %s, Confidence: %.2f\n\n", v2.Score, v2.Level, v2.Confidence)

	// Test 3: Generic AVD
	fmt.Println("---