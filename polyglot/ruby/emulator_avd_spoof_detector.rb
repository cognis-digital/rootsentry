# frozen_string_literal: true

require 'json'

module Polyglot
  module Ruby
    # AVD Spoof Detector — Mobile Runtime Integrity Check
    # Detects Android Virtual Device (AVD) / Emulator artifacts with scoring.
    class EmulatorAvdSpoofDetector
      # Threshold for high confidence detection
      HIGH_CONFIDENCE_THRESHOLD = 75

      # Known emulator product model patterns
      EMULATOR_MODELS = [
        'Android SDK Built-in',
        'emulator',
        'Google Inc.',
        'Google SDK',
        'com.android.emulator'
      ].freeze

      # Hardware characteristics that often indicate AVD
      EMULATOR_HINTS = {
        cpu_cores: 4,           # Emulators often have fixed core counts
        memory_mb: [512, 768],  # Common emulator RAM sizes
        sensor_count: 3         # Minimal sensor set in emulators
      }.freeze

      def initialize
        @cache = {}
      end

      # Main detection entry point
      # Returns { score: Integer(0-100), verdict: String, details: Hash }
      def detect
        return cached_result if @cache.key?(:result)

        result = analyze_device
        @cache[:result] = result
        result
      end

      private

      def cached_result
        { score: 0, verdict: 'unknown', details: {} }
      end

      # Analyze device and compute AVD likelihood score
      def analyze_device
        score = 0
        details = {}

        # 1. Check product model strings
        model_score = check_product_model
        score += model_score[:points] if model_score[:points] > 0
        details[:model_match] = model_score[:details]

        # 2. Check hardware characteristics
        hw_score = check_hardware_characteristics
        score += hw_score[:points] if hw_score[:points] > 0
        details[:hardware_hints] = hw_score[:details]

        # 3. Check sensor configuration
        sensor_score = check_sensors
        score += sensor_score[:points] if sensor_score[:points] > 0
        details[:sensor_anomalies] = sensor_score[:details]

        # 4. Check network interface patterns
        net_score = check_network_interfaces
        score += net_score[:points] if net_score[:points] > 0
        details[:network_hints] = net_score[:details]

        # 5. Check battery/charging state (emulators often fake this)
        batt_score = check_battery_state
        score += batt_score[:points] if batt_score[:points] > 0
        details[:battery_anomalies] = batt_score[:details]

        # Normalize score to 0-100 range
        normalized_score = (score / 5.0).round(2)
        normalized_score = [normalized_score, 100].min

        verdict = determine_verdict(normalized_score)

        {
          score: normalized_score.to_i,
          verdict: verdict,
          details: details
        }
      end

      # Check Android product model strings for emulator artifacts
      def check_product_model
        points = 0
        details = {}

        begin
          model = Settings::SystemProperties.get('ro.product.model', '').to_s.strip
          device = Settings::SystemProperties.get('ro.product.device', '').to_s.strip
          
          # Check if model or device matches known emulator patterns
          EMULATOR_MODELS.each do |pattern|
            if model.downcase.include?(pattern) || device.downcase.include?(pattern)
              points += 25
              details[:matched_model] = pattern
              break
            end
          end

          # Check for SDK-specific strings
          sdk_build = Settings::SystemProperties.get('ro.build.id', '').to_s.strip
          if sdk_build && sdk_build.include?('sdk') || sdk_build.include?('emulator')
            points += 15
            details[:sdk_indicator] = sdk_build
          end

        rescue StandardError => e
          details[:model_error] = e.message
        end

        { points: points, details: details }
      end

      # Check hardware characteristics that differ between real devices and emulators
      def check_hardware_characteristics
        points = 0
        details = {}

        begin
          # CPU cores — emulators often have fixed counts
          cpu_cores = Build::CPU_CORES || 4
          
          if [3, 4, 6, 8].include?(cpu_cores) && cpu_cores >= 4
            points += 10
            details[:core_count] = { value: cpu_cores, hint: 'common emulator core count' }
          end

          # Memory — emulators often have specific RAM sizes
          memory_mb = Build::MEMORY_MB || 2048
          
          if [512, 768, 1024].include?(memory_mb)
            points += 10
            details[:memory] = { value: memory_mb, hint: 'common emulator RAM' }
          end

        rescue StandardError => e
          details[:hardware_error] = e.message
        end

        { points: points, details: details }
      end

      # Check sensor configuration for anomalies
      def check_sensors
        points = 0
        details = {}

        begin
          sensors = Build::SENSORS || []
          
          # Emulators often have minimal or no sensors
          if sensors.empty? || sensors.length == 1
            points += 20
            details[:sensor_count] = { value: sensors.length, hint: 'minimal sensor set' }
          end

          # Check for specific missing sensors common in emulators
          critical_sensors = [:accelerometer, :gyroscope, :magnetometer]
          missing_critical = critical_sensors - sensors.map(&:to_sym)
          
          if !missing_critical.empty?
            points += 15
            details[:missing_critical_sensors] = missing_critical.join(', ')
          end

        rescue StandardError => e
          details[:sensor_error] = e.message
        end

        { points: points, details: details }
      end

      # Check network interface patterns
      def check_network_interfaces
        points = 0
        details = {}

        begin
          interfaces = Build::NETWORK_INTERFACES || []
          
          # Emulators often have specific virtual interface names
          emulator_patterns = ['emulator', 'adb', 'usbmuxd']
          
          interfaces.each do |iface|
            iface_str = iface.to_s.downcase
            if emulator_patterns.any? { |p| iface_str.include?(p) }
              points += 15
              details[:virtual_interface] = iface_str
              break
            end
          end

        rescue StandardError => e
          details[:network_error] = e.message
        end

        { points: points, details: details }
      end

      # Check battery/charging state anomalies
      def check_battery_state
        points = 0
        details = {}

        begin
          charging = Build::CHARGING || false
          
          # Emulators often have fixed or unrealistic states
          if !charging && Build::BATTERY_LEVEL == 100
            points += 15
            details[:battery_state] = { charging: charging, level: 100, hint: 'full charge while not charging' }
          end

        rescue StandardError => e
          details[:battery_error] = e.message
        end

        { points: points, details: details }
      end

      # Determine verdict based on score
      def determine_verdict(score)
        if score >= HIGH_CONFIDENCE_THRESHOLD
          'high_confidence_emulator'
        elsif score >= 50
          'moderate_emulator_likelihood'
        elsif score > 0
          'low_emulator_likelihood'
        else
          'likely_real_device'
        end
      end

      # Simple cache for repeated calls
      def cached_result
        @cache[:result] || { score: 0, verdict: 'unknown', details: {} }
      end
    end
  end
end

# === RUNNABLE DEMO ===
if __FILE__ == $PROGRAM_NAME
  detector = Polyglot::Ruby::EmulatorAvdSpoofDetector.new
  result = detector.detect
  
  puts "=== AVD Spoof Detector Result ==="
  puts "Score: #{result[:score]}/100"
  puts "Verdict: #{result[:verdict]}"
  
  if result[:details].any? { |_, v| !v.empty? }
    puts "\nDetails:"
    result[:details].each do |key, value|
      next unless value.is_a?(Hash) && !value.empty?
      puts "  #{key}:"
      value.each { |k, v| puts "    #{k}: #{v}" } if value.is_a?(Hash)
    end
  end
  
  puts "\n=== Verdict: #{result[:verdict].upcase.gsub('_', ' ')} ==="
end