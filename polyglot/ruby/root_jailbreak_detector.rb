#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'open3'
require 'json'

module Rootsentry
  class PostureVerdict < Struct.new(:score, :level, :details)
    def self.from_score(score)
      level = case score
              when 0..10   then :clean
              when 11..25   then :suspicious
              when 26..50   then :compromised
              else           :critical
              end
      new(score, level, {})
    end

    def self.from_json(json)
      data = JSON.parse(json)
      new(data['score'], data['level'], data['details'])
    end

    def to_json
      { 'score' => score, 'level' => level.to_s, 'details' => details }.to_json
    end
  end

  class RootJailbreakDetector
    # Android root indicators
    ANDROID_ROOT_PATHS = [
      '/system/bin/su',
      '/data/local/tmp/su',
      '/data/local/su',
      '/data/data/com.android.shell/dropbox/su'
    ].freeze

    ANDROID_ROOT_BINARIES = {
      'busybox' => '/system/xbin/busybox',
      'su'       => '/system/bin/su'
    }.freeze

    # iOS jailbreak indicators
    IOS_JAILBREAK_PATHS = [
      '/var/lib/apt/lists/*',
      '/Applications/Cydia.app/Contents/Resources',
      '/Applications/Sileo.app/Contents/Resources',
      '/Applications/Zebra.app/Contents/Resources',
      '/Applications/Rocky.app/Contents/Resources'
    ].freeze

    IOS_JAILBREAK_APPS = [
      'Cydia',
      'Sileo',
      'Zebra',
      'Rocky',
      'Substitute',
      'Filza',
      'iFile',
      'IntelliScreen'
    ].freeze

    # Emulator indicators (Android)
    EMULATOR_BUILD_PROPS = [
      { pattern: /ro\.product\.model=.*Emulator/, name: 'emulator_model' },
      { pattern: /ro\.build\.fingerprint=.*google/ , name: 'android_google' },
      { pattern: /ro\.product\.manufacturer=.*Google/, name: 'android_manufacturer' }
    ].freeze

    # Hook/tamper indicators
    HOOK_INDICATORS = [
      '/data/local/tmp/frida-server',
      '/data/data/com.android.shell/dropbox/frida-server',
      '/system/lib/libfrida.so',
      '/system/lib64/libfrida.so'
    ].freeze

    def initialize(options = {})
      @android_root_score = 0
      @ios_jailbreak_score = 0
      @emulator_score = 0
      @hook_score = 0
      @details = {}
      @options = options.merge({
        android: true,
        ios: false,
        emulator: true,
        hook: true
      })
    end

    def detect_all
      score = 0
      details = {}

      if @options[:android]
        check_android_root(score, details)
      end

      if @options[:ios] || !@options[:android].nil? && File.exist?('/var/lib/apt/lists/*')
        check_ios_jailbreak(score, details)
      end

      if @options[:emulator]
        check_emulator(score, details)
      end

      if @options[:hook]
        check_hook_indicators(score, details)
      end

      PostureVerdict.from_score(score)
    end

    private

    def check_android_root(current_score, details)
      root_found = false

      ANDROID_ROOT_PATHS.each do |path|
        if File.exist?(path) && File.executable?(path)
          root_found = true
          current_score += 15
          details[:'android_root_path'] ||= []
          details[:'android_root_path'] << path
        end
      end

      return unless root_found

      # Check for su binary hash (busybox vs real su)
      if File.exist?('/system/bin/su')
        begin
          output, _status = Open3.capture2('file /system/bin/su 2>/dev/null')
          if output.include?('busybox') || output.include?('ELF')
            current_score += 10
            details[:'android_root_file_type'] = output.strip
          end
        rescue StandardError; end
      end

      # Check uid via shell command
      begin
        uid_output, _status = Open3.capture2('id -u 2>/dev/null')
        if uid_output && uid_output.include?('uid=0')
          current_score += 15
          details[:'android_root_uid'] = 'uid=0'
        end
      rescue StandardError; end

      # Check /proc/self/status for root indicator
      begin
        proc_status, _status = Open3.capture2('cat /proc/self/status 2>/dev/null')
        if proc_status && proc_status.include?('Uid:\t0')
          current_score += 15
          details[:'android_root_proc'] = 'Uid: 0'
        end
      rescue StandardError; end

      # Check for common root apps
      root_apps = ['SuperSU', 'Magisk', 'KernelSU']
      root_apps.each do |app|
        begin
          output, _status = Open3.capture2("pm list packages 2>/dev/null | grep -i #{Regexp.escape(app)}")
          if output && !output.empty?
            current_score += 10
            details[:'android_root_app'] ||= []
            details[:'android_root_app'] << app
          end
        rescue StandardError; end
      end

      @android_root_score = current_score
    end

    def check_ios_jailbreak(current_score, details)
      jailbreak_found = false

      IOS_JAILBREAK_PATHS.each do |path|
        if File.exist?(path)
          jailbreak_found = true
          current_score += 12
          details[:'ios_path'] ||= []
          details[:'ios_path'] << path
        end
      end

      return unless jailbreak_found

      # Check for common jailbreak apps via shell command
      begin
        output, _status = Open3.capture2('ps aux 2>/dev/null | grep -E "Cydia|Sileo|Zebra|Rocky"')
        if output && !output.empty?
          current_score += 15
          details[:'ios_ps_output'] = output.strip[0..200]
        end
      rescue StandardError; end

      # Check for Cydia/Store paths
      begin
        cydia_path, _status = Open3.capture2('find /Applications -name "Cydia.app" 2>/dev/null')
        if cydia_path && !cydia_path.empty?
          current_score += 15
          details[:'ios_app'] ||= []
          details[:'ios_app'] << 'Cydia'
        end
      rescue StandardError; end

      # Check for common jailbreak file signatures
      begin
        output, _status = Open3.capture2('cat /var/lib/apt/lists/* 2>/dev/null | head -c 500')
        if output && !output.empty?
          current_score += 10
          details[:'ios_apt'] = true
        end
      rescue StandardError; end

      @ios_jailbreak_score = current_score
    end

    def check_emulator(current_score, details)
      # Check build.prop for emulator indicators
      begin
        output, _status = Open3.capture2('cat /system/build.prop 2>/dev/null')
        if output && !output.empty?
          lines = output.lines.map(&:strip).select { |l| l.start_with?('ro.') }

          EMULATOR_BUILD_PROPS.each do |indicator|
            pattern = indicator[:pattern]
            if lines.any? { |line| line.match?(pattern) }
              current_score += 8
              details[:'emulator_indicator'] ||= []
              details[:'emulator_indicator'] << indicator[:name]
            end
          end

          # Additional emulator checks
          emulator_patterns = [
            /ro\.product\.model=.*Emulator/,
            /ro\.build\.fingerprint=.*google/,
            /ro\.product\.manufacturer=.*Google/
          ]

          emulator_patterns.each do |pattern|
            if lines.any? { |line| line.match?(pattern) }
              current_score += 5
              details[:'emulator_pattern'] ||= []
              details[:'emulator_pattern'] << pattern.inspect
            end
          end
        end
      rescue StandardError; end

      # Check for common emulator apps
      begin
        output, _status = Open3.capture2('pm list packages 2>/dev/null | grep -iE "com\.android\.vndk|emulator"')
        if output && !output.empty?
          current_score += 5
          details[:'emulator_package'] = true
        end
      rescue StandardError; end

      @emulator_score = current_score
    end

    def check_hook_indicators(current_score, details)
      HOOK_INDICATORS.each do |path|
        if File.exist?(path)
          current_score += 10
          details[:'hook_path'] ||= []
          details[:'hook_path'] << path
        end
      end

      # Check for Frida server running
      begin
        output, _status = Open3.capture2('ps aux 2>/dev/null | grep -i frida')
        if output && !output.empty?
          current_score += 15
          details[:'hook_frida'] = true
        end
      rescue StandardError; end

      # Check for Xposed/Substrate hooks
      begin
        output, _status = Open3.capture2('pm list packages 2>/dev/null | grep -iE "xposed|substrate"')
        if output && !output.empty?
          current_score += 10
          details[:'hook_xposed'] = true
        end
      rescue StandardError; end

      @hook_score = current_score
    end
  end
end

# ============================================================================
# Entry Point / Demo
# ============================================================================

if __FILE__ == $PROGRAM_NAME
  puts "Rootsentry: Mobile Runtime Integrity Detector"
  puts "=" * 40

  detector = Rootsentry::RootJailbreakDetector.new(
    android: true,
    ios: true,
    emulator: true,
    hook: true
  )

  result = detector.detect_all

  puts "\nPosture Verdict:"
  puts "  Score: #{result.score}"
  puts "  Level: #{result.level.to_s.upcase}"

  if result.details.empty?
    puts "  Details: No indicators found"
  else
    puts "  Details:"
    result.details.each do |key, value|
      next unless value
      puts "    - #{key}: #{value.inspect[0..150]}#{'...' if value.is_a?(String) && value.length > 150}"
    end
  end

  # Exit with appropriate code for CI/CD pipelines
  exit result.score > 25 ? 1 : 0
end