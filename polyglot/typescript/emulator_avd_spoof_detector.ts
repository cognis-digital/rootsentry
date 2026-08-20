import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// ============================================================================
// CONSTANTS: Known Emulator/AVD Signatures
// ============================================================================

namespace AVD_SIGNATURES {
  // Build fingerprints that indicate emulator environments
  export const EMULATOR_BUILD_FINGERPRINTS: string[] = [
    'generic',
    'sdk_gphone_x86',
    'sdk_gphone_x86_arm',
    'sdk_gphone64_x86',
    'sdk_gphone64_x86_arm',
    'sdk_gphone64_arm64',
    'sdk_emu',
    'emulator',
    'genymotion',
    'bluestacks',
    'noobphone',
    'mumu',
    'mobogenie',
    'smartgamer',
    'appium',
  ];

  // Product names indicating emulator
  export const EMULATOR_PRODUCT_NAMES: string[] = [
    'sdk_gphone_x86',
    'sdk_gphone_x86_arm',
    'sdk_gphone64_x86',
    'genymotion',
    'bluestacks',
    'noobphone',
    'mumu',
    'mobogenie',
  ];

  // Model names indicating emulator
  export const EMULATOR_MODEL_NAMES: string[] = [
    'Android SDK built for x86',
    'Android SDK built for x86_64',
    'Genymotion',
    'Bluestacks',
    'NoobPhone',
    'Mumu Player',
  ];

  // Hardware manufacturers indicating emulator
  export const EMULATOR_MANUFACTURERS: string[] = [
    'Google Inc.',
    'Genymotion',
    'BlueStacks',
    'Mumu',
    'NoobPhone',
  ];

  // CPU architectures that strongly suggest x86-based emulators
  export const EMULATOR_CPU_ARCHITECTURES: string[] = [
    'x86',
    'x86_64',
    'amd64',
    'i386',
    'i686',
  ];

  // Memory sizes commonly seen in emulators (in MB)
  export const EMULATOR_MEMORY_SIZES: number[] = [
    1024,   // 1GB - very common default
    2048,   // 2GB - common for newer emulators
    3072,   // 3GB
    4096,   // 4GB
    5120,   // 5GB
    6144,   // 6GB
  ];

  // Graphics renderer patterns for emulators
  export const EMULATOR_GRAPHICS_PATTERNS: string[] = [
    'OpenGL ES',
    'GLSurfaceView',
    'SoftwareRenderer',
  ];
}

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface AVDDetectorConfig {
  // Threshold for considering a device as emulated (0.0 - 1.0)
  defaultThreshold: number;
  
  // Whether to include less common signatures in detection
  includeLegacySignatures: boolean;
}

interface DetectionResult {
  isEmulator: boolean;
  confidenceScore: number;           // 0.0 (certain real device) - 1.0 (certain emulator)
  detectedVectors: string[];         // Which signals triggered detection
  details: AVDDetails;               // Detailed breakdown of findings
  metadata: {
    platform: 'android';
    timestamp: number;
    version: string;
  };
}

interface AVDDetails {
  buildFingerprintMatch?: {
    matched: boolean;
    value: string | null;
    confidence: number;
  };
  
  productNameMatch?: {
    matched: boolean;
    value: string | null;
    confidence: number;
  };
  
  modelNameMatch?: {
    matched: boolean;
    value: string | null;
    confidence: number;
  };
  
  manufacturerMatch?: {
    matched: boolean;
    value: string | null;
    confidence: number;
  };
  
  cpuArchitectureMatch?: {
    matched: boolean;
    value: string | null;
    confidence: number;
  };
  
  memorySizeMatch?: {
    matched: boolean;
    value: number | null;
    confidence: number;
  };
  
  graphicsPatternMatch?: {
    matched: boolean;
    value: string | null;
    confidence: number;
  };
}

// ============================================================================
// DETECTION MODULES
// ============================================================================

namespace AVDDetectorModules {
  // Extract build fingerprint from environment
  export function getBuildFingerprint(): string | null {
    try {
      const android = require('android');
      
      if (android && typeof android.build === 'object') {
        return android.build?.fingerprint || null;
      }
    } catch (e) {}

    // Fallback: try to read from environment variables
    const envFp = process.env['ANDROID_BUILD_FINGERPRINT'];
    if (envFp && typeof envFp === 'string') {
      return envFp.trim();
    }

    return null;
  }

  // Extract product name from environment
  export function getProductName(): string | null {
    try {
      const android = require('android');
      
      if (android && typeof android.build === 'object') {
        return android.build?.product || null;
      }
    } catch (e) {}

    // Fallback: environment variable
    const envProduct = process.env['ANDROID_PRODUCT_NAME'];
    if (envProduct && typeof envProduct === 'string') {
      return envProduct.trim();
    }

    return null;
  }

  // Extract model name from environment
  export function getModelName(): string | null {
    try {
      const android = require('android');
      
      if (android && typeof android.build === 'object') {
        return android.build?.model || null;
      }
    } catch (e) {}

    // Fallback: environment variable
    const envModel = process.env['ANDROID_DEVICE_MODEL'];
    if (envModel && typeof envModel === 'string') {
      return envModel.trim();
    }

    return null;
  }

  // Extract manufacturer from environment
  export function getManufacturer(): string | null {
    try {
      const android = require('android');
      
      if (android && typeof android.build === 'object') {
        return android.build?.manufacturer || null;
      }
    } catch (e) {}

    // Fallback: environment variable
    const envManufacturer = process.env['ANDROID_DEVICE_MANUFACTURER'];
    if (envManufacturer && typeof envManufacturer === 'string') {
      return envManufacturer.trim();
    }

    return null;
  }

  // Detect CPU architecture
  export function getCPUArchitecture(): string | null {
    try {
      const os = require('os');
      
      if (typeof os.arch === 'function') {
        const arch = os.arch().toLowerCase();
        
        // Normalize architecture names
        let normalized = arch;
        if (arch.includes('arm')) {
          return 'ARM';
        } else if (arch.includes('x64') || arch.includes('amd64')) {
          return 'x86_64';
        } else if (arch.includes('ia32') || arch.includes('i386')) {
          return 'x86';
        }
        
        return normalized;
      }
    } catch (e) {}

    // Fallback: try to read from /proc/self/kernel on Linux
    if (process.platform === 'linux') {
      try {
        const fs = require('fs');
        const kernelPath = '/proc/self/kernel';
        
        if (fs.existsSync(kernelPath)) {
          const content = fs.readFileSync(kernelPath, 'utf8').toLowerCase();
          
          // Check for x86 indicators in kernel string
          if (content.includes('x86_64') || content.includes('amd64')) {
            return 'x86_64';
          } else if (content.includes('i386') || content.includes('i686')) {
            return 'x86';
          } else if (content.includes('armv7l') || content.includes('aarch64')) {
            return 'ARM';
          }
        }
      } catch (e) {}
    }

    // Fallback: environment variable
    const envArch = process.env['ARCH'];
    if (envArch && typeof envArch === 'string') {
      return envArch.trim();
    }

    // Last resort: platform detection
    if (process.platform.includes('darwin')) {
      return 'ARM' as any;  // macOS on Apple Silicon or Intel
    } else if (process.platform.includes('linux')) {
      return 'x86_64' as any;  // Most common Linux desktop
    }

    return null;
  }

  // Get total memory size in MB
  export function getMemorySizeMB(): number | null {
    try {
      const os = require('os');
      
      if (typeof os.totalmem === 'function') {
        const totalBytes = os.totalmem();
        
        if (totalBytes > 0) {
          return Math.round(totalBytes / (1024 * 1024));
        }
      }
    } catch (e) {}

    // Fallback: environment variable
    const envMem = process.env['ANDROID_TOTAL_MEMORY'];
    if (envMem && typeof envMem === 'string') {
      return parseInt(envMem, 10);
    }

    return null;
  }

  // Get graphics renderer info
  export function getGraphicsRenderer(): string | null {
    try {
      const android = require('android');
      
      if (android && typeof android.build === 'object') {
        return android.build?.graphics || null;
      }
    } catch (e) {}

    // Fallback: environment variable
    const envGraphics = process.env['ANDROID_GRAPHICS_RENDERER'];
    if (envGraphics && typeof envGraphics === 'string') {
      return envGraphics.trim();
    }

    return null;
  }
}

// ============================================================================
// MAIN DETECTOR CLASS
// ============================================================================

export class AVDDetector {
  private config: AVDDetectorConfig;
  
  constructor(config?: Partial<AVDDetectorConfig>) {
    this.config = {
      defaultThreshold: 0.7,
      includeLegacySignatures: true,
      ...config,
    };
  }

  /**
   * Main detection method - returns whether device is likely running in emulator
   */
  detect(): DetectionResult {
    const startTime = Date.now();
    
    // Collect all detection vectors
    const details: AVDDetails = {};
    const detectedVectors: string[] = [];
    
    // 1. Build fingerprint check
    const buildFp = AVDDetectorModules.getBuildFingerprint();
    if (buildFp) {
      details.buildFingerprintMatch = this.checkBuildFingerprint(buildFp);
      if (details.buildFingerprintMatch.confidence > 0) {
        detectedVectors.push('build_fingerprint');
      }
    } else {
      details.buildFingerprintMatch = { matched: false, value: null, confidence: 0 };
    }

    // 2. Product name check
    const productName = AVDDetectorModules.getProductName();
    if (productName) {
      details.productNameMatch = this.checkProductName(productName);
      if (details.productNameMatch.confidence > 0) {
        detectedVectors.push('product_name');
      }
    } else {
      details.productNameMatch = { matched: false, value: null, confidence: 0 };
    }

    // 3. Model name check
    const modelName = AVDDetectorModules.getModelName();
    if (modelName) {
      details.modelNameMatch = this.checkModelName(modelName);
      if (details.modelNameMatch.confidence > 0) {
        detectedVectors.push('model_name');
      }
    } else {
      details.modelNameMatch = { matched: false, value: null, confidence: 0 };
    }

    // 4. Manufacturer check
    const manufacturer = AVDDetectorModules.getManufacturer();
    if (manufacturer) {
      details.manufacturerMatch = this.checkManufacturer(manufacturer);
      if (details.manufacturerMatch.confidence > 0) {
        detectedVectors.push('manufacturer');
      }
    } else {
      details.manufacturerMatch = { matched: false, value: null, confidence: 0 };
    }

    // 5. CPU architecture check
    const cpuArch = AVDDetectorModules.getCPUArchitecture();
    if (cpuArch) {
      details.cpuArchitectureMatch = this.checkCPUArchitecture(cpuArch);
      if (details.cpuArchitectureMatch.confidence > 0) {
        detectedVectors.push('cpu_architecture');
      }
    } else {
      details.cpuArchitectureMatch = { matched: false, value: null, confidence: 0 };
    }

    // 6. Memory size check
    const memorySize = AVDDetectorModules.getMemorySizeMB();
    if (memorySize !== null) {
      details.memorySizeMatch = this.checkMemorySize(memorySize);
      if (details.memorySizeMatch.confidence > 0) {
        detectedVectors.push('memory_size');
      }
    } else {
      details.memorySizeMatch = { matched: false, value: null, confidence: 0 };
    }

    // 7. Graphics renderer check
    const graphicsRenderer = AVDDetectorModules.getGraphicsRenderer();
    if (graphicsRenderer) {
      details.graphicsPatternMatch = this.checkGraphicsRenderer(graphicsRenderer);
      if (details.graphicsPatternMatch.confidence > 0) {
        detectedVectors.push('graphics_renderer');
      }
    } else {
      details.graphicsPatternMatch = { matched: false, value: null, confidence: 0 };
    }

    // Calculate overall confidence score
    const totalConfidence = this.calculateOverallScore(details);
    
    return {
      isEmulator: totalConfidence >= this.config.defaultThreshold,
      confidenceScore: Math.min(1.0, totalConfidence),
      detectedVectors,
      details,
      metadata: {
        platform: 'android',
        timestamp: Date.now(),
        version: '1.0.0',
      },
    };
  }

  /**
   * Check build fingerprint against known emulator signatures
   */
  private checkBuildFingerprint(value: string): { matched: boolean; value: string | null; confidence: number } {
    const lowerValue = value.toLowerCase().trim();
    
    // Exact match or partial prefix match for common patterns
    let confidence = 0.95;
    let matched = false;

    if (AVD_SIGNATURES.EMULATOR_BUILD_FINGERPRINTS.includes(lowerValue)) {
      matched = true;
      confidence = 0.95;
    } else if (lowerValue.startsWith('sdk_gphone')) {
      // Generic SDK phone - high probability of emulator
      matched = true;
      confidence = 0.85;
    } else if (lowerValue.includes('emulator') || lowerValue.includes('genymotion')) {
      matched = true;
      confidence = 0.90;
    }

    return { matched, value: lowerValue || null, confidence };
  }

  /**
   * Check product name against known emulator signatures
   */
  private checkProductName(value: string): { matched: boolean; value: string | null; confidence: number } {
    const lowerValue = value.toLowerCase().trim();
    
    let confidence = 0.95;
    let matched = false;

    if (AVD_SIGNATURES.EMULATOR_PRODUCT_NAMES.includes(lowerValue)) {
      matched = true;
      confidence =