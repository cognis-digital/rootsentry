import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ChildProcess, exec } from 'child_process';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export type Platform = 'android' | 'ios' | 'windows' | 'linux' | 'darwin' | 'unknown';

export interface DetectionResult {
  platform: Platform;
  isRooted: boolean;
  isJailbroken: boolean;
  isEmulated: boolean;
  isHooked: boolean;
  isTampered: boolean;
  score: number;
  indicators: Indicator[];
  verdict: VerdictLevel;
  details: Record<string, string>;
}

export type Indicator = {
  name: string;
  category: 'root' | 'jailbreak' | 'emulator' | 'hook' | 'tamper';
  points: number;
  found: boolean;
  evidence?: string[];
};

export type VerdictLevel = 
  | 'CLEAN'           // 0-25
  | 'MINIMAL_RISK'    // 26-40
  | 'SUSPICIOUS'      // 41-55
  | 'COMPROMISED'     // 56-70
  | 'ROOTED_JAILBROKEN'; // 71+

// ============================================================================
// CONFIGURATION & DATA
// ============================================================================

const ROOT_INDICATORS: Record<string, { points: number; evidence?: string[] }> = {
  // Android root indicators
  '/system/bin/su': { points: 50 },
  '/system/xbin/su': { points: 45 },
  '/data/local/tmp/su': { points: 45 },
  '/data/local/shell/su': { points: 45 },
  '/sbin/.shellsu': { points: 40 },
  '/system/bin/.shellsu': { points: 40 },
  '/system/xbin/daemonsu': { points: 40 },
  '/data/local/su': { points: 35 },
  '/system/app/Superuser.apk': { points: 30, evidence: ['Superuser app'] },
  '/system/app/Face.apk': { points: 25, evidence: ['Face root hide'] },
  '/data/data/com.koushikdutta.superuser/': { points: 30, evidence: ['Superuser data dir'] },
  
  // iOS jailbreak indicators (common paths)
  '/var/lib/apt/lists/dpkg.log.jailbroken': { points: 45 },
  '/Applications/Cydia.app': { points: 40 },
  '/Applications/Sileo.app': { points: 38, evidence: ['Sileo package manager'] },
  '/Library/Receipts/Cydia.pkg': { points: 35 },
  '/var/mobile/Library/Preferences/com.saurik.Cydia.plist': { points: 30 },
};

const EMULATOR_INDICATORS: Record<string, { points: number; evidence?: string[] }> = {
  // Android emulator artifacts
  'ro.product.model=Android SDK Built-in': { points: 45, evidence: ['SDK built-in device'] },
  'ro.product.manufacturer=Google Inc.': { points: 30, evidence: ['Google SDK device'] },
  'ro.product.model=Pixel': { points: 25, evidence: ['Pixel emulator'] },
  'ro.product.model=Pixel XL': { points: 25, evidence: ['Pixel XL emulator'] },
  
  // iOS simulator artifacts
  'SIMULATOR': { points: 40, evidence: ['iOS Simulator detected'] },
  'com.apple.CoreSimulator.SimDeviceType': { points: 35, evidence: ['CoreSimulator metadata'] },
};

const HOOK_INDICATORS: Record<string, { points: number; evidence?: string[] }> = {
  // Frida/Objection hooks
  '/data/data/frida.server/': { points: 40, evidence: ['Frida server data'] },
  '/system/bin/frida-server': { points: 38, evidence: ['Frida server binary'] },
  '/data/local/tmp/frida-server': { points: 35, evidence: ['Temp Frida server'] },
  
  // Cydia Substrate hooks
  '/var/lib/cydia/substrate/': { points: 40, evidence: ['Substrate library'] },
  '/Library/LaunchDaemons/com.cydnaid.plist': { points: 38, evidence: ['Cydnaid launch daemon'] },
  
  // Objection indicators
  '/data/data/net.objectivec.Objection/': { points: 35, evidence: ['Objection data dir'] },
};

const TAMPER_INDICATORS: Record<string, { points: number; evidence?: string[] }> = {
  // Modified system binaries (checksum-based detection)
  '/system/bin/sh': { points: 25, evidence: ['Modified shell binary'] },
  '/system/bin/ls': { points: 20, evidence: ['Modified ls binary'] },
  
  // Suspicious file modifications
  '/data/local/tmp/.hidden_config': { points: 30, evidence: ['Hidden config file'] },
  '/data/data/com.google.android.gms/backup/modified': { points: 25, evidence: ['GMS backup modified'] },
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function normalizePath(p: string): string {
  return p.replace(/\\+/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
}

function pathExists(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function readFileSafe(filePath: string, encoding: BufferEncoding = 'utf8'): string | null {
  try {
    return fs.readFileSync(filePath, encoding).trim();
  } catch {
    return null;
  }
}

function readBinaryFileSafe(filePath: string): Buffer | null {
  try {
    return fs.readFileSync(filePath);
  } catch {
    return null;
  }
}

function getPlatform(): Platform {
  const platform = os.platform();
  
  switch (platform) {
    case 'android':
      // Check for additional Android-specific signals
      if (os.hostname().includes('sdk')) {
        return 'android';
      }
      break;
      
    case 'darwin':
      // iOS Simulator check
      try {
        const simInfo = readFileSafe('/proc/self/cgroup');
        if (simInfo?.includes('SIMULATOR')) {
          return 'ios';
        }
      } catch {}
      return 'darwin';
      
    default:
      break;
  }
  
  return platform as Platform;
}

function executeCommand(command: string, timeoutMs = 5000): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = exec(command, { maxBuffer: 1024 * 1024 });
    
    let stdout = '';
    let stderr = '';
    
    child.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });
    
    child.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });
    
    child.on('error', (err) => {
      reject(err);
    });
    
    child.on('exit', (code) => {
      if (code === 0 || code === null) {
        resolve(stdout.trim());
      } else {
        resolve(stderr.trim() || stdout.trim());
      }
    });
    
    setTimeout(() => {
      child.kill();
      reject(new Error('Command timeout'));
    }, timeoutMs);
  });
}

// ============================================================================
// DETECTION MODULES
// ============================================================================

interface CheckResult {
  name: string;
  category: Indicator['category'];
  found: boolean;
  evidence?: string[];
}

function checkFilesystem(): CheckResult[] {
  const results: CheckResult[] = [];
  
  // Check root indicators
  for (const [path, config] of Object.entries(ROOT_INDICATORS)) {
    if (!pathExists(path)) continue;
    
    let evidence: string[] = [];
    
    // Gather additional evidence
    try {
      const content = readFileSafe(path);
      if (content) {
        evidence.push(`Content preview: ${content.substring(0, 100)}...`);
        
        // Check for common root commands in su binary
        if (path.includes('su')) {
          const hasCommonCommands = /busybox|ash|sh|bash/.test(content || '');
          evidence.push(hasCommonCommands ? 'Contains shell interpreter' : 'Binary found');
        }
      }
    } catch {}
    
    results.push({
      name: path,
      category: config.evidence?.length > 0 ? 
        (config.evidence[0].includes('Superuser') || config.evidence[0].includes('Face') ? 'jailbreak' : 'root') : 'root',
      found: true,
      evidence: evidence.length > 0 ? evidence : undefined,
    });
  }
  
  // Check emulator indicators
  for (const [pattern, config] of Object.entries(EMULATOR_INDICATORS)) {
    try {
      const output = executeCommand(`getprop ${pattern}`);
      if (output.includes('true') || output.includes('1')) {
        results.push({
          name: pattern,
          category: 'emulator',
          found: true,
          evidence: config.evidence,
        });
      }
    } catch {}
  }
  
  // Check hook indicators
  for (const [path, config] of Object.entries(HOOK_INDICATORS)) {
    if (!pathExists(path)) continue;
    
    results.push({
      name: path,
      category: 'hook',
      found: true,
      evidence: config.evidence,
    });
  }
  
  // Check tamper indicators
  for (const [path, config] of Object.entries(TAMPER_INDICATORS)) {
    if (!pathExists(path)) continue;
    
    results.push({
      name: path,
      category: 'tamper',
      found: true,
      evidence: config.evidence,
    });
  }
  
  return results;
}

function checkProcessList(): CheckResult[] {
  const results: CheckResult[] = [];
  
  // Android process list inspection
  if (os.platform() === 'android') {
    try {
      // Try to read running processes
      let procOutput = '';
      
      // Method 1: /proc/self/status for hints
      const statusContent = readFileSafe('/proc/self/status');
      if (statusContent) {
        const hasFrida = /frida/.test(statusContent);
        if (hasFrida) {
          results.push({
            name: '/proc/self/status',
            category: 'hook',
            found: true,
            evidence: ['Frida detected in process status'],
          });
        }
      }
      
      // Method 2: Try to list processes (if running as root)
      try {
        procOutput = executeCommand('ps -A');
        
        const suspiciousProcesses = [
          'frida-server',
          'frida-gadget',
          'objection',
          'substitute',
          'cydia',
          'sileo',
          'burp',
          'mitmproxy',
        ];
        
        for (const proc of suspiciousProcesses) {
          if (procOutput.includes(proc)) {
            results.push({
              name: `Process: ${proc}`,
              category: 'hook',
              found: true,
              evidence: [`Running process detected`],
            });
          }
        }
      } catch {}
      
    } catch {}
  }
  
  // iOS simulator check via sysctl
  if (os.platform() === 'darwin') {
    try {
      const simOutput = executeCommand('sysctl -n kern.simulator');
      if (simOutput.includes('1')) {
        results.push({
          name: 'kern.simulator',
          category: 'emulator',
          found: true,
          evidence: ['iOS Simulator detected via sysctl'],
        });
      }
    } catch {}
  }
  
  return results;
}

function checkNetwork(): CheckResult[] {
  const results: CheckResult[] = [];
  
  // Check for known proxy ports (common in jailbroken devices)
  try {
    const netInterfaces = os.networkInterfaces();
    
    for (const [iface, addresses] of Object.entries(netInterfaces)) {
      if (!addresses || !Array.isArray(addresses)) continue;
      
      for (const addr of addresses) {
        // Check for proxy-like ports
        if (addr.family === 'IPv4' && addr.address !== '::1') {
          const port = addr.port;
          
          // Common proxy/jailbreak ports
          const proxyPorts = [8080, 8888, 9090, 3128, 1080];
          
          if (proxyPorts.includes(port)) {
            results.push({
              name: `Network Interface: ${iface}`,
              category: 'jailbreak',
              found: true,
              evidence: [`Proxy port detected on interface`],
            });
          }
        }
      }
    }
  } catch {}
  
  return results;
}

function checkMemorySignatures(): CheckResult[] {
  const results: CheckResult[] = [];
  
  // Check for common hook library signatures in memory-mapped files
  try {
    const libPaths = [
      '/data/data/frida.server/lib',
      '/var/lib/cydia/substrate/lib',
      '/Library/LaunchDaemons/com.cydnaid.plist',
    ];
    
    for (const libPath of libPaths) {
      if (!pathExists(libPath)) continue;
      
      results.push({
        name: `Memory Library Path: ${libPath}`,
        category: 'hook',
        found: true,
        evidence: [`Library path detected`],
      });
    }
  } catch {}
  
  return results;
}

// ============================================================================
// SCORING & VERDICT ENGINE
// ============================================================================

function calculateScore(indicators: CheckResult[]): number {
  let total = 0;
  
  for (const indicator of indicators) {
    // Base points from filesystem checks
    if (indicator.found && indicator.category === 'root') {
      total += 15;
    } else if (indicator.found && indicator.category === 'jailbreak') {
      total += 20;
    } else if (indicator.found && indicator.category === 'emulator') {
      total += 18;
    } else if (indicator.found && indicator.category === 'hook') {
      total += 25;
    } else if (indicator.found && indicator.category === 'tamper') {
      total += 22;
    }
    
    // Bonus for multiple indicators in same category
    const rootCount = indicators.filter(i => i.found && i.category === 'root').length;
    if (rootCount > 1) {
      total += Math.min(rootCount * 5, 10);
    }
  }
  
  return Math.min(total, 100);
}

function getVerdict(score: number): VerdictLevel {
  if (score <= 25) return 'CLEAN';
  if (score <= 40) return 'MINIMAL_RISK';
  if (score <= 55) return 'SUSPICIOUS';
  if (score <= 70) return 'COMPROMISED';
  return 'ROOTED_JAILBROKEN';
}

function buildDetails(indicators: CheckResult[]): Record<string, string> {
  const details: Record<string, string> = {};
  
  // Group by category
  const categories: Record<string, CheckResult[]> = {
    root: [],
    jailbreak: [],
    emulator: [],
    hook: [],
    tamper: [],
  };
  
  for (const indicator of indicators) {
    if (!indicator.found) continue;
    
    const cat = indicator.category;
    if (!categories[cat]) categories[cat] = [];
    categories[cat].push(indicator);
  }
  
  // Build detailed report
  let report = '';
  for (const [category, items] of Object.entries(categories)) {