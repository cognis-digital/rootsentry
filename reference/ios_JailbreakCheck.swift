// Reference: collecting rootsentry Evidence on iOS (Swift).
//
// Gathers jailbreak/hook telemetry rootsentry's engine scores. Defensive use
// only. Note: App Store apps must be careful which paths they probe; this is a
// reference for in-house / assessment builds.

import Foundation

enum JailbreakEvidence {
    static let suspiciousPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/bin/bash",
        "/etc/apt",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
    ]

    static func collect() -> [String: Any] {
        let files = suspiciousPaths.filter { FileManager.default.fileExists(atPath: $0) }
        var flags: [String] = []
        if canWriteOutsideSandbox() { flags.append("can_write_outside_sandbox") }
        if forkSucceeds() { flags.append("fork_succeeded") }

        return [
            "platform": "ios",
            "present_files": files,
            "runtime_flags": flags,
        ]
    }

    private static func canWriteOutsideSandbox() -> Bool {
        let probe = "/private/rootsentry_probe.txt"
        do {
            try "x".write(toFile: probe, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: probe)
            return true
        } catch { return false }
    }

    private static func forkSucceeds() -> Bool {
        let pid = fork()
        if pid >= 0 {
            if pid > 0 { /* parent: child will exit */ }
            return true   // stock sandboxed iOS denies fork()
        }
        return false
    }
}
