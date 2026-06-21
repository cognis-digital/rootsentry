// Reference: collecting rootsentry Evidence on Android (Kotlin).
//
// This snippet shows how an app gathers the telemetry rootsentry's engine
// scores. Send the resulting JSON to your backend (ideally inside a Play
// Integrity / attestation flow) and run `rootsentry eval` server-side, or port
// the engine on-device. Defensive use only.

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.Socket

object RootEvidence {
    private val SU_PATHS = listOf("/system/xbin/su", "/system/bin/su", "/sbin/su")
    private val ROOT_FILES = SU_PATHS + listOf(
        "/system/xbin/busybox",
        "/system/lib/libsubstrate.so",
        "/data/local/tmp/frida-server",
    )
    private val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "de.robv.android.xposed.installer",
    )

    fun collect(ctx: Context): JSONObject {
        val files = ROOT_FILES.filter { File(it).exists() }
        val pm = ctx.packageManager
        val pkgs = ROOT_PACKAGES.filter {
            runCatching { pm.getPackageInfo(it, 0); true }.getOrDefault(false)
        }
        val props = mapOf(
            "ro.build.tags" to getProp("ro.build.tags"),
            "ro.debuggable" to getProp("ro.debuggable"),
            "ro.secure" to getProp("ro.secure"),
            "ro.hardware" to getProp("ro.hardware"),
            "ro.kernel.qemu" to getProp("ro.kernel.qemu"),
        )
        val ports = listOf(27042).filter { portOpen(it) }

        return JSONObject().apply {
            put("platform", "android")
            put("present_files", files)
            put("installed_packages", pkgs)
            put("system_props", JSONObject(props as Map<*, *>))
            put("open_ports", ports)
        }
    }

    private fun getProp(name: String): String = runCatching {
        val p = Runtime.getRuntime().exec(arrayOf("getprop", name))
        p.inputStream.bufferedReader().readLine().orEmpty().trim()
    }.getOrDefault("")

    private fun portOpen(port: Int): Boolean = runCatching {
        Socket("127.0.0.1", port).use { true }
    }.getOrDefault(false)
}
