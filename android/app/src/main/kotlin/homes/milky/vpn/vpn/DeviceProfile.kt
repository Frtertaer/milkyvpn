package homes.milky.vpn.vpn

import android.os.Build

/**
 * Tells emulators from real hardware.
 *
 * Used only in Diagnostics: a tunnel that fails on LDPlayer/AVD (`EMULATOR_FAILURE`) is a
 * different problem from the same failure on a phone (`REAL_DEVICE_FAILURE`), and the
 * support answer is different. Never shown as a customer-facing error message.
 */
object DeviceProfile {

    private val EMULATOR_TOKENS = listOf(
        "generic", "sdk_gphone", "sdk", "emulator", "android sdk built for x86",
        "goldfish", "ranchu", "vbox", "vbox86", "genymotion", "bluestacks", "nox",
        "mumu", "ldplayer", "changwan", "andy", "memu", "koplayer", "windroye", "qemu",
    )

    /** Pure decision function so it is unit testable on the JVM without a device. */
    fun isEmulator(
        model: String?,
        manufacturer: String?,
        brand: String?,
        device: String?,
        product: String?,
        hardware: String?,
        fingerprint: String?,
        abi: String?,
    ): Boolean {
        val haystack = listOf(model, manufacturer, brand, device, product, hardware, fingerprint)
            .filterNotNull()
            .joinToString(" ")
            .lowercase()
        if (haystack.isBlank()) return false
        if (EMULATOR_TOKENS.any { haystack.contains(it) }) return true
        // x86 Android is effectively never a retail phone.
        if (abi != null && (abi.startsWith("x86") && !abi.contains("arm"))) {
            // But x86_64 Chromebooks/tablets exist: only treat it as an emulator when the
            // build fingerprint also looks virtual, which the token check above covers.
            return haystack.contains("google_sdk") || haystack.contains("aosp") || haystack.contains("intel")
        }
        return false
    }

    /** Reads the current build. Values are non-secret device descriptors. */
    fun currentIsEmulator(): Boolean = isEmulator(
        model = Build.MODEL,
        manufacturer = Build.MANUFACTURER,
        brand = Build.BRAND,
        device = Build.DEVICE,
        product = Build.PRODUCT,
        hardware = Build.HARDWARE,
        fingerprint = Build.FINGERPRINT,
        abi = Build.SUPPORTED_ABIS.firstOrNull(),
    )

    fun describe(): Map<String, Any?> = mapOf(
        "model" to Build.MODEL,
        "manufacturer" to Build.MANUFACTURER,
        "brand" to Build.BRAND,
        "product" to Build.PRODUCT,
        "isEmulator" to currentIsEmulator(),
    )
}
