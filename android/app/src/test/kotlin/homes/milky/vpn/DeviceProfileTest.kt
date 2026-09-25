package homes.milky.vpn

import homes.milky.vpn.vpn.DeviceProfile
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceProfileTest {

    private fun check(
        model: String?,
        manufacturer: String?,
        brand: String? = null,
        device: String? = null,
        product: String? = null,
        hardware: String? = null,
        fingerprint: String? = null,
        abi: String? = "arm64-v8a",
    ) = DeviceProfile.isEmulator(model, manufacturer, brand, device, product, hardware, fingerprint, abi)

    @Test
    fun detectsAndroidStudioAvd() {
        assertTrue(
            check(
                model = "sdk_gphone64_x86_64",
                manufacturer = "Google",
                brand = "google",
                device = "emu64xa",
                product = "sdk_gphone64_x86_64",
                fingerprint = "google/sdk_gphone64_x86_64/emu64xa:14/UE1A.1/123:userdebug/test-keys",
            ),
        )
        assertTrue(check(model = "Android SDK built for x86", manufacturer = "unknown", hardware = "goldfish"))
    }

    @Test
    fun detectsLdplayerAndOtherConsumerEmulators() {
        assertTrue(check(model = "LDPlayer", manufacturer = "LDPlayer", product = "LDPlayer", abi = "x86_64"))
        assertTrue(check(model = "MuMu", manufacturer = "Netease", fingerprint = "vbox86p"))
        assertTrue(check(model = "NOX", manufacturer = "Nox", hardware = "vbox86"))
        assertTrue(check(model = "Bluestacks", manufacturer = "BlueStacks"))
    }

    @Test
    fun keepsRealDevices() {
        assertFalse(check(model = "Pixel 8 Pro", manufacturer = "Google", brand = "google", device = "husky", product = "husky"))
        assertFalse(check(model = "SM-S928B", manufacturer = "samsung", brand = "samsung", device = "e3q"))
        assertFalse(check(model = "M2102K1G", manufacturer = "Xiaomi", brand = "Redmi", device = "haydn"))
    }

    @Test
    fun unknownBuildIsNotCalledAnEmulator() {
        assertFalse(check(null, null))
        assertFalse(check("", ""))
    }
}
