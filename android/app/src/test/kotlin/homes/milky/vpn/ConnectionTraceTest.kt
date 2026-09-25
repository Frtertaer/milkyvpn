package homes.milky.vpn

import homes.milky.vpn.vpn.ConnectionTrace
import homes.milky.vpn.vpn.configShape
import homes.milky.vpn.core.XrayConfigBuilder
import org.junit.Assert.*
import org.junit.Test

class ConnectionTraceTest {
    @Test fun staticConfigFailureRetainsItsActualStage() {
        val trace = ConnectionTrace { }
        trace.success("VPN_PERMISSION_GRANTED")
        trace.begin("CONFIG_BUILT")
        trace.failure("config_invalid")
        assertEquals("VPN_PERMISSION_GRANTED", trace.lastSuccessfulStage)
        assertEquals("CONFIG_BUILT", trace.firstFailedStage)
    }

    @Test fun configFailureDoesNotClaimNativeStartupOrConnection() {
        val events = mutableListOf<String>()
        val trace = ConnectionTrace(events::add)
        trace.success("TUN_FD_RECEIVED")
        trace.begin("XRAY_PROCESS_STARTING")
        trace.failure("config_asset_missing")
        assertEquals("TUN_FD_RECEIVED", trace.lastSuccessfulStage)
        assertEquals("CONFIG_VALIDATED", trace.firstFailedStage)
        assertFalse(events.any { it.contains("stage=CONNECTED") || it.contains("stage=XRAY_PROCESS_STARTED") })
    }

    @Test fun newAttemptHasNoPreviousFailure() {
        val first = ConnectionTrace { }
        first.success("TUN_FD_RECEIVED")
        first.failure("config_asset_missing")
        val second = ConnectionTrace { }
        assertNull(second.lastSuccessfulStage)
        assertNull(second.firstFailedStage)
        second.success("PROFILE_SELECTED")
        assertNull(second.firstFailedStage)
    }

    @Test fun profileShapeCannotExposeSecretsOrEndpoints() {
        val spec = XrayConfigBuilder.ProfileSpec("vless", "secret-endpoint.invalid", 443,
            "secret-credential", security="reality", publicKey="secret-key", shortId="cafe", sni="secret-sni.invalid")
        val shape = configShape(spec, XrayConfigBuilder.build(spec))
        listOf(spec.address, spec.secret, spec.publicKey!!, spec.shortId!!, spec.sni!!).forEach {
            assertFalse(shape.contains(it))
        }
        assertTrue(shape.contains("credentialPresent=true"))
        assertTrue(shape.contains("tunFdViaStartLoop=true"))
    }
}
