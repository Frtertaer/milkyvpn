package homes.milky.vpn

import homes.milky.vpn.core.XrayConfigBuilder
import homes.milky.vpn.vpn.SafeLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeLogTest {

    @Test
    fun redactsUuidSubscriptionTokenAndUserInfo() {
        val raw = "vless://00000000-1111-2222-3333-444444444444@1.2.3.4:443?pbk=FAKEKEY&sid=ab12#x " +
            "from https://sub.milky.homes/s/SECRETTOKEN_123"
        val red = SafeLog.redact(raw)
        assertFalse(red.contains("00000000-1111"))
        assertFalse(red.contains("SECRETTOKEN_123"))
        assertFalse(red.contains("FAKEKEY"))
        assertFalse(red.contains("sid=ab12"))
        assertTrue(red.contains("sub.milky.homes/s/<token>"))
        assertTrue(red.contains("vless://<cred>@"))
    }

    @Test
    fun errorCodesAreShortAndCredentialFree() {
        assertEquals("timeout", SafeLog.errorCode(RuntimeException("dial tcp: i/o timeout")))
        assertEquals("connection_refused", SafeLog.errorCode(RuntimeException("connect: connection refused")))
        assertEquals(
            "tls_handshake",
            SafeLog.errorCode(RuntimeException("TLS handshake failed for 00000000-1111-2222-3333-444444444444")),
        )
        assertEquals("unknown_error", SafeLog.errorCode(null))
    }

    /**
     * Regression: raw JVM/Go class names must never become error codes. They used to reach
     * the UI as "Не удалось выполнить операцию (proxyerror)" and "(S)".
     */
    @Test
    fun neverLeaksRawExceptionClassNames() {
        // A class whose simpleName is a single letter, like R8 produces in release builds.
        assertEquals("core_start_failed", SafeLog.errorCode(S("something odd")))
        assertEquals("core_start_failed", SafeLog.errorCode(S(null)))
        assertEquals("core_start_failed", SafeLog.errorCode(IllegalStateException("core did not start")))
        assertEquals("tunnel_unverified", SafeLog.errorCode(IllegalStateException("verification failed")))
        assertEquals("tun_establish_failed", SafeLog.errorCode(IllegalStateException("establish returned null")))
        assertEquals("config_invalid", SafeLog.errorCode(IllegalArgumentException("bad outbound")))
        assertEquals(
            "unsupported_profile",
            SafeLog.errorCode(XrayConfigBuilder.UnsupportedProfileException("reality.publicKey")),
        )
        assertEquals("dns_failure", SafeLog.errorCode(RuntimeException("failed host lookup")))
        assertEquals("permission_denied", SafeLog.errorCode(SecurityException("not permitted")))
        for (code in listOf(
            SafeLog.errorCode(S("x")),
            SafeLog.errorCode(RuntimeException("weird")),
            SafeLog.errorCode(IllegalStateException("other")),
        )) {
            assertTrue("code must stay in the stable vocabulary: $code", code.matches(Regex("[a-z_]{4,32}")))
        }
    }

    /** Stands in for an R8-shortened exception class (and for gomobile's `proxyerror`). */
    private class S(message: String?) : RuntimeException(message)
}
