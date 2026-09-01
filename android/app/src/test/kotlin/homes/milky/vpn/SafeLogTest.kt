package homes.milky.vpn

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
        assertEquals("tls_handshake", SafeLog.errorCode(RuntimeException("TLS handshake failed for 00000000-1111-2222-3333-444444444444")))
        val code = SafeLog.errorCode(IllegalStateException("something odd"))
        assertEquals("IllegalStateException", code)
        assertEquals("unknown", SafeLog.errorCode(null))
    }
}
