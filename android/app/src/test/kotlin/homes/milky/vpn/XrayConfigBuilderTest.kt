package homes.milky.vpn

import homes.milky.vpn.core.XrayConfigBuilder
import homes.milky.vpn.core.XrayConfigBuilder.ProfileSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Synthetic credentials only — nothing here is a real MilkyVPN profile. */
class XrayConfigBuilderTest {

    private val fakeUuid = "00000000-1111-2222-3333-444444444444"

    private fun reality() = ProfileSpec(
        protocol = "vless", address = "fi1.example.invalid", port = 443, secret = fakeUuid,
        network = "tcp", security = "reality", sni = "www.example.com", fingerprint = "chrome",
        publicKey = "FAKEPUBLICKEYFAKEPUBLICKEYFAKEPUBLICKEYFAKE", shortId = "abcd1234", flow = "xtls-rprx-vision",
    )

    @Test
    fun realityTcpBuildsVlessOutboundWithTunInbound() {
        val cfg = XrayConfigBuilder.build(reality(), resolvedServerIps = listOf("203.0.113.10"))
        val inbounds = cfg.getJSONArray("inbounds")
        assertEquals("tun", inbounds.getJSONObject(0).getString("protocol"))
        assertEquals("milkyvpn0", inbounds.getJSONObject(0).getJSONObject("settings").getString("name"))
        val proxy = cfg.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("proxy", proxy.getString("tag"))
        assertEquals("vless", proxy.getString("protocol"))
        val stream = proxy.getJSONObject("streamSettings")
        assertEquals("reality", stream.getString("security"))
        assertEquals("tcp", stream.getString("network"))
        val r = stream.getJSONObject("realitySettings")
        assertEquals("www.example.com", r.getString("serverName"))
        assertEquals("abcd1234", r.getString("shortId"))
        assertEquals("chrome", r.getString("fingerprint"))
        val user = proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0)
        assertEquals(fakeUuid, user.getString("id"))
        assertEquals("xtls-rprx-vision", user.getString("flow"))
        // pre-resolved host is pinned in dns.hosts
        assertEquals("203.0.113.10", cfg.getJSONObject("dns").getJSONObject("hosts").getString("fi1.example.invalid"))
        assertEquals("UseIP", stream.getJSONObject("sockopt").getString("domainStrategy"))
    }

    @Test
    fun serverDomainIsRoutedDirect() {
        val cfg = XrayConfigBuilder.build(reality())
        val rules = cfg.getJSONObject("routing").getJSONArray("rules")
        var found = false
        for (i in 0 until rules.length()) {
            val r = rules.getJSONObject(i)
            if (r.has("domain") && r.getJSONArray("domain").getString(0) == "fi1.example.invalid") {
                assertEquals("direct", r.getString("outboundTag")); found = true
            }
        }
        assertTrue(found)
        // DNS port 53 from tun goes to dns-out
        val dnsRule = rules.getJSONObject(0)
        assertEquals("53", dnsRule.getString("port"))
        assertEquals("dns-out", dnsRule.getString("outboundTag"))
    }

    @Test
    fun wsTlsBuildsWsSettings() {
        val p = ProfileSpec(
            protocol = "vless", address = "us1.example.invalid", port = 443, secret = fakeUuid,
            network = "ws", security = "tls", host = "cdn.example.invalid", path = "/ws",
        )
        val stream = XrayConfigBuilder.build(p).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
        assertEquals("ws", stream.getString("network"))
        assertEquals("/ws", stream.getJSONObject("wsSettings").getString("path"))
        assertEquals("cdn.example.invalid", stream.getJSONObject("wsSettings").getString("host"))
        assertEquals("cdn.example.invalid", stream.getJSONObject("tlsSettings").getString("serverName"))
        assertFalse(stream.has("realitySettings"))
    }

    @Test
    fun xhttpRealityBuildsXhttpSettings() {
        val p = reality().let {
            ProfileSpec(
                protocol = "vless", address = it.address, port = 443, secret = fakeUuid, network = "xhttp",
                security = "reality", sni = it.sni, publicKey = it.publicKey, shortId = it.shortId,
                path = "/xh", xhttpMode = "packet-up",
            )
        }
        val proxy = XrayConfigBuilder.build(p).getJSONArray("outbounds").getJSONObject(0)
        val stream = proxy.getJSONObject("streamSettings")
        assertEquals("xhttp", stream.getString("network"))
        assertEquals("packet-up", stream.getJSONObject("xhttpSettings").getString("mode"))
        assertEquals("/xh", stream.getJSONObject("xhttpSettings").getString("path"))
        // flow is only valid for raw/tcp
        val user = proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0)
        assertFalse(user.has("flow"))
    }

    @Test
    fun hysteria2BuildsHysteriaOutbound() {
        val p = ProfileSpec(
            protocol = "hysteria2", address = "203.0.113.20", port = 8443, secret = "fakepassword",
            sni = "hy.example.invalid", obfsPassword = "fakeobfs", allowInsecure = false,
        )
        val proxy = XrayConfigBuilder.build(p).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("hysteria", proxy.getString("protocol"))
        assertEquals(2, proxy.getJSONObject("settings").getInt("version"))
        val stream = proxy.getJSONObject("streamSettings")
        assertEquals("hysteria", stream.getString("network"))
        assertEquals("fakepassword", stream.getJSONObject("hysteriaSettings").getString("auth"))
        assertEquals("h3", stream.getJSONObject("tlsSettings").getJSONArray("alpn").getString(0))
        assertEquals("hy.example.invalid", stream.getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("salamander", stream.getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0).getString("type"))
        // IP literal server -> routed by ip rule
        val rules = XrayConfigBuilder.build(p).getJSONObject("routing").getJSONArray("rules")
        assertEquals("203.0.113.20", rules.getJSONObject(1).getJSONArray("ip").getString(0))
    }

    @Test
    fun rejectsUnsupportedProtocolsAndMissingReality() {
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vmess", "a.b", 443, fakeUuid)))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("trojan", "a.b", 443, "x")))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vless", "a.b", 443, fakeUuid, network = "grpc")))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vless", "a.b", 443, fakeUuid, security = "reality"))) // no pbk
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vless", "a.b", 0, fakeUuid)))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vless", "", 443, fakeUuid)))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vless", "a.b", 443, "")))
        assertTrue(XrayConfigBuilder.isSupported(reality()))
        try {
            XrayConfigBuilder.build(ProfileSpec("ssh", "a.b", 22, "x"))
            fail("expected UnsupportedProfileException")
        } catch (e: XrayConfigBuilder.UnsupportedProfileException) {
            assertEquals("protocol", e.message)
        }
    }

    @Test
    fun fromMapHandlesMissingAndNumericValues() {
        val spec = ProfileSpec.fromMap(
            mapOf("protocol" to "vless", "address" to "h", "port" to 443L, "secret" to fakeUuid, "allowInsecure" to true, "sni" to "")
        )
        assertEquals(443, spec.port)
        assertTrue(spec.allowInsecure)
        assertNull(spec.sni)
        assertEquals("tcp", spec.network)
    }

    @Test
    fun socksOnlyConfigHasNoTunInbound() {
        val cfg = XrayConfigBuilder.build(reality(), tunEnabled = false)
        val inbounds = cfg.getJSONArray("inbounds")
        assertEquals(1, inbounds.length())
        assertEquals("socks", inbounds.getJSONObject(0).getString("protocol"))
    }
}
