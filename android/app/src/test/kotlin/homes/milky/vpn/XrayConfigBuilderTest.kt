package homes.milky.vpn

import homes.milky.vpn.core.XrayConfigBuilder
import homes.milky.vpn.core.XrayConfigBuilder.ProfileSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.json.JSONObject
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
        var dnsFound = false
        for (i in 0 until rules.length()) {
            val r = rules.getJSONObject(i)
            if (r.optString("port") == "53" && r.optString("outboundTag") == "dns-out") dnsFound = true
        }
        assertTrue(dnsFound)
    }

    @Test
    fun ruDomainsBypassTunnel() {
        val cfg = XrayConfigBuilder.build(reality())
        val rules = cfg.getJSONObject("routing").getJSONArray("rules")
        var ruRule: JSONObject? = null
        for (i in 0 until rules.length()) {
            val r = rules.getJSONObject(i)
            if (!r.has("domain") || r.optString("outboundTag") != "direct") continue
            val domains = r.getJSONArray("domain")
            val values = (0 until domains.length()).map { domains.getString(it) }
            if ("ru" in values && "su" in values) ruRule = r
        }
        assertTrue("RU domains must route to direct", ruRule != null)
        val ruDomains = ruRule!!.getJSONArray("domain")
        val values = (0 until ruDomains.length()).map { ruDomains.getString(it) }.toSet()
        assertTrue(values.contains("xn--p1ai"))
        assertTrue(values.contains("ozoncdn.net"))

        // Yandex DNS is pinned as a domain-scoped server and reachable directly
        val dnsServers = cfg.getJSONObject("dns").getJSONArray("servers")
        val first = dnsServers.getJSONObject(0)
        assertEquals("77.88.8.8", first.getString("address"))
        var dnsBypass = false
        for (i in 0 until rules.length()) {
            val r = rules.getJSONObject(i)
            if (!r.has("ip") || r.optString("outboundTag") != "direct") continue
            val ips = r.getJSONArray("ip")
            val v = (0 until ips.length()).map { ips.getString(it) }
            if ("77.88.8.8" in v) dnsBypass = true
        }
        assertTrue(dnsBypass)
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
        // IP literal server -> routed by an ip rule to direct
        val rules = XrayConfigBuilder.build(p).getJSONObject("routing").getJSONArray("rules")
        var ipFound = false
        for (i in 0 until rules.length()) {
            val r = rules.getJSONObject(i)
            if (!r.has("ip")) continue
            val ips = r.getJSONArray("ip")
            for (j in 0 until ips.length()) if (ips.getString(j) == "203.0.113.20") ipFound = true
        }
        assertTrue(ipFound)
    }

    @Test
    fun rejectsUnsupportedProtocolsAndMissingReality() {
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("wireguard", "a.b", 443, fakeUuid)))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("tuic", "a.b", 443, "x")))
        assertFalse(XrayConfigBuilder.isSupported(ProfileSpec("vless", "a.b", 443, fakeUuid, network = "mkcp")))
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
    fun vmessBuildsVmessOutbound() {
        val p = ProfileSpec(
            protocol = "vmess", address = "us1.example.invalid", port = 443, secret = fakeUuid,
            network = "ws", security = "tls", host = "cdn.example.invalid", path = "/vm",
            alterId = 0, cipher = "auto",
        )
        val proxy = XrayConfigBuilder.build(p).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vmess", proxy.getString("protocol"))
        val user = proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
            .getJSONArray("users").getJSONObject(0)
        assertEquals(fakeUuid, user.getString("id"))
        assertEquals("auto", user.getString("security"))
        val stream = proxy.getJSONObject("streamSettings")
        assertEquals("ws", stream.getString("network"))
        assertEquals("tls", stream.getString("security"))
        assertEquals("cdn.example.invalid", stream.getJSONObject("tlsSettings").getString("serverName"))
    }

    @Test
    fun trojanBuildsTrojanOutboundWithGrpc() {
        val p = ProfileSpec(
            protocol = "trojan", address = "us1.example.invalid", port = 443, secret = "pw-abc",
            network = "grpc", security = "tls", path = "trojan-grpc",
        )
        val proxy = XrayConfigBuilder.build(p).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("trojan", proxy.getString("protocol"))
        val server = proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("pw-abc", server.getString("password"))
        val stream = proxy.getJSONObject("streamSettings")
        assertEquals("grpc", stream.getString("network"))
        assertEquals("trojan-grpc", stream.getJSONObject("grpcSettings").getString("serviceName"))
        assertEquals("tls", stream.getString("security"))
    }

    @Test
    fun shadowsocksBuildsSsOutboundAndValidatesCipher() {
        val p = ProfileSpec(
            protocol = "ss", address = "us1.example.invalid", port = 8388, secret = "pw-abc",
            cipher = "aes-256-gcm",
        )
        val proxy = XrayConfigBuilder.build(p).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("shadowsocks", proxy.getString("protocol"))
        val server = proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("aes-256-gcm", server.getString("method"))
        assertEquals("pw-abc", server.getString("password"))
        assertFalse(XrayConfigBuilder.isSupported(p.copy(cipher = "aes-256-cfb")))
        assertFalse(XrayConfigBuilder.isSupported(p.copy(plugin = "obfs-local")))
    }

    private fun ProfileSpec.copy(
        cipher: String? = this.cipher,
        plugin: String? = this.plugin,
    ) = ProfileSpec(
        protocol = protocol, address = address, port = port, secret = secret,
        network = network, security = security, cipher = cipher, plugin = plugin,
    )

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

    @Test
    fun generatedConfigsUseInlinePrivateRoutesWithoutGeodataFiles() {
        val expectedPrivateCidrs = setOf(
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "::/128",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        )

        for (tunEnabled in listOf(true, false)) {
            val cfg = XrayConfigBuilder.build(reality(), tunEnabled = tunEnabled)
            val serialized = cfg.toString()
            assertFalse("config must not require geoip.dat", serialized.contains("geoip:"))
            assertFalse("config must not require geosite.dat", serialized.contains("geosite:"))

            val rules = cfg.getJSONObject("routing").getJSONArray("rules")
            var actualPrivateCidrs: Set<String>? = null
            for (i in 0 until rules.length()) {
                val rule = rules.getJSONObject(i)
                if (rule.optString("outboundTag") != "direct" || !rule.has("ip")) continue
                val ips = rule.getJSONArray("ip")
                val values = (0 until ips.length()).map { ips.getString(it) }.toSet()
                if ("10.0.0.0/8" in values) actualPrivateCidrs = values
            }

            assertEquals(expectedPrivateCidrs, actualPrivateCidrs)
        }
    }
}
