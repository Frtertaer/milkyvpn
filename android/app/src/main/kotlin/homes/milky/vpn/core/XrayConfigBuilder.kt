package homes.milky.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds a complete Xray-core JSON configuration for a single outbound profile.
 *
 * The profile comes from Dart already parsed and validated (see lib/core/subscription/).
 * This class is pure Kotlin (no Android dependencies) so it can be unit tested on the JVM.
 *
 * Network topology:
 *   Android TUN (fd passed to core)  ->  "tun" inbound (gVisor stack inside Xray)
 *   -> routing: port 53 -> dns-out, everything else -> "proxy" outbound
 *   -> proxy outbound: vless(+reality|tls, tcp|ws|xhttp) or hysteria2
 *
 * Loop avoidance: the VpnService excludes its own package from the tunnel
 * (Builder.addDisallowedApplication), so the core's uplink sockets never enter the TUN.
 */
object XrayConfigBuilder {

    const val TUN_MTU = 1500
    const val TUN_IPV4 = "10.10.14.1"
    const val TUN_DNS = "1.1.1.1"
    const val TUN_DNS_2 = "8.8.8.8"

    /** Transports that are genuinely executable by this engine. */
    val SUPPORTED_PROTOCOLS = setOf("vless", "hysteria2")
    val SUPPORTED_VLESS_NETWORKS = setOf("tcp", "raw", "ws", "xhttp")
    val SUPPORTED_VLESS_SECURITY = setOf("reality", "tls", "none")

    class ProfileSpec(
        val protocol: String,
        val address: String,
        val port: Int,
        val secret: String,
        val network: String = "tcp",
        val security: String = "none",
        val sni: String? = null,
        val fingerprint: String? = null,
        val publicKey: String? = null,
        val shortId: String? = null,
        val spiderX: String? = null,
        val flow: String? = null,
        val host: String? = null,
        val path: String? = null,
        val xhttpMode: String? = null,
        val alpn: String? = null,
        val allowInsecure: Boolean = false,
        val obfsPassword: String? = null,
    ) {
        companion object {
            fun fromMap(m: Map<*, *>): ProfileSpec {
                fun s(k: String): String? = (m[k] as? String)?.takeIf { it.isNotBlank() }
                return ProfileSpec(
                    protocol = s("protocol") ?: "",
                    address = s("address") ?: "",
                    port = (m["port"] as? Number)?.toInt() ?: 0,
                    secret = s("secret") ?: "",
                    network = s("network") ?: "tcp",
                    security = s("security") ?: "none",
                    sni = s("sni"),
                    fingerprint = s("fingerprint"),
                    publicKey = s("publicKey"),
                    shortId = s("shortId"),
                    spiderX = s("spiderX"),
                    flow = s("flow"),
                    host = s("host"),
                    path = s("path"),
                    xhttpMode = s("xhttpMode"),
                    alpn = s("alpn"),
                    allowInsecure = (m["allowInsecure"] as? Boolean) ?: false,
                    obfsPassword = s("obfsPassword"),
                )
            }
        }
    }

    class UnsupportedProfileException(message: String) : IllegalArgumentException(message)

    fun isSupported(p: ProfileSpec): Boolean = try {
        validate(p); true
    } catch (_: UnsupportedProfileException) {
        false
    }

    fun validate(p: ProfileSpec) {
        if (p.protocol !in SUPPORTED_PROTOCOLS) throw UnsupportedProfileException("protocol")
        if (p.address.isBlank()) throw UnsupportedProfileException("address")
        if (p.port !in 1..65535) throw UnsupportedProfileException("port")
        if (p.secret.isBlank()) throw UnsupportedProfileException("credential")
        if (p.protocol == "vless") {
            val net = normalizeNetwork(p.network)
            if (net !in SUPPORTED_VLESS_NETWORKS) throw UnsupportedProfileException("network")
            if (p.security !in SUPPORTED_VLESS_SECURITY) throw UnsupportedProfileException("security")
            if (p.security == "reality") {
                if (p.publicKey.isNullOrBlank()) throw UnsupportedProfileException("reality.publicKey")
                if (net == "ws") throw UnsupportedProfileException("reality+ws")
            }
        }
    }

    private fun normalizeNetwork(n: String): String = when (n.lowercase()) {
        "raw", "tcp" -> "tcp"
        "splithttp", "xhttp" -> "xhttp"
        else -> n.lowercase()
    }

    /**
     * @param tunEnabled when false, only a local SOCKS inbound is created (used by MeasureOutboundDelay).
     */
    fun build(
        p: ProfileSpec,
        tunEnabled: Boolean = true,
        socksPort: Int = 10808,
        resolvedServerIps: List<String> = emptyList(),
    ): JSONObject {
        validate(p)
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning").put("access", "none"))

        // --- inbounds ---
        val inbounds = JSONArray()
        val sniffing = JSONObject()
            .put("enabled", true)
            .put("destOverride", JSONArray().put("http").put("tls").put("quic"))
            .put("routeOnly", false)
        if (tunEnabled) {
            inbounds.put(
                JSONObject()
                    .put("tag", "tun")
                    .put("protocol", "tun")
                    .put("settings", JSONObject().put("name", "milkyvpn0").put("mtu", TUN_MTU).put("userLevel", 8))
                    .put("sniffing", sniffing)
            )
        }
        inbounds.put(
            JSONObject()
                .put("tag", "socks")
                .put("listen", "127.0.0.1")
                .put("port", socksPort)
                .put("protocol", "socks")
                .put("settings", JSONObject().put("auth", "noauth").put("udp", true).put("userLevel", 8))
                .put("sniffing", sniffing)
        )
        root.put("inbounds", inbounds)

        // --- outbounds ---
        val outbounds = JSONArray()
        val proxy = buildProxyOutbound(p)
        if (resolvedServerIps.isNotEmpty() && !isIpLiteral(p.address)) {
            proxy.getJSONObject("streamSettings")
                .put("sockopt", JSONObject().put("domainStrategy", "UseIP"))
        }
        outbounds.put(proxy)
        outbounds.put(
            JSONObject().put("tag", "direct").put("protocol", "freedom")
                .put("settings", JSONObject().put("domainStrategy", "UseIP"))
        )
        outbounds.put(JSONObject().put("tag", "block").put("protocol", "blackhole"))
        outbounds.put(JSONObject().put("tag", "dns-out").put("protocol", "dns"))
        root.put("outbounds", outbounds)

        // --- dns: resolved through the tunnel; the server hostname itself is resolved directly ---
        val dns = JSONObject()
        val servers = JSONArray()
        servers.put("https://1.1.1.1/dns-query")
        servers.put(TUN_DNS)
        servers.put(TUN_DNS_2)
        dns.put("servers", servers)
        dns.put("queryStrategy", "UseIPv4")
        if (resolvedServerIps.isNotEmpty() && !isIpLiteral(p.address)) {
            // Pre-resolved by the service through the underlying (non-VPN) network so the core
            // never needs to resolve its own uplink through the tunnel.
            val hosts = JSONObject()
            if (resolvedServerIps.size == 1) hosts.put(p.address, resolvedServerIps[0])
            else hosts.put(p.address, JSONArray(resolvedServerIps))
            dns.put("hosts", hosts)
        }
        root.put("dns", dns)

        // --- routing ---
        val rules = JSONArray()
        val inboundTags = JSONArray().put("socks").apply { if (tunEnabled) put("tun") }
        // DNS from the device -> Xray built-in DNS outbound (which uses the "dns" module above).
        rules.put(
            JSONObject().put("type", "field").put("inboundTag", inboundTags)
                .put("port", "53").put("outboundTag", "dns-out")
        )
        // Never send the server's own address back into the tunnel.
        rules.put(
            JSONObject().put("type", "field")
                .put(if (isIpLiteral(p.address)) "ip" else "domain", JSONArray().put(p.address))
                .put("outboundTag", "direct")
        )
        // Local / private ranges bypass.
        rules.put(
            JSONObject().put("type", "field")
                .put("ip", JSONArray().put("geoip:private"))
                .put("outboundTag", "direct")
        )
        root.put(
            "routing", JSONObject()
                .put("domainStrategy", "IPIfNonMatch")
                .put("rules", rules)
        )

        root.put(
            "policy", JSONObject().put(
                "levels", JSONObject().put(
                    "8", JSONObject().put("handshake", 4).put("connIdle", 300).put("uplinkOnly", 1).put("downlinkOnly", 1)
                )
            )
        )
        return root
    }

    private fun buildProxyOutbound(p: ProfileSpec): JSONObject {
        val ob = JSONObject().put("tag", "proxy")
        val stream = JSONObject()
        when (p.protocol) {
            "vless" -> {
                ob.put("protocol", "vless")
                val user = JSONObject().put("id", p.secret).put("encryption", "none").put("level", 8)
                if (!p.flow.isNullOrBlank() && normalizeNetwork(p.network) == "tcp") user.put("flow", p.flow)
                ob.put(
                    "settings", JSONObject().put(
                        "vnext", JSONArray().put(
                            JSONObject().put("address", p.address).put("port", p.port).put("users", JSONArray().put(user))
                        )
                    )
                )
                populateVlessStream(stream, p)
                ob.put("mux", JSONObject().put("enabled", false).put("concurrency", -1))
            }

            "hysteria2" -> {
                ob.put("protocol", "hysteria")
                ob.put("settings", JSONObject().put("version", 2).put("address", p.address).put("port", p.port))
                stream.put("network", "hysteria")
                stream.put("hysteriaSettings", JSONObject().put("version", 2).put("auth", p.secret))
                stream.put("security", "tls")
                val tls = JSONObject()
                    .put("allowInsecure", p.allowInsecure)
                    .put("alpn", JSONArray().put("h3"))
                val sni = p.sni ?: (if (!isIpLiteral(p.address)) p.address else null)
                if (sni != null) tls.put("serverName", sni)
                stream.put("tlsSettings", tls)
                if (!p.obfsPassword.isNullOrBlank()) {
                    stream.put(
                        "finalmask", JSONObject().put(
                            "udp", JSONArray().put(
                                JSONObject().put("type", "salamander").put("settings", JSONObject().put("password", p.obfsPassword))
                            )
                        )
                    )
                }
            }
        }
        ob.put("streamSettings", stream)
        return ob
    }

    private fun populateVlessStream(stream: JSONObject, p: ProfileSpec) {
        val net = normalizeNetwork(p.network)
        var sniHint: String? = null
        when (net) {
            "tcp" -> {
                stream.put("network", "tcp")
                stream.put("tcpSettings", JSONObject().put("header", JSONObject().put("type", "none")))
            }

            "ws" -> {
                stream.put("network", "ws")
                val ws = JSONObject().put("path", p.path ?: "/")
                if (!p.host.isNullOrBlank()) {
                    ws.put("host", p.host)
                    sniHint = p.host
                }
                stream.put("wsSettings", ws)
            }

            "xhttp" -> {
                stream.put("network", "xhttp")
                val xh = JSONObject().put("path", p.path ?: "/")
                if (!p.host.isNullOrBlank()) {
                    xh.put("host", p.host)
                    sniHint = p.host
                }
                xh.put("mode", p.xhttpMode ?: "auto")
                stream.put("xhttpSettings", xh)
            }
        }
        val sni = p.sni ?: sniHint ?: (if (!isIpLiteral(p.address)) p.address else null)
        when (p.security) {
            "reality" -> {
                stream.put("security", "reality")
                val r = JSONObject()
                    .put("publicKey", p.publicKey)
                    .put("fingerprint", p.fingerprint ?: "chrome")
                    .put("shortId", p.shortId ?: "")
                    .put("spiderX", p.spiderX ?: "")
                if (sni != null) r.put("serverName", sni)
                stream.put("realitySettings", r)
            }

            "tls" -> {
                stream.put("security", "tls")
                val t = JSONObject()
                    .put("allowInsecure", p.allowInsecure)
                    .put("fingerprint", p.fingerprint ?: "chrome")
                if (sni != null) t.put("serverName", sni)
                if (!p.alpn.isNullOrBlank()) {
                    val arr = JSONArray()
                    p.alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach { arr.put(it) }
                    if (arr.length() > 0) t.put("alpn", arr)
                }
                stream.put("tlsSettings", t)
            }

            else -> stream.put("security", "none")
        }
    }

    fun isIpLiteral(s: String): Boolean {
        val v4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        if (v4.matches(s)) return true
        return s.contains(':') // IPv6 literal (with or without brackets)
    }
}
