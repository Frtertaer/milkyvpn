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
 *   -> proxy outbound: vless|vmess|trojan|shadowsocks(+reality|tls,
 *   tcp|ws|xhttp|grpc) or hysteria2
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
    val SUPPORTED_PROTOCOLS = setOf("vless", "hysteria2", "vmess", "trojan", "ss", "shadowsocks", "kal2")
    val SUPPORTED_KAL2_CARRIERS = setOf("veil", "drift", "relay")
    val SUPPORTED_VLESS_NETWORKS = setOf("tcp", "raw", "ws", "xhttp", "grpc")
    val SUPPORTED_VLESS_SECURITY = setOf("reality", "tls", "none")
    val SUPPORTED_VMESS_NETWORKS = setOf("tcp", "raw", "ws", "xhttp", "grpc")
    val SUPPORTED_TROJAN_NETWORKS = setOf("tcp", "raw", "ws", "grpc")
    val SUPPORTED_SS_CIPHERS = setOf(
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305",
        "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305", "none", "plain",
    )

    /**
     * Inline equivalent of the upstream `geoip:private` entry.
     *
     * Android embeds the core library without the optional geoip.dat asset. Keeping these
     * prefixes in the generated config preserves local/private bypass routing without making
     * core startup depend on an external geodata file.
     * Source: https://github.com/v2fly/geoip/blob/master/plugin/special/private.go
     */
    private val PRIVATE_AND_LOCAL_CIDRS = listOf(
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
        val ech: String? = null,
        val cover: String? = null,
        val spiderX: String? = null,
        val flow: String? = null,
        val host: String? = null,
        val path: String? = null,
        val xhttpMode: String? = null,
        val alpn: String? = null,
        val allowInsecure: Boolean = false,
        val obfsPassword: String? = null,
        val alterId: Int = 0,
        val cipher: String? = null,
        val plugin: String? = null,
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
                    ech = s("ech"),
                    cover = s("cover"),
                    spiderX = s("spiderX"),
                    flow = s("flow"),
                    host = s("host"),
                    path = s("path"),
                    xhttpMode = s("xhttpMode"),
                    alpn = s("alpn"),
                    allowInsecure = (m["allowInsecure"] as? Boolean) ?: false,
                    obfsPassword = s("obfsPassword"),
                    alterId = (m["alterId"] as? Number)?.toInt() ?: 0,
                    cipher = s("cipher"),
                    plugin = s("plugin"),
                )
            }
        }
    }

    /**
     * RU services bypass the tunnel so they keep seeing the user's real (residential)
     * egress IP instead of a datacentre VPN exit that their anti-bot/fraud checks flag
     * or outright block (e.g. "Похоже, нет соединения" on ozon.ru).
     *
     * [RU_TLD_SUFFIXES] uses plain domain entries: in the core's matcher a bare "ru"
     * covers "ru" itself and every subdomain — i.e. the entire .ru zone.
     * [RU_SERVICE_DOMAINS] lists major RU properties hosted on non-RU TLDs.
     */
    private val RU_TLD_SUFFIXES = listOf("ru", "su", "xn--p1ai")
    private val RU_SERVICE_DOMAINS = listOf(
        // Yandex / VK / Mail group
        "yandex.net", "yandex.com", "yaani.net", "yastatic.net",
        "vk.com", "vk.me", "vk.company", "userapi.com", "mycdn.me", "vkcdn.net", "my.com",
        // Marketplaces & retail
        "ozon.ru", "ozoncdn.net", "ozonusercontent.com", "ozon.tech",
        "wildberries.ru", "wb.ru", "wbstatic.net", "wbbasket.ru",
        "avito.st", "lenta.com", "lemanapro.ru", "vseinstrumenti.ru",
        // Banks & fintech
        "vtb.com", "alfabank.net", "tinkoff.net", "tbank.ru", "sber.ru", "sberdevices.ru",
        // Gov & services
        "2gis.com", "gosuslugi.ru", "esia.gosuslugi.ru",
        // Media & misc
        "kino.pub", "kinopoisk.io",
    )

    /** Yandex public DNS — queried directly for RU domains so CDN geo answers are RU-side. */
    private const val RU_DNS_PRIMARY = "77.88.8.8"
    private const val RU_DNS_SECONDARY = "77.88.8.1"

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
        when (p.protocol) {
            "kal2" -> {
                if (p.publicKey.isNullOrBlank()) throw UnsupportedProfileException("kal2.pub")
                if (p.network.lowercase() !in SUPPORTED_KAL2_CARRIERS)
                    throw UnsupportedProfileException("kal2.carrier")
            }
            "vless" -> {
                val net = normalizeNetwork(p.network)
                if (net !in SUPPORTED_VLESS_NETWORKS) throw UnsupportedProfileException("network")
                if (p.security !in SUPPORTED_VLESS_SECURITY) throw UnsupportedProfileException("security")
                if (p.security == "reality") {
                    if (p.publicKey.isNullOrBlank()) throw UnsupportedProfileException("reality.publicKey")
                    if (net == "ws") throw UnsupportedProfileException("reality+ws")
                }
            }
            "vmess" -> {
                if (normalizeNetwork(p.network) !in SUPPORTED_VMESS_NETWORKS)
                    throw UnsupportedProfileException("network")
            }
            "trojan" -> {
                if (normalizeNetwork(p.network) !in SUPPORTED_TROJAN_NETWORKS)
                    throw UnsupportedProfileException("network")
            }
            "ss", "shadowsocks" -> {
                if (p.cipher.isNullOrBlank()) throw UnsupportedProfileException("method")
                if (p.cipher.lowercase() !in SUPPORTED_SS_CIPHERS)
                    throw UnsupportedProfileException("method")
                if (!p.plugin.isNullOrBlank()) throw UnsupportedProfileException("plugin")
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
     * @param kal2SocksPort loopback SOCKS port of the already-running KAL/2 client; required
     *        when [p.protocol] is "kal2" — the proxy outbound then points at that local bridge
     *        instead of speaking to the server directly.
     */
    fun build(
        p: ProfileSpec,
        tunEnabled: Boolean = true,
        socksPort: Int = 10808,
        resolvedServerIps: List<String> = emptyList(),
        kal2SocksPort: Int? = null,
    ): JSONObject {
        validate(p)
        if (p.protocol == "kal2" && kal2SocksPort == null)
            throw UnsupportedProfileException("kal2.port")
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
        val proxy = buildProxyOutbound(p, kal2SocksPort)
        if (resolvedServerIps.isNotEmpty() && !isIpLiteral(p.address) && proxy.has("streamSettings")) {
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

        // --- dns: RU domains go to Yandex DNS (direct, RU vantage); everything else via tunnel ---
        val dns = JSONObject()
        val servers = JSONArray()
        servers.put(
            JSONObject()
                .put("address", RU_DNS_PRIMARY)
                .put("port", 53)
                .put("domains", JSONArray(RU_TLD_SUFFIXES + RU_SERVICE_DOMAINS))
        )
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
        // RU-resolver queries must reach the real network: without this rule they would be
        // caught by the port-53 rule below and loop back into the DNS module.
        rules.put(
            JSONObject().put("type", "field")
                .put("ip", JSONArray().put(RU_DNS_PRIMARY).put(RU_DNS_SECONDARY))
                .put("outboundTag", "direct")
        )
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
        // RU services bypass the tunnel entirely (anti-VPN-detection on RU apps/sites).
        rules.put(
            JSONObject().put("type", "field")
                .put("domain", JSONArray(RU_TLD_SUFFIXES + RU_SERVICE_DOMAINS))
                .put("outboundTag", "direct")
        )
        // Local / private ranges bypass. Use literal CIDRs because the embedded Android core
        // does not ship geoip.dat; a geoip:private rule would make configuration loading fail.
        rules.put(
            JSONObject().put("type", "field")
                .put("ip", JSONArray(PRIVATE_AND_LOCAL_CIDRS))
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

    private fun buildProxyOutbound(p: ProfileSpec, kal2SocksPort: Int? = null): JSONObject {
        val ob = JSONObject().put("tag", "proxy")
        val stream = JSONObject()
        when (p.protocol) {
            "kal2" -> {
                // The KAL/2 native client (libkal2.so) owns the tunnel session and serves
                // plain SOCKS5 on loopback; Xray's TUN stack is bridged onto it.
                ob.put("protocol", "socks")
                ob.put(
                    "settings", JSONObject().put(
                        "servers", JSONArray().put(
                            JSONObject().put("address", "127.0.0.1").put("port", kal2SocksPort)
                        )
                    )
                )
                return ob // no streamSettings on a socks outbound
            }
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

            "vmess" -> {
                ob.put("protocol", "vmess")
                val user = JSONObject()
                    .put("id", p.secret)
                    .put("alterId", p.alterId)
                    .put("security", p.cipher ?: "auto")
                    .put("level", 8)
                ob.put(
                    "settings", JSONObject().put(
                        "vnext", JSONArray().put(
                            JSONObject().put("address", p.address).put("port", p.port).put("users", JSONArray().put(user))
                        )
                    )
                )
                populateVlessStream(stream, p)
            }

            "trojan" -> {
                ob.put("protocol", "trojan")
                val server = JSONObject()
                    .put("address", p.address)
                    .put("port", p.port)
                    .put("password", p.secret)
                    .put("level", 8)
                ob.put("settings", JSONObject().put("servers", JSONArray().put(server)))
                populateVlessStream(stream, p)
            }

            "ss", "shadowsocks" -> {
                ob.put("protocol", "shadowsocks")
                val server = JSONObject()
                    .put("address", p.address)
                    .put("port", p.port)
                    .put("method", p.cipher)
                    .put("password", p.secret)
                    .put("level", 8)
                ob.put("settings", JSONObject().put("servers", JSONArray().put(server)))
                stream.put("network", "tcp")
                stream.put("security", "none")
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

            "grpc" -> {
                stream.put("network", "grpc")
                val g = JSONObject().put("serviceName", p.path ?: "")
                if (!p.host.isNullOrBlank()) {
                    g.put("authority", p.host)
                    sniHint = p.host
                }
                stream.put("grpcSettings", g)
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
