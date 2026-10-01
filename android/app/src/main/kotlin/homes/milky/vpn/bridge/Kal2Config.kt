package homes.milky.vpn.bridge

import android.os.Build
import homes.milky.vpn.core.XrayConfigBuilder
import homes.milky.vpn.core.XrayConfigBuilder.ProfileSpec
import org.json.JSONObject

/** Maps a parsed kal2:// profile to the JSON config the native core takes. */
object Kal2Config {
    /** Loopback SOCKS endpoint the native client binds; must not collide with the app's own 10808. */
    const val LOCAL_SOCKS_PORT = 11808
    const val LOCAL_SOCKS = "127.0.0.1:$LOCAL_SOCKS_PORT"

    fun isKal2(p: ProfileSpec): Boolean = p.protocol.equals("kal2", ignoreCase = true)

    fun toJson(p: ProfileSpec): JSONObject {
        // "auto" hedges veil+drift in parallel inside the native core — default
        // for plain kal2:// links; any carrier the support gate accepts passes
        // through verbatim (single source: SUPPORTED_KAL2_CARRIERS — a second
        // allowlist here dropped rtc/relay to "auto", BUG-2026-10-02-05).
        val network = p.network.lowercase()
        val carrier =
            if (network in XrayConfigBuilder.SUPPORTED_KAL2_CARRIERS) network
            else "auto"
        return JSONObject()
            // altAddrs: extra entry points of the same server — the native
            // core fails over across the comma list (multi-entry link).
            .put("addr", "${p.address}:${p.port}" + p.altAddrs.orEmpty().let { if (it.isBlank()) "" else ",$it" })
            .put("sni", p.sni ?: "")
            .put("carrier", carrier)
            .put("path", p.path ?: "")
            .put("pub", p.publicKey ?: "")
            .put("psk", p.secret)
            .put("socks", LOCAL_SOCKS)
            .put("ech", p.ech ?: "")
            .put("pin", p.pin ?: "")
            // front= front-relay URL: HTTP-shaped carriers dial it instead
            // of addr (blocked entry / whitelisted-domain only).
            .put("front", p.front ?: "")
            .put("fronts", org.json.JSONArray(p.fronts ?: emptyList<String>()))
            // cover defaults on in the native core; "0"/"false" disables it.
            .put("cover", !p.cover.equals("0") && !p.cover.equals("false", true))
            // The core verifies the outer TLS chain; Android < 7.1.1 lacks
            // ISRG Root X1, so only there it falls back to the KAL/2 identity
            // key + exporter binding alone.
            .put("insecure", Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1)
    }
}
