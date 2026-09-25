package homes.milky.vpn.bridge

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
        // for plain kal2:// links; an explicit carrier is honored.
        val carrier = when (p.network.lowercase()) {
            "drift" -> "drift"
            "veil" -> "veil"
            else -> "auto"
        }
        return JSONObject()
            .put("addr", "${p.address}:${p.port}")
            .put("sni", p.sni ?: "")
            .put("carrier", carrier)
            .put("path", p.path ?: "")
            .put("pub", p.publicKey ?: "")
            .put("psk", p.secret)
            .put("socks", LOCAL_SOCKS)
    }
}
