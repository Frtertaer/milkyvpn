package homes.milky.vpn.bridge

import homes.milky.vpn.core.XrayConfigBuilder.ProfileSpec
import org.json.JSONObject

/** Maps a parsed kal2:// profile to the JSON config the native core takes. */
object Kal2Config {
    /** Loopback SOCKS endpoint the native client binds; must not collide with the app's own 10808. */
    const val LOCAL_SOCKS = "127.0.0.1:11808"

    fun isKal2(p: ProfileSpec): Boolean = p.protocol.equals("kal2", ignoreCase = true)

    fun toJson(p: ProfileSpec): JSONObject {
        // A 'relay' link still speaks a normal last-hop carrier (veil by default).
        val carrier = if (p.network.equals("drift", ignoreCase = true)) "drift" else "veil"
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
