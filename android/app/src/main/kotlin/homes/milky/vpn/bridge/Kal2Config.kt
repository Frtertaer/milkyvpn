package homes.milky.vpn.bridge

import android.os.Build
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
            "cdn" -> "cdn"
            "mosaic" -> "mosaic"
            "quasar" -> "quasar"
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
            .put("ech", p.ech ?: "")
            // cover defaults on in the native core; "0"/"false" disables it.
            .put("cover", !p.cover.equals("0") && !p.cover.equals("false", true))
            // API < 25 ships a stale root store (no ISRG Root X1) — veil's
            // certificate chain can never verify there; skip CA verification
            // on those devices only (session is still KAL/2-authenticated).
            .put("insecure", Build.VERSION.SDK_INT < 25)
    }
}
