package homes.milky.vpn.vpn

import android.content.Context

/**
 * Per-app split tunneling preferences, written by the Flutter bridge and read
 * at TUN-establish time. Modes:
 *   - "all"   — every app through the VPN (default; own package still excluded)
 *   - "allow" — ONLY the listed packages go through the tunnel
 *   - "block" — every app EXCEPT the listed ones goes through the tunnel
 * Changes apply on the next tunnel establish; the bridge restarts the session
 * after a write when one is active.
 */
object SplitTunnelStore {
    private const val PREFS = "milky_split"
    private const val KEY_MODE = "mode"
    private const val KEY_PACKAGES = "packages"

    const val MODE_ALL = "all"
    const val MODE_ALLOW = "allow"
    const val MODE_BLOCK = "block"

    data class Config(val mode: String, val packages: Set<String>)

    fun read(ctx: Context): Config {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val mode = p.getString(KEY_MODE, MODE_ALL) ?: MODE_ALL
        val pkgs = p.getStringSet(KEY_PACKAGES, emptySet()) ?: emptySet()
        return Config(
            if (mode == MODE_ALLOW || mode == MODE_BLOCK) mode else MODE_ALL,
            pkgs.toSet(),
        )
    }

    fun write(ctx: Context, mode: String, packages: Collection<String>) {
        val m = if (mode == MODE_ALLOW || mode == MODE_BLOCK) mode else MODE_ALL
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_MODE, m)
            .putStringSet(KEY_PACKAGES, packages.toSet())
            .apply()
    }
}
