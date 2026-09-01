package homes.milky.vpn.vpn

import android.util.Log
import homes.milky.vpn.BuildConfig

/**
 * Logging wrapper that (a) is silent for debug/verbose in release and (b) redacts anything
 * that looks like a credential before it reaches logcat.
 */
object SafeLog {
    private const val TAG = "MilkyVPN"

    private val uuidRe = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    private val subTokenRe = Regex("(sub\\.milky\\.homes/s/)[A-Za-z0-9_\\-]+")
    private val userInfoRe = Regex("(vless|hysteria2|hy2|trojan|ss)://[^@\\s]+@")
    private val queryCredRe = Regex("([?&](pbk|sid|password|obfs-password|auth|token)=)[^&\\s#]+")

    fun redact(msg: String?): String {
        if (msg == null) return "null"
        var m = msg
        m = uuidRe.replace(m, "<uuid>")
        m = subTokenRe.replace(m) { "${it.groupValues[1]}<token>" }
        m = userInfoRe.replace(m) { "${it.groupValues[1]}://<cred>@" }
        m = queryCredRe.replace(m) { "${it.groupValues[1]}<redacted>" }
        return m
    }

    fun d(msg: String) {
        if (BuildConfig.DEBUG) Log.d(TAG, redact(msg))
    }

    fun i(msg: String) {
        Log.i(TAG, redact(msg))
    }

    fun w(msg: String, t: Throwable? = null) {
        Log.w(TAG, redact(msg) + (t?.let { " :: " + redact(it.javaClass.simpleName + ": " + it.message) } ?: ""))
    }

    fun e(msg: String, t: Throwable? = null) {
        Log.e(TAG, redact(msg) + (t?.let { " :: " + redact(it.javaClass.simpleName + ": " + it.message) } ?: ""))
    }

    /** Converts an exception into a short machine-readable, credential-free error code. */
    fun errorCode(t: Throwable?): String {
        if (t == null) return "unknown"
        val name = t.javaClass.simpleName.ifBlank { "Error" }
        val msg = (t.message ?: "").lowercase()
        return when {
            msg.contains("timeout") || msg.contains("timed out") -> "timeout"
            msg.contains("refused") -> "connection_refused"
            msg.contains("unreachable") || msg.contains("no route") -> "network_unreachable"
            msg.contains("tls") || msg.contains("handshake") || msg.contains("certificate") -> "tls_handshake"
            msg.contains("reality") -> "reality_handshake"
            msg.contains("dns") || msg.contains("resolve") -> "dns_failure"
            msg.contains("establish") -> "tun_establish_failed"
            else -> name.replace(Regex("[^A-Za-z0-9_]"), "_").take(40)
        }
    }
}
