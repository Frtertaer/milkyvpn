package homes.milky.vpn.vpn

import android.util.Log
import homes.milky.vpn.BuildConfig
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CancellationException

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
    private val longBase64Re = Regex("[A-Za-z0-9+/_\\-]{40,}={0,2}")

    fun redact(msg: String?): String {
        if (msg == null) return "null"
        var m = msg
        m = uuidRe.replace(m, "<uuid>")
        m = subTokenRe.replace(m) { "${it.groupValues[1]}<token>" }
        m = userInfoRe.replace(m) { "${it.groupValues[1]}://<cred>@" }
        m = queryCredRe.replace(m) { "${it.groupValues[1]}<redacted>" }
        m = longBase64Re.replace(m, "<blob>")
        return m
    }

    fun d(msg: String) {
        if (BuildConfig.DEBUG) Log.d(TAG, redact(msg))
    }

    fun i(msg: String) {
        Log.i(TAG, redact(msg))
    }

    fun w(msg: String, t: Throwable? = null) {
        Log.w(TAG, redact(msg) + (t?.let { " :: " + errorDetail(it) } ?: ""))
    }

    fun e(msg: String, t: Throwable? = null) {
        Log.e(TAG, redact(msg) + (t?.let { " :: " + errorDetail(it) } ?: ""))
    }

    /**
     * Converts an exception into a short, machine-readable, credential-free error code drawn
     * from a CLOSED vocabulary.
     *
     * History: the previous implementation fell back to `javaClass.simpleName`, which produced
     * `proxyerror` (the gomobile wrapper class `go.Universe$proxyerror` for any Go `error`) and
     * single letters such as `S` (R8-minified kotlinx.coroutines exception classes, e.g.
     * JobCancellationException) in the user interface. Class names are never returned anymore;
     * they only appear, redacted, in [errorDetail] for the diagnostics screen.
     */
    fun errorCode(t: Throwable?): String {
        if (t == null) return "unknown"
        val msg = (t.message ?: "").lowercase()
        val cls = t.javaClass.name.lowercase()
        // kotlinx.coroutines.TimeoutCancellationException is a CancellationException subclass whose
        // message is "Timed out waiting for N ms" — classify it by message before the cancel check.
        if (msg.contains("timed out") || msg.contains("timeout") || msg.contains("deadline exceeded")) return "timeout"
        if (t is CancellationException || cls.contains("cancellation")) return "cancelled"
        return when {
            msg.contains("refused") -> "connection_refused"
            msg.contains("unreachable") || msg.contains("no route") || msg.contains("network is down") -> "network_unreachable"
            msg.contains("reality") -> "reality_handshake"
            msg.contains("tls") || msg.contains("handshake") || msg.contains("certificate") || msg.contains("x509") -> "tls_handshake"
            msg.contains("no such host") || msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup") -> "dns_failure"
            msg.contains("establish") -> "tun_establish_failed"
            msg.contains("permission") || t is SecurityException -> "permission_denied"
            msg.contains("connection reset") || msg.contains("broken pipe") || msg.contains("eof") -> "connection_reset"
            // gomobile wraps every Go `error` in go.Universe$proxyerror (kept by R8 via -keep class go.**).
            cls.startsWith("go.") || cls.contains("proxyerror") -> "core_error"
            t is SocketTimeoutException -> "timeout"
            t is ConnectException -> "connection_refused"
            t is UnknownHostException -> "dns_failure"
            t is IOException -> "network_error"
            t is IllegalArgumentException -> "config_invalid"
            t is IllegalStateException -> "core_state_error"
            t is OutOfMemoryError -> "out_of_memory"
            t is UnsatisfiedLinkError || t is NoClassDefFoundError -> "core_library_missing"
            else -> "internal_error"
        }
    }

    /**
     * Redacted, bounded human-readable detail for the diagnostics screen only (never shown as the
     * primary user message). Contains the (possibly minified) class name and the redacted message.
     */
    fun errorDetail(t: Throwable?): String {
        if (t == null) return ""
        val name = t.javaClass.name.substringAfterLast('.').substringAfterLast('$').ifBlank { "Error" }
        val msg = redact(t.message ?: "")
        val cause = t.cause?.takeIf { it !== t }?.let { " <- " + it.javaClass.name.substringAfterLast('.') + ": " + redact(it.message ?: "") } ?: ""
        return ("$name: $msg$cause").take(240)
    }
}
