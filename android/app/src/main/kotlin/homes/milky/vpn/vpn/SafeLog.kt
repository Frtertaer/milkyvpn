package homes.milky.vpn.vpn

import android.util.Log
import homes.milky.vpn.BuildConfig
import homes.milky.vpn.core.XrayConfigBuilder

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

    /**
     * Converts an exception into a short machine-readable, credential-free error code.
     *
     * Contract: the returned value is a **stable vocabulary**, never a JVM class name.
     * Xray-core is a Go library bound through gomobile, so its failures surface as
     * `go.Universe$proxyerror` (or, in an R8-minified release build, as a one-letter class
     * such as `S`). Those names used to leak straight into the UI as
     * "Не удалось выполнить операцию (proxyerror)". They are now mapped onto the vocabulary
     * the Dart side knows; the raw throwable stays in logcat only.
     */
    fun errorCode(t: Throwable?): String {
        if (t == null) return "unknown_error"
        val msg = (t.message ?: "").lowercase()
        return when {
            msg.contains("timeout") || msg.contains("timed out") -> "timeout"
            msg.contains("refused") -> "connection_refused"
            msg.contains("unreachable") || msg.contains("no route") -> "network_unreachable"
            msg.contains("tls") || msg.contains("handshake") || msg.contains("certificate") -> "tls_handshake"
            msg.contains("reality") -> "reality_handshake"
            msg.contains("dns") || msg.contains("resolve") -> "dns_failure"
            msg.contains("establish") -> "tun_establish_failed"
            msg.contains("verification failed") -> "tunnel_unverified"
            msg.contains("core did not start") -> "core_start_failed"
            msg.contains("permission") || msg.contains("not permitted") -> "permission_denied"
            msg.contains("failed host lookup") -> "dns_failure"
            isGoOrObfuscated(t) -> coreErrorCode(msg)
            t is XrayConfigBuilder.UnsupportedProfileException -> "unsupported_profile"
            t is IllegalArgumentException -> "config_invalid"
            t is SecurityException -> "permission_denied"
            t is java.net.UnknownHostException -> "dns_failure"
            t is java.net.ConnectException -> "connection_refused"
            t is java.net.SocketTimeoutException -> "timeout"
            t is java.io.IOException -> "network_error"
            else -> "core_failure"
        }
    }

    /**
     * True when the throwable came from the Go core (gomobile proxy) or when its class name
     * has been shortened by R8 — in both cases the simple name carries no information.
     */
    private fun isGoOrObfuscated(t: Throwable): Boolean {
        val name = t.javaClass.name
        if (name.startsWith("go.") || name.startsWith("libv2ray.")) return true
        val simple = t.javaClass.simpleName
        if (simple.isBlank()) return true
        if (simple.length <= 2) return true
        if (simple.equals("proxyerror", ignoreCase = true)) return true
        return false
    }

    /** Refines a Go core failure using the message text, which survives obfuscation. */
    private fun coreErrorCode(msg: String): String = when {
        msg.isBlank() -> "core_start_failed"
        msg.contains("dial") || msg.contains("connect") -> "connection_refused"
        msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup") -> "dns_failure"
        msg.contains("tls") || msg.contains("handshake") || msg.contains("certificate") -> "tls_handshake"
        msg.contains("reality") -> "reality_handshake"
        msg.contains("invalid") || msg.contains("parse") || msg.contains("config") -> "config_invalid"
        msg.contains("timeout") || msg.contains("timed out") -> "timeout"
        else -> "core_start_failed"
    }
