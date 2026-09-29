package homes.milky.vpn.bridge

/**
 * JNI bridge to libcore.so — the KAL/2 session core (Go, -buildmode=c-shared).
 * A started core dials the endpoint, keeps a reconnect watchdog inside the Go
 * runtime, and serves SOCKS5 on loopback; Xray-core's TUN stack is then pointed
 * at that SOCKS port as a plain socks5 outbound (see MilkyVpnService).
 */
object NativeBridge {
    init {
        System.loadLibrary("core")
    }

    private external fun nativeStart(configJson: String): Int
    private external fun nativeStop()
    private external fun nativeAlive(): Boolean
    private external fun nativeLastError(): String

    class StartException(message: String) : Exception(message)

    /**
     * Starts the KAL/2 client: dial + SOCKS5 on the configured loopback address.
     * Returns the bound SOCKS port; throws [StartException] on native failure.
     */
    fun start(configJson: String): Int {
        val port = nativeStart(configJson)
        if (port < 0) throw StartException(nativeLastError().ifBlank { "kal2 start failed" })
        return port
    }

    /** Idempotent; safe to call when nothing is running. */
    fun stop() = nativeStop()

    /** Whether a session is currently connected. */
    fun isAlive(): Boolean = nativeAlive()
}
