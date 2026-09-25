package homes.milky.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import go.Seq
import homes.milky.vpn.MainActivity
import homes.milky.vpn.R
import homes.milky.vpn.core.XrayConfigBuilder
import homes.milky.vpn.bridge.Kal2Config
import homes.milky.vpn.kal2.Kal2Service
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Real Android VpnService backed by Xray-core (AndroidLibXrayLite).
 *
 * Lifecycle:
 *  - [ACTION_CONNECT] (from the Flutter bridge, after VpnService.prepare() consent) or a
 *    system start (Always-on VPN, `intent == null` / action android.net.VpnService):
 *      1. startForeground (specialUse type on API 34+)
 *      2. read the active profile from the Keystore-sealed store
 *      3. resolve the server host on the underlying network
 *      4. Builder.establish() -> TUN fd
 *      5. Xray core startLoop(config, fd)   (tun inbound inside the core, gVisor stack)
 *      6. bounded verification: HTTPS GET through the core outbound (core.Dial)
 *      7. CONNECTED  — or teardown + ERROR(errorCode)
 *  - [ACTION_DISCONNECT] / notification action / onRevoke(): clean teardown.
 *
 * Loop avoidance: this package is excluded from the tunnel via addDisallowedApplication, so the
 * core's uplink sockets always use the real network. Side effect (documented): the app's own
 * traffic (subscription refresh) is not tunnelled.
 */
class MilkyVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "homes.milky.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "homes.milky.vpn.action.DISCONNECT"
        const val SEALED_ACTIVE_PROFILE = "active_profile"

        private const val NOTIF_CHANNEL = "milkyvpn_tunnel"
        private const val NOTIF_ID = 1001
        private const val VERIFY_URL = "https://www.gstatic.com/generate_204"
        private const val VERIFY_TIMEOUT_MS = 20_000L
        private const val STARTUP_TIMEOUT_MS = 15_000L

        @Volatile
        var instance: MilkyVpnService? = null
            private set

        fun coreVersion(): String = try {
            Libv2ray.checkVersionX()
        } catch (t: Throwable) {
            "unavailable"
        }
    }

    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO +
            CoroutineExceptionHandler { _, t -> SafeLog.w("service coroutine error", t) }
    )
    private val mutex = Mutex()
    private val attempts = ConnectionAttemptGate()
    private var tunFd: ParcelFileDescriptor? = null
    private var controller: CoreController? = null
    private var connectJob: Job? = null
    private val coreEnvReady = AtomicBoolean(false)
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private lateinit var connectivity: ConnectivityManager

    // ---------------------------------------------------------------- lifecycle

    override fun onCreate() {
        super.onCreate()
        instance = this
        connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                requestDisconnect()
                return START_NOT_STICKY
            }

            ACTION_CONNECT, null, SERVICE_INTERFACE -> {
                // null / SERVICE_INTERFACE == started by the system (Always-on VPN).
                startAsForeground(getString(R.string.vpn_notif_connecting))
                val attemptId = attempts.begin()
                connectJob?.cancel()
                connectJob = scope.launch { connect(attemptId) }
                return START_STICKY
            }

            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        // Another VPN app took over or the user revoked permission in system settings.
        SafeLog.i("onRevoke")
        requestDisconnect(revoked = true)
    }

    override fun onDestroy() {
        // Invalidate queued core/network callbacks before releasing service resources.
        attempts.cancelCurrent()
        instance = null
        unregisterNetworkCallback()
        scope.cancel()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- connect

    private suspend fun connect(attemptId: Long) = mutex.withLock {
        if (!attempts.isActive(attemptId)) return@withLock
        // A newer connect command replaces any previously established core/TUN.
        teardownLocked()

        val store = KeystoreSealedStore(this, SEALED_ACTIVE_PROFILE)
        var profileId = ""
        var remark = ""
        val trace = ConnectionTrace { SafeLog.i("attempt=$attemptId $it") }

        try {
            trace.begin("PROFILE_SELECTED")
            val raw = store.read()
            if (raw == null) {
                throw XrayConfigBuilder.UnsupportedProfileException("no active profile")
            }
            val stored = parseStoredActiveProfile(raw)
            profileId = stored.profileId
            remark = stored.remark
            val spec = stored.spec
            trace.success("PROFILE_SELECTED", "remark=${SafeLog.redact(remark)}")
            trace.success("VPN_SERVICE_STARTED", "foreground=true")

            if (!attempts.runIfActive(attemptId) {
                    VpnStateStore.update(
                        VpnStateStore.State.CONNECTING,
                        profileId = profileId,
                        profileRemark = remark,
                        connectedSinceEpochMs = null,
                        lastSuccessfulStage = null,
                        firstFailedStage = null,
                    )
                }
            ) return@withLock

            trace.begin("VPN_PERMISSION_GRANTED")
            if (prepare(this) != null) {
                throw SecurityException("VPN permission missing")
            }

            trace.success("VPN_PERMISSION_GRANTED")
            trace.begin("CONFIG_BUILT")
            XrayConfigBuilder.validate(spec)

            // 1. Resolve uplink on the underlying network (TUN not yet established).
            val resolved = resolveServer(spec.address)

            // KAL/2 profiles: the native session must be up before the config is built —
            // the SOCKS port it binds goes into the bridge outbound.
            var kal2SocksPort: Int? = null
            if (Kal2Config.isKal2(spec)) {
                trace.begin("KAL2_SESSION_STARTING")
                kal2SocksPort = Kal2Service.startSession(this, Kal2Config.toJson(spec).toString())
                trace.success("KAL2_SESSION_STARTED", "carrier=${spec.network.lowercase()}")
            }

            val config = XrayConfigBuilder.build(
                spec,
                tunEnabled = true,
                resolvedServerIps = resolved,
                kal2SocksPort = kal2SocksPort,
            )
            trace.success("CONFIG_BUILT", configShape(spec, config))

            // 2. Establish TUN.
            trace.begin("TUN_CREATED")
            val fd = establishTun() ?: throw IllegalStateException("establish returned null")
            tunFd = fd
            trace.success("TUN_CREATED", "ipv4=true ipv6=blocked mtu=${XrayConfigBuilder.TUN_MTU} appUidExcluded=true")
            trace.success("TUN_FD_RECEIVED", "valid=${fd.fd >= 0} fd=${fd.fd}")

            // 3. Start core.
            trace.begin("XRAY_PROCESS_STARTING")
            ensureCoreEnv()
            val ctrl = Libv2ray.newCoreController(callbackHandler(attemptId))
            controller = ctrl
            SafeLog.i("attempt=$attemptId nativeMode=inProcess exitCode=not_applicable")
            withTimeout(STARTUP_TIMEOUT_MS) {
                withContext(Dispatchers.IO) { ctrl.startLoop(config.toString(), fd.fd) }
            }
            // Native validation is proven only after startLoop accepts the exact JSON.
            trace.success("CONFIG_VALIDATED", "native=true")
            trace.begin("XRAY_PROCESS_STARTED")
            if (!ctrl.isRunning) throw IllegalStateException("core did not start")
            trace.success("XRAY_PROCESS_STARTED", "isRunning=true exitCode=not_applicable")
            trace.success("OUTBOUND_READY", "configured=true reachabilityNotYetVerified=true")

            // 4. Bounded real connectivity verification through the outbound.
            trace.begin("POST_CONNECT_PROBE")
            val delayMs = withTimeout(VERIFY_TIMEOUT_MS) {
                withContext(Dispatchers.IO) { ctrl.measureDelay(VERIFY_URL) }
            }
            if (delayMs < 0) throw IllegalStateException("verification failed")
            trace.success("POST_CONNECT_PROBE", "delayMs=$delayMs")
            SafeLog.i("outbound probe succeeded in ${delayMs}ms")

            val published = attempts.runIfActive(attemptId) {
                trace.success("CONNECTED")
                registerNetworkCallback(attemptId)
                updateNotification(getString(R.string.vpn_notif_connected) + " · " + remark)
                VpnStateStore.update(
                    VpnStateStore.State.CONNECTED,
                    profileId = profileId,
                    profileRemark = remark,
                    connectedSinceEpochMs = System.currentTimeMillis(),
                    lastSuccessfulStage = trace.lastSuccessfulStage,
                    firstFailedStage = null,
                )
            }
            if (!published) teardownLocked()
        } catch (t: Throwable) {
            val code = SafeLog.errorCode(t)
            trace.failure(code)
            SafeLog.w("connect failed", t)
            teardownLocked()
            failAttemptLocked(
                attemptId,
                profileId = profileId,
                profileRemark = remark,
                errorCode = code,
                lastSuccessfulStage = trace.lastSuccessfulStage,
                firstFailedStage = trace.firstFailedStage,
            )
        }
    }

    /** Must be called with [mutex] held. */
    private fun failAttemptLocked(
        attemptId: Long,
        profileId: String? = null,
        profileRemark: String? = null,
        errorCode: String,
        lastSuccessfulStage: String? = VpnStateStore.current.lastSuccessfulStage,
        firstFailedStage: String? = VpnStateStore.current.firstFailedStage,
    ) {
        attempts.finishIfActive(attemptId) {
            VpnStateStore.update(
                VpnStateStore.State.ERROR,
                profileId = profileId,
                profileRemark = profileRemark,
                connectedSinceEpochMs = null,
                errorCode = errorCode,
                lastSuccessfulStage = lastSuccessfulStage,
                firstFailedStage = firstFailedStage,
            )
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun resolveServer(host: String): List<String> {
        if (XrayConfigBuilder.isIpLiteral(host)) return emptyList()
        return try {
            InetAddress.getAllByName(host)
                .sortedBy { if (it is Inet4Address) 0 else 1 }
                .mapNotNull { it.hostAddress }
        } catch (t: Throwable) {
            SafeLog.w("pre-resolve failed, core will resolve", t)
            emptyList()
        }
    }

    private fun establishTun(): ParcelFileDescriptor? {
        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(XrayConfigBuilder.TUN_MTU)
            .addAddress(XrayConfigBuilder.TUN_IPV4, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(XrayConfigBuilder.TUN_DNS)
            .addDnsServer(XrayConfigBuilder.TUN_DNS_2)
        // Loop avoidance: never route our own (core) sockets into the TUN.
        try {
            b.addDisallowedApplication(packageName)
        } catch (t: Throwable) {
            SafeLog.w("addDisallowedApplication", t)
            throw IllegalStateException("establish: uplink exclusion failed", t)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            b.setMetered(false)
        }
        val intent = Intent(this, MainActivity::class.java)
        b.setConfigureIntent(
            PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
        return b.establish()
    }

    private fun ensureCoreEnv() {
        if (!coreEnvReady.get()) {
            Seq.setContext(applicationContext)
            val assets = File(filesDir, "xray").apply { mkdirs() }
            Libv2ray.initCoreEnv(assets.absolutePath, xudpBaseKey())
            coreEnvReady.set(true)
        }
    }

    /** Random local salt for XUDP global IDs. Not a credential; stored in noBackupFilesDir. */
    private fun xudpBaseKey(): String {
        val f = File(noBackupFilesDir, "xudp.key")
        if (f.exists()) return f.readText()
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val key = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_PADDING or android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP)
        f.writeText(key)
        return key
    }

    private fun callbackHandler(attemptId: Long) = object : CoreCallbackHandler {
            override fun onEmitStatus(p0: Long, p1: String?): Long {
                SafeLog.i("attempt=$attemptId nativeStatus=$p0 core: ${p1 ?: ""}")
                return 0
            }

            override fun shutdown(): Long {
                scope.launch { handleCoreShutdown(attemptId) }
                return 0
            }

            override fun startup(): Long {
                SafeLog.i("attempt=$attemptId nativeCallback=startup")
                return 0
            }
        }

    private suspend fun handleCoreShutdown(attemptId: Long) = mutex.withLock {
        attempts.finishIfActive(attemptId) {
            teardownLocked()
            VpnStateStore.update(
                VpnStateStore.State.ERROR,
                connectedSinceEpochMs = null,
                errorCode = "core_start_failed",
            )
            stopForegroundCompat()
            stopSelf()
        }
    }

    // ---------------------------------------------------------------- disconnect

    private suspend fun disconnect(ticket: DisconnectTicket, revoked: Boolean) {
        // Cancellation happens before waiting for the mutex held by an in-flight connect.
        ticket.connectJob?.cancel()
        mutex.withLock {
            val stillCurrent = attempts.runIfGeneration(ticket.generation) {
                VpnStateStore.update(VpnStateStore.State.DISCONNECTING)
            }
            if (!stillCurrent) return@withLock
            teardownLocked()
            attempts.runIfGeneration(ticket.generation) {
                VpnStateStore.update(
                    VpnStateStore.State.DISCONNECTED,
                    connectedSinceEpochMs = null,
                    errorCode = if (revoked) "revoked_by_system" else null,
                )
                stopForegroundCompat()
                stopSelf()
            }
        }
    }

    /** Must be called with [mutex] held. */
    private fun teardownLocked() {
        unregisterNetworkCallback()
        try {
            controller?.stopLoop()
        } catch (t: Throwable) {
            SafeLog.w("stopLoop", t)
        }
        controller = null
        try {
            Kal2Service.stopSession(this) // idempotent
        } catch (t: Throwable) {
            SafeLog.w("kal2 stop", t)
        }
        try {
            tunFd?.close()
        } catch (t: Throwable) {
            SafeLog.w("tun close", t)
        }
        tunFd = null
    }

    /** Called from the bridge (same process). */
    fun requestDisconnect(revoked: Boolean = false): Job {
        val ticket = DisconnectTicket(
            generation = attempts.cancelCurrent(),
            connectJob = connectJob,
        )
        ticket.connectJob?.cancel()
        return scope.launch { disconnect(ticket, revoked) }
    }

    // ---------------------------------------------------------------- network transitions

    private fun registerNetworkCallback(attemptId: Long) {
        if (networkCallback != null) return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // Tell the system which physical network carries the tunnel so that
                // captive-portal / metered logic and our uplink follow the new network.
                attempts.runIfActive(attemptId) {
                    try {
                        setUnderlyingNetworks(arrayOf(network))
                    } catch (t: Throwable) {
                        SafeLog.w("setUnderlyingNetworks", t)
                    }
                }
            }

            override fun onLost(network: Network) {
                attempts.runIfActive(attemptId) {
                    try {
                        setUnderlyingNetworks(null)
                    } catch (_: Throwable) {
                    }
                    val current = VpnStateStore.current
                    if (current.state == VpnStateStore.State.CONNECTED) {
                        VpnStateStore.update(VpnStateStore.State.CONNECTING, connectedSinceEpochMs = null)
                    }
                    scope.launch { reverifyAfterNetworkChange(attemptId) }
                }
            }
        }
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            connectivity.registerNetworkCallback(req, cb)
            networkCallback = cb
        } catch (t: Throwable) {
            SafeLog.w("registerNetworkCallback", t)
        }
    }

    private suspend fun reverifyAfterNetworkChange(attemptId: Long) = mutex.withLock {
        if (!attempts.isActive(attemptId)) return@withLock
        try {
            val ctrl = controller ?: throw IllegalStateException("core unavailable")
            val delayMs = withTimeout(VERIFY_TIMEOUT_MS) {
                withContext(Dispatchers.IO) { ctrl.measureDelay(VERIFY_URL) }
            }
            if (delayMs < 0) throw IllegalStateException("verification failed")
            attempts.runIfActive(attemptId) {
                VpnStateStore.update(VpnStateStore.State.CONNECTED, connectedSinceEpochMs = System.currentTimeMillis())
            }
        } catch (t: Throwable) {
            teardownLocked()
            failAttemptLocked(attemptId, errorCode = "network_unreachable")
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            try {
                connectivity.unregisterNetworkCallback(it)
            } catch (_: Throwable) {
            }
        }
        networkCallback = null
    }

    // ---------------------------------------------------------------- notification

    private fun createChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val ch = NotificationChannel(NOTIF_CHANNEL, getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW)
        ch.description = getString(R.string.vpn_channel_desc)
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 2, Intent(this, MilkyVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, NOTIF_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .addAction(0, getString(R.string.vpn_notif_disconnect), stop)
            .build()
    }

    private fun startAsForeground(text: String) {
        val n = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }
}

/** Logs only structure and whitelisted enum values, never endpoint or key values. */
internal fun configShape(p: XrayConfigBuilder.ProfileSpec, config: JSONObject): String {
    fun present(value: String?) = !value.isNullOrBlank()
    fun enum(value: String?, allowed: Set<String>) = if (value in allowed) value else "other_or_absent"
    return listOf(
        "protocol=${enum(p.protocol, setOf("vless", "hysteria2", "kal2"))}",
        "network=${enum(p.network, setOf("tcp", "raw", "ws", "xhttp", "veil", "drift", "relay"))}",
        "security=${enum(p.security, setOf("reality", "tls", "none"))}",
        "addressPresent=${p.address.isNotBlank()}", "portValid=${p.port in 1..65535}",
        "credentialPresent=${p.secret.isNotBlank()}", "sniPresent=${present(p.sni)}",
        "publicKeyPresent=${present(p.publicKey)}", "shortIdPresent=${present(p.shortId)}",
        "publicKeyLength=${p.publicKey?.length ?: 0}", "shortIdLength=${p.shortId?.length ?: 0}",
        "fingerprint=${enum(p.fingerprint, setOf("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"))}",
        "flow=${enum(p.flow, setOf("xtls-rprx-vision", "xtls-rprx-vision-udp443"))}",
        "pathPresent=${present(p.path)}", "hostPresent=${present(p.host)}",
        "allowInsecure=${p.allowInsecure}", "routingPresent=${config.has("routing")}",
        "dnsPresent=${config.has("dns")}", "inbounds=${config.getJSONArray("inbounds").length()}",
        "tunInbound=true", "tunFdViaStartLoop=true", "staticSupported=${XrayConfigBuilder.isSupported(p)}",
    ).joinToString(" ")
}

/**
 * Orders native connect/disconnect commands and prevents an older coroutine or core callback
 * from publishing a terminal state for a newer connection.
 */
internal class ConnectionAttemptGate {
    private var generation = 0L
    private var activeAttempt: Long? = null

    @Synchronized
    fun begin(): Long {
        generation += 1
        activeAttempt = generation
        return generation
    }

    @Synchronized
    fun cancelCurrent(): Long {
        generation += 1
        activeAttempt = null
        return generation
    }

    @Synchronized
    fun isActive(attemptId: Long): Boolean = activeAttempt == attemptId

    @Synchronized
    fun runIfActive(attemptId: Long, action: () -> Unit): Boolean {
        if (activeAttempt != attemptId) return false
        action()
        return true
    }

    @Synchronized
    fun finishIfActive(attemptId: Long, action: () -> Unit): Boolean {
        if (activeAttempt != attemptId) return false
        activeAttempt = null
        action()
        return true
    }

    @Synchronized
    fun runIfGeneration(expectedGeneration: Long, action: () -> Unit): Boolean {
        if (generation != expectedGeneration) return false
        action()
        return true
    }
}

private data class DisconnectTicket(
    val generation: Long,
    val connectJob: Job?,
)

internal data class StoredActiveProfile(
    val profileId: String,
    val remark: String,
    val spec: XrayConfigBuilder.ProfileSpec,
)

/** Parses sealed profile data without reflecting malformed JSON or credentials into an error. */
internal fun parseStoredActiveProfile(raw: String): StoredActiveProfile = try {
    val json = JSONObject(raw)
    StoredActiveProfile(
        profileId = json.optString("id", ""),
        remark = json.optString("remark", ""),
        spec = XrayConfigBuilder.ProfileSpec.fromMap(json.toMap()),
    )
} catch (t: RuntimeException) {
    throw IllegalArgumentException("active profile invalid", t)
}

private fun JSONObject.toMap(): Map<String, Any?> {
    val m = HashMap<String, Any?>()
    keys().forEach { k -> m[k] = if (isNull(k)) null else get(k) }
    return m
}
