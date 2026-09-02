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

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
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
                scope.launch { disconnect(userInitiated = true) }
                return START_NOT_STICKY
            }

            ACTION_CONNECT, null, SERVICE_INTERFACE -> {
                // null / SERVICE_INTERFACE == started by the system (Always-on VPN).
                startAsForeground(getString(R.string.vpn_notif_connecting))
                // Never cancel an in-flight attempt from here: doing so surfaced a bare
                // JobCancellationException (R8-minified to e.g. "S") as the user-facing error.
                // Serialise instead: wait for the previous attempt to finish, then start the new one.
                val previous = connectJob
                connectJob = scope.launch {
                    previous?.join()
                    connect()
                }
                return START_STICKY
            }

            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        // Another VPN app took over or the user revoked permission in system settings.
        SafeLog.i("onRevoke")
        scope.launch { disconnect(userInitiated = false, revoked = true) }
    }

    override fun onDestroy() {
        instance = null
        unregisterNetworkCallback()
        scope.cancel()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- connect

    private suspend fun connect() = mutex.withLock {
        val store = KeystoreSealedStore(this, SEALED_ACTIVE_PROFILE)
        val raw = store.read()
        if (raw == null) {
            SafeLog.w("connect: no active profile")
            VpnStateStore.update(VpnStateStore.State.ERROR, errorCode = "no_profile")
            stopForegroundCompat()
            stopSelf()
            return@withLock
        }
        val json = JSONObject(raw)
        val profileId = json.optString("id", "")
        val remark = json.optString("remark", "")
        val spec = XrayConfigBuilder.ProfileSpec.fromMap(json.toMap())

        VpnStateStore.update(
            VpnStateStore.State.CONNECTING,
            profileId = profileId,
            profileRemark = remark,
            connectedSinceEpochMs = null,
        )

        if (prepare(this) != null) {
            // Consent missing (should have been obtained by the activity).
            VpnStateStore.update(VpnStateStore.State.ERROR, errorCode = "vpn_permission_missing")
            stopForegroundCompat()
            stopSelf()
            return@withLock
        }

        try {
            XrayConfigBuilder.validate(spec)

            // 1. Resolve uplink on the underlying network (TUN not yet established).
            val resolved = resolveServer(spec.address)

            // 2. Establish TUN.
            val fd = establishTun() ?: throw IllegalStateException("establish returned null")
            tunFd = fd

            // 3. Start core.
            ensureCoreEnv()
            val config = XrayConfigBuilder.build(spec, tunEnabled = true, resolvedServerIps = resolved)
            val ctrl = Libv2ray.newCoreController(callbackHandler)
            controller = ctrl
            withTimeout(STARTUP_TIMEOUT_MS) {
                withContext(Dispatchers.IO) { ctrl.startLoop(config.toString(), fd.fd) }
            }
            if (!ctrl.isRunning) throw IllegalStateException("core did not start")

            // 4. Bounded real connectivity verification through the outbound.
            val delayMs = withTimeout(VERIFY_TIMEOUT_MS) {
                withContext(Dispatchers.IO) { ctrl.measureDelay(VERIFY_URL) }
            }
            if (delayMs < 0) throw IllegalStateException("verification failed")
            SafeLog.i("tunnel verified in ${delayMs}ms")

            registerNetworkCallback()
            updateNotification(getString(R.string.vpn_notif_connected) + " · " + remark)
            VpnStateStore.update(
                VpnStateStore.State.CONNECTED,
                profileId = profileId,
                profileRemark = remark,
                connectedSinceEpochMs = System.currentTimeMillis(),
            )
        } catch (t: Throwable) {
            SafeLog.w("connect failed", t)
            teardownLocked()
            VpnStateStore.update(
                VpnStateStore.State.ERROR,
                profileId = profileId,
                profileRemark = remark,
                connectedSinceEpochMs = null,
                errorCode = SafeLog.errorCode(t),
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
        if (coreEnvReady.compareAndSet(false, true)) {
            Seq.setContext(applicationContext)
            val assets = File(filesDir, "xray").apply { mkdirs() }
            Libv2ray.initCoreEnv(assets.absolutePath, xudpBaseKey())
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

    private val callbackHandler = object : CoreCallbackHandler {
        override fun onEmitStatus(p0: Long, p1: String?): Long {
            SafeLog.d("core: ${p1 ?: ""}")
            return 0
        }

        override fun shutdown(): Long = 0
        override fun startup(): Long = 0
    }

    // ---------------------------------------------------------------- disconnect

    private suspend fun disconnect(userInitiated: Boolean, revoked: Boolean = false) = mutex.withLock {
        connectJob?.cancel()
        VpnStateStore.update(VpnStateStore.State.DISCONNECTING)
        teardownLocked()
        VpnStateStore.update(
            VpnStateStore.State.DISCONNECTED,
            connectedSinceEpochMs = null,
            errorCode = if (revoked) "revoked_by_system" else null,
        )
        stopForegroundCompat()
        stopSelf()
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
            tunFd?.close()
        } catch (t: Throwable) {
            SafeLog.w("tun close", t)
        }
        tunFd = null
    }

    /** Called from the bridge (same process). */
    fun requestDisconnect() {
        scope.launch { disconnect(userInitiated = true) }
    }

    // ---------------------------------------------------------------- network transitions

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // Tell the system which physical network carries the tunnel so that
                // captive-portal / metered logic and our uplink follow the new network.
                try {
                    setUnderlyingNetworks(arrayOf(network))
                } catch (t: Throwable) {
                    SafeLog.w("setUnderlyingNetworks", t)
                }
            }

            override fun onLost(network: Network) {
                try {
                    setUnderlyingNetworks(null)
                } catch (_: Throwable) {
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

private fun JSONObject.toMap(): Map<String, Any?> {
    val m = HashMap<String, Any?>()
    keys().forEach { k -> m[k] = if (isNull(k)) null else get(k) }
    return m
}
