package homes.milky.vpn.kal2

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import homes.milky.vpn.MainActivity
import homes.milky.vpn.R
import homes.milky.vpn.bridge.NativeBridge
import homes.milky.vpn.vpn.SafeLog
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Hosts the Mirage KAL/2 core (libcore.so) in a dedicated `:kal2` process.
 *
 * The app embeds two independent Go runtimes: libcore.so (Mirage) and
 * libgojni.so (Xray). Go does not support more than one runtime per process —
 * when the second runtime boots, their signal/scheduling state collides and the
 * runtime's channel wait queues corrupt (fatal error: bad g->status in ready /
 * chansend: spurious wakeup -> SIGABRT, observed at XRAY_PROCESS_STARTING).
 * Keeping libcore in its own process gives each runtime an isolated process.
 * The cores already communicate over plain loopback SOCKS5, which crosses
 * process boundaries transparently.
 *
 * The service is used as a BOUND service: binding from MilkyVpnService (a
 * foreground service) with BIND_IMPORTANT keeps this process at the client's
 * importance. A cached secondary process would enter the frozen state
 * (do_freezer_trap) within seconds — its SOCKS listener keeps completing TCP
 * handshakes at kernel level while no thread can accept(), hanging outbound.
 *
 * Doze hardening: binder importance alone does not survive device idle — the
 * system demotes bound-only secondary processes. While a session is up the
 * service therefore promotes itself to a real foreground service
 * (specialUse type on API 34+) with its own low-priority notification; demote
 * happens on stop().
 */
class Kal2Service : Service() {

    private val promoted = AtomicBoolean(false)

    private val binder = object : IKal2.Stub() {
        @Volatile
        private var lastError: String? = null

        // Exceptions cannot cross a binder call (the framework reports only
        // 'Exceptions are not yet supported across processes' and the caller
        // sees a garbage return value) — map failures to <=0 plus lastError().
        override fun start(configJson: String): Int = try {
            NativeBridge.start(configJson).also {
                lastError = null
                promote() // session is up — hold :kal2 in foreground through doze
            }
        } catch (t: Throwable) {
            lastError = t.message ?: t.javaClass.simpleName
            -1
        }

        override fun stop() {
            demote()
            NativeBridge.stop()
        }

        override fun isAlive(): Boolean = NativeBridge.isAlive()

        override fun lastError(): String? = lastError
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        demote()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- foreground promotion

    private fun promote() {
        if (!promoted.compareAndSet(false, true)) return
        runCatching {
            val n = buildNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, n)
            }
        }.onFailure {
            promoted.set(false)
            SafeLog.w("kal2 promote", it)
        }
    }

    private fun demote() {
        if (!promoted.getAndSet(false)) return
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val ch = NotificationChannel(NOTIF_CHANNEL, getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW)
        ch.description = getString(R.string.vpn_channel_desc)
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 3, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, NOTIF_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.vpn_notif_connected))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()
    }

    companion object {
        private const val BIND_TIMEOUT_MS = 10_000L
        private const val NOTIF_CHANNEL = "milkyvpn_tunnel"
        private const val NOTIF_ID = 1002

        @Volatile
        private var connection: ServiceConnection? = null

        @Volatile
        private var remote: IKal2? = null

        /**
         * Binds the :kal2 process, starts the KAL/2 session inside it via binder,
         * and returns the bound SOCKS port. Throws [NativeBridge.StartException]
         * on failure.
         */
        fun startSession(context: Context, configJson: String): Int {
            val appContext = context.applicationContext
            val latch = CountDownLatch(1)
            val conn = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, service: IBinder) {
                    remote = IKal2.Stub.asInterface(service)
                    latch.countDown()
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    remote = null
                }
            }
            val bound = appContext.bindService(
                Intent(appContext, Kal2Service::class.java),
                conn,
                Context.BIND_AUTO_CREATE or Context.BIND_IMPORTANT,
            )
            if (!bound) throw NativeBridge.StartException("kal2 bind failed")
            if (!latch.await(BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                runCatching { appContext.unbindService(conn) }
                throw NativeBridge.StartException("kal2 bind timeout")
            }
            connection = conn
            val port = remote!!.start(configJson)
            if (port <= 0) {
                val err = runCatching { remote?.lastError() }.getOrNull()
                runCatching { remote?.stop() }
                throw NativeBridge.StartException(err ?: "kal2 start failed")
            }
            return port
        }

        /** Idempotent; safe when nothing is bound. */
        fun stopSession(context: Context) {
            val conn = connection
            val appContext = context.applicationContext
            connection = null
            runCatching { remote?.stop() }
            remote = null
            if (conn != null) runCatching { appContext.unbindService(conn) }
        }
    }
}
