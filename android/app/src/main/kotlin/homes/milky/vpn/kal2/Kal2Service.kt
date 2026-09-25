package homes.milky.vpn.kal2

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import homes.milky.vpn.bridge.Kal2Config
import homes.milky.vpn.bridge.NativeBridge
import homes.milky.vpn.vpn.SafeLog
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

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
 */
class Kal2Service : Service() {

    private val binder = object : IKal2.Stub() {
        override fun start(configJson: String): Int = NativeBridge.start(configJson)
        override fun stop() = NativeBridge.stop()
        override fun isAlive(): Boolean = NativeBridge.isAlive()
    }

    override fun onBind(intent: Intent?): IBinder = binder

    companion object {
        private const val BIND_TIMEOUT_MS = 10_000L

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
            return remote!!.start(configJson)
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
