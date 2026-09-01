package homes.milky.vpn

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import homes.milky.vpn.core.XrayConfigBuilder
import homes.milky.vpn.vpn.KeystoreSealedStore
import homes.milky.vpn.vpn.MilkyVpnService
import homes.milky.vpn.vpn.SafeLog
import homes.milky.vpn.vpn.VpnStateStore
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject

class MainActivity : FlutterActivity() {

    companion object {
        private const val METHOD_CHANNEL = "homes.milky.vpn/vpn"
        private const val STATE_CHANNEL = "homes.milky.vpn/vpn_state"
        private const val LINK_CHANNEL = "homes.milky.vpn/links"
        private const val REQ_VPN_PREPARE = 4001
    }

    private var pendingPrepareResult: MethodChannel.Result? = null
    private var stateSink: EventChannel.EventSink? = null
    private var linkSink: EventChannel.EventSink? = null
    private var initialLink: String? = null
    private val main = Handler(Looper.getMainLooper())

    private val stateListener = object : VpnStateStore.Listener {
        override fun onStateChanged(snapshot: VpnStateStore.Snapshot) {
            main.post { stateSink?.success(VpnStateStore.toMap(snapshot)) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        initialLink = extractLink(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        extractLink(intent)?.let { link -> main.post { linkSink?.success(link) } }
    }

    private fun extractLink(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_VIEW) return null
        val data: Uri = intent.data ?: return null
        // Only our own scheme; the URL inside is validated on the Dart side (allowlist).
        if (data.scheme != "milkyvpn") return null
        return data.toString()
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, STATE_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    stateSink = events
                    VpnStateStore.addListener(stateListener)
                    events?.success(VpnStateStore.toMap())
                }

                override fun onCancel(arguments: Any?) {
                    VpnStateStore.removeListener(stateListener)
                    stateSink = null
                }
            }
        )

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, LINK_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    linkSink = events
                }

                override fun onCancel(arguments: Any?) {
                    linkSink = null
                }
            }
        )

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL).setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "getInitialLink" -> {
                        val l = initialLink
                        initialLink = null
                        result.success(l)
                    }

                    "isPrepared" -> result.success(VpnService.prepare(this) == null)

                    "prepare" -> {
                        val intent = VpnService.prepare(this)
                        if (intent == null) {
                            result.success(true)
                        } else {
                            if (pendingPrepareResult != null) {
                                result.error("busy", "prepare already in progress", null)
                            } else {
                                pendingPrepareResult = result
                                startActivityForResult(intent, REQ_VPN_PREPARE)
                            }
                        }
                    }

                    "isProfileSupported" -> {
                        val map = call.arguments as? Map<*, *> ?: emptyMap<String, Any>()
                        result.success(XrayConfigBuilder.isSupported(XrayConfigBuilder.ProfileSpec.fromMap(map)))
                    }

                    "connect" -> {
                        val map = call.arguments as? Map<*, *> ?: throw IllegalArgumentException("profile required")
                        val spec = XrayConfigBuilder.ProfileSpec.fromMap(map)
                        XrayConfigBuilder.validate(spec)
                        if (VpnService.prepare(this) != null) {
                            result.error("permission", "VPN permission not granted", null)
                            return@setMethodCallHandler
                        }
                        // Persist for the service (also enables Always-on / system restarts).
                        val json = JSONObject()
                        map.forEach { (k, v) -> if (k is String && v != null) json.put(k, v) }
                        KeystoreSealedStore(this, MilkyVpnService.SEALED_ACTIVE_PROFILE).write(json.toString())
                        val svc = Intent(this, MilkyVpnService::class.java).setAction(MilkyVpnService.ACTION_CONNECT)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(svc) else startService(svc)
                        result.success(true)
                    }

                    "disconnect" -> {
                        val running = MilkyVpnService.instance
                        if (running != null) {
                            running.requestDisconnect()
                        } else {
                            VpnStateStore.update(VpnStateStore.State.DISCONNECTED, connectedSinceEpochMs = null)
                        }
                        result.success(true)
                    }

                    "clearActiveProfile" -> {
                        KeystoreSealedStore(this, MilkyVpnService.SEALED_ACTIVE_PROFILE).clear()
                        result.success(true)
                    }

                    "getState" -> result.success(VpnStateStore.toMap())

                    "coreVersion" -> result.success(MilkyVpnService.coreVersion())

                    "openVpnSettings" -> {
                        val ok = try {
                            startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                            true
                        } catch (_: Throwable) {
                            try {
                                startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                                true
                            } catch (_: Throwable) {
                                false
                            }
                        }
                        result.success(ok)
                    }

                    "deviceInfo" -> result.success(
                        mapOf(
                            "sdkInt" to Build.VERSION.SDK_INT,
                            "release" to Build.VERSION.RELEASE,
                            "abi" to (Build.SUPPORTED_ABIS.firstOrNull() ?: ""),
                        )
                    )

                    else -> result.notImplemented()
                }
            } catch (e: XrayConfigBuilder.UnsupportedProfileException) {
                result.error("unsupported", e.message, null)
            } catch (t: Throwable) {
                SafeLog.w("method ${call.method} failed", t)
                result.error("error", SafeLog.errorCode(t), null)
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQ_VPN_PREPARE) {
            val r = pendingPrepareResult
            pendingPrepareResult = null
            r?.success(resultCode == Activity.RESULT_OK)
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }
}
