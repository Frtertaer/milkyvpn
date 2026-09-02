package homes.milky.vpn.vpn

import java.util.concurrent.CopyOnWriteArraySet

/**
 * In-process broadcast of VPN service state. Both the service and the Flutter bridge run
 * in the main app process, so a simple listener set is enough (no IPC / no broadcasts that
 * could leak state to other apps).
 */
object VpnStateStore {

    enum class State { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

    data class Snapshot(
        val state: State,
        val profileId: String?,
        val profileRemark: String?,
        val connectedSinceEpochMs: Long?,
        /** Sanitized machine-readable error class from a closed vocabulary (never contains credentials). */
        val errorCode: String?,
        /** Redacted technical detail for the diagnostics screen only. */
        val errorDetail: String? = null,
        /** Which connect stage failed: config | resolve | tun | core_start | verify | null. */
        val errorStage: String? = null,
    )

    interface Listener {
        fun onStateChanged(snapshot: Snapshot)
    }

    private val listeners = CopyOnWriteArraySet<Listener>()

    @Volatile
    var current: Snapshot = Snapshot(State.DISCONNECTED, null, null, null, null)
        private set

    fun addListener(l: Listener) {
        listeners.add(l)
    }

    fun removeListener(l: Listener) {
        listeners.remove(l)
    }

    @Synchronized
    fun update(
        state: State,
        profileId: String? = current.profileId,
        profileRemark: String? = current.profileRemark,
        connectedSinceEpochMs: Long? = current.connectedSinceEpochMs,
        errorCode: String? = null,
        errorDetail: String? = null,
        errorStage: String? = null,
    ) {
        val snap = Snapshot(state, profileId, profileRemark, connectedSinceEpochMs, errorCode, errorDetail, errorStage)
        current = snap
        listeners.forEach { it.onStateChanged(snap) }
    }

    fun toMap(s: Snapshot = current): Map<String, Any?> = mapOf(
        "state" to s.state.name.lowercase(),
        "profileId" to s.profileId,
        "profileRemark" to s.profileRemark,
        "connectedSince" to s.connectedSinceEpochMs,
        "errorCode" to s.errorCode,
        "errorDetail" to s.errorDetail,
        "errorStage" to s.errorStage,
    )
}
