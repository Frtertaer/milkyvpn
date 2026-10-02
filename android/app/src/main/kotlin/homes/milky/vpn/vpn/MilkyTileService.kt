package homes.milky.vpn.vpn

import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import homes.milky.vpn.MainActivity

/**
 * Quick Settings tile: shows tunnel state and toggles it. Connect goes through
 * the sealed active profile (same path as Always-on); without consent or a
 * stored profile the tile just opens the app.
 */
class MilkyTileService : TileService() {

    private val listener = object : VpnStateStore.Listener {
        override fun onStateChanged(snapshot: VpnStateStore.Snapshot) {
            updateTile()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        VpnStateStore.addListener(listener)
        updateTile()
    }

    override fun onStopListening() {
        VpnStateStore.removeListener(listener)
        super.onStopListening()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        tile.state = when (VpnStateStore.current.state) {
            VpnStateStore.State.CONNECTED -> Tile.STATE_ACTIVE
            VpnStateStore.State.CONNECTING -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        when (VpnStateStore.current.state) {
            VpnStateStore.State.CONNECTED, VpnStateStore.State.CONNECTING -> {
                startService(
                    Intent(this, MilkyVpnService::class.java)
                        .setAction(MilkyVpnService.ACTION_DISCONNECT)
                )
            }
            else -> {
                if (VpnService.prepare(this) == null &&
                    KeystoreSealedStore(this, MilkyVpnService.SEALED_ACTIVE_PROFILE).read() != null
                ) {
                    val svc = Intent(this, MilkyVpnService::class.java)
                        .setAction(MilkyVpnService.ACTION_CONNECT)
                    startForegroundService(svc)
                } else {
                    // Consent or profile missing — let the app UI handle it.
                    startActivityAndCollapse(
                        Intent(this, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }
            }
        }
    }
}
