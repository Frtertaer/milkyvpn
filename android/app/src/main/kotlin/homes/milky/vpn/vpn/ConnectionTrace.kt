package homes.milky.vpn.vpn

/** Credential-free milestones. Native config validation completes inside startLoop, not
 * inside our static profile validator. No milestone can itself publish CONNECTED. */
internal class ConnectionTrace(private val emit: (String) -> Unit) {
    var lastSuccessfulStage: String? = null
        private set
    var firstFailedStage: String? = null
        private set
    private var pendingStage: String? = null

    fun begin(stage: String) {
        pendingStage = stage
        emit("stage=$stage result=BEGIN")
    }

    fun success(stage: String, facts: String = "") {
        lastSuccessfulStage = stage
        pendingStage = null
        emit("stage=$stage result=OK $facts".trimEnd())
    }

    fun failure(code: String) {
        // startLoop performs native config validation internally. Earlier static
        // parsing/build failures must retain their actual stage instead.
        firstFailedStage = if (pendingStage == "XRAY_PROCESS_STARTING" &&
            code in setOf("config_asset_missing", "config_invalid")) {
            "CONFIG_VALIDATED"
        } else {
            pendingStage ?: "UNKNOWN"
        }
        emit("stage=$firstFailedStage result=FAILED lastSuccessfulStage=$lastSuccessfulStage code=$code")
    }
}
