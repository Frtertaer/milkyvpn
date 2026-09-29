import Foundation

/// State shared between the app target and the Packet Tunnel extension via the
/// `group.homes.milky.vpn` app-group container. The extension writes the
/// authoritative snapshot (it owns the core session); the app reads it to
/// render VpnSnapshot on the `homes.milky.vpn/vpn_state` EventChannel.
enum SharedTunnelState {
    static let appGroup = "group.homes.milky.vpn"
    static let fileName = "tunnel_state.json"

    private static var stateURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent(fileName)
    }

    /// Writes a VpnSnapshot-shaped dict. Fields mirror Android's
    /// `VpnStateStore.toMap`: state, profileId, profileRemark, connectedSince
    /// (epoch ms), errorCode, lastSuccessfulStage, firstFailedStage.
    static func write(_ snapshot: [String: Any?]) {
        guard let url = stateURL else { return }
        var clean: [String: Any] = [:]
        for (k, v) in snapshot { clean[k] = v ?? NSNull() }
        guard let data = try? JSONSerialization.data(withJSONObject: clean) else { return }
        try? data.write(to: url, options: .atomic)
    }

    static func read() -> [String: Any]? {
        guard let url = stateURL,
              let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj
    }

    static func clear() {
        guard let url = stateURL else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
