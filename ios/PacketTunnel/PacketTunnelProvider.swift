import NetworkExtension
import os.log

/// Packet Tunnel provider: owns the Mirage (kal2) core session inside the
/// NetworkExtension process and plumbs the OS packet flow through
/// `TunSocksBridge` to the core's loopback SOCKS5 endpoint.
///
/// Lifecycle: the app (Runner) saves a NETunnelProviderManager whose
/// `providerConfiguration` carries `configJSON` (same shape Android builds in
/// `Kal2Config.toJson`), then calls `startVPNTunnel`. We start the core, apply
/// tunnel network settings, then pump packets.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "homes.milky.vpn.tunnel", category: "provider")
    private var bridge: TunSocksBridge?
    private var socksPort = 0
    private var profileId: String?
    private var profileRemark: String?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        MirageBridge.installLogger()

        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let providerConfig = proto?.providerConfiguration ?? [:]
        guard let configJSON = providerConfig["configJSON"] as? String else {
            finishStart(error: Self.err("missing_config", "providerConfiguration lacks configJSON"), completionHandler)
            return
        }
        profileId = providerConfig["profileId"] as? String
        profileRemark = providerConfig["profileRemark"] as? String

        do {
            socksPort = try MirageBridge.start(configJSON: configJSON)
        } catch {
            finishStart(error: error, completionHandler)
            return
        }
        SharedTunnelState.write([
            "state": "connecting",
            "profileId": profileId,
            "profileRemark": profileRemark,
            "connectedSince": nil,
            "errorCode": nil,
            "lastSuccessfulStage": "core",
            "firstFailedStage": nil,
        ])

        setTunnelNetworkSettings(makeSettings(serverAddress: proto?.serverAddress)) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.finishStart(error: error, completionHandler)
                return
            }
            SharedTunnelState.write([
                "state": "connected",
                "profileId": self.profileId,
                "profileRemark": self.profileRemark,
                "connectedSince": Int(Date().timeIntervalSince1970 * 1000),
                "errorCode": nil,
                "lastSuccessfulStage": "tunnel",
                "firstFailedStage": nil,
            ])
            self.bridge = TunSocksBridge(packetFlow: self.packetFlow, socksPort: self.socksPort)
            self.bridge?.start()
            self.logger.notice("tunnel up, socks=127.0.0.1:\(self.socksPort)")
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        bridge?.stop()
        bridge = nil
        MirageBridge.stop()
        SharedTunnelState.write(["state": "disconnected"])
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Status probe from the app: report core liveness + bound socks port.
        let reply: [String: Any] = [
            "alive": MirageBridge.alive(),
            "socksPort": socksPort,
        ]
        completionHandler?(try? JSONSerialization.data(withJSONObject: reply))
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {}

    private func finishStart(error: Error, _ completionHandler: (Error?) -> Void) {
        let nsError = error as NSError
        logger.error("start failed: \(nsError.localizedDescription, privacy: .public)")
        MirageBridge.stop()
        SharedTunnelState.write([
            "state": "error",
            "profileId": profileId,
            "profileRemark": profileRemark,
            "errorCode": nsError.domain == "homes.milky.vpn" ? nsError.localizedDescription : "core_start_failed",
            "firstFailedStage": "core",
        ])
        completionHandler(error)
    }

    private func makeSettings(serverAddress: String?) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverAddress ?? "127.0.0.1")
        // Benchmark range 198.18.0.0/15 — conventional for tun interfaces.
        let ipv4 = NEIPv4Settings(
            addresses: ["198.18.0.2"],
            subnetMasks: ["255.255.255.252"]
        )
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1500
        return settings
    }

    private static func err(_ code: String, _ message: String) -> NSError {
        NSError(
            domain: "homes.milky.vpn",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: code, NSLocalizedFailureReasonErrorKey: message]
        )
    }
}
