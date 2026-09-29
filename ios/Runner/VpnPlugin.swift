import Flutter
import NetworkExtension
import UIKit
import os.log

/// Implements the `homes.milky.vpn/vpn` MethodChannel + `vpn_state`/`links`
/// EventChannels, mirroring Android MainActivity's contract so the Dart side
/// (`MethodChannelVpnBridge`) works unchanged.
final class VpnPlugin: NSObject {
    static let providerBundleID = "homes.milky.vpn.PacketTunnel"
    /// Digest prefix of the vendored apple/Frameworks/Mirage.xcframework —
    /// bump it when the framework is rebuilt (see docs/ios-setup.md).
    static let coreVersionString = "mirage@183226d7638a"

    static var shared: VpnPlugin?

    private let logger = Logger(subsystem: "homes.milky.vpn", category: "plugin")
    fileprivate var stateSink: FlutterEventSink?
    fileprivate var linkSink: FlutterEventSink?
    private var lastLink: String?
    private var lastProfile: [String: Any]?
    private var statusState: String = "disconnected"

    static func register(controller: FlutterViewController) {
        let plugin = VpnPlugin()
        shared = plugin
        let messenger = controller.binaryMessenger

        let methods = FlutterMethodChannel(name: "homes.milky.vpn/vpn", binaryMessenger: messenger)
        methods.setMethodCallHandler(plugin.handle)

        let state = FlutterEventChannel(name: "homes.milky.vpn/vpn_state", binaryMessenger: messenger)
        state.setStreamHandler(StateStreamHandler(plugin: plugin))
        let links = FlutterEventChannel(name: "homes.milky.vpn/links", binaryMessenger: messenger)
        links.setStreamHandler(LinkStreamHandler(plugin: plugin))

        NotificationCenter.default.addObserver(
            plugin,
            selector: #selector(plugin.onStatusChanged),
            name: .NEVPNStatusDidChange,
            object: nil
        )
    }

    func emitLink(_ url: String) {
        lastLink = url
        linkSink?(url)
    }

    // MARK: - MethodChannel

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "getState":
            result(snapshot())
        case "isPrepared":
            loadManager { manager in
                result(manager?.isEnabled ?? false)
            }
        case "prepare":
            prepare(result)
        case "isProfileSupported":
            let p = call.arguments as? [String: Any] ?? [:]
            let proto = (p["protocol"] as? String ?? "").lowercased()
            // iOS executes only kal2 profiles — there is no Xray on this platform.
            result(proto == "kal2")
        case "connect":
            connect(call.arguments as? [String: Any] ?? [:], result)
        case "disconnect":
            disconnect(result)
        case "clearActiveProfile":
            clearActiveProfile(result)
        case "coreVersion":
            result(Self.coreVersionString)
        case "openVpnSettings":
            if let url = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(url)
                result(true)
            } else {
                result(false)
            }
        case "deviceInfo":
            result(deviceInfo())
        case "getInitialLink":
            result(lastLink)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - VPN management

    private func loadManager(_ done: @escaping (NETunnelProviderManager?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                self.logger.error("loadAllFromPreferences: \(error.localizedDescription, privacy: .public)")
            }
            done(managers?.first ?? NETunnelProviderManager())
        }
    }

    private func prepare(_ result: @escaping FlutterResult) {
        loadManager { manager in
            guard let manager = manager else { result(false); return }
            if manager.protocolConfiguration == nil {
                manager.protocolConfiguration = NETunnelProviderProtocol()
            }
            manager.localizedDescription = "MilkyVPN"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                result(error == nil)
            }
        }
    }

    private func connect(_ profile: [String: Any], _ result: @escaping FlutterResult) {
        guard let configJSON = kal2ConfigJSON(profile) else {
            result(FlutterError(code: "error", message: "unsupported_profile", details: nil))
            return
        }
        lastProfile = profile
        loadManager { manager in
            guard let manager = manager else {
                result(FlutterError(code: "error", message: "no_manager", details: nil))
                return
            }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleID
            proto.serverAddress = "\(profile["address"] ?? ""):\(profile["port"] ?? "")"
            proto.providerConfiguration = [
                "configJSON": configJSON,
                "profileId": profile["id"] as? String ?? "",
                "profileRemark": profile["remark"] as? String ?? "",
            ]
            proto.includeAllNetworks = true
            manager.protocolConfiguration = proto
            manager.localizedDescription = "MilkyVPN"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error = error {
                    result(FlutterError(code: "error", message: error.localizedDescription, details: nil))
                    return
                }
                do {
                    try manager.connection.startVPNTunnel(options: [:])
                    result(nil)
                } catch {
                    result(FlutterError(code: "error", message: error.localizedDescription, details: nil))
                }
            }
        }
    }

    private func disconnect(_ result: @escaping FlutterResult) {
        loadManager { manager in
            manager?.connection.stopVPNTunnel()
            result(true)
        }
    }

    private func clearActiveProfile(_ result: @escaping FlutterResult) {
        lastProfile = nil
        SharedTunnelState.clear()
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            let group = DispatchGroup()
            for m in managers ?? [] {
                group.enter()
                m.removeFromPreferences { _ in group.leave() }
            }
            group.notify(queue: .main) { result(true) }
        }
    }

    // MARK: - State

    @objc private func onStatusChanged(_ note: Notification) {
        if let conn = note.object as? NEVPNConnection {
            statusState = Self.mapStatus(conn.status)
        }
        emitState()
    }

    private func emitState() {
        DispatchQueue.main.async {
            self.stateSink?(self.snapshot())
        }
    }

    private static func mapStatus(_ s: NEVPNStatus) -> String {
        switch s {
        case .connecting, .reasserting: return "connecting"
        case .connected: return "connected"
        case .disconnecting: return "disconnecting"
        default: return "disconnected"
        }
    }

    /// VpnSnapshot-shaped map, same keys as Android `VpnStateStore.toMap`.
    /// The extension-written app-group snapshot wins when present; otherwise
    /// the raw NEVPNStatus mapping is used.
    fileprivate func snapshot() -> [String: Any?] {
        if let ext = SharedTunnelState.read(),
           let state = ext["state"] as? String, state != "disconnected" {
            return ext.mapValues { $0 is NSNull ? nil : $0 }
        }
        return [
            "state": statusState,
            "profileId": lastProfile?["id"],
            "profileRemark": lastProfile?["remark"],
            "connectedSince": nil,
            "errorCode": nil,
            "lastSuccessfulStage": nil,
            "firstFailedStage": nil,
        ]
    }

    private func deviceInfo() -> [String: Any] {
        var uts = utsname()
        uname(&uts)
        let machine = withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }
        return [
            "platform": "ios",
            "brand": "apple",
            "manufacturer": "Apple",
            "model": UIDevice.current.model,
            "machine": machine,
            "osVersion": UIDevice.current.systemVersion,
            "device": UIDevice.current.name,
        ]
    }

    /// Same JSON shape the Android side builds in `Kal2Config.toJson`.
    private func kal2ConfigJSON(_ p: [String: Any]) -> String? {
        guard let address = p["address"] as? String, !address.isEmpty,
              let secret = p["secret"] as? String, !secret.isEmpty else {
            return nil
        }
        let port = (p["port"] as? NSNumber)?.intValue ?? 0
        let network = (p["network"] as? String ?? "").lowercased()
        let carrier = (network == "drift" || network == "veil") ? network : "auto"
        let cfg: [String: Any] = [
            "addr": "\(address):\(port)",
            "sni": p["sni"] as? String ?? "",
            "carrier": carrier,
            "path": p["path"] as? String ?? "",
            "pub": p["publicKey"] as? String ?? "",
            "psk": secret,
            "socks": "127.0.0.1:11808",
        ]
        guard JSONSerialization.isValidJSONObject(cfg),
              let data = try? JSONSerialization.data(withJSONObject: cfg),
              let json = String(data: data, encoding: .utf8) else {
            return nil
        }
        return json
    }
}

private final class StateStreamHandler: NSObject, FlutterStreamHandler {
    weak var plugin: VpnPlugin?
    init(plugin: VpnPlugin) { self.plugin = plugin }
    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        plugin?.stateSink = events
        DispatchQueue.main.async { [weak self] in
            if let snap = self?.plugin?.snapshot() { events(snap) }
        }
        return nil
    }
    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        plugin?.stateSink = nil
        return nil
    }
}

private final class LinkStreamHandler: NSObject, FlutterStreamHandler {
    weak var plugin: VpnPlugin?
    init(plugin: VpnPlugin) { self.plugin = plugin }
    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        plugin?.linkSink = events
        return nil
    }
    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        plugin?.linkSink = nil
        return nil
    }
}
