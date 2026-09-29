import FlutterMacOS
import Cocoa
import Mirage
import os.log

/// Implements the `homes.milky.vpn/vpn` MethodChannel + `vpn_state`/`links`
/// EventChannels on macOS, mirroring Android MainActivity's contract so the
/// Dart side (`MethodChannelVpnBridge`) works unchanged.
///
/// macOS runs the Mirage (kal2) core in-process — no NetworkExtension
/// consent dance is needed to bind a loopback SOCKS listener. `connect`
/// starts the core and reports `connected` with the SOCKS endpoint
/// 127.0.0.1:11808; apps point their proxy at it. A system-wide transparent
/// proxy path (NETransparentProxyProvider system extension) is the remaining
/// piece for full-device coverage — see docs/macos-setup.md.
final class VpnPlugin: NSObject {
    static let coreVersionString = "mirage@183226d7638a" // vendored xcframework digest
    static let localSocks = "127.0.0.1:11808"

    static var shared: VpnPlugin?
    private let log = OSLog(subsystem: "homes.milky.vpn", category: "plugin")
    fileprivate var stateSink: FlutterEventSink?
    fileprivate var linkSink: FlutterEventSink?
    private var lastLink: String?
    private var sink: MirageLogSink?

    private var state = "disconnected"
    private var profileId: String?
    private var profileRemark: String?
    private var connectedSince: Int?
    private var errorCode: String?

    static func register(messenger: FlutterBinaryMessenger) {
        let plugin = VpnPlugin()
        shared = plugin
        FlutterMethodChannel(name: "homes.milky.vpn/vpn", binaryMessenger: messenger)
            .setMethodCallHandler(plugin.handle)
        FlutterEventChannel(name: "homes.milky.vpn/vpn_state", binaryMessenger: messenger)
            .setStreamHandler(StateStreamHandler(plugin: plugin))
        FlutterEventChannel(name: "homes.milky.vpn/links", binaryMessenger: messenger)
            .setStreamHandler(LinkStreamHandler(plugin: plugin))
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
        case "isPrepared", "prepare":
            // Loopback SOCKS needs no system consent on macOS.
            result(true)
        case "isProfileSupported":
            let p = call.arguments as? [String: Any] ?? [:]
            result((p["protocol"] as? String ?? "").lowercased() == "kal2")
        case "connect":
            connect(call.arguments as? [String: Any] ?? [:], result)
        case "disconnect":
            disconnect(result)
        case "clearActiveProfile":
            clearActiveProfile(result)
        case "coreVersion":
            result(Self.coreVersionString)
        case "openVpnSettings":
            let url = URL(string: "x-apple.systempreferences:com.apple.preference.network?Proxies")!
            result(NSWorkspace.shared.open(url))
        case "deviceInfo":
            result(deviceInfo())
        case "getInitialLink":
            result(lastLink)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Core lifecycle

    private func connect(_ profile: [String: Any], _ result: @escaping FlutterResult) {
        guard let configJSON = kal2ConfigJSON(profile) else {
            result(FlutterError(code: "error", message: "unsupported_profile", details: nil))
            return
        }
        installLogger()
        state = "connecting"
        profileId = profile["id"] as? String
        profileRemark = profile["remark"] as? String
        errorCode = nil
        emitState()
        // Start can take seconds (hedged carrier dial) — keep the UI free.
        DispatchQueue.global(qos: .userInitiated).async {
            var port = 0
            var error: NSError?
            let ok = Kal2mobileStart(configJSON, &port, &error)
            DispatchQueue.main.async {
                if ok {
                    self.state = "connected"
                    self.connectedSince = Int(Date().timeIntervalSince1970 * 1000)
                    self.emitState()
                    result(nil)
                } else {
                    self.state = "error"
                    self.connectedSince = nil
                    self.errorCode = "core_start_failed"
                    self.emitState()
                    result(FlutterError(
                        code: "error",
                        message: error?.localizedDescription ?? "core_start_failed",
                        details: nil
                    ))
                }
            }
        }
    }

    private func disconnect(_ result: @escaping FlutterResult) {
        state = "disconnecting"
        emitState()
        DispatchQueue.global(qos: .userInitiated).async {
            Kal2mobileStop()
            DispatchQueue.main.async {
                self.state = "disconnected"
                self.connectedSince = nil
                self.emitState()
                result(true)
            }
        }
    }

    private func clearActiveProfile(_ result: @escaping FlutterResult) {
        Kal2mobileStop()
        state = "disconnected"
        profileId = nil
        profileRemark = nil
        connectedSince = nil
        errorCode = nil
        emitState()
        result(true)
    }

    private func installLogger() {
        guard sink == nil else { return }
        let s = MirageLogSink()
        Kal2mobileSetLogSink(s)
        sink = s
    }

    // MARK: - State

    private func emitState() {
        DispatchQueue.main.async { self.stateSink?(self.snapshot()) }
    }

    fileprivate func snapshot() -> [String: Any?] {
        [
            "state": state,
            "profileId": profileId,
            "profileRemark": profileRemark,
            "connectedSince": connectedSince,
            "errorCode": errorCode,
            "lastSuccessfulStage": state == "connected" ? "core" : nil,
            "firstFailedStage": state == "error" ? "core" : nil,
        ]
    }

    private func deviceInfo() -> [String: Any] {
        var uts = utsname()
        uname(&uts)
        let machine = withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return [
            "platform": "macos",
            "brand": "apple",
            "manufacturer": "Apple",
            "model": machine,
            "machine": machine,
            "osVersion": "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            "device": Host.current().localizedName ?? "Mac",
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
            "socks": Self.localSocks,
        ]
        guard JSONSerialization.isValidJSONObject(cfg),
              let data = try? JSONSerialization.data(withJSONObject: cfg),
              let json = String(data: data, encoding: .utf8) else {
            return nil
        }
        return json
    }
}

/// kal2 log lines → unified system log (subsystem `homes.milky.vpn`).
final class MirageLogSink: NSObject, Kal2mobileLogSinkProtocol {
    private let log = OSLog(subsystem: "homes.milky.vpn", category: "mirage")
    func log(_ msg: String?) {
        os_log("kal2: %{public}@", log: log, type: .info, msg ?? "")
    }
}

private final class StateStreamHandler: NSObject, FlutterStreamHandler {
    weak var plugin: VpnPlugin?
    init(plugin: VpnPlugin) { self.plugin = plugin }
    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        plugin?.stateSink = events
        if let snap = plugin?.snapshot() { events(snap) }
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
