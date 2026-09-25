import Foundation
import Mirage
import os.log

/// Feeds kal2 core log lines into the unified system log (subsystem
/// `homes.milky.vpn.tunnel`, category `mirage`). Installed once per extension
/// lifetime; gomobile cannot bind SetLogger directly, hence the LogSink
/// interface.
final class MirageLogSink: NSObject, Kal2mobileLogSinkProtocol {
    private let logger = Logger(subsystem: "homes.milky.vpn.tunnel", category: "mirage")
    func log(_ msg: String?) {
        logger.notice("kal2: \(msg ?? "", privacy: .public)")
    }
}

/// Thin Swift facade over the bound gomobile API (`Kal2mobileStart/Stop/Alive`).
enum MirageBridge {
    private static var sink: MirageLogSink?

    static func installLogger() {
        guard sink == nil else { return }
        let s = MirageLogSink()
        Kal2mobileSetLogSink(s)
        sink = s // keep alive for the process lifetime
    }

    /// Starts the core with the JSON config produced by the app target
    /// (same shape as Android `Kal2Config.toJson`). Returns the local SOCKS5
    /// port the core bound inside this extension process.
    @discardableResult
    static func start(configJSON: String) throws -> Int {
        var port = 0
        var error: NSError?
        guard Kal2mobileStart(configJSON, &port, &error) else {
            throw error ?? NSError(
                domain: "homes.milky.vpn.mirage",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "kal2 start failed"]
            )
        }
        return port
    }

    static func stop() {
        Kal2mobileStop()
    }

    static func alive() -> Bool {
        Kal2mobileAlive()
    }
}
