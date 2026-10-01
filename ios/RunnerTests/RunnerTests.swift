import Flutter
import UIKit
import XCTest
import NetworkExtension

@testable import Runner

class RunnerTests: XCTestCase {

    private func decodeConfig(_ p: [String: Any]) -> [String: Any]? {
        guard let json = VpnPlugin.kal2ConfigJSON(p) else { return nil }
        return try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
    }

    private var baseProfile: [String: Any] {
        [
            "id": "p1",
            "remark": "us",
            "protocol": "kal2",
            "address": "23.133.88.167",
            "port": NSNumber(value: 443),
            "secret": "2d4b",
            "network": "veil",
            "sni": "kal.example",
            "publicKey": "9f0d",
        ]
    }

    /// BUG-2026-10-01-05 regression: the first `prepare()` save must carry a
    /// proto NE accepts — providerBundleIdentifier + a non-empty serverAddress —
    /// otherwise saveToPreferences fails "Missing server address" and the
    /// consent prompt never appears (real devices could never connect).
    func testPlaceholderProtocolIsSaveable() {
        let proto = VpnPlugin.placeholderProtocol()
        XCTAssertEqual(proto.providerBundleIdentifier, "homes.milky.vpn.PacketTunnel")
        XCTAssertFalse(proto.serverAddress?.isEmpty ?? true)
        XCTAssertNotNil(proto.providerConfiguration)
        XCTAssertTrue(proto.includeAllNetworks)
    }

    func testConfiguredProtocolCarriesProfile() {
        let proto = VpnPlugin.configuredProtocol(
            configJSON: "{}", profile: baseProfile)
        XCTAssertEqual(proto.providerBundleIdentifier, "homes.milky.vpn.PacketTunnel")
        XCTAssertEqual(proto.serverAddress, "23.133.88.167:443")
        XCTAssertEqual(proto.providerConfiguration?["profileId"] as? String, "p1")
        XCTAssertEqual(proto.providerConfiguration?["configJSON"] as? String, "{}")
    }

    /// BUG-2026-10-01-06 regression: the bridge JSON must pass ech + cover + pin
    /// through and honor every known carrier — Android's Kal2Config.toJson does.
    func testKal2ConfigJSONPassesEchCoverPinAndCarriers() {
        var p = baseProfile
        p["ech"] = "AE3-AAAA"
        p["pin"] = "sha256/xyz"
        p["cover"] = "0"
        p["network"] = "mosaic"
        let cfg = decodeConfig(p)
        XCTAssertEqual(cfg?["ech"] as? String, "AE3-AAAA")
        XCTAssertEqual(cfg?["pin"] as? String, "sha256/xyz")
        XCTAssertEqual(cfg?["cover"] as? Bool, false)
        XCTAssertEqual(cfg?["carrier"] as? String, "mosaic")

        p["cover"] = "false"
        XCTAssertEqual(decodeConfig(p)?["cover"] as? Bool, false)

        p["cover"] = "1"
        p["network"] = "quasar"
        let on = decodeConfig(p)
        XCTAssertEqual(on?["cover"] as? Bool, true)
        XCTAssertEqual(on?["carrier"] as? String, "quasar")

        for c in ["veil", "drift", "cdn", "quic2", "rtc", "relay"] {
            p["network"] = c
            XCTAssertEqual(decodeConfig(p)?["carrier"] as? String, c, c)
        }

        p["cover"] = nil
        p["network"] = "bogus"
        let def = decodeConfig(p)
        XCTAssertEqual(def?["cover"] as? Bool, true)
        XCTAssertEqual(def?["carrier"] as? String, "auto")
    }

    /// Fronting: front= URL, fronts= list and altAddrs= failover entries all
    /// reach the core config (mirrors Kal2Config.toJson on Android).
    func testKal2ConfigJSONPassesFrontingAndAltAddrs() {
        var p = baseProfile
        p["front"] = "https://functions.yandexcloud.net/d4erhmmikarvfr4tsc7e"
        p["fronts"] = ["https://milky-front.example.workers.dev"]
        p["altAddrs"] = "1.2.3.4:443,5.6.7.8:8443"
        let cfg = decodeConfig(p)
        XCTAssertEqual(cfg?["front"] as? String, "https://functions.yandexcloud.net/d4erhmmikarvfr4tsc7e")
        XCTAssertEqual(cfg?["fronts"] as? [String], ["https://milky-front.example.workers.dev"])
        XCTAssertEqual(cfg?["addr"] as? String, "23.133.88.167:443,1.2.3.4:443,5.6.7.8:8443")
    }

    func testKal2ConfigJSONRejectsMissingAddressOrSecret() {
        var p = baseProfile
        p["address"] = ""
        XCTAssertNil(decodeConfig(p))
        p = baseProfile
        p["secret"] = ""
        XCTAssertNil(decodeConfig(p))
    }
}
