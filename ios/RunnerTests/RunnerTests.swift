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

    /// BUG-13 regression: the first `prepare()` save must carry a proto NE
    /// accepts — providerBundleIdentifier + a non-empty serverAddress —
    /// otherwise saveToPreferences fails "Missing server address" and the
    /// consent prompt never appears.
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

    /// BUG-14 regression: the bridge JSON must pass ech + cover through and
    /// honor every known carrier — Android's Kal2Config.toJson already does.
    func testKal2ConfigJSONPassesEchCoverAndCarriers() {
        var p = baseProfile
        p["ech"] = "AE3-AAAA"
        p["cover"] = "0"
        p["network"] = "mosaic"
        let cfg = decodeConfig(p)
        XCTAssertEqual(cfg?["ech"] as? String, "AE3-AAAA")
        XCTAssertEqual(cfg?["cover"] as? Bool, false)
        XCTAssertEqual(cfg?["carrier"] as? String, "mosaic")

        p["cover"] = "false"
        XCTAssertEqual(decodeConfig(p)?["cover"] as? Bool, false)

        p["cover"] = "1"
        p["network"] = "quasar"
        let on = decodeConfig(p)
        XCTAssertEqual(on?["cover"] as? Bool, true)
        XCTAssertEqual(on?["carrier"] as? String, "quasar")

        p["cover"] = nil
        p["network"] = "bogus"
        let def = decodeConfig(p)
        XCTAssertEqual(def?["cover"] as? Bool, true)
        XCTAssertEqual(def?["carrier"] as? String, "auto")
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
