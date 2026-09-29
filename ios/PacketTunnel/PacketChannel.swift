import Foundation

/// Whole-IP-packet I/O. `NEPacketTunnelFlow` conforms natively; the test
/// harness substitutes an in-memory implementation so the bridge logic runs
/// without NetworkExtension.
protocol PacketChannel: AnyObject {
    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
    @discardableResult
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}

#if canImport(NetworkExtension)
import NetworkExtension
extension NEPacketTunnelFlow: PacketChannel {}
#endif
