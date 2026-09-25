import Foundation
import NetworkExtension
import os.log

/// Drives `NEPacketTunnelFlow` reads/writes for the provider.
///
/// What this does today (scaffold):
///   - Parses IPv4 headers and answers ICMPv4 echo requests locally, so the
///     TUN path is verifiably alive end-to-end (`ping <tun peer>` replies).
///   - Counts and drops TCP/UDP/other packets, emitting periodic summaries.
///
/// What remains for real traffic: a userspace TCP/IP stack that terminates
/// TCP flows and forwards them through SOCKS5 at `socksPort` on loopback —
/// the classic tun2socks seam. On iOS the practical options are a gvisor
/// netstack bound into the Go core (packets via a bound `PacketFlow`
/// interface implemented in Swift) or vendoring a C stack such as
/// hev-socks5-tunnel. See docs/ios-setup.md for the exact integration point.
final class TunSocksBridge {
    private let packetFlow: NEPacketTunnelFlow
    private let socksPort: Int
    private let logger = Logger(subsystem: "homes.milky.vpn.tunnel", category: "bridge")
    private let lock = NSLock()

    private var running = false
    private var icmpEchoReplies = 0
    private var droppedTCP = 0
    private var droppedUDP = 0
    private var droppedOther = 0
    private var lastSummary = Date.distantPast

    init(packetFlow: NEPacketTunnelFlow, socksPort: Int) {
        self.packetFlow = packetFlow
        self.socksPort = socksPort
    }

    func start() {
        lock.lock()
        running = true
        lock.unlock()
        logger.notice("bridge up, socks=127.0.0.1:\(self.socksPort)")
        pump()
    }

    func stop() {
        lock.lock()
        running = false
        lock.unlock()
    }

    private func pump() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            self.lock.lock()
            let isRunning = self.running
            self.lock.unlock()
            guard isRunning else { return }

            for (packet, proto) in zip(packets, protocols) {
                self.handle(packet: packet, proto: proto)
            }
            self.pump()
        }
    }

    private func handle(packet: Data, proto: NSNumber) {
        guard packet.count >= 20, packet[0] >> 4 == 4 else {
            noteDrop(&droppedOther)
            return
        }
        switch packet[9] {
        case 1: // ICMP
            if let reply = icmpEchoReply(to: packet) {
                icmpEchoReplies += 1
                packetFlow.writePackets([reply], withProtocols: [NSNumber(value: AF_INET)])
            } else {
                noteDrop(&droppedOther)
            }
        case 6:
            noteDrop(&droppedTCP)
        case 17:
            noteDrop(&droppedUDP)
        default:
            noteDrop(&droppedOther)
        }
    }

    private func noteDrop(_ counter: inout Int) {
        counter += 1
        if Date().timeIntervalSince(lastSummary) > 10 {
            lastSummary = Date()
            logger.notice(
                "drops: tcp=\(self.droppedTCP) udp=\(self.droppedUDP) other=\(self.droppedOther) icmp_echo=\(self.icmpEchoReplies)"
            )
        }
    }

    /// Builds an ICMPv4 echo reply for an echo request, nil otherwise.
    private func icmpEchoReply(to packet: Data) -> Data? {
        let ihl = Int(packet[0] & 0x0F) * 4
        guard packet.count >= ihl + 8, packet[ihl] == 8 else { return nil }

        var reply = packet
        reply[12] = packet[16]; reply[13] = packet[17]
        reply[14] = packet[18]; reply[15] = packet[19]
        reply[16] = packet[12]; reply[17] = packet[13]
        reply[18] = packet[14]; reply[19] = packet[15]
        reply[ihl] = 0 // echo reply
        reply[10] = 0; reply[11] = 0
        let ipSum = Self.checksum(reply.prefix(ihl))
        reply[10] = UInt8(ipSum >> 8); reply[11] = UInt8(ipSum & 0xFF)
        reply[ihl + 2] = 0; reply[ihl + 3] = 0
        let icmpSum = Self.checksum(reply.suffix(from: ihl))
        reply[ihl + 2] = UInt8(icmpSum >> 8); reply[ihl + 3] = UInt8(icmpSum & 0xFF)
        return reply
    }

    private static func checksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = data.startIndex
        while i + 1 < data.endIndex {
            sum += UInt32(data[i]) << 8 | UInt32(data[i + 1])
            i += 2
        }
        if i < data.endIndex {
            sum += UInt32(data[i]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }
}
