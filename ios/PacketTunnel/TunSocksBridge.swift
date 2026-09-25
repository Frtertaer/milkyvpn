import Foundation
import Network
import os.log

/// Userspace tun2socks core.
///
/// Reads whole IP packets from the tunnel flow, demultiplexes them:
///   - ICMPv4 echo / ICMPv6 echo → answered locally (liveness smoke test)
///   - TCP → `TcpFlow` state machine, forwarded via SOCKS5 CONNECT
///   - UDP → `UdpRelay` (DNS-over-TCP fast path for :53, else UDP ASSOCIATE)
///   - anything else → counted and dropped
///
/// All flow state lives on `bridgeQueue`; SOCKS callbacks and packet reads
/// are funnelled onto the same queue, so no locks are needed on flow state.
final class TunSocksBridge: @unchecked Sendable {
    let packetFlow: PacketChannel
    private let socks: SocksClient
    let bridgeQueue = DispatchQueue(label: "homes.milky.vpn.tun.bridge")
    private let logger = Logger(subsystem: "homes.milky.vpn.tunnel", category: "bridge")

    private var running = false
    private var tcpFlows: [TcpFlow.Key: TcpFlow] = [:]
    private var udpRelay: UdpRelay?
    private var icmpEchoReplies = 0
    private var droppedOther = 0
    private var lastSummary = Date.distantPast
    private var sweepTimer: DispatchSourceTimer?

    private static let maxFlows = 512

    init(packetFlow: PacketChannel, socksPort: Int) {
        self.packetFlow = packetFlow
        self.socks = SocksClient(socksPort: socksPort, queue: bridgeQueue)
    }

    func start() {
        bridgeQueue.async {
            self.running = true
            self.udpRelay = UdpRelay(owner: self, queue: self.bridgeQueue, socks: self.socks)
            self.logger.notice("bridge up, socks=127.0.0.1:\(self.socks.socksPort)")
            self.pump()
            self.startSweep()
        }
    }

    func stop() {
        bridgeQueue.async {
            self.running = false
            self.sweepTimer?.cancel()
            self.sweepTimer = nil
            self.udpRelay?.closeAll()
            for flow in self.tcpFlows.values { flow.forceClose() }
            self.tcpFlows.removeAll()
        }
    }

    // MARK: - packet pump

    private func pump() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            self.bridgeQueue.async {
                guard self.running else { return }
                for (packet, proto) in zip(packets, protocols) {
                    self.handle(packet: packet, proto: proto)
                }
                self.pump()
            }
        }
    }

    private func handle(packet: Data, proto: NSNumber) {
        guard let ip = IPPacket.parse(packet) else {
            noteDrop()
            return
        }
        switch ip.proto {
        case 1, 58: // ICMPv4 / ICMPv6
            if let reply = icmpEchoReply(to: ip) {
                icmpEchoReplies += 1
                emit(reply)
            } else {
                noteDrop()
            }
        case 6:
            handleTCP(ip)
        case 17:
            guard let udp = UDPDatagram.parse(ip.payload) else { noteDrop(); return }
            let (src, dst) = ip.addresses
            udpRelay?.handle(udp: udp, src: src, dst: dst)
        default:
            noteDrop()
        }
    }

    private func handleTCP(_ ip: IPPacket) {
        guard let seg = TCPSegment.parse(ip.payload) else {
            noteDrop()
            return
        }
        let (src, dst) = ip.addresses
        let key = TcpFlow.Key(src: src, dst: dst, srcPort: seg.srcPort, dstPort: seg.dstPort)
        if let flow = tcpFlows[key] {
            flow.handle(seg)
            return
        }
        guard seg.flags & TCPSegment.SYN != 0, seg.flags & TCPSegment.ACK == 0 else {
            return // mid-stream packet for an unknown flow: ignore
        }
        guard tcpFlows.count < Self.maxFlows else {
            noteDrop()
            return
        }
        let flow = TcpFlow(syn: seg, key: key, owner: self)
        tcpFlows[key] = flow
        // SYN|ACK immediately; SOCKS dial starts when the handshake ACK lands.
        flow.handle(seg)
    }

    // MARK: - API used by flow objects (all on bridgeQueue)

    func emit(_ ipPacket: Data) {
        packetFlow.writePackets([ipPacket], withProtocols: [NSNumber(value: packetAF(ipPacket))])
    }

    private func packetAF(_ packet: Data) -> Int32 {
        (packet.first ?? 0) >> 4 == 6 ? AF_INET6 : AF_INET
    }

    func connectSocks(dst: [UInt8], port: UInt16, done: @escaping (Result<NWConnection, Error>) -> Void) {
        socks.connect(address: dst, port: port, done: done)
    }

    func flowClosed(_ flow: TcpFlow) {
        tcpFlows.removeValue(forKey: flow.key)
    }

    func log(_ message: String) {
        logger.notice("\(message, privacy: .public)")
    }

    // MARK: - maintenance

    private func startSweep() {
        let t = DispatchSource.makeTimerSource(queue: bridgeQueue)
        t.schedule(deadline: .now() + 1, repeating: 1.0)
        t.setEventHandler { [weak self] in self?.tick() }
        sweepTimer = t
        t.resume()
    }

    private func tick() {
        guard running else { return }
        var retransmits = 0
        for flow in tcpFlows.values { retransmits += flow.retransmitTick() }
        let cutoff = Date().addingTimeInterval(-300)
        let stale = tcpFlows.values.filter { $0.isClosed || $0.lastTouch < cutoff }
        for f in stale { f.forceClose() }
        udpRelay?.sweep(olderThan: 120)
        if Date().timeIntervalSince(lastSummary) > 15 {
            lastSummary = Date()
            logger.notice(
                "tcp_flows=\(self.tcpFlows.count) icmp_echo=\(self.icmpEchoReplies) drops=\(self.droppedOther) retransmits=\(retransmits)"
            )
        }
    }

    private func noteDrop() {
        droppedOther += 1
    }
}
