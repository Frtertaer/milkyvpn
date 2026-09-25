import Foundation
import Network

/// One proxied TCP flow: terminates the tunnel-side TCP connection and
/// shuttles payload through a SOCKS5 CONNECT stream on loopback.
///
/// Correctness targets, not performance: strict seq tracking, retransmission
/// of unacked outbound segments, RST on unreachable destinations.
final class TcpFlow {

    enum State {
        case synReceived   // sent SYN|ACK, awaiting client's ACK
        case connecting    // handshake done, SOCKS dial in flight
        case established
        case closeWait     // client FIN received; remote may still send
        case lastAck       // we sent FIN, awaiting final ACK
        case closed
    }

    struct Key: Hashable {
        let src: [UInt8] // client (tun peer) address
        let dst: [UInt8] // remote address
        let srcPort: UInt16
        let dstPort: UInt16
    }

    let key: Key
    private(set) var state: State = .synReceived

    // Tunnel-side sequence state.
    private var sndNxt: UInt32   // next seq we will send
    private var sndUna: UInt32   // oldest unacked seq
    private var rcvNxt: UInt32   // next seq expected from client
    private let clientMss: Int
    private let clientWindow: UInt16

    private var pump: StreamPump?
    private var unacked: [(end: UInt32, packet: Data)] = []
    private var pendingClientPayload: [Data] = [] // arrived before SOCKS was up
    private var finSent = false
    private var clientFinAcked = false
    private var lastActivity = Date()

    private weak var owner: TunSocksBridge?

    private static let advertisedWindow: UInt16 = 65535
    private static let defaultMss = 1380
    private static let retransmitInterval: TimeInterval = 1.0
    private static let maxRetransmits = 8

    var isClosed: Bool { state == .closed }
    var lastTouch: Date { lastActivity }

    init(syn: TCPSegment, key: Key, owner: TunSocksBridge) {
        self.key = key
        self.owner = owner
        clientWindow = syn.window
        clientMss = TcpFlow.parseMss(syn.options) ?? TcpFlow.defaultMss
        sndUna = UInt32.random(in: 0...UInt32.max / 4) & 0xFFFF_FFF0
        sndNxt = sndUna
        rcvNxt = syn.seq &+ 1
    }

    private static func parseMss(_ options: Data) -> Int? {
        var i = options.startIndex
        while i < options.endIndex {
            let kind = options[i]
            if kind == 0 { break }
            if kind == 1 { i += 1; continue }
            guard i + 1 < options.endIndex else { return nil }
            let len = Int(options[i + 1])
            if kind == 2, len == 4, i + 3 < options.endIndex {
                return Int(options[i + 2]) << 8 | Int(options[i + 3])
            }
            i += len
        }
        return nil
    }

    // MARK: - client packet handling (called on bridge queue)

    func handle(_ seg: TCPSegment) {
        lastActivity = Date()
        if seg.flags & TCPSegment.RST != 0 {
            teardown()
            return
        }
        if seg.flags & TCPSegment.SYN != 0 {
            // Duplicate SYN → re-send SYN|ACK; a SYN+ACK is answered with RST.
            if seg.flags & TCPSegment.ACK != 0 {
                sendRst(for: seg)
                return
            }
            sendSynAck()
            return
        }

        // Advance our unacked window.
        if seg.flags & TCPSegment.ACK != 0 {
            acceptAck(seg.ack)
        }

        switch state {
        case .synReceived:
            if seg.flags & TCPSegment.ACK != 0, seg.ack == sndNxt {
                state = .connecting
                connect()
            }
            return
        case .closed:
            return
        default:
            break
        }

        if !seg.payload.isEmpty {
            if seg.seq == rcvNxt {
                rcvNxt &+= UInt32(seg.payload.count)
                deliverToRemote(seg.payload)
            } else if isBefore(seg.seq, rcvNxt) {
                // Retransmitted / overlapping data: only the tail beyond
                // rcvNxt is new.
                let skip = Int(rcvNxt &- seg.seq)
                if skip < seg.payload.count {
                    let fresh = seg.payload.suffix(from: seg.payload.startIndex + skip)
                    rcvNxt &+= UInt32(fresh.count)
                    deliverToRemote(Data(fresh))
                }
            } else {
                // Out of order: keep it simple — ask the client to resend
                // from rcvNxt with a duplicate ACK.
                sendAck()
                return
            }
        }

        if seg.flags & TCPSegment.FIN != 0 {
            rcvNxt &+= 1
            clientFinAcked = true
            sendAck()
            if state == .established || state == .connecting {
                state = .closeWait
                pump?.send(Data(), isFinal: true) // half-close remote write
            }
            if finSent { state = .closed; owner?.flowClosed(self) }
            return
        }

        if !seg.payload.isEmpty {
            sendAck()
        }
    }

    private func acceptAck(_ ack: UInt32) {
        guard !unacked.isEmpty else { return }
        while let first = unacked.first, !isAfter(first.end, ack) {
            unacked.removeFirst()
        }
        if isAfter(ack, sndUna) { sndUna = ack }
        if state == .lastAck, unacked.isEmpty, !finSent {
            // unreachable in practice; kept for clarity
        }
        if state == .lastAck, finSent, ack == sndNxt {
            state = .closed
            owner?.flowClosed(self)
        }
    }

    // MARK: - SOCKS side

    private func connect() {
        owner?.connectSocks(dst: key.dst, port: key.dstPort) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let conn):
                self.state = .established
                self.pump = StreamPump(conn: conn, queue: self.ownerQueue(),
                                       onData: { [weak self] data in self?.remoteRead(data) },
                                       onEnd: { [weak self] in self?.remoteClosed() })
                self.pump?.start()
                for pending in self.pendingClientPayload { self.sendRemote(pending) }
                self.pendingClientPayload.removeAll()
                self.sendAck()
            case .failure:
                self.sendRst()
                self.state = .closed
                self.owner?.flowClosed(self)
            }
        }
    }

    private func deliverToRemote(_ payload: Data) {
        switch state {
        case .established:
            sendRemote(payload)
        case .connecting:
            pendingClientPayload.append(payload)
        default:
            break
        }
    }

    private func sendRemote(_ data: Data) {
        pump?.send(data)
    }

    /// SOCKS → TUN: chunk into MSS segments and transmit.
    private func remoteRead(_ data: Data) {
        lastActivity = Date()
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = data.index(offset, offsetBy: min(clientMss, data.endIndex - offset))
            sendSegment(flags: TCPSegment.ACK | TCPSegment.PSH, payload: data[offset..<end])
            offset = end
        }
    }

    private func remoteClosed() {
        sendFin()
        if state == .established {
            state = .lastAck
        } else if state == .closeWait {
            state = .lastAck
        }
    }

    // MARK: - outbound segment helpers (bridge queue)

    private func sendSynAck() {
        var opts = Data([0x02, 0x04]) // MSS option
        opts.append(UInt8(TcpFlow.defaultMss >> 8))
        opts.append(UInt8(TcpFlow.defaultMss & 0xFF))
        send(flags: TCPSegment.SYN | TCPSegment.ACK, payload: Data(), options: opts)
        sndNxt &+= 1 // SYN consumes one seq
    }

    private func sendAck() {
        send(flags: TCPSegment.ACK, payload: Data())
    }

    private func sendFin() {
        guard !finSent else { return }
        finSent = true
        send(flags: TCPSegment.FIN | TCPSegment.ACK, payload: Data())
    }

    private func sendRst(for seg: TCPSegment? = nil) {
        send(flags: TCPSegment.RST | TCPSegment.ACK,
             payload: Data(),
             seqOverride: seg.map { $0.ack })
    }

    private func sendSegment(flags: UInt8, payload: Data.SubSequence) {
        send(flags: flags, payload: Data(payload))
    }

    private func send(flags: UInt8, payload: Data, options: Data = Data(), seqOverride: UInt32? = nil) {
        let seg = TCPSegment(
            srcPort: key.dstPort, dstPort: key.srcPort,
            seq: seqOverride ?? sndNxt, ack: rcvNxt,
            flags: flags, window: TcpFlow.advertisedWindow,
            options: options, payload: payload
        )
        let segData = seg.encode(src: key.dst, dst: key.src)
        let ip = IPPacket.build(src: key.dst, dst: key.src, proto: 6, payload: segData)
        owner?.emit(ip)
        if seqOverride == nil {
            sndNxt &+= UInt32(payload.count)
            if flags & TCPSegment.FIN != 0 { sndNxt &+= 1 }
            if !payload.isEmpty || flags & (TCPSegment.SYN | TCPSegment.FIN) != 0 {
                unacked.append((end: sndNxt, packet: ip))
            }
        }
    }

    /// Periodic retransmission of the oldest unacked segment.
    func retransmitTick() -> Int {
        guard !unacked.isEmpty else { return 0 }
        guard Date().timeIntervalSince(lastActivity) >= TcpFlow.retransmitInterval else { return 0 }
        var sent = 0
        for entry in unacked.prefix(2) {
            owner?.emit(entry.packet)
            sent += 1
        }
        return sent
    }

    private func teardown() {
        state = .closed
        pump?.close()
        owner?.flowClosed(self)
    }

    func forceClose() { teardown() }

    private func ownerQueue() -> DispatchQueue {
        owner!.bridgeQueue
    }

    /// Returns true when `a` is sequence-wise before `b` (wrap-safe).
    private func isBefore(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) < 0
    }

    private func isAfter(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) > 0
    }
}
