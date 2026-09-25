import Foundation
import Network

/// UDP handling for the bridge, two tiers:
///   1. DNS fast path — every datagram to :53 is relayed over a one-shot
///      SOCKS5 CONNECT to the resolver's TCP/53 (DNS-over-TCP framing:
///      2-byte length prefix). Works on every SOCKS5 server; needed for any
///      name resolution through the tunnel.
///   2. Generic UDP — a single SOCKS5 UDP ASSOCIATE multiplexed by a NAT
///      table keyed on the remote endpoint. Best-effort for non-DNS UDP.
final class UdpRelay {

    struct FlowKey: Hashable {
        let clientAddr: [UInt8]
        let clientPort: UInt16
        let remoteAddr: [UInt8]
        let remotePort: UInt16
    }

    private weak var owner: TunSocksBridge?
    private let queue: DispatchQueue
    private let socks: SocksClient

    // UDP ASSOCIATE state (lazily created, shared by all flows).
    private var assocCtrl: NWConnection?
    private var assocConn: NWConnection?
    private var assocStarting = false
    private var assocReady = false
    private var pendingDatagrams: [(FlowKey, Data)] = []
    private var flows: [FlowKey: Date] = [:]          // flow -> last activity
    private var remoteIndex: [[UInt8]: FlowKey] = [:] // remote addr+port key -> flow

    init(owner: TunSocksBridge, queue: DispatchQueue, socks: SocksClient) {
        self.owner = owner
        self.queue = queue
        self.socks = socks
    }

    func handle(udp: UDPDatagram, src: [UInt8], dst: [UInt8]) {
        let key = FlowKey(clientAddr: src, clientPort: udp.srcPort,
                          remoteAddr: dst, remotePort: udp.dstPort)
        flows[key] = Date()
        if udp.dstPort == 53 || udp.srcPort == 53 {
            relayDns(udp, key: key)
        } else {
            relayViaAssociate(udp, key: key)
        }
    }

    // MARK: - DNS over TCP fast path

    private func relayDns(_ udp: UDPDatagram, key: FlowKey) {
        socks.connect(address: key.remoteAddr, port: 53) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure:
                self.owner?.log("dns: socks connect failed for \(self.addrStr(key.remoteAddr)):53")
            case .success(let conn):
                var framed = Data()
                let q = udp.payload
                framed.append(UInt8(q.count >> 8))
                framed.append(UInt8(q.count & 0xFF))
                framed.append(q)
                conn.send(content: framed, completion: .contentProcessed { _ in })
                self.readLenPrefixed(conn, into: Data(), expectHeader: true, key: key)
            }
        }
    }

    /// Reads the 2-byte length prefix then the full DNS message.
    private func readLenPrefixed(_ conn: NWConnection, into acc: Data, expectHeader: Bool, key: FlowKey) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: expectHeader ? 2 : 4096) { [weak self] chunk, _, isComplete, error in
            guard let self = self else { return }
            self.queue.async {
                var buf = acc
                if let chunk = chunk { buf.append(chunk) }
                if expectHeader {
                    guard buf.count >= 2 else {
                        if isComplete || error != nil { conn.cancel() } else { self.readLenPrefixed(conn, into: buf, expectHeader: true, key: key) }
                        return
                    }
                    let msgLen = Int(buf[0]) << 8 | Int(buf[1])
                    let rest = buf.subdata(in: 2..<buf.count)
                    self.readDnsBody(conn, have: rest, need: msgLen, key: key)
                } else {
                    self.readDnsBody(conn, have: buf, need: 0, key: key)
                }
            }
        }
    }

    private func readDnsBody(_ conn: NWConnection, have: Data, need: Int, key: FlowKey) {
        if have.count >= need && need > 0 {
            conn.cancel()
            self.emitUdpResponse(payload: have.subdata(in: 0..<need), key: key)
            return
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] chunk, _, isComplete, error in
            guard let self = self else { return }
            self.queue.async {
                var buf = have
                if let chunk = chunk { buf.append(chunk) }
                if buf.count >= need, need > 0 {
                    conn.cancel()
                    self.emitUdpResponse(payload: buf.subdata(in: 0..<need), key: key)
                } else if isComplete || error != nil || buf.isEmpty && isComplete {
                    conn.cancel()
                } else {
                    self.readDnsBody(conn, have: buf, need: need, key: key)
                }
            }
        }
    }

    // MARK: - Generic UDP via a shared UDP ASSOCIATE

    private func relayViaAssociate(_ udp: UDPDatagram, key: FlowKey) {
        if assocReady, let conn = assocConn {
            sendRelay(conn, udp: udp, key: key)
            return
        }
        if pendingDatagrams.count < 128 {
            pendingDatagrams.append((key, udp.payload))
        }
        startAssociateIfNeeded()
    }

    private func startAssociateIfNeeded() {
        guard !assocStarting, assocCtrl == nil else { return }
        assocStarting = true
        socks.udpAssociate { [weak self] result in
            guard let self = self else { return }
            self.assocStarting = false
            switch result {
            case .failure:
                self.owner?.log("udp: UDP ASSOCIATE rejected; non-DNS UDP stays dropped")
            case .success(let (ctrl, addr, port)):
                self.assocCtrl = ctrl
                let host = self.addrStr(addr)
                guard let p = NWEndpoint.Port(rawValue: port) else { return }
                let udp = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: p), using: .udp)
                udp.stateUpdateHandler = { [weak self] state in
                    guard let self = self else { return }
                    self.queue.async {
                        switch state {
                        case .ready:
                            self.assocConn = udp
                            self.assocReady = true
                            self.drainPending()
                            self.readRelay(udp)
                        case .failed, .cancelled:
                            self.assocReady = false
                            self.assocConn = nil
                        default:
                            break
                        }
                    }
                }
                udp.start(queue: self.queue)
            }
        }
    }

    private func drainPending() {
        let queued = pendingDatagrams
        pendingDatagrams.removeAll()
        guard let conn = assocConn else { return }
        for (key, payload) in queued {
            let dg = UDPDatagram(srcPort: key.clientPort, dstPort: key.remotePort, payload: payload)
            sendRelay(conn, udp: dg, key: key)
        }
    }

    /// SOCKS5 UDP datagram: RSV(2) FRAG(1=0) ATYP addr port data.
    private func sendRelay(_ conn: NWConnection, udp: UDPDatagram, key: FlowKey) {
        var wire = Data([0x00, 0x00, 0x00])
        wire.append(NWEndpoint.socksEncode(address: key.remoteAddr, port: key.remotePort))
        wire.append(udp.payload)
        remoteIndex[remoteKey(addr: key.remoteAddr, port: key.remotePort)] = key
        conn.send(content: wire, completion: .contentProcessed { _ in })
    }

    private func readRelay(_ conn: NWConnection) {
        conn.receiveMessage { [weak self] content, _, _, error in
            guard let self = self else { return }
            self.queue.async {
                if let content = content, let decoded = NWEndpoint.socksDecode(content, at: 3) {
                    let rKey = self.remoteKey(addr: decoded.addr, port: decoded.port)
                    if let flow = self.remoteIndex[rKey] {
                        let payload = content.subdata(in: decoded.next..<content.count)
                        self.emitUdpResponse(payload: payload, key: flow)
                    }
                }
                if error == nil { self.readRelay(conn) }
            }
        }
    }

    private func remoteKey(addr: [UInt8], port: UInt16) -> [UInt8] {
        var k = addr
        k.append(UInt8(port >> 8)); k.append(UInt8(port & 0xFF))
        return k
    }

    // MARK: - shared emit

    /// Wraps an inbound UDP payload back into a tunnel packet:
    /// remote → client.
    private func emitUdpResponse(payload: Data, key: FlowKey) {
        let dg = UDPDatagram(srcPort: key.remotePort, dstPort: key.clientPort, payload: payload)
        let wire = dg.encode(src: key.remoteAddr, dst: key.clientAddr)
        owner?.emit(IPPacket.build(src: key.remoteAddr, dst: key.clientAddr, proto: 17, payload: wire))
    }

    /// Expires flows idle for more than `seconds`. Returns count removed.
    @discardableResult
    func sweep(olderThan seconds: TimeInterval) -> Int {
        let cutoff = Date().addingTimeInterval(-seconds)
        let stale = flows.filter { $0.value < cutoff }.map { $0.key }
        for key in stale {
            flows.removeValue(forKey: key)
            remoteIndex = remoteIndex.filter { $0.value != key }
        }
        return stale.count
    }

    func closeAll() {
        assocConn?.cancel()
        assocCtrl?.cancel()
        assocReady = false
    }

    private func addrStr(_ addr: [UInt8]) -> String {
        if addr.count == 4 {
            return addr.map(String.init).joined(separator: ".")
        }
        if addr.count == 16 {
            var parts: [String] = []
            var i = 0
            while i < 16 {
                parts.append(String(UInt16(addr[i]) << 8 | UInt16(addr[i + 1]), radix: 16))
                i += 2
            }
            return parts.joined(separator: ":")
        }
        return String(bytes: addr, encoding: .utf8) ?? "?"
    }
}
