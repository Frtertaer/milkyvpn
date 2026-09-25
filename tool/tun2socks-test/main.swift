import Foundation
import Network

// Test harness for TunSocksBridge. Links the real bridge sources plus:
//   FakeChannel  — in-memory PacketChannel (inject packets in, capture out)
//   SocksRelay   — real-socket fake SOCKS5 server (CONNECT → dial target,
//                  optional rewrite map; UDP ASSOCIATE → UDP echo-forwarder)
//   Target servers — HTTP responder + DNS-over-TCP responder on loopback.
//
// Verifies: ICMPv4 echo end-to-end, full TCP handshake + HTTP exchange
// through the SOCKS wire protocol, and DNS-over-TCP relaying for UDP/53.

let tunIP: [UInt8] = [198, 18, 0, 2]
let httpPort: UInt16 = 8080
let httpIP: [UInt8] = [127, 0, 0, 1]           // target: real loopback server
let dnsIP: [UInt8] = [1, 1, 1, 1]              // fake resolver address on the wire
let dnsRealPort: UInt16 = 5353                 // where the relay really dials

var failures = 0
var checks = 0

func check(_ name: String, _ cond: Bool, _ detail: String = "") {
    checks += 1
    if cond {
        print("  PASS \(name)")
    } else {
        failures += 1
        print("  FAIL \(name) \(detail)")
    }
}

// MARK: - FakeChannel

final class FakeChannel: PacketChannel {
    private let queue = DispatchQueue(label: "fake.channel")
    private var pendingRead: (([Data], [NSNumber]) -> Void)?
    private var inbox: [(Data, NSNumber)] = []
    private(set) var outbox: [Data] = []

    func inject(_ packet: Data) {
        let af: Int32 = (packet.first ?? 0) >> 4 == 6 ? AF_INET6 : AF_INET
        queue.async {
            if let cb = self.pendingRead {
                self.pendingRead = nil
                cb([packet], [NSNumber(value: af)])
            } else {
                self.inbox.append((packet, NSNumber(value: af)))
            }
        }
    }

    func readPackets(completionHandler: @escaping ([Data], [NSNumber]) -> Void) {
        queue.async {
            if !self.inbox.isEmpty {
                let batch = self.inbox
                self.inbox.removeAll()
                completionHandler(batch.map { $0.0 }, batch.map { $0.1 })
            } else {
                self.pendingRead = completionHandler
            }
        }
    }

    @discardableResult
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        queue.async { self.outbox.append(contentsOf: packets) }
        return true
    }

    /// Waits until at least `n` packets have been emitted or the deadline passes.
    func awaitOutbox(_ n: Int, timeout: TimeInterval = 5) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var count = 0
            queue.sync { count = self.outbox.count }
            if count >= n { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return false
    }

    @discardableResult
    func outboxSnapshot() -> [Data] {
        queue.sync { self.outbox }
    }
}

// MARK: - Fake SOCKS5 relay

final class SocksRelay {
    let port: UInt16
    /// Wire dst "ip:port" → real dial "ip:port" (keeps the test hermetic).
    var rewrite: [String: (host: String, port: UInt16)] = [:]
    private var listener: NWListener?

    init(port: UInt16) { self.port = port }

    func start() throws {
        let p = NWEndpoint.Port(rawValue: port)!
        listener = try NWListener(using: .tcp, on: p)
        listener?.newConnectionHandler = { conn in
            conn.start(queue: .global())
            Self.serve(conn, rewrite: self.rewrite)
        }
        listener?.start(queue: .global())
    }

    private static func recvN(_ conn: NWConnection, _ n: Int, into acc: Data = Data(), done: @escaping (Data?) -> Void) {
        guard acc.count < n else { done(acc); return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: n - acc.count) { data, _, _, err in
            guard let d = data, !d.isEmpty, err == nil else { done(nil); return }
            var b = acc; b.append(d)
            recvN(conn, n, into: b, done: done)
        }
    }

    static func serve(_ conn: NWConnection, rewrite: [String: (host: String, port: UInt16)]) {
        recvN(conn, 2) { head in
            guard let head = head, head[0] == 0x05 else { conn.cancel(); return }
            recvN(conn, Int(head[1])) { _ in
                conn.send(content: Data([0x05, 0x00]), completion: .contentProcessed { _ in })
                recvN(conn, 4) { req in
                    guard let req = req, req[0] == 0x05 else { conn.cancel(); return }
                    let cmd = req[1]
                    if cmd == 0x01 {
                        serveConnect(conn, atyp: req[3], rewrite: rewrite)
                    } else if cmd == 0x03 {
                        serveAssociate(conn, atyp: req[3])
                    } else {
                        conn.cancel()
                    }
                }
            }
        }
    }

    static func readAddr(_ conn: NWConnection, atyp: UInt8, done: @escaping ([UInt8]?, UInt16?) -> Void) {
        switch atyp {
        case 0x01:
            recvN(conn, 6) { d in
                guard let d = d else { done(nil, nil); return }
                done(Array(d[0..<4]), UInt16(d[4]) << 8 | UInt16(d[5]))
            }
        case 0x04:
            recvN(conn, 18) { d in
                guard let d = d else { done(nil, nil); return }
                done(Array(d[0..<16]), UInt16(d[16]) << 8 | UInt16(d[17]))
            }
        case 0x03:
            recvN(conn, 1) { l in
                guard let l = l else { done(nil, nil); return }
                recvN(conn, Int(l[0]) + 2) { d in
                    guard let d = d else { done(nil, nil); return }
                    done(Array(d[0..<Int(l[0])]), UInt16(d[Int(l[0])]) << 8 | UInt16(d[Int(l[0]) + 1]))
                }
            }
        default:
            done(nil, nil)
        }
    }

    static func addrStr(_ a: [UInt8]) -> String {
        if a.count == 4 { return a.map(String.init).joined(separator: ".") }
        return a.map { String(format: "%02x", $0) }.joined()
    }

    static func serveConnect(_ conn: NWConnection, atyp: UInt8, rewrite: [String: (host: String, port: UInt16)]) {
        readAddr(conn, atyp: atyp) { addr, port in
            guard let addr = addr, let port = port else { conn.cancel(); return }
            let key = "\(addrStr(addr)):\(port)"
            let target = rewrite[key] ?? (addrStr(addr), port)
            let ep = NWEndpoint.hostPort(host: NWEndpoint.Host(target.host), port: NWEndpoint.Port(rawValue: target.port)!)
            let upstream = NWConnection(to: ep, using: .tcp)
            upstream.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    var rep = Data([0x05, 0x00, 0x00])
                    rep.append(NWEndpoint.socksEncode(address: [0, 0, 0, 0], port: 0))
                    conn.send(content: rep, completion: .contentProcessed { _ in })
                    Self.pipe(conn, upstream)
                    Self.pipe(upstream, conn)
                case .failed, .cancelled:
                    var rep = Data([0x05, 0x05, 0x00])
                    rep.append(NWEndpoint.socksEncode(address: [0, 0, 0, 0], port: 0))
                    conn.send(content: rep, isComplete: true, completion: .contentProcessed { _ in conn.cancel() })
                default:
                    break
                }
            }
            upstream.start(queue: .global())
        }
    }

    static func serveAssociate(_ conn: NWConnection, atyp: UInt8) {
        readAddr(conn, atyp: atyp) { _, _ in
            // One UDP echo-forwarder per associate: datagrams are unwrapped,
            // echoed back through the relay (deterministic round trip).
            do {
                let udp = try NWListener(using: .udp, on: 0)
                let relayPort = udp.port?.rawValue ?? 0
                udp.newConnectionHandler = { up in
                    up.start(queue: .global())
                    func readLoop() {
                        up.receiveMessage { content, _, _, _ in
                            guard let content = content else { readLoop(); return }
                            guard let dec = NWEndpoint.socksDecode(content, at: 3) else { readLoop(); return }
                            let payload = content.subdata(in: dec.next..<content.count)
                            // echo back: header mirrors dst, payload = payload
                            var resp = Data([0x00, 0x00, 0x00])
                            resp.append(NWEndpoint.socksEncode(address: dec.addr, port: dec.port))
                            resp.append(payload)
                            up.send(content: resp, completion: .contentProcessed { _ in })
                            readLoop()
                        }
                    }
                    readLoop()
                }
                udp.start(queue: .global())
                var rep = Data([0x05, 0x00, 0x00])
                rep.append(NWEndpoint.socksEncode(address: [127, 0, 0, 1], port: relayPort))
                conn.send(content: rep, completion: .contentProcessed { _ in })
                // control conn stays open until client cancels
            } catch {
                conn.cancel()
            }
        }
    }

    static func pipe(_ a: NWConnection, _ b: NWConnection) {
        a.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, _ in
            if let d = data, !d.isEmpty {
                b.send(content: d, completion: .contentProcessed { _ in })
            }
            if isComplete {
                b.send(content: nil, isComplete: true, completion: .contentProcessed { _ in b.cancel() })
            } else {
                pipe(a, b)
            }
        }
    }
}

// MARK: - canned target servers

func startHttpServer(port: UInt16, body: String) -> NWListener? {
    let listener = try? NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)
    listener?.newConnectionHandler = { conn in
        conn.start(queue: .global())
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
            let resp = "HTTP/1.0 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
            conn.send(content: resp.data(using: .utf8)!, isComplete: true, completion: .contentProcessed { _ in conn.cancel() })
        }
    }
    listener?.start(queue: .global())
    return listener
}

/// Minimal DNS-over-TCP responder: echoes the query header with an appended
/// A-record answer, enough to prove the framing end-to-end.
func startDnsTcpServer(port: UInt16) -> NWListener? {
    let listener = try? NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)
    listener?.newConnectionHandler = { conn in
        conn.start(queue: .global())
        var buf = Data()
        func readLoop() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, _ in
                if let d = data { buf.append(d) }
                while buf.count >= 2 {
                    let msgLen = Int(buf[0]) << 8 | Int(buf[1])
                    guard buf.count >= 2 + msgLen else { break }
                    let query = buf.subdata(in: 2..<(2 + msgLen))
                    buf = buf.subdata(in: (2 + msgLen)..<buf.count)
                    conn.send(content: framedDnsAnswer(query), completion: .contentProcessed { _ in })
                }
                if isComplete { conn.cancel() } else { readLoop() }
            }
        }
        readLoop()
    }
    listener?.start(queue: .global())
    return listener
}

/// Minimal DNS-over-TCP answer: echoes the query header, sets QR/ANCOUNT,
/// appends one A record pointing at 203.0.113.7.
func framedDnsAnswer(_ query: Data) -> Data {
        // response = query + minimal answer section; set QR + RCODE + ANCOUNT
        var resp = query
        if resp.count >= 12 {
            resp[2] = (resp[2] & 0x01) | 0x80 // QR=1, keep opcode, RD
            resp[3] = 0x80                   // RA
            let qd = Int(resp[4]) << 8 | Int(resp[5])
            resp[6] = 0; resp[7] = UInt8(qd & 0xFF)
            // append one A answer pointing at 203.0.113.7 (name ptr 0xC00C)
            resp.append(contentsOf: [0xC0, 0x0C,
                                     0x00, 0x01, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x3C,
                                     0x00, 0x04,
                                     203, 0, 113, 7])
        }
        var framed = Data()
        framed.append(UInt8(resp.count >> 8)); framed.append(UInt8(resp.count & 0xFF))
        framed.append(resp)
        return framed
}

// MARK: - packet builders for the driver

func buildTCPPacket(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16,
                    seq: UInt32, ack: UInt32, flags: UInt8, payload: Data = Data()) -> Data {
    let seg = TCPSegment(srcPort: sport, dstPort: dport, seq: seq, ack: ack,
                         flags: flags, window: 65535, options: flags & TCPSegment.SYN != 0 ? Data([0x02, 0x04, 0x05, 0xB4]) : Data(),
                         payload: payload)
    return IPPacket.build(src: src, dst: dst, proto: 6, payload: seg.encode(src: src, dst: dst))
}

func buildUDPPacket(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, payload: Data) -> Data {
    let dg = UDPDatagram(srcPort: sport, dstPort: dport, payload: payload)
    return IPPacket.build(src: src, dst: dst, proto: 17, payload: dg.encode(src: src, dst: dst))
}

func buildICMPv4Echo(src: [UInt8], dst: [UInt8]) -> Data {
    var icmp = Data([0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01])
    icmp.append(contentsOf: [UInt8](repeating: 0xAB, count: 16))
    let sum = InternetChecksum.finalize(icmp)
    icmp[2] = UInt8(sum >> 8); icmp[3] = UInt8(sum & 0xFF)
    return IPPacket.build(src: src, dst: dst, proto: 1, payload: icmp)
}

func parseTCP(_ packet: Data) -> (seg: TCPSegment, src: [UInt8], dst: [UInt8])? {
    guard let ip = IPPacket.parse(packet), ip.proto == 6,
          let seg = TCPSegment.parse(ip.payload) else { return nil }
    let (src, dst) = ip.addresses
    return (seg, src, dst)
}

// MARK: - driver

let socksPort: UInt16 = 11808
let channel = FakeChannel()
let bridge = TunSocksBridge(packetFlow: channel, socksPort: Int(socksPort))

let relay = SocksRelay(port: socksPort)
relay.rewrite["\(httpIP.map(String.init).joined(separator: ".")):\(httpPort)"] = ("127.0.0.1", httpPort)
relay.rewrite["1.1.1.1:53"] = ("127.0.0.1", dnsRealPort)

let http = startHttpServer(port: httpPort, body: "hello-tun")
let dns = startDnsTcpServer(port: dnsRealPort)
try relay.start()
Thread.sleep(forTimeInterval: 0.3)
bridge.start()
Thread.sleep(forTimeInterval: 0.2)

print("== ICMPv4 echo ==")
let peer: [UInt8] = [198, 18, 0, 1]
channel.inject(buildICMPv4Echo(src: peer, dst: tunIP))
check("echo reply emitted", channel.awaitOutbox(1))
if let reply = channel.outboxSnapshot().last, let ip = IPPacket.parse(reply), ip.proto == 1 {
    check("reply is ICMPv4 type 0", ip.payload.first == 0)
    let (src, dst) = ip.addresses
    check("reply swaps src/dst", src == tunIP && dst == peer)
} else {
    check("reply parses as IPv4/ICMP", false)
}

print("== TCP end-to-end HTTP via SOCKS5 ==")
let sport: UInt16 = 51000
let cSeq: UInt32 = 1000
channel.outboxSnapshot() // baseline

channel.inject(buildTCPPacket(src: tunIP, dst: httpIP, sport: sport, dport: httpPort,
                              seq: cSeq, ack: 0, flags: TCPSegment.SYN))
check("SYN|ACK emitted", channel.awaitOutbox(2))
var serverIsn: UInt32 = 0
if let parsed = channel.outboxSnapshot().last.flatMap(parseTCP) {
    check("flags SYN+ACK", parsed.seg.flags & (TCPSegment.SYN | TCPSegment.ACK) == (TCPSegment.SYN | TCPSegment.ACK))
    check("ack = cSeq+1", parsed.seg.ack == cSeq &+ 1, "got \(parsed.seg.ack)")
    serverIsn = parsed.seg.seq &+ 1
} else { check("SYN|ACK parses", false) }

channel.inject(buildTCPPacket(src: tunIP, dst: httpIP, sport: sport, dport: httpPort,
                              seq: cSeq &+ 1, ack: serverIsn, flags: TCPSegment.ACK))
Thread.sleep(forTimeInterval: 0.4) // SOCKS dial + CONNECT handshake

let getReq = "GET / HTTP/1.0\r\nHost: test\r\n\r\n".data(using: .utf8)!
channel.inject(buildTCPPacket(src: tunIP, dst: httpIP, sport: sport, dport: httpPort,
                              seq: cSeq &+ 1, ack: serverIsn, flags: TCPSegment.ACK | TCPSegment.PSH,
                              payload: getReq))
check("HTTP response packets emitted", channel.awaitOutbox(4, timeout: 5))

let out = channel.outboxSnapshot()
var reassembled = Data()
var expectAck = serverIsn
var sawAckForGet = false
for p in out.suffix(from: 2) {
    guard let parsed = parseTCP(p) else { continue }
    let seg = parsed.seg
    if seg.flags & TCPSegment.ACK != 0 && seg.ack == cSeq &+ 1 &+ UInt32(getReq.count) {
        sawAckForGet = true
    }
    if seg.payload.count > 0 && seg.seq == expectAck {
        reassembled.append(seg.payload)
        expectAck = seg.seq &+ UInt32(seg.payload.count)
    }
}
check("bridge ACKed our GET payload", sawAckForGet)
check("response seq continuity", reassembled.count > 0)
let respStr = String(data: reassembled, encoding: .utf8) ?? ""
check("got HTTP 200", respStr.contains("HTTP/1.0 200"), "got: \(respStr.prefix(60))")
check("got body", respStr.contains("hello-tun"))

print("== UDP/53 DNS over SOCKS5 TCP ==")
let dnsQuery = Data([0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00,
                     0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
                     0x00, 0x01, 0x00, 0x01])
let beforeDns = channel.outboxSnapshot().count
channel.inject(buildUDPPacket(src: tunIP, dst: dnsIP, sport: 53000, dport: 53, payload: dnsQuery))
check("DNS response emitted", channel.awaitOutbox(beforeDns + 1, timeout: 5))
if let last = channel.outboxSnapshot().last, let ip = IPPacket.parse(last), ip.proto == 17,
   let udp = UDPDatagram.parse(ip.payload) {
    check("response is UDP from 1.1.1.1:53", udp.srcPort == 53 && ip.addresses.src == dnsIP)
    check("response keeps txid", udp.payload.count >= 2 && udp.payload[0] == 0xAB && udp.payload[1] == 0xCD)
    check("response has answer", udp.payload.count >= 6 && udp.payload[7] > 0,
          "ancount byte: \(udp.payload.count > 7 ? String(udp.payload[7]) : "n/a")")
} else {
    check("DNS response parses", false)
}

print("== TCP FIN teardown ==")
channel.inject(buildTCPPacket(src: tunIP, dst: httpIP, sport: sport, dport: httpPort,
                              seq: cSeq &+ 1 &+ UInt32(getReq.count), ack: expectAck,
                              flags: TCPSegment.FIN | TCPSegment.ACK))
check("FIN acked or closed cleanly", channel.awaitOutbox(channel.outboxSnapshot().count + 1, timeout: 3))

print("")
print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
