import Foundation
import Network

/// SOCKS5 client implemented over `NWConnection` — no-auth method only
/// (mirage's SOCKS listener is loopback-only).
enum SocksError: Error {
    case connectFailed
    case authRejected
    case commandRejected(UInt8)
    case malformedReply
    case timeout
}

extension NWEndpoint {
    /// SOCKS5 wire encoding: ATYP + address + port.
    /// `addr` is the raw address (4 or 16 octets) or a hostname string.
    static func socksEncode(address: [UInt8], port: UInt16) -> Data {
        var d = Data()
        if address.count == 4 {
            d.append(0x01)
            d.append(contentsOf: address)
        } else if address.count == 16 {
            d.append(0x04)
            d.append(contentsOf: address)
        } else {
            d.append(0x03)
            d.append(UInt8(address.count))
            d.append(contentsOf: address)
        }
        d.append(UInt8(port >> 8))
        d.append(UInt8(port & 0xFF))
        return d
    }

    /// Parses ATYP+addr+port at `offset`. Returns (address bytes, port, nextOffset).
    static func socksDecode(_ data: Data, at offset: Int) -> (addr: [UInt8], port: UInt16, next: Int)? {
        guard data.count > offset else { return nil }
        let atyp = data[offset]
        let len: Int
        switch atyp {
        case 0x01: len = 4
        case 0x04: len = 16
        case 0x03:
            guard data.count > offset + 1 else { return nil }
            len = 1 + Int(data[offset + 1])
        default: return nil
        }
        guard data.count >= offset + 1 + len + 2 else { return nil }
        let addr: [UInt8]
        if atyp == 0x03 {
            addr = Array(data[(offset + 2)..<(offset + 1 + len)])
        } else {
            addr = Array(data[(offset + 1)..<(offset + 1 + len)])
        }
        let p = offset + 1 + len
        let port = UInt16(data[p]) << 8 | UInt16(data[p + 1])
        return (addr, port, p + 2)
    }
}

final class SocksClient {
    let socksPort: Int
    let queue: DispatchQueue

    init(socksPort: Int, queue: DispatchQueue) {
        self.socksPort = socksPort
        self.queue = queue
    }

    private func dial() -> NWConnection {
        let ep = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(socksPort))!)
        return NWConnection(to: ep, using: .tcp)
    }

    /// Waits for the connection to reach `.ready` (or fail). Must be called
    /// from any queue; completion fires on `queue`.
    private func waitReady(_ conn: NWConnection, done: @escaping (Bool) -> Void) {
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                conn.stateUpdateHandler = nil
                self?.queue.async { done(true) }
            case .failed, .cancelled:
                conn.stateUpdateHandler = nil
                self?.queue.async { done(false) }
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func send(_ conn: NWConnection, _ data: Data, done: @escaping (Bool) -> Void) {
        conn.send(content: data, completion: .contentProcessed { [weak self] error in
            self?.queue.async { done(error == nil) }
        })
    }

    /// Receives exactly `n` bytes (looping on partial reads).
    private func recv(_ conn: NWConnection, _ n: Int, into acc: Data = Data(), done: @escaping (Data?) -> Void) {
        guard acc.count < n else {
            queue.async { done(acc) }
            return
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: n - acc.count) { [weak self] chunk, _, _, error in
            guard let self = self else { return }
            self.queue.async {
                if let chunk = chunk, !chunk.isEmpty, error == nil {
                    var next = acc
                    next.append(chunk)
                    self.recv(conn, n, into: next, done: done)
                } else {
                    done(nil)
                }
            }
        }
    }

    /// SOCKS5 CONNECT through the local proxy.
    /// `address`: raw v4/v6 octets or hostname bytes; calls back with the
    /// streaming NWConnection once the server acknowledges.
    func connect(address: [UInt8], port: UInt16, done: @escaping (Result<NWConnection, Error>) -> Void) {
        let conn = dial()
        waitReady(conn) { [weak self] ok in
            guard let self = self, ok else {
                self?.queue.async { done(.failure(SocksError.connectFailed)) }
                return
            }
            self.greeting(conn, command: 0x01, address: address, port: port) { ok in
                self.queue.async {
                    if ok { done(.success(conn)) } else { done(.failure(SocksError.commandRejected(0))) }
                }
            }
        }
    }

    /// SOCKS5 UDP ASSOCIATE. Returns the control connection (must stay open)
    /// and the relay address the server reports.
    func udpAssociate(done: @escaping (Result<(NWConnection, [UInt8], UInt16), Error>) -> Void) {
        let conn = dial()
        waitReady(conn) { [weak self] ok in
            guard let self = self, ok else {
                self?.queue.async { done(.failure(SocksError.connectFailed)) }
                return
            }
            self.send(conn, Data([0x05, 0x01, 0x00])) { ok in
                guard ok else { self.queue.async { done(.failure(SocksError.connectFailed)) }; return }
                self.recv(conn, 2) { resp in
                    guard let resp = resp, resp.count == 2, resp[0] == 0x05, resp[1] == 0x00 else {
                        self.queue.async { done(.failure(SocksError.authRejected)) }
                        return
                    }
                    var req = Data([0x05, 0x03, 0x00]) // UDP ASSOCIATE
                    req.append(NWEndpoint.socksEncode(address: [0, 0, 0, 0], port: 0))
                    self.send(conn, req) { ok in
                        guard ok else { self.queue.async { done(.failure(SocksError.connectFailed)) }; return }
                        self.recvReply(conn) { addr, port in
                            self.queue.async {
                                if let addr = addr, let port = port {
                                    done(.success((conn, addr, port)))
                                } else {
                                    done(.failure(SocksError.malformedReply))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func greeting(_ conn: NWConnection, command: UInt8, address: [UInt8], port: UInt16, done: @escaping (Bool) -> Void) {
        send(conn, Data([0x05, 0x01, 0x00])) { [weak self] ok in
            guard let self = self, ok else { self?.queue.async { done(false) }; return }
            self.recv(conn, 2) { resp in
                guard let resp = resp, resp.count == 2, resp[0] == 0x05, resp[1] == 0x00 else {
                    self.queue.async { done(false) }
                    return
                }
                var req = Data([0x05, command, 0x00])
                req.append(NWEndpoint.socksEncode(address: address, port: port))
                self.send(conn, req) { ok in
                    guard ok else { self.queue.async { done(false) }; return }
                    self.recvReply(conn) { addr, _ in done(addr != nil) }
                }
            }
        }
    }

    /// Reads a SOCKS reply: ver cmd rep rsv atyp addr port. Returns bound
    /// address/port when rep == 0.
    private func recvReply(_ conn: NWConnection, done: @escaping ([UInt8]?, UInt16?) -> Void) {
        recv(conn, 4) { [weak self] head in
            guard let self = self, let head = head, head.count == 4,
                  head[0] == 0x05, head[1] == 0x00 else {
                self?.queue.async { done(nil, nil) }
                return
            }
            // remaining bytes depend on ATYP
            let restLen: Int
            switch head[3] {
            case 0x01: restLen = 4 + 2
            case 0x04: restLen = 16 + 2
            case 0x03: restLen = 256 + 2 // worst case; decode incrementally
            default: restLen = -1
            }
            if head[3] == 0x03 {
                self.recv(conn, 1) { lenB in
                    guard let lenB = lenB else { self.queue.async { done(nil, nil) }; return }
                    self.recv(conn, Int(lenB[0]) + 2) { tail in
                        guard let tail = tail else { self.queue.async { done(nil, nil) }; return }
                        let port = UInt16(tail[Int(lenB[0])]) << 8 | UInt16(tail[Int(lenB[0]) + 1])
                        self.queue.async { done(Array(tail.prefix(Int(lenB[0]))), port) }
                    }
                }
            } else if restLen > 0 {
                self.recv(conn, restLen) { tail in
                    guard let tail = tail else { self.queue.async { done(nil, nil) }; return }
                    let port = UInt16(tail[restLen - 2]) << 8 | UInt16(tail[restLen - 1])
                    self.queue.async { done(Array(tail.prefix(restLen - 2)), port) }
                }
            } else {
                self.queue.async { done(nil, nil) }
            }
        }
    }
}

/// Bidirectional byte pump: reads on `conn`, forwards via `onData`, ends the
/// stream with `onEnd`. Runs entirely on the given queue.
final class StreamPump {
    private let conn: NWConnection
    private let queue: DispatchQueue
    private let onData: (Data) -> Void
    private let onEnd: () -> Void
    private var open = true

    init(conn: NWConnection, queue: DispatchQueue, onData: @escaping (Data) -> Void, onEnd: @escaping () -> Void) {
        self.conn = conn
        self.queue = queue
        self.onData = onData
        self.onEnd = onEnd
    }

    func start() { read() }

    private func read() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            self.queue.async {
                guard self.open else { return }
                if let data = data, !data.isEmpty { self.onData(data) }
                if isComplete || error != nil {
                    self.open = false
                    self.onEnd()
                } else {
                    self.read()
                }
            }
        }
    }

    func send(_ data: Data, isFinal: Bool = false) {
        conn.send(content: data, isComplete: isFinal, completion: .contentProcessed { _ in })
    }

    func close() {
        open = false
        conn.cancel()
    }
}
