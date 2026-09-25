import Foundation

/// IPv4/IPv6 packet decode + encode for the userspace tunnel stack.
/// All multi-byte fields on the wire are big-endian.

struct IPv4Packet {
    var src: [UInt8]      // 4 bytes
    var dst: [UInt8]
    var proto: UInt8
    var payload: Data     // bytes after the IHL
    var ihl: Int
    var ttl: UInt8
}

struct IPv6Packet {
    var src: [UInt8]      // 16 bytes
    var dst: [UInt8]
    var nextHeader: UInt8
    var payload: Data
    var hopLimit: UInt8
}

enum IPPacket {
    case v4(IPv4Packet)
    case v6(IPv6Packet)

    var proto: UInt8 {
        switch self {
        case .v4(let p): return p.proto
        case .v6(let p): return p.nextHeader
        }
    }

    /// (src, dst) address bytes — 4 or 16 octets each.
    var addresses: (src: [UInt8], dst: [UInt8]) {
        switch self {
        case .v4(let p): return (p.src, p.dst)
        case .v6(let p): return (p.src, p.dst)
        }
    }

    var payload: Data {
        switch self {
        case .v4(let p): return p.payload
        case .v6(let p): return p.payload
        }
    }

    var afNum: NSNumber {
        switch self {
        case .v4: return NSNumber(value: AF_INET)
        case .v6: return NSNumber(value: AF_INET6)
        }
    }

    static func parse(_ data: Data) -> IPPacket? {
        guard let first = data.first else { return nil }
        switch first >> 4 {
        case 4:
            guard data.count >= 20 else { return nil }
            let ihl = Int(data[0] & 0x0F) * 4
            guard ihl >= 20, data.count >= ihl else { return nil }
            return .v4(IPv4Packet(
                src: Array(data[12..<16]),
                dst: Array(data[16..<20]),
                proto: data[9],
                payload: data.subdata(in: ihl..<data.count),
                ihl: ihl,
                ttl: data[8]
            ))
        case 6:
            guard data.count >= 40 else { return nil }
            return .v6(IPv6Packet(
                src: Array(data[8..<24]),
                dst: Array(data[24..<40]),
                nextHeader: data[6],
                payload: data.subdata(in: 40..<data.count),
                hopLimit: data[7]
            ))
        default:
            return nil
        }
    }

    /// Builds an IP packet carrying `payload`. `src`/`dst` are raw address
    /// bytes: 4 octets produces IPv4, 16 produces IPv6.
    static func build(src: [UInt8], dst: [UInt8], proto: UInt8, payload: Data, ttl: UInt8 = 64) -> Data {
        if src.count == 4 {
            var ip = Data(count: 20 + payload.count)
            ip[0] = 0x45
            ip[1] = 0
            let total = UInt16(20 + payload.count)
            ip[2] = UInt8(total >> 8); ip[3] = UInt8(total & 0xFF)
            ip[4] = 0; ip[5] = 0; ip[6] = 0x40; ip[7] = 0 // DF
            ip[8] = ttl; ip[9] = proto
            ip.replaceSubrange(12..<16, with: src)
            ip.replaceSubrange(16..<20, with: dst)
            let sum = InternetChecksum.finalize(ip[0..<20])
            ip[10] = UInt8(sum >> 8); ip[11] = UInt8(sum & 0xFF)
            ip.replaceSubrange(20..<(20 + payload.count), with: payload)
            return ip
        }
        var ip = Data(count: 40 + payload.count)
        ip[0] = 0x60
        ip[1] = 0; ip[2] = 0; ip[3] = 0
        let plen = UInt16(payload.count)
        ip[4] = UInt8(plen >> 8); ip[5] = UInt8(plen & 0xFF)
        ip[6] = proto; ip[7] = 64
        ip.replaceSubrange(8..<24, with: src)
        ip.replaceSubrange(24..<40, with: dst)
        ip.replaceSubrange(40..<(40 + payload.count), with: payload)
        return ip
    }
}

enum InternetChecksum {
    /// Finalized one's-complement checksum of the byte range.
    static func finalize<S: Sequence>(_ bytes: S) -> UInt16 where S.Element == UInt8 {
        var sum: UInt32 = 0
        var it = bytes.makeIterator()
        while let hi = it.next() {
            let lo = it.next() ?? 0
            sum += UInt32(hi) << 8 | UInt32(lo)
        }
        return reduce(sum)
    }

    static func reduce(_ sum: UInt32) -> UInt16 {
        var s = sum
        while s >> 16 != 0 { s = (s & 0xFFFF) + (s >> 16) }
        return ~UInt16(s & 0xFFFF)
    }
}

/// TCP segment layout constants + encode/decode.
struct TCPSegment {
    var srcPort: UInt16
    var dstPort: UInt16
    var seq: UInt32
    var ack: UInt32
    var flags: UInt8      // FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10
    var window: UInt16
    var options: Data
    var payload: Data

    static let FIN: UInt8 = 0x01
    static let SYN: UInt8 = 0x02
    static let RST: UInt8 = 0x04
    static let PSH: UInt8 = 0x08
    static let ACK: UInt8 = 0x10

    static func parse(_ data: Data) -> TCPSegment? {
        guard data.count >= 20 else { return nil }
        let offset = Int(data[12] >> 4) * 4
        guard offset >= 20, data.count >= offset else { return nil }
        return TCPSegment(
            srcPort: UInt16(data[0]) << 8 | UInt16(data[1]),
            dstPort: UInt16(data[2]) << 8 | UInt16(data[3]),
            seq: be32(data, at: 4),
            ack: be32(data, at: 8),
            flags: data[13],
            window: UInt16(data[14]) << 8 | UInt16(data[15]),
            options: data.subdata(in: 20..<offset),
            payload: data.subdata(in: offset..<data.count)
        )
    }

    /// Serializes the segment with the checksum computed against the given
    /// pseudo-header addresses (v4 or v6).
    func encode(src: [UInt8], dst: [UInt8]) -> Data {
        let headerLen = 20 + options.count
        var seg = Data(count: headerLen + payload.count)
        seg[0] = UInt8(srcPort >> 8); seg[1] = UInt8(srcPort & 0xFF)
        seg[2] = UInt8(dstPort >> 8); seg[3] = UInt8(dstPort & 0xFF)
        put32(&seg, at: 4, seq)
        put32(&seg, at: 8, ack)
        seg[12] = UInt8((headerLen / 4) << 4)
        seg[13] = flags
        seg[14] = UInt8(window >> 8); seg[15] = UInt8(window & 0xFF)
        seg[16] = 0; seg[17] = 0
        seg[18] = 0; seg[19] = 0
        seg.replaceSubrange(20..<headerLen, with: options)
        if !payload.isEmpty {
            seg.replaceSubrange(headerLen..<seg.count, with: payload)
        }
        // Pseudo-header: src + dst + protocol + length (v4: proto u8 + len u16;
        // v6: len u32 + zeros + next u8).
        var sum: UInt32 = pseudoSum(src: src, dst: dst, proto: 6, len: seg.count)
        var it = seg.makeIterator()
        while let hi = it.next() {
            let lo = it.next() ?? 0
            sum += UInt32(hi) << 8 | UInt32(lo)
        }
        let cksum = InternetChecksum.reduce(sum)
        seg[16] = UInt8(cksum >> 8); seg[17] = UInt8(cksum & 0xFF)
        return seg
    }

    private static func be32(_ d: Data, at: Int) -> UInt32 {
        UInt32(d[at]) << 24 | UInt32(d[at + 1]) << 16 | UInt32(d[at + 2]) << 8 | UInt32(d[at + 3])
    }
}

/// UDP datagram decode/encode.
struct UDPDatagram {
    var srcPort: UInt16
    var dstPort: UInt16
    var payload: Data

    static func parse(_ data: Data) -> UDPDatagram? {
        guard data.count >= 8 else { return nil }
        let len = Int(UInt16(data[4]) << 8 | UInt16(data[5]))
        guard len >= 8, data.count >= len else { return nil }
        return UDPDatagram(
            srcPort: UInt16(data[0]) << 8 | UInt16(data[1]),
            dstPort: UInt16(data[2]) << 8 | UInt16(data[3]),
            payload: data.subdata(in: 8..<len)
        )
    }

    func encode(src: [UInt8], dst: [UInt8]) -> Data {
        var seg = Data(count: 8 + payload.count)
        seg[0] = UInt8(srcPort >> 8); seg[1] = UInt8(srcPort & 0xFF)
        seg[2] = UInt8(dstPort >> 8); seg[3] = UInt8(dstPort & 0xFF)
        let len = UInt16(seg.count)
        seg[4] = UInt8(len >> 8); seg[5] = UInt8(len & 0xFF)
        seg[6] = 0; seg[7] = 0
        seg.replaceSubrange(8..<seg.count, with: payload)
        var sum: UInt32 = pseudoSum(src: src, dst: dst, proto: 17, len: seg.count)
        var it = seg.makeIterator()
        while let hi = it.next() {
            let lo = it.next() ?? 0
            sum += UInt32(hi) << 8 | UInt32(lo)
        }
        let cksum = InternetChecksum.reduce(sum)
        seg[6] = UInt8(cksum >> 8); seg[7] = UInt8(cksum & 0xFF)
        return seg
    }
}

/// Running sum for a TCP/UDP pseudo-header (works for v4 and v6 addresses).
private func pseudoSum(src: [UInt8], dst: [UInt8], proto: UInt8, len: Int) -> UInt32 {
    var sum: UInt32 = 0
    var acc: [UInt8] = []
    acc.append(contentsOf: src)
    acc.append(contentsOf: dst)
    var it = acc.makeIterator()
    while let hi = it.next() {
        let lo = it.next() ?? 0
        sum += UInt32(hi) << 8 | UInt32(lo)
    }
    if src.count == 4 {
        sum += UInt32(len & 0xFFFF)
        sum += UInt32(proto)
    } else {
        sum += UInt32(len >> 16) + UInt32(len & 0xFFFF)
        sum += UInt32(proto)
    }
    return sum
}

func put32(_ d: inout Data, at: Int, _ v: UInt32) {
    d[at] = UInt8(v >> 24); d[at + 1] = UInt8((v >> 16) & 0xFF)
    d[at + 2] = UInt8((v >> 8) & 0xFF); d[at + 3] = UInt8(v & 0xFF)
}

/// ICMPv4/v6 echo request → echo reply, else nil.
func icmpEchoReply(to packet: IPPacket) -> Data? {
    let (src, dst) = packet.addresses
    let payload = packet.payload
    switch packet {
    case .v4:
        guard payload.count >= 8, payload[0] == 8 else { return nil }
        var reply = payload
        reply[0] = 0 // echo reply
        reply[2] = 0; reply[3] = 0
        let sum = InternetChecksum.finalize(reply)
        reply[2] = UInt8(sum >> 8); reply[3] = UInt8(sum & 0xFF)
        return IPPacket.build(src: dst, dst: src, proto: 1, payload: reply)
    case .v6:
        // ICMPv6 echo request type 128 → reply 129; checksum includes pseudo-header.
        guard payload.count >= 8, payload[0] == 128 else { return nil }
        var reply = payload
        reply[0] = 129
        reply[2] = 0; reply[3] = 0
        var sum: UInt32 = 0
        var acc: [UInt8] = []
        acc.append(contentsOf: dst) // pseudo src/dst swapped (reply direction)
        acc.append(contentsOf: src)
        var it = acc.makeIterator()
        while let hi = it.next() {
            let lo = it.next() ?? 0
            sum += UInt32(hi) << 8 | UInt32(lo)
        }
        sum += UInt32(reply.count >> 16) + UInt32(reply.count & 0xFFFF)
        sum += 58 // next header: icmpv6
        var it2 = reply.makeIterator()
        while let hi = it2.next() {
            let lo = it2.next() ?? 0
            sum += UInt32(hi) << 8 | UInt32(lo)
        }
        let cksum = InternetChecksum.reduce(sum)
        reply[2] = UInt8(cksum >> 8); reply[3] = UInt8(cksum & 0xFF)
        return IPPacket.build(src: dst, dst: src, proto: 58, payload: reply)
    }
}
