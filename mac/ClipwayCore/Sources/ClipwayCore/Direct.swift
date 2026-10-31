import CryptoKit
import Darwin
import Foundation

/// Direct transfer of images and files (docs/PROTOCOL.md, section 14). They never go through the
/// relay: the sender listens on the local network and sends an offer through the relay; the
/// receiver connects, proves it holds the chain key, and the content comes encrypted with a key of
/// that transfer only. BSD sockets on background threads; tested against docs/VECTORS.json and on
/// the loopback interface.
///
///     K_t = HKDF(K_direct, "clipway-direct|" + transfer)
///     receiver: "CWD1" || transfer (16 bytes), then get 0 {"v":1,"get":transfer}
///     sender:   put 0..n-1, 65 536 bytes of content each
///     receiver: get 1 {"v":1,"status":"done"} once the content is checked and written
///     record:   length (4, big-endian) || nonce (12) || ciphertext || tag (16)
public enum Direct {
    public static let magic = Data("CWD1".utf8)
    public static let preambleSize = 20
    public static let recordData = 65_536
    public static let recordMax = ClipwayCrypto.nonceSize + recordData + ClipwayCrypto.tagSize
    public static let getMax = 1_024
    public static let connectEachMs = 3_000
    public static let connectTotalMs = 12_000
    public static let idleMs = 15_000
    public static let handshakeMs = 5_000
    public static let unprovenMax = 8

    public enum Failure: Error, Equatable {
        case invalidTransfer, recordSize, closed, timeout, request, socket(Int32)
    }

    // MARK: Keys and records

    /// K_t = HKDF-SHA256(K_direct, empty salt, "clipway-direct|" + transfer, 32).
    public static func transferKey(direct: SymmetricKey, transfer: String) throws -> SymmetricKey {
        guard ClipwayCrypto.isId(transfer) else { throw Failure.invalidTransfer }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: direct, salt: Data(), info: Data("clipway-direct|\(transfer)".utf8), outputByteCount: 32)
    }

    public static func aad(transfer: String, dir: String, index: Int) -> String { "clipway-direct|\(transfer)|\(dir)|\(index)" }

    public static func preamble(_ transfer: String) throws -> Data {
        guard ClipwayCrypto.isId(transfer) else { throw Failure.invalidTransfer }
        return magic + (try ClipwayCrypto.fromHex(transfer))
    }

    /// The transfer id of a preamble, or nil.
    public static func readPreamble(_ bytes: Data) -> String? {
        let b = Data(bytes)
        guard b.count == preambleSize, b.prefix(4) == magic else { return nil }
        return ClipwayCrypto.hex(b.suffix(16))
    }

    /// A record on the wire, length first. Never pass a fixed nonce outside tests.
    public static func sealRecord(key: SymmetricKey, transfer: String, dir: String, index: Int, plaintext: Data, nonce: Data? = nil) throws -> Data {
        let iv = nonce ?? ClipwayCrypto.randomBytes(ClipwayCrypto.nonceSize)
        let box = try AES.GCM.seal(
            plaintext, using: key, nonce: try AES.GCM.Nonce(data: iv), authenticating: Data(aad(transfer: transfer, dir: dir, index: index).utf8))
        let body = iv + box.ciphertext + box.tag
        var length = UInt32(body.count).bigEndian
        return Data(bytes: &length, count: 4) + body
    }

    /// Opens a record body (without its length). Throws if anything does not match.
    public static func openRecord(key: SymmetricKey, transfer: String, dir: String, index: Int, body: Data) throws -> Data {
        let b = Data(body)
        guard b.count >= ClipwayCrypto.nonceSize + ClipwayCrypto.tagSize, b.count <= recordMax else { throw Failure.recordSize }
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: b.prefix(ClipwayCrypto.nonceSize)),
            ciphertext: b.subdata(in: ClipwayCrypto.nonceSize..<(b.count - ClipwayCrypto.tagSize)),
            tag: b.suffix(ClipwayCrypto.tagSize))
        return try AES.GCM.open(box, using: key, authenticating: Data(aad(transfer: transfer, dir: dir, index: index).utf8))
    }

    public static func recordCount(_ size: Int) -> Int { (size + recordData - 1) / recordData }

    public static func getRequest(_ transfer: String) -> String { "{\"v\":1,\"get\":\"\(transfer)\"}" }
    public static func getStatus(_ status: String) -> String { "{\"v\":1,\"status\":\"\(status)\"}" }

    // MARK: Addresses: the local network only

    /// 10/8, 172.16/12, 192.168/16 and link-local 169.254/16.
    public static func isPrivate(_ host: String) -> Bool {
        guard Head.isIPv4(host) else { return false }
        let p = host.split(separator: ".").compactMap { Int($0) }
        return p[0] == 10 || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 192 && p[1] == 168) || (p[0] == 169 && p[1] == 254)
    }

    /// Release builds connect to the local network only; debug builds also to this computer.
    public static func mayConnect(_ host: String, debug: Bool) -> Bool { isPrivate(host) || (debug && host == "127.0.0.1") }

    /// This Mac's private IPv4 addresses, the ones an offer lists (8 at most).
    public static func localHosts() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var out: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            let flags = Int32(entry.pointee.ifa_flags)
            if let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
               flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 {
                var host = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var a = sin.pointee.sin_addr
                    _ = inet_ntop(AF_INET, &a, &host, socklen_t(INET_ADDRSTRLEN))
                }
                let text = String(cString: host)
                if isPrivate(text) && !out.contains(text) { out.append(text) }
            }
            cursor = entry.pointee.ifa_next
        }
        return Array(out.prefix(Head.hostsMax))
    }

    // MARK: Sockets

    final class Connection {
        let fd: Int32

        init(fd: Int32) {
            self.fd = fd
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, socklen_t(MemoryLayout<Int32>.size))
        }

        func timeout(ms: Int) {
            var tv = timeval(tv_sec: ms / 1000, tv_usec: Int32((ms % 1000) * 1000))
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        }

        func read(_ n: Int) throws -> Data {
            var buffer = [UInt8](repeating: 0, count: n)
            var got = 0
            while got < n {
                let r = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress! + got, n - got) }
                if r > 0 {
                    got += r
                } else if r == 0 {
                    throw Failure.closed
                } else if errno == EINTR {
                    continue
                } else if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw Failure.timeout
                } else {
                    throw Failure.socket(errno)
                }
            }
            return Data(buffer)
        }

        func record(max: Int) throws -> Data {
            let length = try read(4).withUnsafeBytes { Int(UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))) }
            guard length >= ClipwayCrypto.nonceSize + ClipwayCrypto.tagSize, length <= max else { throw Failure.recordSize }
            return try read(length)
        }

        func write(_ data: Data) throws {
            try data.withUnsafeBytes { raw in
                var sent = 0
                while sent < raw.count {
                    let w = Darwin.write(fd, raw.baseAddress! + sent, raw.count - sent)
                    if w > 0 {
                        sent += w
                    } else if w < 0 && errno == EINTR {
                        continue
                    } else {
                        throw Failure.socket(errno)
                    }
                }
            }
        }

        func close() { Darwin.close(fd) }
    }

    /// Opens a TCP connection, waiting at most `ms`.
    static func connect(host: String, port: Int, ms: Int) -> Connection? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
            Darwin.close(fd)
            return nil
        }
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if r != 0 {
            guard errno == EINPROGRESS else {
                Darwin.close(fd)
                return nil
            }
            var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            var error: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            guard poll(&p, 1, Int32(ms)) == 1, getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else {
                Darwin.close(fd)
                return nil
            }
        }
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
        return Connection(fd: fd)
    }

    // MARK: Sender: listens while it has offers open, serves each one once

    /// What happened to an offer: delivered, failed, nobody came in time, or a reply said why.
    public enum Outcome: String, Sendable {
        case done, failed, expired, unreachable, declined
    }

    /// The listening side. `offer` registers a content and returns the port; `onOutcome` is called
    /// once per offer, on a background queue. The socket closes when no offer is open.
    public final class Server: @unchecked Sendable {
        private struct Pending {
            let key: SymmetricKey
            let content: Data
            let onOutcome: @Sendable (Outcome) -> Void
            var taken = false
        }

        private let lock = NSLock()
        private var pending: [String: Pending] = [:]
        private var listener: Int32 = -1
        private var bound = 0
        private var unproven = 0
        private var generation = 0
        private let ttlMs: Int

        public init(ttlMs: Int = Int(Head.offerMs)) {
            self.ttlMs = ttlMs
        }

        public var port: Int { lock.withLock { bound } }

        public func isOpen(_ transfer: String) -> Bool { lock.withLock { pending[transfer] != nil } }

        /// Starts listening if needed and registers the offer. Returns the port.
        public func offer(transfer: String, key: SymmetricKey, content: Data, onOutcome: @escaping @Sendable (Outcome) -> Void) throws -> Int {
            guard content.count <= ClipwayCrypto.fileMax else { throw ItemCodec.Failure.tooBig }
            let port: Int = try lock.withLock {
                if listener < 0 { try open() }
                pending[transfer] = Pending(key: key, content: content, onOutcome: onOutcome)
                return bound
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(ttlMs)) { [weak self] in
                self?.finish(transfer, .expired)
            }
            return port
        }

        /// A reply came through the relay: stop waiting for this offer.
        public func cancel(_ transfer: String, outcome: Outcome) { finish(transfer, outcome) }

        public func close() {
            lock.withLock {
                pending.removeAll()
                shut()
            }
        }

        /// Called with the lock held.
        private func open() throws {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { throw Failure.socket(errno) }
            var on: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = 0
            addr.sin_addr = in_addr(s_addr: INADDR_ANY)
            let ok = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            guard ok == 0, listen(fd, 16) == 0 else {
                let e = errno
                Darwin.close(fd)
                throw Failure.socket(e)
            }
            var got = sockaddr_in()
            var size = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &got) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) } }
            listener = fd
            bound = Int(UInt16(bigEndian: got.sin_port))
            generation += 1
            let mine = generation
            Thread.detachNewThread { [weak self] in self?.accept(fd: fd, generation: mine) }
        }

        /// Called with the lock held.
        private func shut() {
            if listener >= 0 {
                Darwin.close(listener)
                listener = -1
                bound = 0
                generation += 1
            }
        }

        private func accept(fd: Int32, generation mine: Int) {
            while lock.withLock({ generation == mine }) {
                var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                guard poll(&p, 1, 250) == 1 else { continue }
                guard lock.withLock({ generation == mine }) else { break }
                let c = Darwin.accept(fd, nil, nil)
                guard c >= 0 else { continue }
                let admitted = lock.withLock { () -> Bool in
                    guard unproven < unprovenMax else { return false }
                    unproven += 1
                    return true
                }
                guard admitted else {
                    Darwin.close(c)
                    continue
                }
                Thread.detachNewThread { [weak self] in self?.serve(Connection(fd: c)) }
            }
        }

        private func serve(_ c: Connection) {
            var proven = false
            var transfer: String?
            defer {
                if !proven { lock.withLock { unproven -= 1 } }
                c.close()
            }
            do {
                c.timeout(ms: handshakeMs)
                guard let t = readPreamble(try c.read(preambleSize)) else { throw Failure.request }
                guard let p = lock.withLock({ pending[t] }) else { throw Failure.request }
                let request = try openRecord(key: p.key, transfer: t, dir: "get", index: 0, body: try c.record(max: getMax))
                guard let o = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
                      Head.integer(o["v"]) == 1, o["get"] as? String == t else { throw Failure.request }
                let took = lock.withLock { () -> Bool in
                    guard var q = pending[t], !q.taken else { return false }
                    q.taken = true
                    pending[t] = q
                    unproven -= 1
                    return true
                }
                guard took else { throw Failure.request }
                proven = true
                transfer = t
                c.timeout(ms: idleMs)
                let content = p.content
                for i in 0..<recordCount(content.count) {
                    let start = content.startIndex + i * recordData
                    let end = min(content.endIndex, start + recordData)
                    try c.write(try sealRecord(key: p.key, transfer: t, dir: "put", index: i, plaintext: content.subdata(in: start..<end)))
                }
                let answer = try openRecord(key: p.key, transfer: t, dir: "get", index: 1, body: try c.record(max: getMax))
                let a = try? JSONSerialization.jsonObject(with: answer) as? [String: Any]
                finish(t, Head.integer(a?["v"]) == 1 && a?["status"] as? String == "done" ? .done : .failed)
            } catch {
                if let transfer { finish(transfer, .failed) }
            }
        }

        private func finish(_ transfer: String, _ outcome: Outcome) {
            let p: Pending? = lock.withLock {
                guard let p = pending.removeValue(forKey: transfer) else { return nil }
                if pending.isEmpty { shut() }
                return p
            }
            p?.onOutcome(outcome)
        }
    }

    // MARK: Receiver: connects to an offer and fetches its content

    public enum Fetched: Equatable {
        case ok(Data)
        /// No address answered: not on the same network.
        case unreachable
        /// Connected, but the transfer broke or the content did not match.
        case failed
    }

    /// Fetches the content of an offer head (blocking: call it off the main thread). `save` runs
    /// once the size and fingerprint are checked; get 1 says "done" when it returns, "failed" when it throws.
    public static func fetch(keys: ChainKeys, head: Head, debug: Bool, save: (Data) throws -> Void) -> Fetched {
        guard head.type == .offer, let port = head.port, let size = head.size, let fp = head.fp,
              let key = try? transferKey(direct: keys.direct, transfer: head.item) else { return .failed }
        let started = Date()
        var reached = false
        var tried: [String] = []
        for host in head.hosts ?? [] where mayConnect(host, debug: debug) && !tried.contains(host) {
            tried.append(host)
            let left = connectTotalMs - Int(Date().timeIntervalSince(started) * 1000)
            guard left > 0 else { break }
            guard let c = connect(host: host, port: port, ms: min(connectEachMs, left)) else { continue }
            reached = true
            defer { c.close() }
            return transfer(c, key: key, keys: keys, transfer: head.item, size: size, fp: fp, save: save)
        }
        return reached ? .failed : .unreachable
    }

    private static func transfer(_ c: Connection, key: SymmetricKey, keys: ChainKeys, transfer t: String, size: Int, fp: String, save: (Data) throws -> Void) -> Fetched {
        do {
            c.timeout(ms: idleMs)
            try c.write(try preamble(t) + (try sealRecord(key: key, transfer: t, dir: "get", index: 0, plaintext: Data(getRequest(t).utf8))))
            var content = Data(capacity: size)
            for i in 0..<recordCount(size) {
                let chunk = try openRecord(key: key, transfer: t, dir: "put", index: i, body: try c.record(max: recordMax))
                guard content.count + chunk.count <= size, chunk.count == recordData || content.count + chunk.count == size else {
                    throw Failure.recordSize
                }
                content.append(chunk)
            }
            guard content.count == size, keys.fingerprint(content) == fp else { throw Failure.request }
            var saved = true
            do {
                try save(content)
            } catch {
                saved = false
            }
            try c.write(try sealRecord(key: key, transfer: t, dir: "get", index: 1, plaintext: Data(getStatus(saved ? "done" : "failed").utf8)))
            return saved ? .ok(content) : .failed
        } catch {
            return .failed
        }
    }
}
