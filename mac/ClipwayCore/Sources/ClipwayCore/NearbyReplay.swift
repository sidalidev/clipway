import Foundation

/// The command line check of nearby pairing (`Clipway --debug-nearby-vectors`, Debug builds): with
/// the nearby block of docs/VECTORS.json and no Bluetooth, it checks the derivations and packets,
/// replays the 8 scripted sessions against NearbyMacSession, then plays the phone (the central)
/// against NearbyHost, request by request, as the app's CoreBluetooth shell would pass them.
public enum NearbyReplay {
    public struct Report: Sendable {
        public var lines: [String] = []
        public var failures = 0
        public var checks = 0
        public var passed: Bool { failures == 0 && checks > 0 }
    }

    /// Runs every check. `vectors` is the content of docs/VECTORS.json.
    public static func run(vectors: Data) -> Report {
        var report = Report()
        guard let root = try? JSONSerialization.jsonObject(with: vectors) as? [String: Any],
              let n = root["nearby"] as? [String: Any], let s = root["S"] as? String
        else {
            report.lines.append("FAIL  docs/VECTORS.json has no nearby block")
            report.failures = 1
            return report
        }
        var c = Checker()
        let v = Vectors(n: n, s: s)
        c.section("derivations") { try derivations(v, &$0) }
        c.section("packets") { try packets(v, &$0) }
        c.section("negative cases") { try negatives(v, &$0) }
        for (index, session) in (n["sessions"] as? [[String: Any]] ?? []).enumerated() {
            let name = session["name"] as? String ?? "session \(index + 1)"
            c.section("session \(index + 1)/8, \(name)") { try replay(session, v, &$0) }
        }
        c.section("phone against the Mac, fixed keys, Mac pairs first, MTU 185") { try phonePlays(v, &$0, fixed: true, macFirst: true, mtu: 185) }
        c.section("phone against the Mac, fresh keys, phone pairs first, MTU 35") { try phonePlays(v, &$0, fixed: false, macFirst: false, mtu: 35) }
        c.section("clock: 120 s, a ready session is not cut, 10 s of grace") { try clock(v, &$0) }
        c.section("one answer per batch, prepared writes refused") { try batches(v, &$0) }
        report.lines = c.lines
        report.failures = c.failures
        report.checks = c.checks
        report.lines.append(report.passed ? "nearby: all \(c.checks) checks passed" : "nearby: \(c.failures) of \(c.checks) checks failed")
        return report
    }

    // MARK: Plumbing

    struct Failed: Error { let why: String }

    struct Checker {
        var lines: [String] = []
        var failures = 0
        var checks = 0
        var count = 0

        mutating func equal<T: Equatable>(_ a: T, _ b: T, _ what: String) throws {
            count += 1
            if a != b { throw Failed(why: "\(what): got \(a), expected \(b)") }
        }

        mutating func ok(_ condition: Bool, _ what: String) throws {
            count += 1
            if !condition { throw Failed(why: what) }
        }

        mutating func section(_ title: String, _ body: (inout Checker) throws -> Void) {
            count = 0
            do {
                try body(&self)
                lines.append("ok    \(title) (\(count) checks)")
                checks += count
            } catch let failed as Failed {
                lines.append("FAIL  \(title): \(failed.why)")
                failures += 1
                checks += count
            } catch {
                lines.append("FAIL  \(title): \(error)")
                failures += 1
                checks += count
            }
        }
    }

    struct Vectors {
        let n: [String: Any]
        let s: String

        func str(_ key: String, in object: [String: Any]? = nil) throws -> String {
            guard let value = (object ?? n)[key] as? String else { throw Failed(why: "missing \(key)") }
            return value
        }

        func bytes(_ key: String, in object: [String: Any]? = nil) throws -> Data { try ClipwayCrypto.fromHex(try str(key, in: object)) }

        func obj(_ key: String, in object: [String: Any]? = nil) throws -> [String: Any] {
            guard let value = (object ?? n)[key] as? [String: Any] else { throw Failed(why: "missing \(key)") }
            return value
        }

        var secret: Data { get throws { try ClipwayCrypto.fromHex(s) } }
    }

    static func hex(_ data: Data) -> String { ClipwayCrypto.hex(data) }

    // MARK: Derivations, packets, negative cases

    static func derivations(_ v: Vectors, _ c: inout Checker) throws {
        let macKey = try Nearby.privateKey(raw: try v.bytes("mac_private"))
        let phoneKey = try Nearby.privateKey(raw: try v.bytes("phone_private"))
        let pkMac = macKey.publicKey.rawRepresentation
        let pkPhone = phoneKey.publicKey.rawRepresentation
        try c.equal(hex(pkMac), try v.str("mac_public"), "Mac public key")
        try c.equal(hex(pkPhone), try v.str("phone_public"), "phone public key")
        try c.equal(hex(try Nearby.sharedSecret(macKey, pkPhone)), try v.str("shared"), "Z on the Mac")
        try c.equal(hex(try Nearby.sharedSecret(phoneKey, pkMac)), try v.str("shared"), "Z on the phone")
        try c.equal(hex(Nearby.commitment(pkMac)), try v.str("commit"), "commit")
        try c.equal(hex(Nearby.transcript(pkMac, pkPhone)), try v.str("transcript"), "T")
        let keys = Nearby.derive(z: try v.bytes("shared"), pkMac: pkMac, pkPhone: pkPhone)
        try c.equal(hex(keys.n), try v.str("N"), "N")
        try c.equal(hex(keys.sas), try v.str("K_sas"), "K_sas")
        try c.equal(hex(keys.key), try v.str("K_key"), "K_key")
        try c.equal(hex(Nearby.sasBytes(kSas: keys.sas, pkMac: pkMac, pkPhone: pkPhone)), try v.str("sas_bytes"), "code bytes")
        try c.equal(Nearby.sasCode(kSas: keys.sas, pkMac: pkMac, pkPhone: pkPhone), try v.str("sas"), "code")
        try c.equal(hex(Nearby.confirmTag(kSas: keys.sas, pkMac: pkMac, pkPhone: pkPhone)), try v.str("confirm"), "confirm")
        try c.equal(Nearby.packetAad(pkMac: pkMac, pkPhone: pkPhone), try v.str("aad"), "AAD")
        try c.equal(Nearby.packetAad(pkMac: pkMac, pkPhone: pkPhone).utf8.count, 144, "AAD length")
        for sample in v.n["sas_samples"] as? [[String: Any]] ?? [] {
            try c.equal(Nearby.sas(fromBytes: try v.bytes("bytes", in: sample)), try v.str("sas", in: sample), "code of \(try v.str("bytes", in: sample))")
        }
        let zero = try v.obj("leading_zero")
        let phone2 = try Nearby.privateKey(raw: try v.bytes("phone_private", in: zero))
        let handshake = try Nearby.phoneHandshake(privateKey: phone2, commit: try v.bytes("commit"), pkMac: pkMac)
        try c.equal(handshake.sas, try v.str("sas", in: zero), "code with a leading zero")
        try c.equal(hex(handshake.confirm), try v.str("confirm", in: zero), "confirm, leading zero")
        try c.equal(hex(handshake.key), try v.str("K_key", in: zero), "K_key, leading zero")
    }

    static func packets(_ v: Vectors, _ c: inout Checker) throws {
        let pkMac = try v.bytes("mac_public")
        let pkPhone = try v.bytes("phone_public")
        let key = try v.bytes("K_key")
        for name in ["packet", "packet_with_relay"] {
            let p = try v.obj(name)
            let code = try ClipwayCrypto.toQr(try v.secret, relay: try v.str("relay", in: p), defaultRelay: ClipwayInfo.defaultRelay)
            try c.equal(code, try v.str("code", in: p), "\(name) code")
            try c.equal(try Nearby.packetPlaintext(code: code), try v.str("plaintext", in: p), "\(name) plaintext")
            let sealed = try Nearby.sealPacket(kKey: key, pkMac: pkMac, pkPhone: pkPhone, code: code, nonce: try v.bytes("nonce", in: p))
            try c.equal(hex(sealed), try v.str("bytes", in: p), "\(name) bytes")
            let opened = try Nearby.openPacket(kKey: key, pkMac: pkMac, pkPhone: pkPhone, packet: try v.bytes("bytes", in: p))
            try c.equal(opened.secret, try v.secret, "\(name) opens to S")
            try c.equal(opened.relay, (try v.obj("opened", in: p))["relay"] as? String, "\(name) relay")
        }
        let longest = "clipway:" + String(repeating: "A", count: Nearby.maxCodeLength - 8)
        try c.ok(Nearby.fits(code: longest) && !Nearby.fits(code: longest + "A"), "a code of 230 characters fits, 231 does not")
    }

    static func negatives(_ v: Vectors, _ c: inout Checker) throws {
        let neg = try v.obj("negative")
        let macKey = try Nearby.privateKey(raw: try v.bytes("mac_private"))
        let pkMac = macKey.publicKey.rawRepresentation
        let pkPhone = try v.bytes("phone_public")
        for key in (try v.obj("low_order_keys", in: neg))["keys"] as? [String] ?? [] {
            try c.ok((try? Nearby.sharedSecret(macKey, try ClipwayCrypto.fromHex(key))) == nil, "low-order key \(key.prefix(8)) refused")
        }
        try c.ok((try? Nearby.checkPeerKey(try v.bytes("key", in: try v.obj("high_bit_key", in: neg)), own: pkMac)) == nil, "top bit refused")
        try c.ok((try? Nearby.checkPeerKey(try v.bytes("key", in: try v.obj("own_key", in: neg)), own: pkMac)) == nil, "own key refused")
        let wrong = try v.obj("wrong_commitment", in: neg)
        let phoneKey = try Nearby.privateKey(raw: try v.bytes("phone_private"))
        try c.ok((try? Nearby.phoneHandshake(privateKey: phoneKey, commit: try v.bytes("commit", in: wrong), pkMac: try v.bytes("mac_public", in: wrong))) == nil,
                 "Mac key that does not match the commitment refused")
        try c.ok(!Nearby.checkConfirm(kSas: try v.bytes("K_sas"), pkMac: pkMac, pkPhone: pkPhone, tag: try v.bytes("confirm", in: try v.obj("wrong_confirm", in: neg))),
                 "wrong confirm refused")
        let key = try v.bytes("K_key")
        let packet = try v.bytes("bytes", in: try v.obj("packet"))
        try c.ok((try? Nearby.openPacket(kKey: key, pkMac: pkMac, pkPhone: pkPhone, packet: try v.bytes("bytes", in: try v.obj("tampered_packet", in: neg)))) == nil, "tampered packet refused")
        try c.ok((try? Nearby.openPacket(kKey: key, pkMac: pkPhone, pkPhone: pkMac, packet: packet)) == nil, "swapped AAD refused")
        try c.ok((try? Nearby.openPacket(kKey: key, pkMac: pkMac, pkPhone: pkPhone, packet: packet.prefix(283))) == nil, "short packet refused")
    }

    // MARK: The 8 sessions of the vectors

    static func replay(_ session: [String: Any], _ v: Vectors, _ c: inout Checker) throws {
        let mac = try NearbyMacSession(secret: try v.secret, relay: ClipwayInfo.defaultRelay,
                                       privateKey: try v.bytes("mac_private"), nonce: try v.bytes("nonce", in: try v.obj("packet")))
        for (i, step) in (session["steps"] as? [[String: Any]] ?? []).enumerated() {
            let at = "step \(i + 1)"
            let by = try v.str("by", in: step)
            let op = try v.str("op", in: step)
            let offset = step["offset"] as? Int ?? 0
            let characteristic = (step["char"] as? String).flatMap { Nearby.Characteristic(rawValue: $0) }
            var answer: NearbyMacSession.Answer?
            var notify: [UInt8]
            switch op {
            case "subscribe": (answer, notify) = unpack(mac.subscribe(by))
            case "unsubscribe": (answer, notify) = unpack(mac.unsubscribe(by))
            case "read":
                guard let characteristic else { throw Failed(why: "\(at): unknown characteristic") }
                (answer, notify) = unpack(mac.read(by, characteristic, offset: offset))
            case "write":
                guard let characteristic else { throw Failed(why: "\(at): unknown characteristic") }
                (answer, notify) = unpack(mac.write(by, characteristic, value: try v.bytes("value", in: step), offset: offset))
            case "pair": notify = mac.pair()
            case "cancel": notify = mac.cancel()
            case "expire": notify = mac.expire()
            case "grace_over": notify = mac.graceOver()
            default: throw Failed(why: "\(at): unknown operation \(op)")
            }
            if let expect = step["expect"] as? [String: Any] {
                if let value = expect["value"] as? String {
                    try c.equal(answer, .value(try ClipwayCrypto.fromHex(value)), "\(at) value")
                } else if let error = expect["error"] as? Int {
                    try c.equal(answer, .error(Nearby.ATTError(rawValue: UInt8(error)) ?? .unlikelyError), "\(at) error")
                } else {
                    try c.equal(answer, .ok, "\(at) answer")
                }
            }
            try c.equal(notify.map { String(format: "%02x", $0) }, step["notify"] as? [String] ?? [], "\(at) notify")
            try c.equal(mac.state.rawValue, try v.str("state", in: step), "\(at) state")
            try c.equal(mac.sas, step["mac_shows"] as? String, "\(at) code on the Mac")
            try c.equal(mac.end?.rawValue, step["end"] as? String, "\(at) end")
        }
        if mac.state == .ended { try c.ok(mac.forgotten, "keys forgotten at the end") }
    }

    static func unpack(_ outcome: NearbyMacSession.Outcome) -> (NearbyMacSession.Answer?, [UInt8]) { (outcome.answer, outcome.notify) }

    // MARK: The phone plays against the Mac

    /// A phone as the Android app drives it (13.3), against NearbyHost.
    static func phonePlays(_ v: Vectors, _ c: inout Checker, fixed: Bool, macFirst: Bool, mtu: Int) throws {
        let secret = try v.secret
        let code = try ClipwayCrypto.toQr(secret, relay: fixed ? ClipwayInfo.defaultRelay : "http://127.0.0.1:7710", defaultRelay: ClipwayInfo.defaultRelay)
        let session = try NearbyMacSession(code: code, privateKey: fixed ? try v.bytes("mac_private") : nil,
                                           nonce: fixed ? try v.bytes("nonce", in: try v.obj("packet")) : nil)
        var now: TimeInterval = 1000
        let host = NearbyHost(session: session, now: now)
        let phoneKey = fixed ? try Nearby.privateKey(raw: try v.bytes("phone_private")) : Nearby.newPrivateKey()
        let me = "phone", other = "other"
        try c.equal(host.phase, .open, "advertising")
        try c.ok(host.advertises, "advertises")

        // 5. Subscribe to Status first, 6. read Commit, 7. write Phone key.
        try c.equal(host.subscribe(me, now: now), [], "subscribe")
        let commit = try value(host.read(me, .commit, offset: 0, now: now), &c, "Commit")
        try c.equal(try value(host.read(me, .status, offset: 0, now: now), &c, "Status"), Data([0]), "Status waiting")
        now += 0.4
        try c.equal(host.write([.init(central: me, characteristic: .phoneKey, value: phoneKey.publicKey.rawRepresentation)], now: now).answer, .ok, "Phone key accepted")
        try c.ok(!host.advertises, "advertising stops once locked")
        guard case let .code(macCode, macConfirmed: false) = host.phase else { throw Failed(why: "the Mac shows no code") }
        // Another phone is refused from now on.
        try c.equal(try value(host.read(other, .status, offset: 0, now: now), &c, "other Status"), Data([Nearby.Status.busy.rawValue]), "other phone reads busy")
        try c.equal(host.read(other, .macKey, offset: 0, now: now).answer, .error(.readNotPermitted), "other phone cannot read Mac key")
        // 8. Read Mac key, 9. check the commitment, 10. compute the code.
        let pkMac = try value(host.read(me, .macKey, offset: 0, now: now), &c, "Mac key")
        let handshake = try Nearby.phoneHandshake(privateKey: phoneKey, commit: commit, pkMac: pkMac)
        try c.equal(handshake.sas, macCode, "both screens show the same code")
        if fixed { try c.equal(macCode, try v.str("sas"), "the code of the vectors") }

        // 11. Both press Pair, in the chosen order.
        now += 3
        if macFirst {
            try c.equal(host.pair(now: now), [], "Pair on the Mac first: no status yet")
            try c.equal(host.phase, .code(macCode, macConfirmed: true), "the Mac waits for the phone")
            let reply = host.write([.init(central: me, characteristic: .confirm, value: handshake.confirm)], now: now)
            try c.equal(reply, NearbyHost.Reply(answer: .ok, notify: [Nearby.Status.ready.rawValue]), "Confirm, then Status 01")
        } else {
            let reply = host.write([.init(central: me, characteristic: .confirm, value: handshake.confirm)], now: now)
            try c.equal(reply, NearbyHost.Reply(answer: .ok, notify: []), "Confirm first: no status yet")
            try c.equal(host.write([.init(central: me, characteristic: .confirm, value: handshake.confirm)], now: now).answer,
                        .error(.writeNotPermitted), "a second Confirm is refused")
            try c.equal(host.pair(now: now), [Nearby.Status.ready.rawValue], "Pair on the Mac, then Status 01")
        }
        try c.equal(host.phase, .ready, "ready")
        try c.equal(host.read(other, .packet, offset: 0, now: now).answer, .error(.readNotPermitted), "other phone cannot read Packet")

        // 12. Read Packet: the stack sends MTU - 1 bytes per answer, then Read Blob from the offset.
        var packet = Data()
        while true {
            let piece = try value(host.read(me, .packet, offset: packet.count, now: now), &c, "Packet at \(packet.count)")
            packet += piece.prefix(mtu - 1)
            if piece.count < mtu - 1 || packet.count == Nearby.packetSize { break }
            now += 0.05
        }
        try c.equal(packet.count, Nearby.packetSize, "Packet length")
        if fixed { try c.equal(hex(packet), try v.str("bytes", in: try v.obj("packet")), "the packet of the vectors") }
        try c.equal(host.read(me, .packet, offset: Nearby.packetSize + 1, now: now).answer, .error(.invalidOffset), "offset past the end")

        // 13. Open it, 14. the pairing code gives S and the relay.
        let opened = try Nearby.openPacket(kKey: handshake.key, pkMac: pkMac, pkPhone: handshake.pkPhone, packet: packet)
        try c.equal(opened.secret, secret, "the phone gets S")
        try c.equal(opened.relay, fixed ? nil : "http://127.0.0.1:7710", "and the relay")
        try c.equal(opened.code, code, "and the exact pairing code")

        if fixed {
            // The phone disconnects: CoreBluetooth reports it as an unsubscription.
            try c.equal(host.unsubscribe(me, now: now), [], "the phone leaves")
            try c.equal(host.phase, .ended(.done), "done when the phone leaves after the packet")
        } else {
            // The phone stays connected: the Mac stops 10 s after the first read of the packet.
            try c.ok(host.nextDeadline != nil, "the grace is scheduled")
            try c.equal(host.tick(now: now + Nearby.graceSeconds - 1), [], "still waiting before the grace ends")
            try c.equal(host.tick(now: now + Nearby.graceSeconds), [], "no status when the grace ends")
            try c.equal(host.phase, .ended(.done), "done after the grace")
        }
        try c.ok(session.forgotten, "keys forgotten")
        try c.equal(host.read(me, .commit, offset: 0, now: now + 20).answer, .error(.readNotPermitted), "every read refused after the end")
        try c.equal(host.write([.init(central: me, characteristic: .confirm, value: handshake.confirm)], now: now + 20).answer,
                    .error(.writeNotPermitted), "every write refused after the end")
    }

    static func value(_ reply: NearbyHost.Reply, _ c: inout Checker, _ what: String) throws -> Data {
        guard case let .value(data) = reply.answer else { throw Failed(why: "\(what): \(reply.answer)") }
        try c.ok(reply.notify.isEmpty, "\(what): no notification")
        return data
    }

    // MARK: The clock and batches

    static func clock(_ v: Vectors, _ c: inout Checker) throws {
        let secret = try v.secret
        let phoneKey = try Nearby.privateKey(raw: try v.bytes("phone_private"))
        // No phone in 120 s: expired, nothing to notify.
        var host = NearbyHost(session: try NearbyMacSession(secret: secret, relay: ClipwayInfo.defaultRelay), now: 0)
        try c.equal(host.nextDeadline, Nearby.sessionSeconds, "the deadline is 120 s after the start")
        try c.equal(host.tick(now: 119.9), [], "open at 119.9 s")
        try c.equal(host.phase, .open, "still open")
        try c.equal(host.tick(now: 120), [], "nobody to tell")
        try c.equal(host.phase, .ended(.expired), "expired at 120 s")

        // Locked, not confirmed: Status 03 to the phone. A request after the deadline sees it first.
        host = NearbyHost(session: try NearbyMacSession(secret: secret, relay: ClipwayInfo.defaultRelay), now: 0)
        _ = host.subscribe("phone", now: 1)
        try c.equal(host.write([.init(central: "phone", characteristic: .phoneKey, value: phoneKey.publicKey.rawRepresentation)], now: 2).answer, .ok, "key")
        _ = host.pair(now: 50)
        let late = host.read("phone", .status, offset: 0, now: 121)
        try c.equal(late, NearbyHost.Reply(answer: .error(.readNotPermitted), notify: [Nearby.Status.expired.rawValue]), "expired before the late read")

        // Ready before 120 s: not cut at 120 s, ends 10 s after the first read of the packet.
        host = NearbyHost(session: try NearbyMacSession(secret: secret, relay: ClipwayInfo.defaultRelay), now: 0)
        _ = host.subscribe("phone", now: 1)
        _ = host.write([.init(central: "phone", characteristic: .phoneKey, value: phoneKey.publicKey.rawRepresentation)], now: 2)
        let pkMac = try value(host.read("phone", .macKey, offset: 0, now: 2), &c, "Mac key")
        let handshake = try Nearby.phoneHandshake(privateKey: phoneKey, commit: Nearby.commitment(pkMac), pkMac: pkMac)
        _ = host.write([.init(central: "phone", characteristic: .confirm, value: handshake.confirm)], now: 100)
        try c.equal(host.pair(now: 119), [Nearby.Status.ready.rawValue], "ready at 119 s")
        try c.equal(host.tick(now: 130), [], "not cut at 120 s")
        try c.equal(host.phase, .ready, "still ready at 130 s")
        try c.equal(host.nextDeadline, nil, "no deadline until the packet is read")
        _ = try value(host.read("phone", .packet, offset: 0, now: 131), &c, "Packet")
        try c.equal(host.nextDeadline, 141, "grace until 141 s")
        _ = try value(host.read("phone", .packet, offset: 100, now: 135), &c, "Packet again")
        try c.equal(host.nextDeadline, 141, "the grace counts from the first read")
        try c.equal(host.tick(now: 141), [], "the grace ends")
        try c.equal(host.phase, .ended(.done), "done")
    }

    static func batches(_ v: Vectors, _ c: inout Checker) throws {
        let host = NearbyHost(session: try NearbyMacSession(secret: try v.secret, relay: ClipwayInfo.defaultRelay), now: 0)
        let pkPhone = try v.bytes("phone_public")
        _ = host.subscribe("phone", now: 0)
        // A prepared (long) write: two requests, the second at an offset. Refused whole.
        let prepared = host.write([
            .init(central: "phone", characteristic: .phoneKey, offset: 0, value: pkPhone.prefix(16)),
            .init(central: "phone", characteristic: .phoneKey, offset: 16, value: pkPhone.dropFirst(16)),
        ], now: 1)
        try c.equal(prepared.answer, .error(.invalidOffset), "prepared write refused")
        try c.equal(host.phase, .open, "nothing applied")
        // A characteristic the service does not have.
        try c.equal(host.write([.init(central: "phone", characteristic: nil, value: Data([1]))], now: 1).answer, .error(.writeNotPermitted), "unknown characteristic")
        try c.equal(host.read("phone", nil, offset: 0, now: 1).answer, .error(.readNotPermitted), "unknown read")
        // The first error of a batch is the answer.
        let mixed = host.write([
            .init(central: "phone", characteristic: .phoneKey, value: pkPhone),
            .init(central: "phone", characteristic: .confirm, value: Data(count: 15)),
        ], now: 1)
        try c.equal(mixed.answer, .error(.invalidAttributeValueLength), "first error of the batch")
        // Canceled by the Mac: Status 02 to the locked phone, then every request refused.
        try c.equal(host.cancel(now: 2), [Nearby.Status.canceled.rawValue], "Cancel on the Mac notifies 02")
        try c.equal(host.phase, .ended(.canceled), "canceled")
        try c.equal(host.subscribe("phone", now: 3), [], "nothing more")
    }
}
