import AppKit
import ClipwayCore
@preconcurrency import CoreBluetooth
import Observation

/// Pair nearby on the Mac (docs/PROTOCOL.md, section 13): the Bluetooth LE peripheral. Every request
/// goes to NearbyHost (ClipwayCore), which holds the session and the rules; this class only turns
/// CoreBluetooth calls into host calls, answers, notifies, advertises and keeps time.
///
/// The peripheral manager exists only while a Pair nearby window is open, so macOS asks for
/// Bluetooth at that moment, never at launch. It advertises the service UUID alone (no name), for
/// 120 seconds at most, and is released at the end of each attempt with the keys.
@MainActor
@Observable
final class NearbyPairing: NSObject {
    enum Screen: Equatable {
        case idle
        /// Waiting for Bluetooth, the system's permission dialog, or the service.
        case starting
        case advertising
        case code(String, macConfirmed: Bool)
        /// Both pressed Pair; then waiting for the phone's hello through the relay.
        case finishing
        case stoppedOnPhone
        case expired
        case failed
        case bluetoothOff
        case notAllowed
        case unsupported
    }

    private(set) var screen: Screen = .idle
    /// When the current attempt started: a hello after it means the phone joined.
    private(set) var startedAt = Date.distantFuture
    /// The window that runs the attempt.
    private(set) var owner: String?

    @ObservationIgnored var trace: (String) -> Void = { _ in }
    @ObservationIgnored private(set) var isPreview = false
    @ObservationIgnored private var code = ""
    @ObservationIgnored private var manager: CBPeripheralManager?
    @ObservationIgnored private var host: NearbyHost?
    @ObservationIgnored private var statusCharacteristic: CBMutableCharacteristic?
    @ObservationIgnored private var centrals: [String: CBCentral] = [:]
    @ObservationIgnored private var queued: [Data] = []
    @ObservationIgnored private var advertising = false
    @ObservationIgnored private var restartPending = false
    @ObservationIgnored private var timer: Task<Void, Never>?
    @ObservationIgnored private var teardown: Task<Void, Never>?

    private static var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    /// The window opened on Pair nearby (or switched to it). A running attempt of another window ends first.
    func start(code: String, owner: String) {
        guard !isPreview, Nearby.fits(code: code) else { return }
        self.code = code
        self.owner = owner
        if host != nil || teardown != nil {
            restartPending = true
            screen = .starting
            if let host, !host.isOver { send(host.cancel(now: Self.now)) }
            finishAttempt()
        } else {
            attempt()
        }
    }

    /// Try again after an attempt ended.
    func retry() {
        guard owner != nil else { return }
        if teardown != nil {
            restartPending = true
            screen = .starting
        } else {
            attempt()
        }
    }

    /// Pair on the Mac.
    func pair() {
        guard let host else { return }
        send(host.pair(now: Self.now))
        Haptics.success()
        trace("nearby: pair on the Mac")
        refresh()
    }

    /// Cancel on the Mac: the phone hears Status 02, and the Mac advertises again with new keys.
    func cancel() {
        guard let host, !host.isOver else { return }
        trace("nearby: canceled on the Mac")
        send(host.cancel(now: Self.now))
        restartPending = true
        screen = .starting
        finishAttempt()
    }

    /// The window closed, or Show a code instead. A ready attempt is left to finish on its own.
    func stop(owner: String) {
        guard self.owner == owner else { return }
        self.owner = nil
        restartPending = false
        if let host, !host.isOver, host.phase != .ready {
            trace("nearby: stopped on the Mac")
            send(host.cancel(now: Self.now))
        }
        if host == nil || host?.isOver == true || host?.phase != .ready { finishAttempt() }
        if screen != .finishing { screen = .idle }
    }

    // MARK: Attempts

    private func attempt() {
        guard owner != nil else { return }
        restartPending = false
        startedAt = Date()
        switch CBPeripheralManager.authorization {
        case .denied, .restricted:
            screen = .notAllowed
            return
        default:
            break
        }
        screen = .starting
        if let manager {
            stateChanged(manager)
        } else {
            // macOS asks for Bluetooth here the first time, with NSBluetoothAlwaysUsageDescription.
            manager = CBPeripheralManager(delegate: self, queue: .main, options: [CBPeripheralManagerOptionShowPowerAlertKey: false])
        }
    }

    private func stateChanged(_ manager: CBPeripheralManager) {
        switch manager.state {
        case .poweredOn:
            if owner != nil, host == nil, teardown == nil, [.starting, .bluetoothOff, .notAllowed].contains(screen) { begin(manager) }
        case .poweredOff:
            dropSession()
            if owner != nil { screen = .bluetoothOff }
        case .unauthorized:
            dropSession()
            if owner != nil { screen = .notAllowed }
        case .unsupported:
            dropSession()
            if owner != nil { screen = .unsupported }
        case .resetting, .unknown:
            break
        @unknown default:
            break
        }
    }

    /// A new session: fresh keys, the service, then advertising once the service is added.
    private func begin(_ manager: CBPeripheralManager) {
        guard let session = try? NearbyMacSession(code: code) else {
            screen = .failed
            return
        }
        host = NearbyHost(session: session, now: Self.now)
        startedAt = Date()
        advertising = false
        func characteristic(_ c: Nearby.Characteristic) -> CBMutableCharacteristic {
            // Values are answered in the delegate (value nil). Never the EncryptionRequired permissions:
            // they start Bluetooth bonding and a system dialog.
            switch c {
            case .phoneKey, .confirm:
                return CBMutableCharacteristic(type: CBUUID(string: c.uuid), properties: [.write], value: nil, permissions: [.writeable])
            case .status:
                return CBMutableCharacteristic(type: CBUUID(string: c.uuid), properties: [.read, .notify], value: nil, permissions: [.readable])
            case .commit, .macKey, .packet:
                return CBMutableCharacteristic(type: CBUUID(string: c.uuid), properties: [.read], value: nil, permissions: [.readable])
            }
        }
        let service = CBMutableService(type: CBUUID(string: Nearby.serviceUUID), primary: true)
        let all = Nearby.Characteristic.allCases.map { ($0, characteristic($0)) }
        service.characteristics = all.map(\.1)
        statusCharacteristic = all.first { $0.0 == .status }?.1
        manager.removeAllServices()
        manager.add(service)
        trace("nearby: service added")
        schedule()
    }

    /// Bluetooth went off or was refused: the attempt is over, nobody can be told.
    private func dropSession() {
        timer?.cancel()
        if let host, !host.isOver { _ = host.cancel(now: Self.now) }
        host = nil
        statusCharacteristic = nil
        centrals = [:]
        queued = []
        advertising = false
    }

    /// The attempt is over: stop advertising now, remove the service and release Bluetooth once the
    /// last Status had time to go, then start again if Cancel or Try again asked for it.
    private func finishAttempt() {
        timer?.cancel()
        if manager?.isAdvertising == true { manager?.stopAdvertising() }
        guard teardown == nil else { return }
        let wait: UInt64 = host?.lockedCentral != nil ? 1_000_000_000 : 0
        teardown = Task { @MainActor [weak self] in
            if wait > 0 { try? await Task.sleep(nanoseconds: wait) }
            guard let self else { return }
            // A ready session still running (the window closed meanwhile) keeps its service until it ends.
            if let host = self.host, !host.isOver {
                self.teardown = nil
                self.refresh()
                return
            }
            self.release()
            self.teardown = nil
            if self.restartPending { self.attempt() }
        }
    }

    private func release() {
        dropSession()
        manager?.stopAdvertising()
        manager?.removeAllServices()
        manager?.delegate = nil
        manager = nil
        trace("nearby: Bluetooth released")
    }

    // MARK: Answers, notifications, time

    /// What the window shows, from the session; ends the attempt when the session ended.
    private func refresh() {
        guard let host else { return }
        let before = screen
        switch host.phase {
        case .open:
            screen = advertising ? .advertising : .starting
        case let .code(code, macConfirmed):
            screen = .code(code, macConfirmed: macConfirmed)
        case .ready:
            screen = .finishing
        case let .ended(reason):
            switch reason {
            case .done: screen = .finishing
            case .left: screen = .stoppedOnPhone
            case .expired: screen = .expired
            case .failed: screen = .failed
            case .canceled: break
            }
            trace("nearby: ended, \(reason.rawValue)")
        }
        if case .code = screen {
            if case .code = before {} else { Haptics.alignment() }
        }
        if screen == .failed && before != .failed { Haptics.reject() }
        if !host.advertises, manager?.isAdvertising == true {
            manager?.stopAdvertising()
            trace("nearby: phone key accepted, advertising stopped")
        }
        if host.isOver { finishAttempt() } else { schedule() }
    }

    private func schedule() {
        timer?.cancel()
        guard let host, let deadline = host.nextDeadline else { return }
        let delay = max(0, deadline - Self.now)
        timer = Task { @MainActor [weak self, weak host] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000) + 5_000_000)
            guard !Task.isCancelled, let self, let host, host === self.host else { return }
            self.send(host.tick(now: Self.now))
            self.refresh()
        }
    }

    /// Status notifications, only to the locked phone, after the answer to the request that caused them.
    private func send(_ bytes: [UInt8]) {
        queued += bytes.map { Data([$0]) }
        flush()
    }

    private func flush() {
        guard let manager, let statusCharacteristic, let id = host?.lockedCentral, let central = centrals[id] else {
            queued = []
            return
        }
        while let next = queued.first {
            // false: the queue is full, peripheralManagerIsReady(toUpdateSubscribers:) sends it later.
            guard manager.updateValue(next, for: statusCharacteristic, onSubscribedCentrals: [central]) else { return }
            queued.removeFirst()
        }
    }

    private static func result(_ answer: NearbyMacSession.Answer) -> CBATTError.Code {
        switch answer {
        case .ok, .value: .success
        case let .error(error): CBATTError.Code(rawValue: Int(error.rawValue)) ?? .unlikelyError
        }
    }

    // MARK: Snapshots

    #if DEBUG
    static func preview(_ screen: Screen) -> NearbyPairing {
        let nearby = NearbyPairing()
        nearby.isPreview = true
        nearby.screen = screen
        nearby.owner = "preview"
        return nearby
    }
    #endif
}

extension NearbyPairing: @preconcurrency CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral === manager else { return }
        trace("nearby: Bluetooth state \(peripheral.state.rawValue)")
        stateChanged(peripheral)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        guard peripheral === manager, let host, !host.isOver else { return }
        if error != nil {
            trace("nearby: the service could not be added")
            fail(host)
            return
        }
        // The service UUID and nothing else: no local name.
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [CBUUID(string: Nearby.serviceUUID)]])
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        guard peripheral === manager, let host, !host.isOver else { return }
        if error != nil {
            trace("nearby: advertising failed")
            fail(host)
            return
        }
        advertising = true
        trace("nearby: advertising")
        refresh()
    }

    private func fail(_ host: NearbyHost) {
        send(host.cancel(now: Self.now))
        screen = .failed
        Haptics.reject()
        finishAttempt()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        guard peripheral === manager, let host, Nearby.Characteristic(uuid: characteristic.uuid.uuidString) == .status else { return }
        let id = central.identifier.uuidString
        centrals[id] = central
        send(host.subscribe(id, now: Self.now))
        refresh()
    }

    /// CoreBluetooth reports no disconnection to a peripheral: the phone leaving shows up here.
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard peripheral === manager, let host, Nearby.Characteristic(uuid: characteristic.uuid.uuidString) == .status else { return }
        send(host.unsubscribe(central.identifier.uuidString, now: Self.now))
        refresh()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        guard peripheral === manager, let host else {
            peripheral.respond(to: request, withResult: .readNotPermitted)
            return
        }
        let id = request.central.identifier.uuidString
        centrals[id] = request.central
        let reply = host.read(id, Nearby.Characteristic(uuid: request.characteristic.uuid.uuidString), offset: request.offset, now: Self.now)
        if case let .value(bytes) = reply.answer { request.value = bytes }
        peripheral.respond(to: request, withResult: Self.result(reply.answer))
        send(reply.notify)
        refresh()
    }

    /// Every request of one ATT write: one answer, to the first request.
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        guard let first = requests.first else { return }
        guard peripheral === manager, let host else {
            peripheral.respond(to: first, withResult: .writeNotPermitted)
            return
        }
        let batch = requests.map { request in
            centrals[request.central.identifier.uuidString] = request.central
            return NearbyHost.Write(central: request.central.identifier.uuidString,
                                    characteristic: Nearby.Characteristic(uuid: request.characteristic.uuid.uuidString),
                                    offset: request.offset, value: request.value ?? Data())
        }
        let reply = host.write(batch, now: Self.now)
        peripheral.respond(to: first, withResult: Self.result(reply.answer))
        send(reply.notify)
        refresh()
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        guard peripheral === manager else { return }
        flush()
    }
}
