import CBOR
import Crypto
import Foundation
import Testing

@testable import Juicebox

/// Drives the full three-phase recovery against fake realms that hold Shamir
/// shares of the OPRF key and the user-secret scalar.
struct RecoveryFlowTests {
  init() throws {
    try #require(juiceboxSodiumIsReady)
  }

  private static let version = [UInt8](repeating: 5, count: 16)
  private static let pin = Array("1234".utf8)
  private static let userSecret =
    Array("a 64-byte user secret".utf8)
    + [UInt8](
      repeating: 0, count: 43)
  private static let threshold = 2
  private static let realmCount = 3

  // MARK: Fake network

  struct FakeRealm {
    var id: [UInt8]
    var url: String
    var token: String
    var oprfShare: RistrettoScalar
    var scalarShare: RistrettoScalar
    var encryptedSecret: [UInt8]
    var secretCommitment: [UInt8]
    var unlockKeyCommitment: [UInt8]
    var unlockKey: [UInt8]
    var signingKey: Curve25519.Signing.PrivateKey
    var numGuesses: UInt16
    var guessCount: UInt16
  }

  final class FakeNetwork: JuiceboxHTTPTransport, Sendable {
    let realms: [String: FakeRealm]
    init(realms: [FakeRealm]) {
      self.realms = Dictionary(uniqueKeysWithValues: realms.map { ($0.url, $0) })
    }

    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
      guard let realm = realms[request.url] else {
        return JuiceboxHTTPResponse(statusCode: 404, body: [])
      }
      guard request.headers["Authorization"] == "Bearer \(realm.token)" else {
        return JuiceboxHTTPResponse(statusCode: 401, body: [])
      }
      let value = try decodeCBOR(request.body)
      if value == .textString("Recover1") {
        return JuiceboxHTTPResponse(
          statusCode: 200, body: encodeRecover1Ok(version: Self.versionForNetwork))
      }
      if let body = value["Recover2"] {
        return JuiceboxHTTPResponse(
          statusCode: 200, body: try recover2(realm: realm, body: body))
      }
      if let body = value["Recover3"] {
        return JuiceboxHTTPResponse(
          statusCode: 200, body: try recover3(realm: realm, body: body))
      }
      return JuiceboxHTTPResponse(statusCode: 400, body: [])
    }

    static let versionForNetwork = RecoveryFlowTests.version

    private func recover2(realm: FakeRealm, body: CBOR) throws -> [UInt8] {
      guard let blindedInputBytes = body["oprf_blinded_input"]?.bytes,
        let blindedInput = try? OPRF.BlindedInput(compressed: blindedInputBytes)
      else { return [] }
      let publicKey = OPRF.publicKey(for: realm.oprfShare)
      let blindedOutput = OPRF.evaluate(
        privateKey: realm.oprfShare, blindedInput: blindedInput)
      let proof = OPRF.generateProof(
        privateKey: realm.oprfShare, nonce: .random(),
        blindedInput: blindedInput, publicKey: publicKey,
        blindedOutput: blindedOutput)
      var message: [UInt8] = []
      message += be16(16)
      message += realm.id
      message += be16(32)
      message += publicKey
      let signature = try realm.signingKey.signature(for: message)

      return CBOR.map([
        "Recover2": .map([
          "Ok": .map([
            "oprf_signed_public_key": .map([
              "public_key": .byteString(publicKey),
              "verifying_key": .byteString(Array(realm.signingKey.publicKey.rawRepresentation)),
              "signature": .byteString(Array(signature)),
            ]),
            "oprf_blinded_result": .byteString(blindedOutput.compressed),
            "oprf_proof": .map([
              "c": .byteString(proof.c.bytes),
              "beta_z": .byteString(proof.betaZ.bytes),
            ]),
            "unlock_key_commitment": .byteString(realm.unlockKeyCommitment),
            "num_guesses": .unsignedInt(UInt64(realm.numGuesses)),
            "guess_count": .unsignedInt(UInt64(realm.guessCount)),
          ])
        ])
      ]).encode()
    }

    private func recover3(realm: FakeRealm, body: CBOR) throws -> [UInt8] {
      guard let tag = body["unlock_key_tag"]?.bytes else { return [] }
      let expected = JuiceboxKeys.unlockKeyTag(unlockKey: realm.unlockKey, realmId: realm.id)
      guard constantTimeEqual(tag, expected) else {
        return CBOR.map([
          "Recover3": .map([
            "BadUnlockKeyTag": .map([
              "guesses_remaining": .unsignedInt(4)
            ])
          ])
        ]).encode()
      }
      return CBOR.map([
        "Recover3": .map([
          "Ok": .map([
            "encryption_key_scalar_share": .byteString(realm.scalarShare.bytes),
            "encrypted_secret": .byteString(realm.encryptedSecret),
            "encrypted_secret_commitment": .byteString(realm.secretCommitment),
          ])
        ])
      ]).encode()
    }

    private func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
      guard lhs.count == rhs.count else { return false }
      var difference: UInt8 = 0
      for i in 0..<lhs.count { difference |= lhs[i] ^ rhs[i] }
      return difference == 0
    }
  }

  static func encodeRecover1Ok(version: [UInt8]) -> [UInt8] {
    CBOR.map([
      "Recover1": .map([
        "Ok": .map([
          "version": .byteString(version)
        ])
      ])
    ]).encode()
  }

  // MARK: Setup

  /// Builds fake realms that hold shares of `userSecret` registered under
  /// `pin`, and the configuration and tokens for them.
  ///
  /// Without `pinHash`, the setup hashes `pin` with `Self.version`, `mode`,
  /// and an empty `userInfo`, so the test must give `JuiceboxRecovery` the
  /// default (empty) `userInfo`.
  ///
  /// - Parameter pinHash: The PIN's hash, when it is already known, so the
  ///   setup does not hash the PIN itself (Standard2019 takes seconds).
  ///   `pin` is then unused. The hash must be of the PIN that the test
  ///   recovers with, `Self.version`, `mode`, and the `userInfo` the test
  ///   gives `JuiceboxRecovery`.
  func makeNetwork(
    pin: [UInt8] = RecoveryFlowTests.pin, mode: JuiceboxPinHashingMode = .fastInsecure,
    pinHash: (accessKey: [UInt8], encryptionKeySeed: [UInt8])? = nil
  ) throws -> (FakeNetwork, JuiceboxConfiguration, [String: String]) {
    let realmIds = (0..<Self.realmCount).map { index in
      [UInt8](repeating: UInt8(index + 1), count: 16)
    }
    let tokens = Dictionary(
      uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })

    let (accessKey, seed) =
      try pinHash ?? juiceboxPinHash(pin: pin, registrationVersion: Self.version, mode: mode)
    let masterOPRF = RistrettoScalar.random()
    let oprfShares = createShares(
      secret: masterOPRF, threshold: Self.threshold, count: Self.realmCount,
      random: { RistrettoScalar.random() })
    let oprfOutput = OPRF.unobliviousEvaluate(privateKey: masterOPRF, input: accessKey)
    let (unlockKey, unlockKeyCommitment) = JuiceboxKeys.unlockKeyAndCommitment(
      oprfOutput: oprfOutput)

    let scalar = RistrettoScalar.random()
    let scalarShares = createShares(
      secret: scalar, threshold: Self.threshold, count: Self.realmCount,
      random: { RistrettoScalar.random() })
    let encryptionKey = JuiceboxKeys.userSecretEncryptionKey(
      seed: seed, scalar: scalar.bytes)
    let encryptedSecret = JuiceboxKeys.encryptUserSecret(
      Self.userSecret, key: encryptionKey)!

    var realms: [FakeRealm] = []
    let signer = Curve25519.Signing.PrivateKey()
    for index in 0..<Self.realmCount {
      let id = realmIds[index]
      let commitment = JuiceboxKeys.encryptedUserSecretCommitment(
        unlockKey: unlockKey, realmId: id,
        scalarShare: scalarShares[index].secret.bytes,
        encryptedSecret: encryptedSecret)
      realms.append(
        FakeRealm(
          id: id, url: "https://realm\(index + 1).test/req", token: tokens[hexString(id)]!,
          oprfShare: oprfShares[index].secret, scalarShare: scalarShares[index].secret,
          encryptedSecret: encryptedSecret, secretCommitment: commitment,
          unlockKeyCommitment: unlockKeyCommitment, unlockKey: unlockKey,
          signingKey: signer, numGuesses: 5, guessCount: 1))
    }

    let json = """
      {
        "realms": [
          {"id": "\(hexString(realmIds[0]))", "address": "https://realm1.test/"},
          {"id": "\(hexString(realmIds[1]))", "address": "https://realm2.test/"},
          {"id": "\(hexString(realmIds[2]))", "address": "https://realm3.test/"}
        ],
        "register_threshold": 3,
        "recover_threshold": 2,
        "pin_hashing_mode": "\(mode.rawValue)"
      }
      """
    let configuration = try! JuiceboxConfiguration.parse(Array(json.utf8))
    return (FakeNetwork(realms: realms), configuration, tokens)
  }

  private actor CancellingTransport: JuiceboxHTTPTransport {
    enum Mode {
      /// Every PIN request throws `CancellationError` without the caller
      /// having cancelled.
      case throwsCancellation
      /// Every PIN request throws `URLError(.cancelled)` without the caller
      /// having cancelled.
      case throwsURLCancellation
      /// Every PIN request cancels only the task that sends it, which the
      /// caller did not cancel, and then answers.
      case cancelsItsOwnTaskThenAnswers
      /// Only the first realm's PIN requests throw `CancellationError`; the
      /// other realms answer.
      case cancelsOneRealm
      /// Only the first realm's PIN requests cancel their own task and then
      /// answer; the other realms answer normally.
      case oneRealmCancelsItsOwnTask
    }

    let network: FakeNetwork
    let mode: Mode
    private(set) var unlockRequests = 0

    init(network: FakeNetwork, mode: Mode) {
      self.network = network
      self.mode = mode
    }

    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
      let value = try decodeCBOR(request.body)
      if value == .textString("Recover1") {
        return try await network.send(request)
      }
      if value["Recover3"] != nil { unlockRequests += 1 }
      switch mode {
      case .throwsCancellation:
        throw CancellationError()
      case .throwsURLCancellation:
        throw URLError(.cancelled)
      case .cancelsItsOwnTaskThenAnswers:
        unsafe withUnsafeCurrentTask { unsafe $0?.cancel() }
        return try await network.send(request)
      case .cancelsOneRealm:
        guard request.url.hasPrefix("https://realm1.") else {
          return try await network.send(request)
        }
        throw CancellationError()
      case .oneRealmCancelsItsOwnTask:
        if request.url.hasPrefix("https://realm1.") {
          unsafe withUnsafeCurrentTask { unsafe $0?.cancel() }
        }
        return try await network.send(request)
      }
    }
  }

  // MARK: Tests

  @Test func recoverUserSecret() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let secret = try await recovery.recover(pin: Self.pin, transport: network)
    #expect(secret == Self.userSecret)
  }

  #if os(macOS)
    private struct OffMainTransport: JuiceboxHTTPTransport {
      var network: FakeNetwork

      func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
        checkThread()
        return try await network.send(request)
      }

      private func checkThread() {
        #expect(!Thread.isMainThread)
      }
    }

    /// The transport is called off the main actor even when recovery is
    /// started from it.
    @MainActor
    @Test func transportIsCalledOffTheMainActor() async throws {
      let (network, configuration, tokens) = try makeNetwork()
      let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
      let secret = try await recovery.recover(
        pin: Self.pin, transport: OffMainTransport(network: network))
      #expect(secret == Self.userSecret)
    }
  #endif

  /// Recovery started from the main actor runs its PIN hashing (Argon2 with
  /// the real Standard2019 parameters, about a second or more) off the main
  /// actor, so the main actor keeps running. The transport is called from
  /// child tasks, so only the main actor's own progress shows where
  /// `recover` itself runs.
  @MainActor
  @Test(.timeLimit(.minutes(1)))
  func recoveryLeavesTheMainActorFree() async throws {
    // The reference vector has this test's PIN and version, so only
    // `recover` hashes the PIN.
    try #require(
      Self.pin == PinHashVector.pin && Self.version == PinHashVector.registrationVersion)
    let (network, configuration, tokens) = try makeNetwork(
      mode: .standard2019,
      pinHash: (
        try #require(hexBytes(PinHashVector.accessKey)),
        try #require(hexBytes(PinHashVector.encryptionKeySeed))
      ))
    let recovery = JuiceboxRecovery(
      configuration: configuration, tokens: tokens, userInfo: PinHashVector.userInfo)
    // Measure from before the ticker first runs, so a stall before its
    // first tick (when `recover` hashes before giving up the main actor)
    // also counts.
    let started = ContinuousClock.now
    let ticker = Task { @MainActor in
      var longestGap = Duration.zero
      var last = started
      while !Task.isCancelled {
        try? await Task.sleep(for: .milliseconds(10))
        let now = ContinuousClock.now
        longestGap = max(longestGap, now - last)
        last = now
      }
      return longestGap
    }
    // Stop the ticker even when `recover` throws, so it does not keep
    // waking the main actor during the other tests.
    defer { ticker.cancel() }
    let secret = try await recovery.recover(pin: Self.pin, transport: network)
    let elapsed = ContinuousClock.now - started
    ticker.cancel()
    let longestGap = await ticker.value
    #expect(secret == Self.userSecret)
    // The main actor must not stall for anything close to the hashing time.
    #expect(longestGap < elapsed / 2)
  }

  /// Cancels the caller's task when it receives a PIN request, and then
  /// answers anyway, as a transport that ignores cancellation does.
  private actor CallerCancellingTransport: JuiceboxHTTPTransport {
    let network: FakeNetwork
    private var caller: Task<[UInt8], any Error>?
    private(set) var pinRequests = 0
    private(set) var unlockRequests = 0

    init(network: FakeNetwork) {
      self.network = network
    }

    func setCaller(_ task: Task<[UInt8], any Error>) {
      caller = task
    }

    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
      let value = try decodeCBOR(request.body)
      if value == .textString("Recover1") {
        return try await network.send(request)
      }
      pinRequests += 1
      if value["Recover3"] != nil { unlockRequests += 1 }
      // The test sets the caller right after starting it.
      while caller == nil { await Task.yield() }
      caller?.cancel()
      return try await network.send(request)
    }
  }

  /// When the caller cancels recovery during the PIN phase, recovery stops
  /// before the unlock phase, even if the transport answers anyway. Anywhere
  /// from one realm to all of them get a PIN request: a phase asks each realm
  /// once and recovery never reaches the unlock phase, while a request
  /// whose task sees the cancellation before calling the transport is not
  /// sent.
  @Test(.timeLimit(.minutes(1)))
  func theCallersCancellationStopsRecoveryBeforeTheNextPhase() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let transport = CallerCancellingTransport(network: network)
    let task = Task { [pin = Self.pin] in
      try await recovery.recover(pin: pin, transport: transport)
    }
    await transport.setCaller(task)
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect((1...Self.realmCount).contains(await transport.pinRequests))
    #expect(await transport.unlockRequests == 0)
  }

  /// A cancellation the transport reports while the caller has not cancelled
  /// (an invalidated session, a cancelled redirect, a cancelled request task)
  /// is a failure of that realm, not the caller's cancellation: recovery
  /// fails with a recovery error, and the other realms can still answer.
  @Test func aTransportCancellationIsARealmFailure() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    for mode in [
      CancellingTransport.Mode.throwsCancellation, .throwsURLCancellation,
      .cancelsItsOwnTaskThenAnswers,
    ] {
      let transport = CancellingTransport(network: network, mode: mode)
      await #expect(throws: JuiceboxRecoveryError.transient) {
        try await recovery.recover(pin: Self.pin, transport: transport)
      }
      #expect(await transport.unlockRequests == 0)
    }
    for mode in [CancellingTransport.Mode.cancelsOneRealm, .oneRealmCancelsItsOwnTask] {
      let oneRealm = CancellingTransport(network: network, mode: mode)
      let secret = try await recovery.recover(pin: Self.pin, transport: oneRealm)
      #expect(secret == Self.userSecret)
    }
  }

  /// Answers each phase's requests in the reverse of the realms' order: the
  /// last realm answers first and the first realm answers last. Each request
  /// waits for its turn (for up to five seconds) and records the realm it
  /// answered for. Recovery must still pair every answer with its realm.
  private actor ReversingTransport: JuiceboxHTTPTransport {
    let network: FakeNetwork
    private(set) var answered: [Int] = []

    init(network: FakeNetwork) {
      self.network = network
    }

    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
      let realmCount = RecoveryFlowTests.realmCount
      let realmNumber = request.url.first(where: \.isNumber).flatMap { Int(String($0)) } ?? 0
      let deadline = ContinuousClock.now + .seconds(5)
      while answered.count % realmCount != realmCount - realmNumber, ContinuousClock.now < deadline
      {
        try await Task.sleep(for: .milliseconds(1))
      }
      answered.append(realmNumber)
      return try await network.send(request)
    }
  }

  @Test(.timeLimit(.minutes(1)))
  func answersInReverseOrderArePairedWithTheirRealms() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let transport = ReversingTransport(network: network)
    let secret = try await recovery.recover(pin: Self.pin, transport: transport)
    #expect(secret == Self.userSecret)
    // Three phases, each answered from the last realm to the first.
    #expect(await transport.answered == [3, 2, 1, 3, 2, 1, 3, 2, 1])
  }

  /// Holds each request for up to five seconds until the other realms of its
  /// phase have been asked too, and records how many were in flight at once.
  /// Every phase here asks all realms, so the requests arrive in batches of
  /// `realmCount`. When the realms are contacted one at a time, all but the
  /// last request of each batch wait out the five seconds alone, so the test
  /// fails (in about 30 seconds) instead of hanging.
  private actor GatheringTransport: JuiceboxHTTPTransport {
    let network: FakeNetwork
    private var arrivals = 0
    private var inFlight = 0
    private(set) var mostInFlight = 0

    init(network: FakeNetwork) {
      self.network = network
    }

    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
      let batchSize = RecoveryFlowTests.realmCount
      arrivals += 1
      let batchEnd = (arrivals + batchSize - 1) / batchSize * batchSize
      inFlight += 1
      defer { inFlight -= 1 }
      mostInFlight = max(mostInFlight, inFlight)
      let deadline = ContinuousClock.now + .seconds(5)
      while arrivals < batchEnd, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(5))
      }
      return try await network.send(request)
    }
  }

  @Test(.timeLimit(.minutes(1)))
  func realmsAreContactedTogether() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let transport = GatheringTransport(network: network)
    let secret = try await recovery.recover(pin: Self.pin, transport: transport)
    #expect(secret == Self.userSecret)
    #expect(await transport.mostInFlight == Self.realmCount)
  }

  /// Answers the registration version at once and holds every PIN request
  /// until the request is cancelled.
  private actor HoldingTransport: JuiceboxHTTPTransport {
    let network: FakeNetwork
    private(set) var pinRequests = 0
    private(set) var unlockRequests = 0

    init(network: FakeNetwork) {
      self.network = network
    }

    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
      let value = try decodeCBOR(request.body)
      if value == .textString("Recover1") {
        return try await network.send(request)
      }
      pinRequests += 1
      if value["Recover3"] != nil { unlockRequests += 1 }
      try await Task.sleep(for: .seconds(30))
      return try await network.send(request)
    }
  }

  /// Cancelling the caller's task while the PIN requests are in flight
  /// cancels those requests and ends recovery at once, before the unlock
  /// phase.
  @Test(.timeLimit(.minutes(1)))
  func cancellingTheCallerStopsTheRequestsInFlight() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let transport = HoldingTransport(network: network)
    let task = Task { [pin = Self.pin] in
      try await recovery.recover(pin: pin, transport: transport)
    }
    // Recovery may end before any PIN request (for example, if the first
    // phase fails); give up instead of waiting forever.
    let deadline = ContinuousClock.now + .seconds(10)
    while await transport.pinRequests == 0 {
      guard ContinuousClock.now < deadline else {
        task.cancel()
        do {
          _ = try await task.value
          Issue.record("no PIN request was sent, and recovery succeeded")
        } catch {
          Issue.record("no PIN request was sent: \(error)")
        }
        return
      }
      try await Task.sleep(for: .milliseconds(5))
    }
    let cancelled = ContinuousClock.now
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(ContinuousClock.now - cancelled < .seconds(10))
    #expect(await transport.pinRequests <= Self.realmCount)
    #expect(await transport.unlockRequests == 0)
  }

  @Test func recoverWithOneRealmDown() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    // Drop the second realm by pointing it at an unreachable address.
    let json = """
      {
        "realms": [
          {"id": "\(hexString(configuration.realms[0].id))", "address": "https://realm1.test/"},
          {"id": "\(hexString(configuration.realms[1].id))", "address": "https://down.test/"},
          {"id": "\(hexString(configuration.realms[2].id))", "address": "https://realm3.test/"}
        ],
        "register_threshold": 3,
        "recover_threshold": 2,
        "pin_hashing_mode": "FastInsecure"
      }
      """
    let degraded = try JuiceboxConfiguration.parse(Array(json.utf8))
    let recovery = JuiceboxRecovery(configuration: degraded, tokens: tokens)
    let secret = try await recovery.recover(pin: Self.pin, transport: network)
    #expect(secret == Self.userSecret)
  }

  @Test func wrongPinReportsGuesses() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    do {
      _ = try await recovery.recover(pin: Array("0000".utf8), transport: network)
      Issue.record("wrong PIN must fail")
    } catch let error as JuiceboxRecoveryError {
      #expect(error == .invalidPin(guessesRemaining: 4))
    }
  }

  @Test func missingTokenIsInvalidAuth() async throws {
    let (network, configuration, _) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: [:])
    do {
      _ = try await recovery.recover(pin: Self.pin, transport: network)
      Issue.record("missing tokens must fail")
    } catch let error as JuiceboxRecoveryError {
      #expect(error == .invalidAuth)
    }
  }

  @Test func tooFewRealmsIsTransientOrNotRegistered() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let json = """
      {
        "realms": [
          {"id": "\(hexString(configuration.realms[0].id))", "address": "https://down1.test/"},
          {"id": "\(hexString(configuration.realms[1].id))", "address": "https://down2.test/"},
          {"id": "\(hexString(configuration.realms[2].id))", "address": "https://realm3.test/"}
        ],
        "register_threshold": 3,
        "recover_threshold": 2,
        "pin_hashing_mode": "FastInsecure"
      }
      """
    let degraded = try JuiceboxConfiguration.parse(Array(json.utf8))
    let recovery = JuiceboxRecovery(configuration: degraded, tokens: tokens)
    do {
      _ = try await recovery.recover(pin: Self.pin, transport: network)
      Issue.record("too few realms must fail")
    } catch let error as JuiceboxRecoveryError {
      #expect(error == .transient)
    }
  }
}
