import CBOR
import Crypto
import Foundation
import HTTPClient
import HTTPTypes
import Testing

@testable import Juicebox

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// Drives the full three-phase recovery against fake realms that hold Shamir
/// shares of the OPRF key and the user-secret scalar. A "PIN request" is a
/// request of the OPRF or unlock phase (Recover2 or Recover3), which follow
/// the PIN hashing.
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

  final class FakeNetwork: BytesHTTPClient, Sendable {
    let realms: [String: FakeRealm]
    init(realms: [FakeRealm]) {
      self.realms = Dictionary(uniqueKeysWithValues: realms.map { ($0.url, $0) })
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      guard let realm = realms[request.urlString] else {
        return (HTTPResponse(status: .notFound), [])
      }
      guard request.headerFields[.authorization] == "Bearer \(realm.token)" else {
        return (HTTPResponse(status: .unauthorized), [])
      }
      let value = try decodeCBOR(body)
      if value == .textString("Recover1") {
        return (HTTPResponse(status: .ok), encodeRecover1Ok(version: Self.versionForNetwork))
      }
      if let fields = value["Recover2"] {
        return (HTTPResponse(status: .ok), try recover2(realm: realm, body: fields))
      }
      if let fields = value["Recover3"] {
        return (HTTPResponse(status: .ok), try recover3(realm: realm, body: fields))
      }
      return (HTTPResponse(status: .badRequest), [])
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

  /// Builds fake realms that hold shares of `Self.userSecret` registered
  /// under `pin` (or the PIN that `pinHash` is of), and the configuration and
  /// tokens for them.
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

  private actor CancellingHTTPClient: BytesHTTPClient {
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
    /// The first realm's PIN requests that failed (`cancelsOneRealm`) or
    /// cancelled their own task (`oneRealmCancelsItsOwnTask`).
    private(set) var firstRealmCancellations = 0

    init(network: FakeNetwork, mode: Mode) {
      self.network = network
      self.mode = mode
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      let value = try decodeCBOR(body)
      if value == .textString("Recover1") {
        return try await network.send(request, body: body)
      }
      if value["Recover3"] != nil { unlockRequests += 1 }
      switch mode {
      case .throwsCancellation:
        throw CancellationError()
      case .throwsURLCancellation:
        throw URLError(.cancelled)
      case .cancelsItsOwnTaskThenAnswers:
        unsafe withUnsafeCurrentTask { unsafe $0?.cancel() }
        return try await network.send(request, body: body)
      case .cancelsOneRealm:
        guard request.urlString.hasPrefix("https://realm1.") else {
          return try await network.send(request, body: body)
        }
        firstRealmCancellations += 1
        throw CancellationError()
      case .oneRealmCancelsItsOwnTask:
        if request.urlString.hasPrefix("https://realm1.") {
          firstRealmCancellations += 1
          unsafe withUnsafeCurrentTask { unsafe $0?.cancel() }
        }
        return try await network.send(request, body: body)
      }
    }
  }

  // MARK: Tests

  @Test func recoverUserSecret() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let secret = try await recovery.recover(pin: Self.pin, httpClient: network)
    #expect(secret == Self.userSecret)
  }

  /// `URLSession` is passed as it is. When it cannot reach the realms
  /// (nothing listens on port 1), each request throws, and recovery fails
  /// with `transient`, as for any error the HTTP client throws.
  @Test(.timeLimit(.minutes(1)))
  func urlSessionThatCannotReachTheRealmsIsTransient() async throws {
    let (_, configuration, tokens) = try makeNetwork()
    let realms = configuration.realms.map { realm in
      #"{"id": "\#(hexString(realm.id))", "address": "https://127.0.0.1:1/"}"#
    }
    let json = """
      {
        "realms": [\(realms.joined(separator: ","))],
        "register_threshold": 3,
        "recover_threshold": 2,
        "pin_hashing_mode": "FastInsecure"
      }
      """
    let unreachable = try JuiceboxConfiguration.parse(Array(json.utf8))
    let recovery = JuiceboxRecovery(configuration: unreachable, tokens: tokens)
    await #expect(throws: JuiceboxRecoveryError.transient) {
      try await recovery.recover(pin: Self.pin, httpClient: .urlSession(.shared))
    }
  }

  #if os(macOS)
    private struct OffMainHTTPClient: BytesHTTPClient {
      var network: FakeNetwork

      func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
        checkThread()
        return try await network.send(request, body: body)
      }

      private func checkThread() {
        #expect(!Thread.isMainThread)
      }
    }

    /// The HTTP client is called off the main actor even when recovery is
    /// started from it.
    @MainActor
    @Test func httpClientIsCalledOffTheMainActor() async throws {
      let (network, configuration, tokens) = try makeNetwork()
      let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
      let secret = try await recovery.recover(
        pin: Self.pin, httpClient: OffMainHTTPClient(network: network))
      #expect(secret == Self.userSecret)
    }
  #endif

  /// Recovery started from the main actor runs its PIN hashing (Argon2 with
  /// the real Standard2019 parameters, about a second or more) off the main
  /// actor, so the main actor keeps running. The HTTP client is called from
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
    let secret = try await recovery.recover(pin: Self.pin, httpClient: network)
    let elapsed = ContinuousClock.now - started
    ticker.cancel()
    let longestGap = await ticker.value
    #expect(secret == Self.userSecret)
    // The main actor must not stall for anything close to the hashing time.
    #expect(longestGap < elapsed / 2)
  }

  /// Cancels the caller's task when it receives a PIN request, and then
  /// answers anyway, as an HTTP client that ignores cancellation does.
  private actor CallerCancellingHTTPClient: BytesHTTPClient {
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

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      let value = try decodeCBOR(body)
      if value == .textString("Recover1") {
        return try await network.send(request, body: body)
      }
      pinRequests += 1
      if value["Recover3"] != nil { unlockRequests += 1 }
      // The test sets the caller right after starting it.
      while caller == nil { await Task.yield() }
      caller?.cancel()
      return try await network.send(request, body: body)
    }
  }

  /// When the caller cancels recovery during the OPRF phase, recovery stops
  /// before the unlock phase, even if the HTTP client answers anyway. Anywhere
  /// from one realm to all of them get a PIN request: a phase asks each realm
  /// once and recovery never reaches the unlock phase, while a request
  /// whose task sees the cancellation before calling the HTTP client is not
  /// sent.
  @Test(.timeLimit(.minutes(1)))
  func theCallersCancellationStopsRecoveryBeforeTheNextPhase() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = CallerCancellingHTTPClient(network: network)
    let task = Task { [pin = Self.pin] in
      try await recovery.recover(pin: pin, httpClient: httpClient)
    }
    await httpClient.setCaller(task)
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect((1...Self.realmCount).contains(await httpClient.pinRequests))
    #expect(await httpClient.unlockRequests == 0)
  }

  /// A cancellation the HTTP client reports while the caller has not cancelled
  /// (an invalidated session, a cancelled authentication challenge, a
  /// cancelled request task) is a failure of that realm, not the caller's
  /// cancellation: recovery fails with a recovery error, and the other realms
  /// can still answer.
  @Test func anHTTPClientCancellationIsARealmFailure() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    for mode in [
      CancellingHTTPClient.Mode.throwsCancellation, .throwsURLCancellation,
      .cancelsItsOwnTaskThenAnswers,
    ] {
      let httpClient = CancellingHTTPClient(network: network, mode: mode)
      await #expect(throws: JuiceboxRecoveryError.transient) {
        try await recovery.recover(pin: Self.pin, httpClient: httpClient)
      }
      #expect(await httpClient.unlockRequests == 0)
    }
    for mode in [CancellingHTTPClient.Mode.cancelsOneRealm, .oneRealmCancelsItsOwnTask] {
      let oneRealm = CancellingHTTPClient(network: network, mode: mode)
      let secret = try await recovery.recover(pin: Self.pin, httpClient: oneRealm)
      #expect(secret == Self.userSecret)
      // The first realm's requests did take the cancelling path. That
      // recovery drops an answer whose task was cancelled is checked by
      // `cancelsItsOwnTaskThenAnswers` above.
      #expect(await oneRealm.firstRealmCancellations > 0)
    }
  }

  /// Scenarios for `aFailedPhaseIsJudgedByItsOwnAnswers` (the cases with an
  /// expected error) and `aSingleMismatchedAnswerIsSkipped` (the two without
  /// one, which recover). A phase fails with the best of its own errors
  /// (`bestError` picks the lowest rank) when more of its realms fail than
  /// can be spared, never with an earlier phase's error. In the unlock
  /// phase, too few matching answers with no more errors than can be spared
  /// come from answers whose encrypted-secret commitment does not match, and
  /// report `assertion`. In the version and OPRF phases, when no more realms
  /// fail than can be spared but too few answers agree to reach the
  /// threshold, the phase reports `notRegistered` or `assertion`
  /// respectively, even if the other realm's failure is transient or a rate
  /// limit.
  enum PhaseScenario: CaseIterable, Sendable {
    /// The first realm reports no guesses left in the version phase (an
    /// error that ranks ahead), and the second realm's OPRF request fails
    /// with a server error.
    case oprfAfterAVersionError
    /// The third realm's OPRF request is rate limited (an error that ranks
    /// ahead), and the second and third realms' unlock requests fail with a
    /// server error. The unlock phase also asks a realm that failed in the
    /// OPRF phase (zunda-pixel/juicebox-swift#4), so three answers are made
    /// up.
    case unlockAfterAnOprfRateLimit
    /// In the unlock phase, the first and third realms fail with a server
    /// error and the second reports a bad unlock key tag with 3 guesses left:
    /// the best of the phase's own errors, which is neither the first nor the
    /// last one.
    case unlockWithThreeErrors
    /// The first realm reports no guesses left in the version phase, so the
    /// unlock phase asks two realms and can spare none; the second realm
    /// reports a bad unlock key tag with 3 guesses left: one error is more
    /// than the phase's realms can spare (counting all configured realms
    /// would spare it).
    case unlockAfterAVersionError
    /// The first realm reports no guesses left in the version phase, and the
    /// other two realms answer the unlock request with a wrong commitment,
    /// which adds no error.
    case unlockWithoutErrors
    /// In the unlock phase, the first realm reports a bad unlock key tag, the
    /// second answers with a wrong commitment, and the third answers
    /// correctly: one error can be spared, so too few answers match because
    /// of the mismatch.
    case unlockWithAnErrorAndAMismatch
    /// The same with a server error instead of the bad tag: one error can be
    /// spared, so the result is `assertion`, not `transient` (the reference
    /// client reports `Assertion` only after its retries of the 503 fail;
    /// this package does not retry, zunda-pixel/juicebox-swift#7).
    case unlockWithAServerErrorAndAMismatch
    /// In the version phase, the first realm fails with a server error and
    /// the second reports another registration version: one error can be
    /// spared, but no version has enough realms.
    case versionWithAServerErrorAndAMismatch
    /// In the OPRF phase, the first realm fails with a server error and the
    /// second answers with a wrong unlock key commitment: one error can be
    /// spared, but no OPRF verifying key and commitment has enough realms.
    case oprfWithAServerErrorAndAMismatch
    /// The same with a rate limit instead of the server error: if the made-up
    /// OPRF answer failed to verify, the phase would have two errors and
    /// report the better one, `rateLimitExceeded`, so `assertion` shows that
    /// the answer verified and was set apart by its commitment.
    case oprfWithARateLimitAndAMismatch
    /// In the version phase, the first realm reports no guesses left and the
    /// second fails with a server error: the phase falls short, and the best
    /// of its errors is `invalidPin(guessesRemaining: 0)`, although the
    /// realms that did not fail may still have guesses.
    case versionWithNoGuessesAndAServerError
    /// In the unlock phase, the first realm reports a bad unlock key tag with
    /// 3 guesses left and the second with 2: between two `invalidPin`s, the
    /// fewer guesses left ranks ahead.
    case unlockWithTwoBadUnlockKeyTags
    /// In the unlock phase, only the second realm answers with a wrong
    /// commitment: its answer is skipped, and the other two recover the
    /// secret (no error is expected).
    case unlockWithOnlyAMismatch
    /// In the OPRF phase, only the second realm answers with a wrong unlock
    /// key commitment: the other two agree on the OPRF key, and recovery
    /// succeeds (no error is expected).
    case oprfWithOnlyAMismatch

    /// The answers `ScenarioHTTPClient` makes up or rewrites when recovery
    /// gets as far as the scenario.
    var injectedAnswers: Int {
      switch self {
      case .oprfAfterAVersionError, .unlockAfterAVersionError, .unlockWithAnErrorAndAMismatch,
        .unlockWithAServerErrorAndAMismatch, .versionWithAServerErrorAndAMismatch,
        .oprfWithAServerErrorAndAMismatch, .oprfWithARateLimitAndAMismatch,
        .versionWithNoGuessesAndAServerError, .unlockWithTwoBadUnlockKeyTags:
        2
      case .unlockAfterAnOprfRateLimit, .unlockWithThreeErrors, .unlockWithoutErrors: 3
      case .unlockWithOnlyAMismatch, .oprfWithOnlyAMismatch: 1
      }
    }

    /// The error recovery reports, or nil when it recovers the secret.
    var expectedError: JuiceboxRecoveryError? {
      switch self {
      case .oprfAfterAVersionError, .unlockAfterAnOprfRateLimit: .transient
      case .unlockWithThreeErrors, .unlockAfterAVersionError: .invalidPin(guessesRemaining: 3)
      case .unlockWithoutErrors, .unlockWithAnErrorAndAMismatch,
        .unlockWithAServerErrorAndAMismatch, .oprfWithAServerErrorAndAMismatch,
        .oprfWithARateLimitAndAMismatch:
        .assertion
      case .versionWithAServerErrorAndAMismatch: .notRegistered
      case .versionWithNoGuessesAndAServerError: .invalidPin(guessesRemaining: 0)
      case .unlockWithTwoBadUnlockKeyTags: .invalidPin(guessesRemaining: 2)
      case .unlockWithOnlyAMismatch, .oprfWithOnlyAMismatch: nil
      }
    }
  }

  private actor ScenarioHTTPClient: BytesHTTPClient {
    let network: FakeNetwork
    let scenario: PhaseScenario
    /// The answers made up or rewritten instead of passed on as they are, so
    /// the test can tell that recovery got as far as the scenario.
    private(set) var injectedAnswers = 0

    init(network: FakeNetwork, scenario: PhaseScenario) {
      self.network = network
      self.scenario = scenario
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      if let answer = try await injectedAnswer(for: request, body: body) {
        injectedAnswers += 1
        return answer
      }
      return try await network.send(request, body: body)
    }

    private func injectedAnswer(for request: HTTPRequest, body: [UInt8]) async throws
      -> (HTTPResponse, [UInt8])?
    {
      let value = try decodeCBOR(body)
      let isRecover1 = value == .textString("Recover1")
      let isRecover2 = value["Recover2"] != nil
      let isRecover3 = value["Recover3"] != nil
      let isRealm1 = request.urlString.hasPrefix("https://realm1.")
      let isRealm2 = request.urlString.hasPrefix("https://realm2.")
      let isRealm3 = request.urlString.hasPrefix("https://realm3.")
      switch scenario {
      case .oprfAfterAVersionError:
        if isRealm1, isRecover1 { return try Self.noGuesses() }
        if isRealm2, isRecover2 { return Self.serverError }
      case .unlockAfterAnOprfRateLimit:
        if isRealm3, isRecover2 { return (HTTPResponse(status: .tooManyRequests), []) }
        if isRealm2 || isRealm3, isRecover3 { return Self.serverError }
      case .unlockWithThreeErrors:
        if isRealm1 || isRealm3, isRecover3 { return Self.serverError }
        if isRealm2, isRecover3 { return try Self.badUnlockKeyTag() }
      case .unlockAfterAVersionError:
        if isRealm1, isRecover1 { return try Self.noGuesses() }
        if isRealm2, isRecover3 { return try Self.badUnlockKeyTag() }
      case .unlockWithoutErrors:
        if isRealm1, isRecover1 { return try Self.noGuesses() }
        if isRealm2 || isRealm3, isRecover3 { return try mismatchedCommitment(for: request) }
      case .unlockWithAnErrorAndAMismatch:
        if isRealm1, isRecover3 { return try Self.badUnlockKeyTag() }
        if isRealm2, isRecover3 { return try mismatchedCommitment(for: request) }
      case .unlockWithAServerErrorAndAMismatch:
        if isRealm1, isRecover3 { return Self.serverError }
        if isRealm2, isRecover3 { return try mismatchedCommitment(for: request) }
      case .versionWithAServerErrorAndAMismatch:
        if isRealm1, isRecover1 { return Self.serverError }
        if isRealm2, isRecover1 { return try Self.otherVersion() }
      case .oprfWithAServerErrorAndAMismatch:
        if isRealm1, isRecover2 { return Self.serverError }
        if isRealm2, isRecover2 {
          return try await mismatchedUnlockKeyCommitment(for: request, body: body)
        }
      case .oprfWithARateLimitAndAMismatch:
        if isRealm1, isRecover2 { return (HTTPResponse(status: .tooManyRequests), []) }
        if isRealm2, isRecover2 {
          return try await mismatchedUnlockKeyCommitment(for: request, body: body)
        }
      case .unlockWithOnlyAMismatch:
        if isRealm2, isRecover3 { return try mismatchedCommitment(for: request) }
      case .oprfWithOnlyAMismatch:
        if isRealm2, isRecover2 {
          return try await mismatchedUnlockKeyCommitment(for: request, body: body)
        }
      case .versionWithNoGuessesAndAServerError:
        if isRealm1, isRecover1 { return try Self.noGuesses() }
        if isRealm2, isRecover1 { return Self.serverError }
      case .unlockWithTwoBadUnlockKeyTags:
        if isRealm1, isRecover3 { return try Self.badUnlockKeyTag() }
        if isRealm2, isRecover3 { return try Self.badUnlockKeyTag(guessesRemaining: 2) }
      }
      return nil
    }

    static let serverError: (HTTPResponse, [UInt8]) = (
      HTTPResponse(status: .serviceUnavailable), []
    )

    static func noGuesses() throws -> (HTTPResponse, [UInt8]) {
      try answer(
        CBOR.map(["Recover1": .textString("NoGuesses")]).encode(),
        decodingAs: .recover1(.noGuesses))
    }

    static func otherVersion() throws -> (HTTPResponse, [UInt8]) {
      let version = [UInt8](repeating: 6, count: 16)
      return try answer(
        RecoveryFlowTests.encodeRecover1Ok(version: version),
        decodingAs: .recover1(.ok(version: version)))
    }

    static func badUnlockKeyTag(guessesRemaining: UInt16 = 3) throws -> (HTTPResponse, [UInt8]) {
      try answer(
        CBOR.map([
          "Recover3": .map([
            "BadUnlockKeyTag": .map(["guesses_remaining": .unsignedInt(UInt64(guessesRemaining))])
          ])
        ]).encode(),
        decodingAs: .recover3(.badUnlockKeyTag(guessesRemaining: guessesRemaining)))
    }

    /// The realm's own unlock answer, but with a wrong encrypted-secret
    /// commitment.
    private func mismatchedCommitment(for request: HTTPRequest) throws
      -> (HTTPResponse, [UInt8])
    {
      let realm = try #require(network.realms[request.urlString])
      let wrongCommitment = [UInt8](repeating: 0, count: 16)
      return try Self.answer(
        CBOR.map([
          "Recover3": .map([
            "Ok": .map([
              "encryption_key_scalar_share": .byteString(realm.scalarShare.bytes),
              "encrypted_secret": .byteString(realm.encryptedSecret),
              "encrypted_secret_commitment": .byteString(wrongCommitment),
            ])
          ])
        ]).encode(),
        decodingAs: .recover3(
          .ok(
            scalarShare: realm.scalarShare.bytes, encryptedSecret: realm.encryptedSecret,
            commitment: wrongCommitment)))
    }

    /// The realm's own OPRF answer, but with a wrong unlock key commitment.
    private func mismatchedUnlockKeyCommitment(for request: HTTPRequest, body: [UInt8]) async throws
      -> (HTTPResponse, [UInt8])
    {
      let (realmResponse, realmBody) = try await network.send(request, body: body)
      guard
        case .recover2(
          .ok(let signed, let blindedResult, let proof, _, let numGuesses, let guessCount)) =
          try SecretsResponse.decode(realmBody)
      else {
        Issue.record("the realm's own OPRF answer must be Ok")
        return (realmResponse, realmBody)
      }
      let wrongCommitment = [UInt8](repeating: 0, count: 32)
      return try Self.answer(
        CBOR.map([
          "Recover2": .map([
            "Ok": .map([
              "oprf_signed_public_key": .map([
                "public_key": .byteString(signed.publicKey),
                "verifying_key": .byteString(signed.verifyingKey),
                "signature": .byteString(signed.signature),
              ]),
              "oprf_blinded_result": .byteString(blindedResult),
              "oprf_proof": .map([
                "c": .byteString(proof.c),
                "beta_z": .byteString(proof.betaZ),
              ]),
              "unlock_key_commitment": .byteString(wrongCommitment),
              "num_guesses": .unsignedInt(UInt64(numGuesses)),
              "guess_count": .unsignedInt(UInt64(guessCount)),
            ])
          ])
        ]).encode(),
        decodingAs: .recover2(
          .ok(
            signedPublicKey: signed, blindedResult: blindedResult, proof: proof,
            unlockKeyCommitment: wrongCommitment, numGuesses: numGuesses, guessCount: guessCount)))
    }

    /// Recovery counts a 2xx answer it cannot decode as a failed request
    /// (`assertion`), and an error the HTTP client throws as `transient`;
    /// either could let a case pass for another reason, so each hand-built
    /// answer must decode as intended, or the test records an issue here
    /// (throwing would not: recovery catches it).
    private static func answer(_ body: [UInt8], decodingAs expected: SecretsResponse) throws
      -> (HTTPResponse, [UInt8])
    {
      let decoded = try? SecretsResponse.decode(body)
      try #require(decoded == expected)
      return (HTTPResponse(status: .ok), body)
    }
  }

  /// A phase that fails is judged by its own realms' answers, never by
  /// an earlier phase's error, even one that ranks ahead. See `PhaseScenario`
  /// for the unlock phase's rule and each case.
  @Test(arguments: PhaseScenario.allCases.filter { $0.expectedError != nil })
  func aFailedPhaseIsJudgedByItsOwnAnswers(scenario: PhaseScenario) async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = ScenarioHTTPClient(network: network, scenario: scenario)
    let expected = try #require(scenario.expectedError)
    await #expect(throws: expected) {
      try await recovery.recover(pin: Self.pin, httpClient: httpClient)
    }
    #expect(await httpClient.injectedAnswers == scenario.injectedAnswers)
  }

  /// With one answer that does not agree, recovery still succeeds when the
  /// other answers reach the threshold. That the unlock phase counts no error
  /// for a mismatch is checked by `.unlockWithAnErrorAndAMismatch`. In the
  /// unlock phase, the reference client continues past a mismatch "as there
  /// may still be enough material from other realms"; in the OPRF phase it
  /// groups the answers and keeps the group that reaches the threshold.
  @Test(arguments: PhaseScenario.allCases.filter { $0.expectedError == nil })
  func aSingleMismatchedAnswerIsSkipped(scenario: PhaseScenario) async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = ScenarioHTTPClient(network: network, scenario: scenario)
    let secret = try await recovery.recover(pin: Self.pin, httpClient: httpClient)
    #expect(secret == Self.userSecret)
    #expect(await httpClient.injectedAnswers == scenario.injectedAnswers)
  }

  /// Answers each phase's requests in the reverse of the realms' order: the
  /// last realm answers first and the first realm answers last. Each request
  /// waits for its turn (for up to five seconds) and records the realm it
  /// answered for. Recovery must still pair every answer with its realm.
  private actor ReversingHTTPClient: BytesHTTPClient {
    let network: FakeNetwork
    private(set) var answered: [Int] = []

    init(network: FakeNetwork) {
      self.network = network
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      let realmCount = RecoveryFlowTests.realmCount
      let realmNumber = request.urlString.first(where: \.isNumber).flatMap { Int(String($0)) } ?? 0
      let deadline = ContinuousClock.now + .seconds(5)
      while answered.count % realmCount != realmCount - realmNumber, ContinuousClock.now < deadline
      {
        try await Task.sleep(for: .milliseconds(1))
      }
      answered.append(realmNumber)
      return try await network.send(request, body: body)
    }
  }

  @Test(.timeLimit(.minutes(1)))
  func answersInReverseOrderArePairedWithTheirRealms() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = ReversingHTTPClient(network: network)
    let secret = try await recovery.recover(pin: Self.pin, httpClient: httpClient)
    #expect(secret == Self.userSecret)
    // Three phases, each answered from the last realm to the first.
    #expect(await httpClient.answered == [3, 2, 1, 3, 2, 1, 3, 2, 1])
  }

  /// Holds each request for up to five seconds until the other realms of its
  /// phase have been asked too, and records how many were in flight at once.
  /// Every phase here asks all realms, so the requests arrive in batches of
  /// `realmCount`. When the realms are contacted one at a time, all but the
  /// last request of each batch wait out the five seconds alone, so the test
  /// fails (in about 30 seconds) instead of hanging.
  private actor GatheringHTTPClient: BytesHTTPClient {
    let network: FakeNetwork
    private var arrivals = 0
    private var inFlight = 0
    private(set) var mostInFlight = 0

    init(network: FakeNetwork) {
      self.network = network
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
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
      return try await network.send(request, body: body)
    }
  }

  @Test(.timeLimit(.minutes(1)))
  func realmsAreContactedTogether() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = GatheringHTTPClient(network: network)
    let secret = try await recovery.recover(pin: Self.pin, httpClient: httpClient)
    #expect(secret == Self.userSecret)
    #expect(await httpClient.mostInFlight == Self.realmCount)
  }

  /// Answers the registration version at once and holds every PIN request
  /// until the request is cancelled.
  private actor HoldingHTTPClient: BytesHTTPClient {
    let network: FakeNetwork
    private(set) var pinRequests = 0
    private(set) var unlockRequests = 0

    init(network: FakeNetwork) {
      self.network = network
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      let value = try decodeCBOR(body)
      if value == .textString("Recover1") {
        return try await network.send(request, body: body)
      }
      pinRequests += 1
      if value["Recover3"] != nil { unlockRequests += 1 }
      try await Task.sleep(for: .seconds(30))
      return try await network.send(request, body: body)
    }
  }

  /// Cancelling the caller's task while the PIN requests are in flight
  /// cancels those requests and ends recovery at once, before the unlock
  /// phase.
  @Test(.timeLimit(.minutes(1)))
  func cancellingTheCallerStopsTheRequestsInFlight() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = HoldingHTTPClient(network: network)
    let task = Task { [pin = Self.pin] in
      try await recovery.recover(pin: pin, httpClient: httpClient)
    }
    // Recovery may end before any PIN request (for example, if the first
    // phase fails); give up instead of waiting forever.
    let deadline = ContinuousClock.now + .seconds(10)
    while await httpClient.pinRequests == 0 {
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
    #expect(await httpClient.pinRequests <= Self.realmCount)
    #expect(await httpClient.unlockRequests == 0)
  }

  /// Records the kind of each request and the URL it went to, and passes
  /// the request on. The realm at `otherVersionPrefix`, if any, reports a
  /// different registration version in phase 1.
  private actor RecordingHTTPClient: BytesHTTPClient {
    let network: FakeNetwork
    let otherVersionPrefix: String?
    private(set) var requests: [(url: String, kind: String)] = []

    init(network: FakeNetwork, otherVersionPrefix: String? = nil) {
      self.network = network
      self.otherVersionPrefix = otherVersionPrefix
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      let value = try decodeCBOR(body)
      let kind =
        value == .textString("Recover1")
        ? "Recover1"
        : ["Recover2", "Recover3"].first { value[$0] != nil } ?? "other"
      requests.append((request.urlString, kind))
      if kind == "Recover1", let otherVersionPrefix, request.urlString.hasPrefix(otherVersionPrefix)
      {
        return (
          HTTPResponse(status: .ok),
          RecoveryFlowTests.encodeRecover1Ok(version: [UInt8](repeating: 6, count: 16))
        )
      }
      return try await network.send(request, body: body)
    }

    func kinds(sentTo prefix: String) -> [String] {
      requests.filter { $0.url.hasPrefix(prefix) }.map(\.kind)
    }
  }

  /// With one realm down, recovery succeeds with the others, and the OPRF
  /// and unlock phases ask only the realms that reported the chosen version.
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
    let httpClient = RecordingHTTPClient(network: network)
    let secret = try await recovery.recover(pin: Self.pin, httpClient: httpClient)
    #expect(secret == Self.userSecret)
    #expect(await httpClient.kinds(sentTo: "https://down.test/") == ["Recover1"])
    for realm in ["https://realm1.test/", "https://realm3.test/"] {
      #expect(await httpClient.kinds(sentTo: realm) == ["Recover1", "Recover2", "Recover3"])
    }
  }

  /// A realm that reports another registration version is not asked in the
  /// OPRF and unlock phases; the realms with the chosen version recover.
  @Test func aRealmWithAnotherVersionIsNotAskedLater() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let httpClient = RecordingHTTPClient(
      network: network, otherVersionPrefix: "https://realm2.test/")
    let secret = try await recovery.recover(pin: Self.pin, httpClient: httpClient)
    #expect(secret == Self.userSecret)
    #expect(await httpClient.kinds(sentTo: "https://realm2.test/") == ["Recover1"])
    for realm in ["https://realm1.test/", "https://realm3.test/"] {
      #expect(await httpClient.kinds(sentTo: realm) == ["Recover1", "Recover2", "Recover3"])
    }
  }

  /// A phase that falls short reports the error that ranks first, in the
  /// order the documentation of `JuiceboxRecoveryError` lists: `invalidPin`
  /// (between two, the fewer guesses left), `notRegistered`, `invalidAuth`,
  /// `upgradeRequired`, `rateLimitExceeded`, `assertion`, `transient`.
  @Test func errorsRankInTheDocumentedOrder() {
    let documented: [JuiceboxRecoveryError] = [
      .invalidPin(guessesRemaining: 0), .invalidPin(guessesRemaining: 3), .notRegistered,
      .invalidAuth, .upgradeRequired, .rateLimitExceeded, .assertion, .transient,
    ]
    #expect(documented.reversed().sorted { $0.sortKey < $1.sortKey } == documented)
  }

  @Test func wrongPinReportsGuesses() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    do {
      _ = try await recovery.recover(pin: Array("0000".utf8), httpClient: network)
      Issue.record("wrong PIN must fail")
    } catch let error as JuiceboxRecoveryError {
      #expect(error == .invalidPin(guessesRemaining: 4))
    }
  }

  /// A wrong PIN reports the fewest guesses left among the realms whose OPRF
  /// answers agreed, not the first realm's.
  @Test func wrongPinReportsTheFewestGuesses() async throws {
    let (network, configuration, tokens) = try makeNetwork()
    var realms = network.realms.values.sorted { $0.url < $1.url }
    realms[1].guessCount = 3
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    await #expect(throws: JuiceboxRecoveryError.invalidPin(guessesRemaining: 2)) {
      try await recovery.recover(pin: Array("0000".utf8), httpClient: FakeNetwork(realms: realms))
    }
  }

  @Test func missingTokenIsInvalidAuth() async throws {
    let (network, configuration, _) = try makeNetwork()
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: [:])
    do {
      _ = try await recovery.recover(pin: Self.pin, httpClient: network)
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
      _ = try await recovery.recover(pin: Self.pin, httpClient: network)
      Issue.record("too few realms must fail")
    } catch let error as JuiceboxRecoveryError {
      #expect(error == .transient)
    }
  }
}
