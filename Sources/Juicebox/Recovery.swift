import Clibsodium
import Crypto
import Foundation
public import HTTPClient
import HTTPTypes

let juiceboxSodiumIsReady = sodium_init() >= 0

/// Why recovery failed.
///
/// Each phase asks some realms (the first phase all of them, the later ones
/// those with the chosen registration version) and needs answers from at
/// least the recover threshold of them; the rest can be spared. When more of
/// a phase's realms fail than it can spare (the phase falls short),
/// `recover` reports the best of that phase's errors, in this order:
/// `invalidPin` (between two, the fewer guesses left), `notRegistered`,
/// `invalidAuth`, `upgradeRequired`, `rateLimitExceeded`, `assertion`,
/// `transient`. Other failures report the case that fits them, such as
/// `invalidPin` for a wrong PIN, `notRegistered` or `assertion` for answers
/// that do not agree, or `assertion` for a secret that does not decrypt.
///
/// So the reported case need not be the only reason recovery failed: another
/// realm may have failed transiently or been rate limited, and a retry with
/// the same inputs may then succeed, whichever case was reported. Any retry,
/// even with the right PIN, may use up a guess on a realm the OPRF phase asks
/// whose unlock does not then succeed (see
/// ``JuiceboxRecovery/recover(pin:httpClient:)``), and after a wrong PIN, the
/// usual source of `invalidPin`, a retry with the same PIN fails again (see
/// ``JuiceboxRecoveryError/invalidPin(guessesRemaining:)``). `recover`
/// itself does not retry a realm (zunda-pixel/juicebox-swift#7).
///
/// The descriptions are based on the reference client's (juicebox-sdk)
/// `RecoverError`, with the differences noted under each case. Unlike the
/// reference client, which stops a phase as soon as it falls short,
/// `recover` waits for every answer and picks from all of the phase's
/// errors, so the two can report different cases for the same answers.
public enum JuiceboxRecoveryError: Error, Equatable, Sendable {
  /// The secret could not be unlocked.
  ///
  /// `guessesRemaining` comes from the answers that decided the failure: for
  /// a wrong PIN, the fewest among the realms whose OPRF answers agreed; when
  /// a phase falls short, the fewest among that phase's `invalidPin`s. A
  /// value above zero does not mean that every realm has guesses left.
  ///
  /// Usually the OPRF phase found the PIN wrong, and another PIN can be
  /// tried while guesses remain; an attempt with a wrong PIN may use up a
  /// guess on the realms its OPRF phase asks (see
  /// ``JuiceboxRecovery/recover(pin:httpClient:)``). Less often, the PIN may
  /// have been right: this case also comes from a realm's bad unlock key tag
  /// after the OPRF phase has confirmed the PIN (as in the reference client,
  /// juicebox-sdk), or from a realm with no guesses left. The same PIN may
  /// then succeed on a retry if another realm's failure is what left the
  /// phase short (see ``JuiceboxRecoveryError``). Unlike the reference
  /// client's description, zero alone does not mean the secret is locked:
  /// other realms may still have guesses.
  case invalidPin(guessesRemaining: Int)
  /// The secret is not registered, or not fully registered, with the realms,
  /// or enough realms answered but disagree on the registration version, so
  /// that no version has answers from enough of them (see
  /// ``JuiceboxRecoveryError`` for when a retry may help).
  case notRegistered
  /// A realm rejected the authentication token, or no token was given for
  /// a realm. A retry may still succeed if another realm's failure is what
  /// left the phase short (see ``JuiceboxRecoveryError``).
  case invalidAuth
  /// A realm requires a newer client. A retry may still succeed if another
  /// realm's failure is what left the phase short (see
  /// ``JuiceboxRecoveryError``).
  case upgradeRequired
  /// The tenant made too many requests; try again later.
  case rateLimitExceeded
  /// A software error or an inconsistency on the realms' side.
  ///
  /// For example, an answer that does not verify, or too few answers that
  /// agree (on the OPRF verifying key and unlock key commitment, or on an
  /// encrypted secret whose commitment matches). Retrying with the same
  /// inputs is not expected to help. Unlike the reference client's
  /// description, which rules out a retry with the same parameters, a retry
  /// may help in the cases described under ``JuiceboxRecoveryError``.
  case assertion
  /// A failure in sending a request or receiving its answer.
  ///
  /// This covers a non-2xx status other than 401, 426 and 429 whose body is
  /// not a realm answer, a hardware realm's unavailable error or its
  /// missing-session or session error (zunda-pixel/juicebox-swift#8; the
  /// reference client, juicebox-sdk, reports these two as an assertion on a
  /// new session, which `recover` always opens), any error the HTTP client
  /// throws, and the answer to a request whose own task was cancelled, as
  /// long as the caller has not cancelled (then `recover` throws
  /// `CancellationError`). Retrying with the same inputs may succeed.
  case transient

  /// The reference client's error ordering, used to pick the most specific
  /// failure when more of a phase's realms fail than it can spare.
  var rank: Int {
    switch self {
    case .invalidPin: return 0
    case .notRegistered: return 1
    case .invalidAuth: return 2
    case .upgradeRequired: return 3
    case .rateLimitExceeded: return 4
    case .assertion: return 5
    case .transient: return 6
    }
  }

  var sortKey: (Int, Int) {
    switch self {
    case .invalidPin(let guesses): return (rank, guesses)
    default: return (rank, 0)
    }
  }
}

/// Runs the three-phase Juicebox recovery: learn the registration version,
/// evaluate the PIN's OPRF across realms, then unlock and decrypt the user
/// secret. The SDK owns the Juicebox protocol, not the HTTP stack: every
/// network call goes through the `HTTPClientProtocol` value passed to
/// ``recover(pin:httpClient:)``.
public struct JuiceboxRecovery: Sendable {
  var configuration: JuiceboxConfiguration
  /// Bearer tokens keyed by lowercased realm id hex.
  var tokens: [String: String]
  var userInfo: [UInt8]

  static let juiceboxVersion = "0.3.7"

  public init(
    configuration: JuiceboxConfiguration, tokens: [String: String],
    userInfo: [UInt8] = []
  ) {
    self.configuration = configuration
    var normalized: [String: String] = [:]
    for (key, value) in tokens {
      normalized[hexString(hexBytes(key) ?? Array(key.utf8))] = value
    }
    self.tokens = normalized
    self.userInfo = userInfo
  }

  /// Recovers the user secret, sending the realm requests with `httpClient`,
  /// with PIN hashing off the caller's actor.
  ///
  /// `httpClient` can be a `URLSession`, such as `URLSession.shared`,
  /// AsyncHTTPClient's `HTTPClient` when http-client's `AsyncHTTPClient` trait
  /// is enabled, or any other `HTTPClientProtocol`. Each request is a POST of
  /// a CBOR message to a realm's `req` endpoint. Recovery reads a realm's
  /// error from the body of a non-2xx response when there is one, and from
  /// the status otherwise, so `execute(for:from:)` must return the response
  /// whatever its status, as `HTTPClientProtocol` requires.
  ///
  /// Recovery calls `execute(for:from:)` concurrently: each phase asks all of
  /// its realms at once. Within one recovery, a realm has at most one request
  /// in flight; for a hardware realm, the OPRF and unlock phases (Recover2 and
  /// Recover3) send two requests in turn (the Noise handshake, then the
  /// request).
  ///
  /// A client that follows redirects, as `URLSession.shared` and
  /// AsyncHTTPClient's `HTTPClient.shared` do, can carry a realm's token to
  /// wherever a redirect points: on a 307 or 308 redirect to another host,
  /// `URLSession` on Apple platforms and AsyncHTTPClient send the body again
  /// (a hardware realm's token is in the body), and `URLSession` on Linux
  /// sends the `Authorization` header again (a software realm's token). Pass
  /// a client that refuses redirects to keep the tokens on the realm's host;
  /// a refused redirect is a non-2xx answer, so that realm fails with
  /// `transient`.
  ///
  /// Throws `CancellationError` only when the caller cancelled recovery.
  /// Otherwise a failure is a `JuiceboxRecoveryError`. An error `httpClient`
  /// throws, including `CancellationError` or `URLError(.cancelled)`, is a
  /// failure of that realm (`transient`) unless the caller cancelled
  /// recovery; the other realms can still answer. Each phase waits for all
  /// of its requests, so recovery stops promptly when the caller cancels only
  /// if `execute(for:from:)` responds to its task's cancellation (as
  /// `URLSession` and AsyncHTTPClient do).
  ///
  /// A realm counts a guess when the OPRF phase (Recover2) asks it, and
  /// clears the count only when the unlock phase (Recover3) succeeds there,
  /// so cancelling once the OPRF phase has started may leave a guess used on
  /// each realm it asked. The phase asks all of its realms at once, so that
  /// can be every realm that reported the chosen version.
  ///
  /// A cancellation that arrives while the PIN is being hashed (Standard2019
  /// takes seconds) takes effect once the hashing ends, before the OPRF
  /// phase.
  @concurrent
  public func recover(
    pin: [UInt8], httpClient: some HTTPClientProtocol
  ) async throws -> [UInt8] {
    try Task.checkCancellation()
    guard juiceboxSodiumIsReady else { throw JuiceboxRecoveryError.assertion }
    let threshold = configuration.recoverThreshold

    // Each phase keeps its own errors, as the reference client joins each
    // phase anew: a phase never reports an earlier phase's error. As in the
    // reference client (`join_at_least_threshold`), more errors than the
    // phase's realms can spare fail the phase with the best of them (of all
    // of them, since every answer is awaited; see `requestEach`). Each phase
    // counts its errors rather than its answers, so an answer skipped without
    // an error never makes the phase report an error it could spare: too few
    // usable answers end in the phase's check that enough of them agree.

    // Phase 1: every realm reports the registration version.
    var versions: [(version: [UInt8], realm: JuiceboxRealm)] = []
    var versionErrors: [JuiceboxRecoveryError] = []
    let phase1 = try await requestEach(
      configuration.realms, httpClient: httpClient, request: .recover1)
    for (realm, outcome) in zip(configuration.realms, phase1) {
      do {
        guard case .recover1(let response) = try outcome.get() else {
          versionErrors.append(.assertion)
          continue
        }
        switch response {
        case .ok(let version): versions.append((version, realm))
        case .notRegistered: versionErrors.append(.notRegistered)
        case .noGuesses: versionErrors.append(.invalidPin(guessesRemaining: 0))
        }
      } catch {
        try Task.checkCancellation()
        versionErrors.append(recoveryError(from: error))
      }
    }
    guard versionErrors.count <= configuration.realms.count - threshold else {
      throw bestError(versionErrors)
    }

    let byVersion = Dictionary(grouping: versions, by: { $0.version })
    let viableVersions = byVersion.filter { $0.value.count >= threshold }
    guard viableVersions.count == 1, let chosen = viableVersions.first else {
      throw JuiceboxRecoveryError.notRegistered
    }
    let version = chosen.key
    let realms = chosen.value.map { $0.realm }

    // Phase 2: evaluate the OPRF across realms and recover the blinded
    // result.
    let (accessKey, encryptionKeySeed) = try juiceboxPinHash(
      pin: pin, registrationVersion: version, userInfo: userInfo,
      mode: configuration.pinHashingMode)
    let (blindingFactor, blindedInput) = OPRF.start(input: accessKey)

    var oprfErrors: [JuiceboxRecoveryError] = []
    var pointShares:
      [(
        share: SecretShare<RistrettoPoint>, commitment: [UInt8],
        verifyingKey: [UInt8], guessesRemaining: Int
      )] = []
    let phase2 = try await requestEach(
      realms, httpClient: httpClient,
      request: .recover2(version: version, blindedInput: blindedInput.compressed))
    for (realm, outcome) in zip(realms, phase2) {
      do {
        guard case .recover2(let recover2) = try outcome.get() else {
          oprfErrors.append(.assertion)
          continue
        }
        switch recover2 {
        case .ok(
          let signedPublicKey, let blindedResult, let proofFields,
          let unlockKeyCommitment, let numGuesses, let guessCount
        ):
          guard verifySignedPublicKey(signedPublicKey, realmId: realm.id),
            let blindedOutput = try? OPRF.BlindedOutput(compressed: blindedResult),
            let proof = try? OPRF.Proof(bytes: proofFields.c + proofFields.betaZ),
            OPRF.verifyProof(
              blindedInput: blindedInput, blindedOutput: blindedOutput,
              publicKey: signedPublicKey.publicKey, proof: proof),
            let index = configuration.shareIndex(for: realm.id),
            numGuesses >= guessCount
          else {
            oprfErrors.append(.assertion)
            continue
          }
          pointShares.append(
            (
              SecretShare(index: index, secret: blindedOutput.point),
              unlockKeyCommitment, signedPublicKey.verifyingKey,
              Int(numGuesses - guessCount)
            ))
        case .versionMismatch: oprfErrors.append(.assertion)
        case .notRegistered: oprfErrors.append(.notRegistered)
        case .noGuesses: oprfErrors.append(.invalidPin(guessesRemaining: 0))
        }
      } catch {
        try Task.checkCancellation()
        oprfErrors.append(recoveryError(from: error))
      }
    }
    guard oprfErrors.count <= realms.count - threshold else { throw bestError(oprfErrors) }

    let byKey = Dictionary(
      grouping: pointShares,
      by: {
        PointShareKey(commitment: $0.commitment, verifyingKey: $0.verifyingKey)
      })
    let viableKeys = byKey.filter { $0.value.count >= threshold }
    guard viableKeys.count == 1, let pointGroup = viableKeys.first?.value else {
      throw JuiceboxRecoveryError.assertion
    }

    let blindedResult: RistrettoPoint
    do {
      blindedResult = try recoverSecret(pointGroup.map { $0.share })
    } catch {
      throw JuiceboxRecoveryError.assertion
    }
    let oprfOutput = OPRF.finalize(
      input: accessKey, blindingFactor: blindingFactor,
      blindedOutput: OPRF.BlindedOutput(point: blindedResult))
    let (unlockKey, commitment) = JuiceboxKeys.unlockKeyAndCommitment(oprfOutput: oprfOutput)
    guard constantTimeEquals(commitment, pointGroup[0].commitment) else {
      throw JuiceboxRecoveryError.invalidPin(
        guessesRemaining: pointGroup.reduce(pointGroup[0].guessesRemaining) {
          min($0, $1.guessesRemaining)
        })
    }

    // Phase 3: exchange the unlock key tag for each realm's scalar share,
    // then decrypt the user secret.
    var unlockErrors: [JuiceboxRecoveryError] = []
    var scalarShares: [(share: SecretShare<RistrettoScalar>, encryptedSecret: [UInt8])] = []
    let phase3 = try await requestEach(realms, httpClient: httpClient) { realm in
      .recover3(
        version: version,
        unlockKeyTag: JuiceboxKeys.unlockKeyTag(unlockKey: unlockKey, realmId: realm.id))
    }
    for (realm, outcome) in zip(realms, phase3) {
      do {
        guard case .recover3(let recover3) = try outcome.get() else {
          unlockErrors.append(.assertion)
          continue
        }
        switch recover3 {
        case .ok(let scalarShare, let encryptedSecret, let secretCommitment):
          guard let scalar = canonicalScalar(scalarShare),
            let index = configuration.shareIndex(for: realm.id)
          else {
            unlockErrors.append(.assertion)
            continue
          }
          let ours = JuiceboxKeys.encryptedUserSecretCommitment(
            unlockKey: unlockKey, realmId: realm.id, scalarShare: scalarShare,
            encryptedSecret: encryptedSecret)
          guard constantTimeEquals(ours, secretCommitment) else { continue }
          scalarShares.append(
            (
              SecretShare(index: index, secret: scalar), encryptedSecret
            ))
        case .versionMismatch: unlockErrors.append(.assertion)
        case .notRegistered: unlockErrors.append(.notRegistered)
        case .badUnlockKeyTag(let guesses):
          unlockErrors.append(.invalidPin(guessesRemaining: Int(guesses)))
        case .noGuesses: unlockErrors.append(.invalidPin(guessesRemaining: 0))
        }
      } catch {
        try Task.checkCancellation()
        unlockErrors.append(recoveryError(from: error))
      }
    }
    // As in the reference client (`recover.rs`), answers whose encrypted-secret
    // commitment did not match are skipped without an error, so this phase
    // can have too few matching answers with no more errors than it can spare
    // (an inconsistency on the realms' side), which reports an assertion.
    guard unlockErrors.count <= realms.count - threshold else { throw bestError(unlockErrors) }
    guard scalarShares.count >= threshold else { throw JuiceboxRecoveryError.assertion }

    let bySecret = Dictionary(grouping: scalarShares, by: { $0.encryptedSecret })
    let viableSecrets = bySecret.filter { $0.value.count >= threshold }
    guard viableSecrets.count == 1, let secretGroup = viableSecrets.first else {
      throw JuiceboxRecoveryError.assertion
    }

    let scalar: RistrettoScalar
    do {
      scalar = try recoverSecret(secretGroup.value.map { $0.share })
    } catch {
      throw JuiceboxRecoveryError.assertion
    }
    let encryptionKey = JuiceboxKeys.userSecretEncryptionKey(
      seed: encryptionKeySeed, scalar: scalar.bytes)
    guard
      let secret = JuiceboxKeys.decryptUserSecret(
        secretGroup.key, key: encryptionKey)
    else { throw JuiceboxRecoveryError.assertion }
    try Task.checkCancellation()
    return secret
  }

  // MARK: Realm requests

  /// Sends the same request to each of `realms` at once; see the overload
  /// below.
  private func requestEach(
    _ realms: [JuiceboxRealm], httpClient: some HTTPClientProtocol,
    request: SecretsRequest
  ) async throws -> [Result<SecretsResponse, any Error>] {
    try await requestEach(realms, httpClient: httpClient) { _ in request }
  }

  /// Sends one request to each of `realms` at once and returns each outcome
  /// in the realms' order, so a phase checks the answers in the same order
  /// however they arrive. A phase then takes as long as its slowest realm
  /// instead of the sum of all of them, which matters when several realms
  /// are slow or unresponsive. Every request is awaited; the reference client
  /// also returns early once too many realms have failed, which this does
  /// not do. A failed request is a failed outcome. The phase checks whether
  /// the caller cancelled recovery and throws `CancellationError` only then;
  /// any other failure, including a cancellation the HTTP client reports, is
  /// a failure of that realm.
  private func requestEach(
    _ realms: [JuiceboxRealm], httpClient: some HTTPClientProtocol,
    makeRequest: (JuiceboxRealm) -> SecretsRequest
  ) async throws -> [Result<SecretsResponse, any Error>] {
    try Task.checkCancellation()
    let requests = realms.map(makeRequest)
    return await withTaskGroup(of: (Int, Result<SecretsResponse, any Error>).self) { group in
      for (index, (realm, secretsRequest)) in zip(realms, requests).enumerated() {
        group.addTask {
          do {
            return (
              index,
              .success(try await request(secretsRequest, realm: realm, httpClient: httpClient))
            )
          } catch {
            return (index, .failure(error))
          }
        }
      }
      // The group waits for every child, so every slot is filled. A missing
      // one is a bug in this function, not a cancellation, so stop there.
      var outcomes = [Result<SecretsResponse, any Error>?](repeating: nil, count: realms.count)
      for await (index, outcome) in group {
        outcomes[index] = outcome
      }
      return outcomes.map { outcome in
        guard let outcome else { preconditionFailure("a realm request returned no outcome") }
        return outcome
      }
    }
  }

  private func request(
    _ request: SecretsRequest, realm: JuiceboxRealm,
    httpClient: some HTTPClientProtocol
  ) async throws -> SecretsResponse {
    guard let token = tokens[hexString(realm.id)] else {
      throw JuiceboxRecoveryError.invalidAuth
    }
    if let publicKey = realm.publicKey {
      return try await hardwareRequest(
        request, realm: realm, publicKey: publicKey, token: token, httpClient: httpClient)
    }

    let (response, body) = try await post(
      request.encoded(), to: realm, headerFields: [.authorization: "Bearer \(token)"],
      httpClient: httpClient)
    if response.status.kind == .successful {
      guard let decoded = try? SecretsResponse.decode(body) else {
        throw JuiceboxRecoveryError.assertion
      }
      return decoded
    }
    // A realm may describe an error in the body along with a non-2xx
    // status; prefer the body when it parses.
    if let decoded = try? SecretsResponse.decode(body) {
      return decoded
    }
    throw statusError(response.status)
  }

  private func hardwareRequest(
    _ request: SecretsRequest, realm: JuiceboxRealm, publicKey: [UInt8], token: String,
    httpClient: some HTTPClientProtocol
  ) async throws -> SecretsResponse {
    let needsForwardSecrecy = request.needsForwardSecrecy
    let handshakePayload = needsForwardSecrecy ? [] : request.encoded()

    let (handshake, handshakeMessage): (NoiseNK.Handshake, NoiseNK.HandshakeRequest)
    do {
      (handshake, handshakeMessage) = try NoiseNK.Handshake.start(
        serverStaticPublic: publicKey, payload: handshakePayload)
    } catch {
      throw JuiceboxRecoveryError.assertion
    }

    let sessionId = UInt32.random(in: UInt32.min...UInt32.max)
    let handshakeResponse = try await postClientRequest(
      ClientRequest(
        realmId: realm.id, authToken: token, sessionId: sessionId,
        kind: needsForwardSecrecy ? .handshakeOnly : .secretsRequest,
        encrypted: .handshake(
          clientEphemeralPublic: handshakeMessage.clientEphemeralPublic,
          payloadCiphertext: handshakeMessage.payloadCiphertext)),
      realm: realm, httpClient: httpClient)

    guard case .okHandshake(let fields) = handshakeResponse else {
      throw clientResponseError(handshakeResponse)
    }
    var session: NoiseNK.Transport
    let payload: [UInt8]
    do {
      (session, payload) = try handshake.finish(
        NoiseNK.HandshakeResponse(
          serverEphemeralPublic: fields.serverEphemeralPublic,
          payloadCiphertext: fields.payloadCiphertext))
    } catch {
      throw JuiceboxRecoveryError.assertion
    }
    if !needsForwardSecrecy {
      return try unpackPadded(payload)
    }
    guard payload.isEmpty else { throw JuiceboxRecoveryError.assertion }

    let ciphertext: [UInt8]
    do {
      ciphertext = try session.encrypt(request.encoded())
    } catch {
      throw JuiceboxRecoveryError.assertion
    }
    let transportResponse = try await postClientRequest(
      ClientRequest(
        realmId: realm.id, authToken: token, sessionId: sessionId,
        kind: .secretsRequest, encrypted: .transport(ciphertext: ciphertext)),
      realm: realm, httpClient: httpClient)
    guard case .okTransport(let responseCiphertext) = transportResponse else {
      throw clientResponseError(transportResponse)
    }
    let plaintext: [UInt8]
    do {
      plaintext = try session.decrypt(responseCiphertext)
    } catch {
      throw JuiceboxRecoveryError.assertion
    }
    return try unpackPadded(plaintext)
  }

  private func postClientRequest(
    _ request: ClientRequest, realm: JuiceboxRealm,
    httpClient: some HTTPClientProtocol
  ) async throws -> ClientResponse {
    // A hardware realm takes its token inside the body, not in a header.
    let (response, body) = try await post(
      request.encoded(), to: realm, headerFields: [:], httpClient: httpClient)
    if response.status.kind == .successful {
      guard let decoded = try? ClientResponse.decode(body) else {
        throw JuiceboxRecoveryError.assertion
      }
      return decoded
    }
    if let decoded = try? ClientResponse.decode(body) {
      return decoded
    }
    throw statusError(response.status)
  }

  /// POSTs `body` to the realm's endpoint with the protocol version and
  /// `headerFields`.
  private func post(
    _ body: [UInt8], to realm: JuiceboxRealm, headerFields: HTTPFields,
    httpClient: some HTTPClientProtocol
  ) async throws -> (HTTPResponse, [UInt8]) {
    // `JuiceboxConfiguration.parse` rejects a realm without a request URL,
    // so this does not fail; it is checked here because `HTTPRequest` stops
    // the process on a URL without a scheme.
    guard let url = realm.requestURL else { throw JuiceboxRecoveryError.assertion }
    var request = HTTPRequest(method: .post, url: url, headerFields: headerFields)
    request.headerFields[.juiceboxVersion] = Self.juiceboxVersion
    try Task.checkCancellation()
    let response: HTTPResponse
    let responseBody: Data
    do {
      // An error status does not throw (`HTTPClientProtocol` returns the
      // response whatever its status), so the callers read the realm's error
      // from the status and the body.
      (responseBody, response) = try await httpClient.execute(for: request, from: Data(body))
    } catch {
      // Recovery stops only when the caller cancelled it. The HTTP client may
      // also report a cancellation for its own reasons (an invalidated
      // session, a cancelled authentication challenge); that is a failure of
      // this realm, so the other realms can still answer, and the caller does
      // not mistake a real failure for its own cancellation. This only checks
      // the request's own task; the phase decides whether the caller
      // cancelled.
      try Task.checkCancellation()
      throw JuiceboxRecoveryError.transient
    }
    try Task.checkCancellation()
    return (response, Array(responseBody))
  }

  private func unpackPadded(_ payload: [UInt8]) throws -> SecretsResponse {
    do {
      return try PaddedSecretsResponse.decode(payload).unpack()
    } catch {
      throw JuiceboxRecoveryError.assertion
    }
  }

  // MARK: Helpers

  private func statusError(_ status: HTTPResponse.Status) -> JuiceboxRecoveryError {
    switch status {
    case .unauthorized: return .invalidAuth
    case .upgradeRequired: return .upgradeRequired
    case .tooManyRequests: return .rateLimitExceeded
    default: return .transient
    }
  }

  private func clientResponseError(_ response: ClientResponse) -> JuiceboxRecoveryError {
    switch response {
    case .invalidAuth: return .invalidAuth
    case .unavailable, .missingSession, .sessionError: return .transient
    case .rateLimitExceeded: return .rateLimitExceeded
    case .decodingError, .payloadTooLarge: return .assertion
    case .okHandshake, .okTransport: return .assertion
    }
  }

  private func recoveryError(from error: any Error) -> JuiceboxRecoveryError {
    if let error = error as? JuiceboxRecoveryError { return error }
    return .transient
  }

  /// The best of a phase's errors. Each caller has more errors than its phase
  /// can spare, and a phase can spare zero or more realms (`parse` keeps the
  /// threshold within the realm count), so `errors` is never empty; the
  /// `assertion` fallback only keeps a later caller from crashing.
  private func bestError(_ errors: [JuiceboxRecoveryError]) -> JuiceboxRecoveryError {
    errors.min {
      ($0.sortKey.0, $0.sortKey.1) < ($1.sortKey.0, $1.sortKey.1)
    } ?? .assertion
  }

  private func verifySignedPublicKey(
    _ signed: OPRFSignedPublicKey, realmId: [UInt8]
  ) -> Bool {
    guard signed.publicKey.count == 32, signed.verifyingKey.count == 32,
      signed.signature.count == 64
    else { return false }
    var message: [UInt8] = []
    message += be16(UInt16(realmId.count))
    message += realmId
    message += be16(UInt16(signed.publicKey.count))
    message += signed.publicKey
    guard
      let key = try? Curve25519.Signing.PublicKey(
        rawRepresentation: signed.verifyingKey)
    else { return false }
    return key.isValidSignature(signed.signature, for: message)
  }

  private func canonicalScalar(_ bytes: [UInt8]) -> RistrettoScalar? {
    RistrettoScalar(canonicalBytes: bytes)
  }
}

private struct PointShareKey: Hashable {
  var commitment: [UInt8]
  var verifyingKey: [UInt8]
}

private func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
  guard lhs.count == rhs.count else { return false }
  return unsafe sodium_memcmp(lhs, rhs, lhs.count) == 0
}

extension SecretsRequest {
  var needsForwardSecrecy: Bool {
    switch self {
    case .recover1: return false
    case .recover2, .recover3: return true
    }
  }
}

extension HTTPField.Name {
  /// The header that names the Juicebox protocol version the client speaks.
  static let juiceboxVersion = Self("X-Juicebox-Version")!
}
