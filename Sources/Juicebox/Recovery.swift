import Crypto
import Foundation
import _Clibsodium

/// A request the recovery driver asks the host app to perform. The SDK owns
/// the Juicebox protocol, not the HTTP stack.
public struct JuiceboxHTTPRequest: Sendable {
    public let method: String
    public let url: String
    public let headers: [String: String]
    public let body: [UInt8]

    public init(method: String, url: String, headers: [String: String], body: [UInt8]) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct JuiceboxHTTPResponse: Sendable {
    public let statusCode: Int
    public let body: [UInt8]

    public init(statusCode: Int, body: [UInt8]) {
        self.statusCode = statusCode
        self.body = body
    }
}

public protocol JuiceboxHTTPTransport: Sendable {
    func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse
}

/// Why recovery failed. `invalidPin` carries the guesses left when the realms
/// report them.
public enum JuiceboxRecoveryError: Error, Equatable, Sendable {
    case invalidPin(guessesRemaining: Int?)
    case notRegistered
    case invalidAuth
    case upgradeRequired
    case rateLimitExceeded
    case assertion
    case transient
    case invalidConfiguration

    /// The reference client's error ordering, used to pick the most specific
    /// failure when too few realms answer.
    var rank: Int {
        switch self {
        case .invalidPin: return 0
        case .notRegistered: return 1
        case .invalidAuth: return 2
        case .upgradeRequired: return 3
        case .rateLimitExceeded: return 4
        case .assertion: return 5
        case .transient: return 6
        case .invalidConfiguration: return 7
        }
    }

    var sortKey: (Int, Int) {
        switch self {
        case .invalidPin(let guesses): return (rank, guesses ?? Int.min)
        default: return (rank, 0)
        }
    }
}

/// Runs the three-phase Juicebox recovery: learn the registration version,
/// evaluate the PIN's OPRF across realms, then unlock and decrypt the user
/// secret. Every network call is delegated to a `JuiceboxHTTPTransport`.
public struct JuiceboxRecovery: Sendable {
    let configuration: JuiceboxConfiguration
    /// Bearer tokens keyed by lowercased realm id hex.
    let tokens: [String: String]
    let userInfo: [UInt8]

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

    public func recover(
        pin: [UInt8], transport: any JuiceboxHTTPTransport
    ) async throws -> [UInt8] {
        try Task.checkCancellation()
        guard sodium_init() >= 0 else { throw JuiceboxRecoveryError.assertion }
        let threshold = configuration.recoverThreshold

        // Phase 1: every realm reports the registration version.
        var versions: [(version: [UInt8], realm: JuiceboxRealm)] = []
        var errors: [JuiceboxRecoveryError] = []
        for realm in configuration.realms {
            do {
                guard case .recover1(let response) = try await request(
                    .recover1, realm: realm, transport: transport)
                else {
                    errors.append(.assertion)
                    continue
                }
                switch response {
                case .ok(let version): versions.append((version, realm))
                case .notRegistered: errors.append(.notRegistered)
                case .noGuesses: errors.append(.invalidPin(guessesRemaining: 0))
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                errors.append(recoveryError(from: error))
            }
        }
        guard versions.count >= threshold else { throw bestError(errors) }

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

        var pointShares: [(share: SecretShare<RistrettoPoint>, commitment: [UInt8],
            verifyingKey: [UInt8], guessesRemaining: Int)] = []
        for realm in realms {
            do {
                let response = try await request(
                    .recover2(version: version, blindedInput: blindedInput.compressed),
                    realm: realm, transport: transport)
                guard case .recover2(let recover2) = response else {
                    errors.append(.assertion)
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
                        errors.append(.assertion)
                        continue
                    }
                    pointShares.append((
                        SecretShare(index: index, secret: blindedOutput.point),
                        unlockKeyCommitment, signedPublicKey.verifyingKey,
                        Int(numGuesses - guessCount)))
                case .versionMismatch: errors.append(.assertion)
                case .notRegistered: errors.append(.notRegistered)
                case .noGuesses: errors.append(.invalidPin(guessesRemaining: 0))
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                errors.append(recoveryError(from: error))
            }
        }
        guard pointShares.count >= threshold else { throw bestError(errors) }

        let byKey = Dictionary(grouping: pointShares, by: {
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
                guessesRemaining: pointGroup.map { $0.guessesRemaining }.min())
        }

        // Phase 3: exchange the unlock key tag for each realm's scalar share,
        // then decrypt the user secret.
        var scalarShares: [(share: SecretShare<RistrettoScalar>, encryptedSecret: [UInt8])] = []
        for realm in realms {
            let tag = JuiceboxKeys.unlockKeyTag(unlockKey: unlockKey, realmId: realm.id)
            do {
                let response = try await request(
                    .recover3(version: version, unlockKeyTag: tag), realm: realm,
                    transport: transport)
                guard case .recover3(let recover3) = response else {
                    errors.append(.assertion)
                    continue
                }
                switch recover3 {
                case .ok(let scalarShare, let encryptedSecret, let secretCommitment):
                    guard let scalar = canonicalScalar(scalarShare),
                        let index = configuration.shareIndex(for: realm.id)
                    else {
                        errors.append(.assertion)
                        continue
                    }
                    let ours = JuiceboxKeys.encryptedUserSecretCommitment(
                        unlockKey: unlockKey, realmId: realm.id, scalarShare: scalarShare,
                        encryptedSecret: encryptedSecret)
                    guard constantTimeEquals(ours, secretCommitment) else { continue }
                    scalarShares.append((
                        SecretShare(index: index, secret: scalar), encryptedSecret))
                case .versionMismatch: errors.append(.assertion)
                case .notRegistered: errors.append(.notRegistered)
                case .badUnlockKeyTag(let guesses):
                    errors.append(.invalidPin(guessesRemaining: Int(guesses)))
                case .noGuesses: errors.append(.invalidPin(guessesRemaining: 0))
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try Task.checkCancellation()
                errors.append(recoveryError(from: error))
            }
        }
        guard scalarShares.count >= threshold else { throw bestError(errors) }

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
        guard let secret = JuiceboxKeys.decryptUserSecret(
            secretGroup.key, key: encryptionKey)
        else { throw JuiceboxRecoveryError.assertion }
        try Task.checkCancellation()
        return secret
    }

    // MARK: Realm requests

    private func request(
        _ request: SecretsRequest, realm: JuiceboxRealm,
        transport: any JuiceboxHTTPTransport
    ) async throws -> SecretsResponse {
        guard let token = tokens[hexString(realm.id)] else {
            throw JuiceboxRecoveryError.invalidAuth
        }
        if let publicKey = realm.publicKey {
            return try await hardwareRequest(
                request, realm: realm, publicKey: publicKey, token: token, transport: transport)
        }

        let response = try await send(
            JuiceboxHTTPRequest(
                method: "POST", url: realm.requestURL,
                headers: [
                    "Authorization": "Bearer \(token)",
                    "X-Juicebox-Version": Self.juiceboxVersion,
                ],
                body: request.encoded()),
            transport: transport)
        if (200..<300).contains(response.statusCode) {
            guard let decoded = try? SecretsResponse.decode(response.body) else {
                throw JuiceboxRecoveryError.assertion
            }
            return decoded
        }
        // A realm may describe an error in the body along with a non-2xx
        // status; prefer the body when it parses.
        if let decoded = try? SecretsResponse.decode(response.body) {
            return decoded
        }
        throw statusError(response.statusCode)
    }

    private func hardwareRequest(
        _ request: SecretsRequest, realm: JuiceboxRealm, publicKey: [UInt8], token: String,
        transport: any JuiceboxHTTPTransport
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
            realm: realm, transport: transport)

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
            realm: realm, transport: transport)
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
        transport: any JuiceboxHTTPTransport
    ) async throws -> ClientResponse {
        let response = try await send(
            JuiceboxHTTPRequest(
                method: "POST", url: realm.requestURL,
                headers: ["X-Juicebox-Version": Self.juiceboxVersion],
                body: request.encoded()),
            transport: transport)
        if (200..<300).contains(response.statusCode) {
            guard let decoded = try? ClientResponse.decode(response.body) else {
                throw JuiceboxRecoveryError.assertion
            }
            return decoded
        }
        if let decoded = try? ClientResponse.decode(response.body) {
            return decoded
        }
        throw statusError(response.statusCode)
    }

    private func send(
        _ request: JuiceboxHTTPRequest, transport: any JuiceboxHTTPTransport
    ) async throws -> JuiceboxHTTPResponse {
        try Task.checkCancellation()
        let response: JuiceboxHTTPResponse
        do {
            response = try await transport.send(request)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch {
            try Task.checkCancellation()
            throw JuiceboxRecoveryError.transient
        }
        try Task.checkCancellation()
        return response
    }

    private func unpackPadded(_ payload: [UInt8]) throws -> SecretsResponse {
        do {
            return try PaddedSecretsResponse.decode(payload).unpack()
        } catch {
            throw JuiceboxRecoveryError.assertion
        }
    }

    // MARK: Helpers

    private func statusError(_ status: Int) -> JuiceboxRecoveryError {
        switch status {
        case 401: return .invalidAuth
        case 426: return .upgradeRequired
        case 429: return .rateLimitExceeded
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
        guard let key = try? Curve25519.Signing.PublicKey(
            rawRepresentation: signed.verifyingKey)
        else { return false }
        return key.isValidSignature(signed.signature, for: message)
    }

    private func canonicalScalar(_ bytes: [UInt8]) -> RistrettoScalar? {
        RistrettoScalar(canonicalBytes: bytes)
    }
}

private struct PointShareKey: Hashable {
    let commitment: [UInt8]
    let verifyingKey: [UInt8]
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
