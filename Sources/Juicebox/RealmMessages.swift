/// The Juicebox realm wire messages this client needs: the recovery phases,
/// the padded hardware-realm envelope, and the Noise wrapper. Encodings match
/// serde's CBOR representation (structs as maps, externally tagged enums as
/// one-entry maps).
enum RealmMessageError: Error, Equatable {
    case malformed
}

struct OPRFSignedPublicKey: Equatable, Sendable {
    let publicKey: [UInt8]
    let verifyingKey: [UInt8]
    let signature: [UInt8]
}

struct OPRFProofFields: Equatable, Sendable {
    let c: [UInt8]
    let betaZ: [UInt8]
}

enum SecretsRequest: Equatable, Sendable {
    case recover1
    case recover2(version: [UInt8], blindedInput: [UInt8])
    case recover3(version: [UInt8], unlockKeyTag: [UInt8])

    func encoded() -> [UInt8] {
        switch self {
        case .recover1:
            return encodeCBOR(.text("Recover1"))
        case .recover2(let version, let blindedInput):
            return encodeCBOR(.map([
                CBORPair(key: .text("Recover2"), value: .map([
                    CBORPair(key: .text("version"), value: .bytes(version)),
                    CBORPair(key: .text("oprf_blinded_input"), value: .bytes(blindedInput)),
                ])),
            ]))
        case .recover3(let version, let unlockKeyTag):
            return encodeCBOR(.map([
                CBORPair(key: .text("Recover3"), value: .map([
                    CBORPair(key: .text("version"), value: .bytes(version)),
                    CBORPair(key: .text("unlock_key_tag"), value: .bytes(unlockKeyTag)),
                ])),
            ]))
        }
    }
}

enum Recover1Response: Equatable, Sendable {
    case ok(version: [UInt8])
    case notRegistered
    case noGuesses
}

enum Recover2Response: Equatable, Sendable {
    case ok(
        signedPublicKey: OPRFSignedPublicKey, blindedResult: [UInt8], proof: OPRFProofFields,
        unlockKeyCommitment: [UInt8], numGuesses: UInt16, guessCount: UInt16)
    case versionMismatch
    case notRegistered
    case noGuesses
}

enum Recover3Response: Equatable, Sendable {
    case ok(scalarShare: [UInt8], encryptedSecret: [UInt8], commitment: [UInt8])
    case versionMismatch
    case notRegistered
    case badUnlockKeyTag(guessesRemaining: UInt16)
    case noGuesses
}

enum SecretsResponse: Equatable, Sendable {
    case recover1(Recover1Response)
    case recover2(Recover2Response)
    case recover3(Recover3Response)

    static func decode(_ bytes: [UInt8]) throws -> SecretsResponse {
        let (variant, body) = try enumVariant(decodeCBOR(bytes))
        switch variant {
        case "Recover1":
            return .recover1(try decodeRecover1(body))
        case "Recover2":
            return .recover2(try decodeRecover2(body))
        case "Recover3":
            return .recover3(try decodeRecover3(body))
        default:
            throw RealmMessageError.malformed
        }
    }
}

// MARK: Recovery phase responses

private func decodeRecover1(_ value: CBORValue) throws -> Recover1Response {
    if value == .text("NotRegistered") { return .notRegistered }
    if value == .text("NoGuesses") { return .noGuesses }
    let (variant, body) = try enumVariant(value)
    guard variant == "Ok" else { throw RealmMessageError.malformed }
    return .ok(version: try bytesField(body, "version", count: 16))
}

private func decodeRecover2(_ value: CBORValue) throws -> Recover2Response {
    if value == .text("VersionMismatch") { return .versionMismatch }
    if value == .text("NotRegistered") { return .notRegistered }
    if value == .text("NoGuesses") { return .noGuesses }
    let (variant, body) = try enumVariant(value)
    guard variant == "Ok" else { throw RealmMessageError.malformed }

    let signed = try structField(body, "oprf_signed_public_key")
    let proof = try structField(body, "oprf_proof")
    return .ok(
        signedPublicKey: OPRFSignedPublicKey(
            publicKey: try bytesField(signed, "public_key", count: 32),
            verifyingKey: try bytesField(signed, "verifying_key", count: 32),
            signature: try bytesField(signed, "signature", count: 64)),
        blindedResult: try bytesField(body, "oprf_blinded_result", count: 32),
        proof: OPRFProofFields(
            c: try bytesField(proof, "c", count: 32),
            betaZ: try bytesField(proof, "beta_z", count: 32)),
        unlockKeyCommitment: try bytesField(body, "unlock_key_commitment", count: 32),
        numGuesses: try u16Field(body, "num_guesses"),
        guessCount: try u16Field(body, "guess_count"))
}

private func decodeRecover3(_ value: CBORValue) throws -> Recover3Response {
    if value == .text("VersionMismatch") { return .versionMismatch }
    if value == .text("NotRegistered") { return .notRegistered }
    if value == .text("NoGuesses") { return .noGuesses }
    let (variant, body) = try enumVariant(value)
    if variant == "BadUnlockKeyTag" {
        return .badUnlockKeyTag(guessesRemaining: try u16Field(body, "guesses_remaining"))
    }
    guard variant == "Ok" else { throw RealmMessageError.malformed }
    return .ok(
        scalarShare: try bytesField(body, "encryption_key_scalar_share", count: 32),
        encryptedSecret: try bytesField(body, "encrypted_secret", count: 145),
        commitment: try bytesField(body, "encrypted_secret_commitment", count: 16))
}

// MARK: Padded hardware responses

struct PaddedSecretsResponse: Equatable, Sendable {
    let unpaddedLength: UInt16
    let paddedBytes: [UInt8]

    static let maximumLength = 436

    static func decode(_ bytes: [UInt8]) throws -> PaddedSecretsResponse {
        let value = try decodeCBOR(bytes)
        let padded = try bytesField(value, "padded_bytes")
        guard padded.count == maximumLength else { throw RealmMessageError.malformed }
        return PaddedSecretsResponse(
            unpaddedLength: try u16Field(value, "unpadded_length"), paddedBytes: padded)
    }

    func unpack() throws -> SecretsResponse {
        guard Int(unpaddedLength) <= paddedBytes.count else { throw RealmMessageError.malformed }
        return try SecretsResponse.decode(Array(paddedBytes[0..<Int(unpaddedLength)]))
    }
}

// MARK: Hardware Noise wrapper

enum NoiseRequest: Equatable, Sendable {
    case handshake(clientEphemeralPublic: [UInt8], payloadCiphertext: [UInt8])
    case transport(ciphertext: [UInt8])

    var encodedValue: CBORValue {
        switch self {
        case .handshake(let clientEphemeralPublic, let payloadCiphertext):
            return .map([
                CBORPair(key: .text("Handshake"), value: .map([
                    CBORPair(key: .text("handshake"), value: .map([
                        CBORPair(
                            key: .text("client_ephemeral_public"),
                            value: .bytes(clientEphemeralPublic)),
                        CBORPair(
                            key: .text("payload_ciphertext"), value: .bytes(payloadCiphertext)),
                    ])),
                ])),
            ])
        case .transport(let ciphertext):
            return .map([
                CBORPair(key: .text("Transport"), value: .map([
                    CBORPair(key: .text("ciphertext"), value: .bytes(ciphertext)),
                ])),
            ])
        }
    }
}

struct ClientRequest: Sendable {
    enum Kind: String, Sendable {
        case handshakeOnly = "HandshakeOnly"
        case secretsRequest = "SecretsRequest"
    }

    let realmId: [UInt8]
    let authToken: String
    let sessionId: UInt32
    let kind: Kind
    let encrypted: NoiseRequest

    func encoded() -> [UInt8] {
        encodeCBOR(.map([
            CBORPair(key: .text("realm"), value: .bytes(realmId)),
            CBORPair(key: .text("auth_token"), value: .text(authToken)),
            CBORPair(key: .text("session_id"), value: .unsigned(UInt64(sessionId))),
            CBORPair(key: .text("kind"), value: .text(kind.rawValue)),
            CBORPair(key: .text("encrypted"), value: encrypted.encodedValue),
        ]))
    }
}

enum ClientResponse: Equatable, Sendable {
    struct Handshake: Equatable, Sendable {
        let serverEphemeralPublic: [UInt8]
        let payloadCiphertext: [UInt8]
        let sessionLifetimeSeconds: UInt64
        let sessionLifetimeNanos: UInt32
    }

    case okHandshake(Handshake)
    case okTransport(ciphertext: [UInt8])
    case unavailable
    case invalidAuth
    case missingSession
    case sessionError
    case decodingError
    case payloadTooLarge
    case rateLimitExceeded

    static func decode(_ bytes: [UInt8]) throws -> ClientResponse {
        let value = try decodeCBOR(bytes)
        if case .text(let name) = value {
            switch name {
            case "Unavailable": return .unavailable
            case "InvalidAuth": return .invalidAuth
            case "MissingSession": return .missingSession
            case "SessionError": return .sessionError
            case "DecodingError": return .decodingError
            case "PayloadTooLarge": return .payloadTooLarge
            case "RateLimitExceeded": return .rateLimitExceeded
            default: throw RealmMessageError.malformed
            }
        }

        let (variant, noise) = try enumVariant(value)
        guard variant == "Ok" else { throw RealmMessageError.malformed }
        let (noiseVariant, body) = try enumVariant(noise)
        switch noiseVariant {
        case "Handshake":
            let handshake = try structField(body, "handshake")
            let lifetime = try structField(body, "session_lifetime")
            let nanos = try u64Field(lifetime, "nanos")
            guard nanos <= UInt64(UInt32.max) else { throw RealmMessageError.malformed }
            return .okHandshake(Handshake(
                serverEphemeralPublic: try bytesField(
                    handshake, "server_ephemeral_public", count: 32),
                payloadCiphertext: try bytesField(handshake, "payload_ciphertext"),
                sessionLifetimeSeconds: try u64Field(lifetime, "secs"),
                sessionLifetimeNanos: UInt32(nanos)))
        case "Transport":
            return .okTransport(ciphertext: try bytesField(body, "ciphertext"))
        default:
            throw RealmMessageError.malformed
        }
    }
}

// MARK: Field helpers

private func enumVariant(_ value: CBORValue) throws -> (String, CBORValue) {
    guard case .map(let pairs) = value, pairs.count == 1,
        case .text(let name) = pairs[0].key
    else { throw RealmMessageError.malformed }
    return (name, pairs[0].value)
}

private func structField(_ value: CBORValue, _ name: String) throws -> CBORValue {
    guard let field = value.field(name) else { throw RealmMessageError.malformed }
    return field
}

private func bytesField(
    _ value: CBORValue, _ name: String, count: Int? = nil
) throws -> [UInt8] {
    guard let bytes = try structField(value, name).bytesValue else {
        throw RealmMessageError.malformed
    }
    if let count, bytes.count != count { throw RealmMessageError.malformed }
    return bytes
}

private func u16Field(_ value: CBORValue, _ name: String) throws -> UInt16 {
    let number = try u64Field(value, name)
    guard number <= UInt64(UInt16.max) else { throw RealmMessageError.malformed }
    return UInt16(number)
}

private func u64Field(_ value: CBORValue, _ name: String) throws -> UInt64 {
    guard let number = try structField(value, name).unsignedValue else {
        throw RealmMessageError.malformed
    }
    return number
}
