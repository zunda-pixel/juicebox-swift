import CBOR
/// The Juicebox realm wire messages this client needs: the recovery phases,
/// the padded hardware-realm envelope, and the Noise wrapper. Encodings match
/// serde's CBOR representation (structs as maps, externally tagged enums as
/// one-entry maps).
enum RealmMessageError: Error, Equatable {
    case malformed
}

struct OPRFSignedPublicKey: Equatable, Sendable {
    var publicKey: [UInt8]
    var verifyingKey: [UInt8]
    var signature: [UInt8]
}

struct OPRFProofFields: Equatable, Sendable {
    var c: [UInt8]
    var betaZ: [UInt8]
}

enum SecretsRequest: Equatable, Sendable {
    case recover1
    case recover2(version: [UInt8], blindedInput: [UInt8])
    case recover3(version: [UInt8], unlockKeyTag: [UInt8])

    func encoded() -> [UInt8] {
        switch self {
        case .recover1:
            return CBOR.textString("Recover1").encode()
        case .recover2(let version, let blindedInput):
            return CBOR.map([
                "Recover2": .map([
                    "version": .byteString(version),
                    "oprf_blinded_input": .byteString(blindedInput),
                ]),
            ]).encode()
        case .recover3(let version, let unlockKeyTag):
            return CBOR.map([
                "Recover3": .map([
                    "version": .byteString(version),
                    "unlock_key_tag": .byteString(unlockKeyTag),
                ]),
            ]).encode()
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

private func decodeRecover1(_ value: CBOR) throws -> Recover1Response {
    if value == .textString("NotRegistered") { return .notRegistered }
    if value == .textString("NoGuesses") { return .noGuesses }
    let (variant, body) = try enumVariant(value)
    guard variant == "Ok" else { throw RealmMessageError.malformed }
    return .ok(version: try bytesField(body, "version", count: 16))
}

private func decodeRecover2(_ value: CBOR) throws -> Recover2Response {
    if value == .textString("VersionMismatch") { return .versionMismatch }
    if value == .textString("NotRegistered") { return .notRegistered }
    if value == .textString("NoGuesses") { return .noGuesses }
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

private func decodeRecover3(_ value: CBOR) throws -> Recover3Response {
    if value == .textString("VersionMismatch") { return .versionMismatch }
    if value == .textString("NotRegistered") { return .notRegistered }
    if value == .textString("NoGuesses") { return .noGuesses }
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
    var unpaddedLength: UInt16
    var paddedBytes: [UInt8]

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

    var encodedValue: CBOR {
        switch self {
        case .handshake(let clientEphemeralPublic, let payloadCiphertext):
            return .map([
                "Handshake": .map([
                    "handshake": .map([
                        "client_ephemeral_public": .byteString(clientEphemeralPublic),
                        "payload_ciphertext": .byteString(payloadCiphertext),
                    ]),
                ]),
            ])
        case .transport(let ciphertext):
            return .map([
                "Transport": .map([
                    "ciphertext": .byteString(ciphertext),
                ]),
            ])
        }
    }
}

struct ClientRequest: Sendable {
    enum Kind: String, Sendable {
        case handshakeOnly = "HandshakeOnly"
        case secretsRequest = "SecretsRequest"
    }

    var realmId: [UInt8]
    var authToken: String
    var sessionId: UInt32
    var kind: Kind
    var encrypted: NoiseRequest

    func encoded() -> [UInt8] {
        CBOR.map([
            "realm": .byteString(realmId),
            "auth_token": .textString(authToken),
            "session_id": .unsignedInt(UInt64(sessionId)),
            "kind": .textString(kind.rawValue),
            "encrypted": encrypted.encodedValue,
        ]).encode()
    }
}

enum ClientResponse: Equatable, Sendable {
    struct Handshake: Equatable, Sendable {
        var serverEphemeralPublic: [UInt8]
        var payloadCiphertext: [UInt8]
        var sessionLifetimeSeconds: UInt64
        var sessionLifetimeNanos: UInt32
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
        if case .textString(let name) = value {
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

private func enumVariant(_ value: CBOR) throws -> (String, CBOR) {
    guard case .map(let fields) = value, fields.count == 1,
        let (key, body) = fields.first, let name = key.string
    else { throw RealmMessageError.malformed }
    return (name, body)
}

private func structField(_ value: CBOR, _ name: String) throws -> CBOR {
    guard let field = value[name] else { throw RealmMessageError.malformed }
    return field
}

private func bytesField(
    _ value: CBOR, _ name: String, count: Int? = nil
) throws -> [UInt8] {
    guard let bytes = try structField(value, name).bytes else {
        throw RealmMessageError.malformed
    }
    if let count, bytes.count != count { throw RealmMessageError.malformed }
    return bytes
}

private func u16Field(_ value: CBOR, _ name: String) throws -> UInt16 {
    let number = try u64Field(value, name)
    guard number <= UInt64(UInt16.max) else { throw RealmMessageError.malformed }
    return UInt16(number)
}

private func u64Field(_ value: CBOR, _ name: String) throws -> UInt64 {
    guard let number = try structField(value, name).uint64 else {
        throw RealmMessageError.malformed
    }
    return number
}
