import Crypto
import Foundation
import Testing

@testable import Juicebox

/// Recovery across two Noise NK hardware realms and one plain HTTP software
/// realm, with a test-side Noise server built independently of the client.
struct HardwareRecoveryTests {
    private static let version = [UInt8](repeating: 5, count: 16)
    private static let pin = Array("13579".utf8)
    private static let secret = Array("two hardware realms".utf8) + [UInt8](
        repeating: 0, count: 44)

    // MARK: Server-side Noise

    private struct ServerCipher {
        private let key: SymmetricKey
        private var nonce: UInt64 = 0

        init(key: [UInt8]) {
            self.key = SymmetricKey(data: key)
        }

        mutating func seal(_ plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
            let sealed = try ChaChaPoly.seal(
                plaintext, using: key, nonce: try ChaChaPoly.Nonce(data: nonceBytes),
                authenticating: aad)
            nonce += 1
            return Array(sealed.ciphertext) + Array(sealed.tag)
        }

        mutating func open(_ ciphertext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
            guard ciphertext.count >= 16 else { throw NoiseNK.NoiseError.decryption }
            let split = ciphertext.count - 16
            let box = try ChaChaPoly.SealedBox(
                nonce: try ChaChaPoly.Nonce(data: nonceBytes),
                ciphertext: Array(ciphertext[..<split]), tag: Array(ciphertext[split...]))
            let opened = try ChaChaPoly.open(box, using: key, authenticating: aad)
            nonce += 1
            return Array(opened)
        }

        private var nonceBytes: [UInt8] {
            [0, 0, 0, 0] + littleEndianBytes(nonce)
        }
    }

    private final class ServerTransport {
        private var inbound: ServerCipher
        private var outbound: ServerCipher

        init(inboundKey: [UInt8], outboundKey: [UInt8]) {
            inbound = ServerCipher(key: inboundKey)
            outbound = ServerCipher(key: outboundKey)
        }

        func open(_ ciphertext: [UInt8]) throws -> [UInt8] {
            try inbound.open(ciphertext, aad: [])
        }

        func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
            try outbound.seal(plaintext, aad: [])
        }
    }

    private struct ServerHandshake {
        var h: [UInt8]
        var ck: [UInt8]
        var cipher: ServerCipher
        let serverEphemeralPublic: [UInt8]
        let requestPlaintext: [UInt8]

        static func begin(
            staticSecret: Curve25519.KeyAgreement.PrivateKey, clientEphemeralPublic: [UInt8],
            payloadCiphertext: [UInt8]
        ) throws -> ServerHandshake {
            let clientEphemeral = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: clientEphemeralPublic)
            let staticPublic = Array(staticSecret.publicKey.rawRepresentation)
            var h = Blake2s.hash(Array("Noise_NK_25519_ChaChaPoly_BLAKE2s".utf8))
            var ck = h
            h = mixHash(h, [])
            h = mixHash(h, staticPublic)
            h = mixHash(h, clientEphemeralPublic)

            let (chainingKey, key) = hkdfPair(
                salt: ck,
                ikm: try sharedSecret(staticSecret, clientEphemeral))
            ck = chainingKey
            var cipher = ServerCipher(key: key)
            let requestPlaintext = try cipher.open(payloadCiphertext, aad: h)
            h = mixHash(h, payloadCiphertext)

            let serverEphemeral = Curve25519.KeyAgreement.PrivateKey()
            let serverEphemeralPublic = Array(serverEphemeral.publicKey.rawRepresentation)
            h = mixHash(h, serverEphemeralPublic)
            let (nextChainingKey, nextKey) = hkdfPair(
                salt: ck,
                ikm: try sharedSecret(serverEphemeral, clientEphemeral))

            return ServerHandshake(
                h: h, ck: nextChainingKey, cipher: ServerCipher(key: nextKey),
                serverEphemeralPublic: serverEphemeralPublic,
                requestPlaintext: requestPlaintext)
        }

        mutating func finish(payload: [UInt8]) throws -> ([UInt8], ServerTransport) {
            let ciphertext = try cipher.seal(payload, aad: h)
            let (k1, k2) = hkdfPair(salt: ck, ikm: [])
            return (ciphertext, ServerTransport(inboundKey: k1, outboundKey: k2))
        }
    }

    private static func mixHash(_ h: [UInt8], _ data: [UInt8]) -> [UInt8] {
        Blake2s.hash(h + data)
    }

    private static func hkdfPair(salt: [UInt8], ikm: [UInt8]) -> ([UInt8], [UInt8]) {
        let okm = hkdfBlake2s(salt: salt, ikm: ikm, length: 64)
        return (Array(okm[0..<32]), Array(okm[32..<64]))
    }

    private static func sharedSecret(
        _ privateKey: Curve25519.KeyAgreement.PrivateKey,
        _ publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> [UInt8] {
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return unsafe secret.withUnsafeBytes { unsafe Array($0) }
    }

    // MARK: Fake realms

    private struct RealmFixture {
        let id: [UInt8]
        let address: String
        let token: String
        let oprfShare: RistrettoScalar
        let scalarShare: RistrettoScalar
        let encryptedSecret: [UInt8]
        let secretCommitment: [UInt8]
        let unlockKeyCommitment: [UInt8]
        let unlockKey: [UInt8]
        let numGuesses: UInt16
        let guessCount: UInt16
        let noiseStaticSecret: Curve25519.KeyAgreement.PrivateKey?
    }

    private final class FakeNetwork: JuiceboxHTTPTransport, @unchecked Sendable {
        let realms: [String: RealmFixture]
        let signer: Curve25519.Signing.PrivateKey
        var sessions: [UInt32: ServerTransport] = [:]

        init(realms: [RealmFixture]) {
            self.realms = Dictionary(
                uniqueKeysWithValues: realms.map { ($0.address + "req", $0) })
            self.signer = Curve25519.Signing.PrivateKey()
        }

        func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
            guard let realm = realms[request.url] else {
                return JuiceboxHTTPResponse(statusCode: 404, body: [])
            }
            if realm.noiseStaticSecret == nil {
                guard request.headers["Authorization"] == "Bearer \(realm.token)" else {
                    return JuiceboxHTTPResponse(statusCode: 401, body: [])
                }
                return JuiceboxHTTPResponse(
                    statusCode: 200,
                    body: try response(for: realm, request: decodeCBOR(request.body)))
            }

            let clientRequest = try decodeCBOR(request.body)
            guard let sessionId = clientRequest.field("session_id")?.unsignedValue,
                let encrypted = clientRequest.field("encrypted")
            else { return JuiceboxHTTPResponse(statusCode: 400, body: []) }

            if let handshake = encrypted.field("Handshake")?.field("handshake"),
                let ephemeral = handshake.field("client_ephemeral_public")?.bytesValue,
                let payloadCiphertext = handshake.field("payload_ciphertext")?.bytesValue
            {
                var server = try ServerHandshake.begin(
                    staticSecret: realm.noiseStaticSecret!, clientEphemeralPublic: ephemeral,
                    payloadCiphertext: payloadCiphertext)
                var responsePayload: [UInt8] = []
                if !server.requestPlaintext.isEmpty {
                    let inner = try response(
                        for: realm, request: decodeCBOR(server.requestPlaintext))
                    responsePayload = paddedEnvelope(inner)
                }
                let (ciphertext, transport) = try server.finish(payload: responsePayload)
                sessions[UInt32(sessionId)] = transport
                return JuiceboxHTTPResponse(
                    statusCode: 200,
                    body: encodeCBOR(.map([
                        CBORPair(key: .text("Ok"), value: .map([
                            CBORPair(key: .text("Handshake"), value: .map([
                                CBORPair(key: .text("handshake"), value: .map([
                                    CBORPair(
                                        key: .text("server_ephemeral_public"),
                                        value: .bytes(server.serverEphemeralPublic)),
                                    CBORPair(
                                        key: .text("payload_ciphertext"),
                                        value: .bytes(ciphertext)),
                                ])),
                                CBORPair(key: .text("session_lifetime"), value: .map([
                                    CBORPair(key: .text("secs"), value: .unsigned(30)),
                                    CBORPair(key: .text("nanos"), value: .unsigned(0)),
                                ])),
                            ])),
                        ])),
                    ])))
            }

            guard let transportCiphertext = encrypted.field("Transport")?.field("ciphertext")?
                .bytesValue,
                let transport = sessions[UInt32(sessionId)]
            else { return JuiceboxHTTPResponse(statusCode: 400, body: []) }
            let plaintext = try transport.open(transportCiphertext)
            let inner = try response(for: realm, request: decodeCBOR(plaintext))
            let responseCiphertext = try transport.seal(paddedEnvelope(inner))
            return JuiceboxHTTPResponse(
                statusCode: 200,
                body: encodeCBOR(.map([
                    CBORPair(key: .text("Ok"), value: .map([
                        CBORPair(key: .text("Transport"), value: .map([
                            CBORPair(key: .text("ciphertext"), value: .bytes(responseCiphertext)),
                        ])),
                    ])),
                ])))
        }

        private func paddedEnvelope(_ inner: [UInt8]) -> [UInt8] {
            var padded = inner
            padded += [UInt8](repeating: 0, count: PaddedSecretsResponse.maximumLength - inner.count)
            return encodeCBOR(.map([
                CBORPair(key: .text("unpadded_length"), value: .unsigned(UInt64(inner.count))),
                CBORPair(key: .text("padded_bytes"), value: .bytes(padded)),
            ]))
        }

        private func response(for realm: RealmFixture, request: CBORValue) throws -> [UInt8] {
            if request == .text("Recover1") {
                return encodeCBOR(.map([
                    CBORPair(key: .text("Recover1"), value: .map([
                        CBORPair(key: .text("Ok"), value: .map([
                            CBORPair(
                                key: .text("version"),
                                value: .bytes(HardwareRecoveryTests.version)),
                        ])),
                    ])),
                ]))
            }
            if let body = request.field("Recover2") {
                return try recover2(realm: realm, body: body)
            }
            if let body = request.field("Recover3") {
                return try recover3(realm: realm, body: body)
            }
            throw RealmMessageError.malformed
        }

        private func recover2(realm: RealmFixture, body: CBORValue) throws -> [UInt8] {
            guard let blindedInputBytes = body.field("oprf_blinded_input")?.bytesValue,
                let blindedInput = try? OPRF.BlindedInput(compressed: blindedInputBytes)
            else { return [] }
            let publicKey = OPRF.publicKey(for: realm.oprfShare)
            let blindedOutput = OPRF.evaluate(
                privateKey: realm.oprfShare, blindedInput: blindedInput)
            let proof = OPRF.generateProof(
                privateKey: realm.oprfShare, nonce: .random(), blindedInput: blindedInput,
                publicKey: publicKey, blindedOutput: blindedOutput)
            var message: [UInt8] = []
            message += be16(16)
            message += realm.id
            message += be16(32)
            message += publicKey
            let signature = try signer.signature(for: message)

            return encodeCBOR(.map([
                CBORPair(key: .text("Recover2"), value: .map([
                    CBORPair(key: .text("Ok"), value: .map([
                        CBORPair(key: .text("oprf_signed_public_key"), value: .map([
                            CBORPair(key: .text("public_key"), value: .bytes(publicKey)),
                            CBORPair(
                                key: .text("verifying_key"),
                                value: .bytes(Array(signer.publicKey.rawRepresentation))),
                            CBORPair(key: .text("signature"), value: .bytes(Array(signature))),
                        ])),
                        CBORPair(
                            key: .text("oprf_blinded_result"),
                            value: .bytes(blindedOutput.compressed)),
                        CBORPair(key: .text("oprf_proof"), value: .map([
                            CBORPair(key: .text("c"), value: .bytes(proof.c.bytes)),
                            CBORPair(key: .text("beta_z"), value: .bytes(proof.betaZ.bytes)),
                        ])),
                        CBORPair(
                            key: .text("unlock_key_commitment"),
                            value: .bytes(realm.unlockKeyCommitment)),
                        CBORPair(key: .text("num_guesses"), value: .unsigned(UInt64(realm.numGuesses))),
                        CBORPair(key: .text("guess_count"), value: .unsigned(UInt64(realm.guessCount))),
                    ])),
                ])),
            ]))
        }

        private func recover3(realm: RealmFixture, body: CBORValue) throws -> [UInt8] {
            guard let tag = body.field("unlock_key_tag")?.bytesValue else { return [] }
            let expected = JuiceboxKeys.unlockKeyTag(unlockKey: realm.unlockKey, realmId: realm.id)
            guard constantTimeEqual(tag, expected) else {
                return encodeCBOR(.map([
                    CBORPair(key: .text("Recover3"), value: .map([
                        CBORPair(key: .text("BadUnlockKeyTag"), value: .map([
                            CBORPair(key: .text("guesses_remaining"), value: .unsigned(4)),
                        ])),
                    ])),
                ]))
            }
            return encodeCBOR(.map([
                CBORPair(key: .text("Recover3"), value: .map([
                    CBORPair(key: .text("Ok"), value: .map([
                        CBORPair(
                            key: .text("encryption_key_scalar_share"),
                            value: .bytes(realm.scalarShare.bytes)),
                        CBORPair(
                            key: .text("encrypted_secret"),
                            value: .bytes(realm.encryptedSecret)),
                        CBORPair(
                            key: .text("encrypted_secret_commitment"),
                            value: .bytes(realm.secretCommitment)),
                    ])),
                ])),
            ]))
        }

        private func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
            guard lhs.count == rhs.count else { return false }
            var difference: UInt8 = 0
            for i in 0..<lhs.count { difference |= lhs[i] ^ rhs[i] }
            return difference == 0
        }
    }

    // MARK: Tests

    @Test func hardwareAndSoftwareRealmsTogether() async throws {
        let realmIds = (0..<3).map { [UInt8](repeating: UInt8($0 + 1), count: 16) }
        let tokens = Dictionary(
            uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })

        let (accessKey, seed) = try juiceboxPinHash(
            pin: Self.pin, registrationVersion: Self.version, mode: .fastInsecure)
        let masterOPRF = RistrettoScalar.random()
        let oprfShares = createShares(
            secret: masterOPRF, threshold: 2, count: 3, random: { RistrettoScalar.random() })
        let oprfOutput = OPRF.unobliviousEvaluate(privateKey: masterOPRF, input: accessKey)
        let (unlockKey, unlockCommitment) = JuiceboxKeys.unlockKeyAndCommitment(
            oprfOutput: oprfOutput)
        let scalar = RistrettoScalar.random()
        let scalarShares = createShares(
            secret: scalar, threshold: 2, count: 3, random: { RistrettoScalar.random() })
        let encryptionKey = JuiceboxKeys.userSecretEncryptionKey(
            seed: seed, scalar: scalar.bytes)
        let encryptedSecret = JuiceboxKeys.encryptUserSecret(Self.secret, key: encryptionKey)!

        var realms: [RealmFixture] = []
        for index in 0..<3 {
            let id = realmIds[index]
            let commitment = JuiceboxKeys.encryptedUserSecretCommitment(
                unlockKey: unlockKey, realmId: id,
                scalarShare: scalarShares[index].secret.bytes,
                encryptedSecret: encryptedSecret)
            realms.append(
                RealmFixture(
                    id: id, address: "https://realm\(index + 1).test/",
                    token: tokens[hexString(id)]!, oprfShare: oprfShares[index].secret,
                    scalarShare: scalarShares[index].secret, encryptedSecret: encryptedSecret,
                    secretCommitment: commitment, unlockKeyCommitment: unlockCommitment,
                    unlockKey: unlockKey, numGuesses: 5, guessCount: 0,
                    noiseStaticSecret: index < 2 ? Curve25519.KeyAgreement.PrivateKey() : nil))
        }

        let network = FakeNetwork(realms: realms)
        let jsonRealms = realms.enumerated().map { index, realm -> String in
            let key =
                index < 2
                ? ",\"public_key\": \"\(hexString(Array(realm.noiseStaticSecret!.publicKey.rawRepresentation)))\""
                : ""
            return """
                {"id": "\(hexString(realm.id))", "address": "\(realm.address)"\(key)}
                """
        }
        let json = """
            {
              "realms": [\(jsonRealms.joined(separator: ","))],
              "register_threshold": 3,
              "recover_threshold": 2,
              "pin_hashing_mode": "FastInsecure"
            }
            """
        let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
        let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
        let secret = try await recovery.recover(pin: Self.pin, transport: network)
        #expect(secret == Self.secret)
    }

    @Test func wrongPinOnHardwareRealm() async throws {
        let realmIds = (0..<2).map { [UInt8](repeating: UInt8($0 + 1), count: 16) }
        let tokens = Dictionary(
            uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })
        let (accessKey, seed) = try juiceboxPinHash(
            pin: Self.pin, registrationVersion: Self.version, mode: .fastInsecure)
        let masterOPRF = RistrettoScalar.random()
        let oprfShares = createShares(
            secret: masterOPRF, threshold: 2, count: 2, random: { RistrettoScalar.random() })
        let oprfOutput = OPRF.unobliviousEvaluate(privateKey: masterOPRF, input: accessKey)
        let (unlockKey, unlockCommitment) = JuiceboxKeys.unlockKeyAndCommitment(
            oprfOutput: oprfOutput)
        let scalar = RistrettoScalar.random()
        let scalarShares = createShares(
            secret: scalar, threshold: 2, count: 2, random: { RistrettoScalar.random() })
        let encryptionKey = JuiceboxKeys.userSecretEncryptionKey(
            seed: seed, scalar: scalar.bytes)
        let encryptedSecret = JuiceboxKeys.encryptUserSecret(Self.secret, key: encryptionKey)!

        var realms: [RealmFixture] = []
        for index in 0..<2 {
            let id = realmIds[index]
            realms.append(
                RealmFixture(
                    id: id, address: "https://realm\(index + 1).test/",
                    token: tokens[hexString(id)]!, oprfShare: oprfShares[index].secret,
                    scalarShare: scalarShares[index].secret, encryptedSecret: encryptedSecret,
                    secretCommitment: JuiceboxKeys.encryptedUserSecretCommitment(
                        unlockKey: unlockKey, realmId: id,
                        scalarShare: scalarShares[index].secret.bytes,
                        encryptedSecret: encryptedSecret),
                    unlockKeyCommitment: unlockCommitment, unlockKey: unlockKey,
                    numGuesses: 5, guessCount: 1,
                    noiseStaticSecret: Curve25519.KeyAgreement.PrivateKey()))
        }
        let network = FakeNetwork(realms: realms)
        let json = """
            {
              "realms": [
                {"id": "\(hexString(realms[0].id))", "address": "\(realms[0].address)",
                 "public_key": "\(hexString(Array(realms[0].noiseStaticSecret!.publicKey.rawRepresentation)))"},
                {"id": "\(hexString(realms[1].id))", "address": "\(realms[1].address)",
                 "public_key": "\(hexString(Array(realms[1].noiseStaticSecret!.publicKey.rawRepresentation)))"}
              ],
              "register_threshold": 2,
              "recover_threshold": 2,
              "pin_hashing_mode": "FastInsecure"
            }
            """
        let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
        let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
        do {
            _ = try await recovery.recover(pin: Array("00000".utf8), transport: network)
            Issue.record("wrong PIN must fail")
        } catch let error as JuiceboxRecoveryError {
            #expect(error == .invalidPin(guessesRemaining: 4))
        }
    }
}

private func littleEndianBytes(_ value: UInt64) -> [UInt8] {
    var value = value
    var bytes = [UInt8](repeating: 0, count: 8)
    for i in 0..<8 {
        bytes[i] = UInt8(truncatingIfNeeded: value & 0xff)
        value >>= 8
    }
    return bytes
}
