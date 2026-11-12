import Crypto
import Foundation
import XCTest

@testable import Juicebox

/// Drives the full three-phase recovery against fake realms that hold Shamir
/// shares of the OPRF key and the user-secret scalar.
final class RecoveryFlowTests: XCTestCase {
    private static let version = [UInt8](repeating: 5, count: 16)
    private static let pin = Array("1234".utf8)
    private static let userSecret = Array("a 64-byte user secret".utf8) + [UInt8](
        repeating: 0, count: 43)
    private static let threshold = 2
    private static let realmCount = 3

    // MARK: Fake network

    struct FakeRealm {
        let id: [UInt8]
        let url: String
        let token: String
        let oprfShare: RistrettoScalar
        let scalarShare: RistrettoScalar
        let encryptedSecret: [UInt8]
        let secretCommitment: [UInt8]
        let unlockKeyCommitment: [UInt8]
        let unlockKey: [UInt8]
        let signingKey: Curve25519.Signing.PrivateKey
        let numGuesses: UInt16
        let guessCount: UInt16
    }

    final class FakeNetwork: JuiceboxHTTPTransport, @unchecked Sendable {
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
            if value == .text("Recover1") {
                return JuiceboxHTTPResponse(
                    statusCode: 200, body: encodeRecover1Ok(version: Self.versionForNetwork))
            }
            if let body = value.field("Recover2") {
                return JuiceboxHTTPResponse(
                    statusCode: 200, body: try recover2(realm: realm, body: body))
            }
            if let body = value.field("Recover3") {
                return JuiceboxHTTPResponse(
                    statusCode: 200, body: try recover3(realm: realm, body: body))
            }
            return JuiceboxHTTPResponse(statusCode: 400, body: [])
        }

        static let versionForNetwork = RecoveryFlowTests.version

        private func recover2(realm: FakeRealm, body: CBORValue) throws -> [UInt8] {
            guard let blindedInputBytes = body.field("oprf_blinded_input")?.bytesValue,
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

            return encodeCBOR(.map([
                CBORPair(key: .text("Recover2"), value: .map([
                    CBORPair(key: .text("Ok"), value: .map([
                        CBORPair(key: .text("oprf_signed_public_key"), value: .map([
                            CBORPair(key: .text("public_key"), value: .bytes(publicKey)),
                            CBORPair(
                                key: .text("verifying_key"),
                                value: .bytes(Array(realm.signingKey.publicKey.rawRepresentation))),
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

        private func recover3(realm: FakeRealm, body: CBORValue) throws -> [UInt8] {
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

    static func encodeRecover1Ok(version: [UInt8]) -> [UInt8] {
        encodeCBOR(.map([
            CBORPair(key: .text("Recover1"), value: .map([
                CBORPair(key: .text("Ok"), value: .map([
                    CBORPair(key: .text("version"), value: .bytes(version)),
                ])),
            ])),
        ]))
    }

    // MARK: Setup

    func makeNetwork(
        pin: [UInt8] = RecoveryFlowTests.pin
    ) throws -> (FakeNetwork, JuiceboxConfiguration, [String: String]) {
        let realmIds = (0..<Self.realmCount).map { index in
            [UInt8](repeating: UInt8(index + 1), count: 16)
        }
        let tokens = Dictionary(
            uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })

        let (accessKey, seed) = try juiceboxPinHash(
            pin: pin, registrationVersion: Self.version, mode: .fastInsecure)
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
            realms.append(FakeRealm(
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
              "pin_hashing_mode": "FastInsecure"
            }
            """
        let configuration = try! JuiceboxConfiguration.parse(Array(json.utf8))
        return (FakeNetwork(realms: realms), configuration, tokens)
    }

    private actor CancellingTransport: JuiceboxHTTPTransport {
        enum Mode: CaseIterable {
            case throwsCancellation
            case throwsURLCancellation
            case returnsAfterCancellation
        }

        let network: FakeNetwork
        let mode: Mode
        private(set) var pinRequests = 0

        init(network: FakeNetwork, mode: Mode) {
            self.network = network
            self.mode = mode
        }

        func send(_ request: JuiceboxHTTPRequest) async throws -> JuiceboxHTTPResponse {
            if try decodeCBOR(request.body) == .text("Recover1") {
                return try await network.send(request)
            }
            pinRequests += 1
            switch mode {
            case .throwsCancellation:
                throw CancellationError()
            case .throwsURLCancellation:
                throw URLError(.cancelled)
            case .returnsAfterCancellation:
                unsafe withUnsafeCurrentTask { unsafe $0?.cancel() }
                return try await network.send(request)
            }
        }
    }

    // MARK: Tests

    func testRecoverUserSecret() async throws {
        let (network, configuration, tokens) = try makeNetwork()
        let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
        let secret = try await recovery.recover(pin: Self.pin, transport: network)
        XCTAssertEqual(secret, Self.userSecret)
    }

    func testCancellationStopsBeforeTheNextPINRequest() async throws {
        let (network, configuration, tokens) = try makeNetwork()
        let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
        for mode in CancellingTransport.Mode.allCases {
            let transport = CancellingTransport(network: network, mode: mode)
            let task = Task { [pin = Self.pin] in
                try await recovery.recover(pin: pin, transport: transport)
            }
            do {
                _ = try await task.value
                XCTFail("expected cancellation")
            } catch is CancellationError {
                let requests = await transport.pinRequests
                XCTAssertEqual(requests, 1)
            }
        }
    }

    func testRecoverWithOneRealmDown() async throws {
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
        XCTAssertEqual(secret, Self.userSecret)
    }

    func testWrongPinReportsGuesses() async throws {
        let (network, configuration, tokens) = try makeNetwork()
        let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
        do {
            _ = try await recovery.recover(pin: Array("0000".utf8), transport: network)
            XCTFail("wrong PIN must fail")
        } catch let error as JuiceboxRecoveryError {
            XCTAssertEqual(error, .invalidPin(guessesRemaining: 4))
        }
    }

    func testMissingTokenIsInvalidAuth() async throws {
        let (network, configuration, _) = try makeNetwork()
        let recovery = JuiceboxRecovery(configuration: configuration, tokens: [:])
        do {
            _ = try await recovery.recover(pin: Self.pin, transport: network)
            XCTFail("missing tokens must fail")
        } catch let error as JuiceboxRecoveryError {
            XCTAssertEqual(error, .invalidAuth)
        }
    }

    func testTooFewRealmsIsTransientOrNotRegistered() async throws {
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
            XCTFail("too few realms must fail")
        } catch let error as JuiceboxRecoveryError {
            XCTAssertEqual(error, .transient)
        }
    }
}
