import CBOR
import Foundation
import Testing

@testable import Juicebox

/// CBOR encoding, configuration parsing, and realm message framing.
struct RealmProtocolTests {
    private static func hex(_ string: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            out.append(UInt8(string[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private static func hexString(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var chars: [UInt8] = []
        for byte in bytes {
            chars.append(digits[Int(byte >> 4)])
            chars.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: chars, as: UTF8.self)
    }

    @Test func cborIntegers() throws {
        #expect(CBOR.unsignedInt(0).encode() == [0x00])
        #expect(CBOR.unsignedInt(23).encode() == [0x17])
        #expect(CBOR.unsignedInt(24).encode() == [0x18, 0x18])
        #expect(CBOR.unsignedInt(255).encode() == [0x18, 0xff])
        #expect(CBOR.unsignedInt(256).encode() == [0x19, 0x01, 0x00])
        #expect(CBOR.unsignedInt(65535).encode() == [0x19, 0xff, 0xff])
        #expect(CBOR.unsignedInt(65536).encode() == [0x1a, 0x00, 0x01, 0x00, 0x00])
        #expect(CBOR.negativeInt(0).encode() == [0x20])
        #expect(CBOR.negativeInt(23).encode() == [0x37])
        #expect(CBOR.negativeInt(24).encode() == [0x38, 0x18])

        for value in [UInt64(0), 1, 23, 24, 255, 256, 65535, 65536, 1 << 32, UInt64.max] {
            #expect(try decodeCBOR(CBOR.unsignedInt(value).encode()) == .unsignedInt(value))
        }
        for value in [Int64(-1), -24, -25, -256, -65536, Int64.min + 1] {
            #expect(try decodeCBOR(CBOR.negativeInt(UInt64(-1 - value)).encode()) == .negativeInt(UInt64(-1 - value)))
        }
    }

    @Test func cborContainers() throws {
        let value = CBOR.map([
            "a": .array([.unsignedInt(1), .bool(true), .null]),
            "b": .byteString([0, 1, 2]),
            "c": .negativeInt(2),
        ])
        let encoded = value.encode()
        #expect(try decodeCBOR(encoded) == value)
        #expect((try decodeCBOR(encoded)).encode() == encoded)
    }

    /// The reference implementation's serialized proof: a two-entry map of
    /// byte strings.
    @Test func cborReferenceProofVector() throws {
        let bytes = Self.hex(
            "a261635820ebd3f55c1a631258d69cf7a2def9de140000000000000000000000000000001066626574615f7a"
                + "5820ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        let value = try decodeCBOR(bytes)
        #expect(
            value
                == .map([
                    "c": .byteString(
                            Self.hex(
                                "ebd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")),
                    "beta_z": .byteString(
                            Self.hex(
                                "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")),
                ]))
        #expect(value.encode() == bytes)
    }

    @Test func cborRejectsMalformedInput() {
        #expect(throws: CBORError.self) { _ = try decodeCBOR([0x18]) }  // missing argument
        #expect(throws: CBORError.self) { _ = try decodeCBOR([0x58, 0x05, 0x00]) }  // short byte string
        #expect(throws: CBORError.self) { _ = try decodeCBOR([0x00, 0x00]) }  // trailing byte
        #expect(throws: CBORError.self) {
            _ = try decodeCBOR([0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        }
        #expect(throws: CBORError.self) { _ = try decodeCBOR([0xff]) }
        #expect(throws: CBORError.self) { _ = try decodeCBOR([0x5f]) }  // indefinite lengths
    }

    @Test func cborTagsCountTowardNestingLimit() throws {
        #expect(try decodeCBOR([0xc0, 0x00]) == .unsignedInt(0))
        let tags = [UInt8](repeating: 0xc0, count: 64)
        #expect(throws: CBORError.maxDepthExceeded(31)) { _ = try decodeCBOR(tags + [0x00]) }
    }

    @Test func cborRejectsDuplicateMapKeys() {
        let duplicateKeys: [UInt8] = [0xa2, 0x61, 0x78, 0x01, 0x61, 0x78, 0x02]
        let taggedDuplicate: [UInt8] = [0xa2, 0x61, 0x78, 0x01, 0xc0, 0x61, 0x78, 0x02]
        for bytes in [duplicateKeys, taggedDuplicate] {
            #expect(throws: CBORError.duplicateMapKey) { _ = try decodeCBOR(bytes) }
        }
    }

    @Test func cborRejectsOversizedResponses() {
        let bytes = [UInt8](repeating: 0, count: 64 * 1024 + 1)
        #expect(throws: RealmMessageError.malformed) { _ = try decodeCBOR(bytes) }
    }

    // MARK: Configuration

    static let configurationJSON = """
        {
          "realms": [
            {
              "id": "0102030405060708090a0b0c0d0e0f10",
              "address": "https://juicebox.hsm.realm.address/",
              "public_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            },
            {
              "id": "2102030405060708090a0b0c0d0e0f10",
              "address": "https://your.software.realm.address/"
            },
            {
              "id": "3102030405060708090a0b0c0d0e0f10",
              "address": "https://juicebox.software.realm.address/"
            }
          ],
          "register_threshold": 3,
          "recover_threshold": 3,
          "pin_hashing_mode": "Standard2019"
        }
        """

    @Test func configurationParsing() throws {
        let configuration = try JuiceboxConfiguration.parse(
            Array(Self.configurationJSON.utf8))
        #expect(configuration.realms.count == 3)
        #expect(configuration.registerThreshold == 3)
        #expect(configuration.recoverThreshold == 3)
        #expect(configuration.pinHashingMode == .standard2019)
        #expect(configuration.realms[0].id == Self.hex("0102030405060708090a0b0c0d0e0f10"))
        #expect(configuration.realms[0].publicKey != nil)
        #expect(configuration.realms[1].publicKey == nil)
        #expect(
            configuration.shareIndex(
                for: Self.hex("0102030405060708090a0b0c0d0e0f10")) == 1)
        #expect(
            configuration.shareIndex(
                for: Self.hex("3102030405060708090a0b0c0d0e0f10")) == 3)
    }

    @Test func configurationRejectsBadInput() {
        let duplicateIds = Self.configurationJSON.replacingOccurrences(
            of: "\"id\": \"2102030405060708090a0b0c0d0e0f10\"",
            with: "\"id\": \"0102030405060708090a0b0c0d0e0f10\"")
        let bad = [
            "{}",
            #"{"realms":[]}"#,
            Self.configurationJSON.replacingOccurrences(
                of: #""recover_threshold": 3"#, with: #""recover_threshold": 1"#),
            Self.configurationJSON.replacingOccurrences(
                of: #""pin_hashing_mode": "Standard2019""#,
                with: #""pin_hashing_mode": "MD5""#),
            duplicateIds,
            Self.configurationJSON.replacingOccurrences(
                of: "\"id\": \"3102030405060708090a0b0c0d0e0f10\"",
                with: "\"id\": \"31\""),
        ]
        for json in bad {
            #expect(throws: JuiceboxConfigurationError.self, Comment(rawValue: json)) {
                _ = try JuiceboxConfiguration.parse(Array(json.utf8))
            }
        }
    }

    @Test func configurationRejectsBadPublicKey() {
        let json = Self.configurationJSON.replacingOccurrences(
            of: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            with: "0102")
        #expect(throws: JuiceboxConfigurationError.self) {
            _ = try JuiceboxConfiguration.parse(Array(json.utf8))
        }
    }

    @Test func configurationDistinguishesNullPublicKeyFromAnInvalidType() throws {
        let key = #""0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20""#
        for value in ["42", "[]", "{}", "false"] {
            let json = Self.configurationJSON.replacingOccurrences(of: key, with: value)
            #expect(throws: JuiceboxConfigurationError.self) {
                _ = try JuiceboxConfiguration.parse(Array(json.utf8))
            }
        }
        let json = Self.configurationJSON.replacingOccurrences(of: key, with: "null")
        let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
        #expect(configuration.realms[0].publicKey == nil)
    }

    // MARK: Messages

    @Test func secretsRequestEncoding() {
        #expect(
            Self.hexString(SecretsRequest.recover1.encoded())
                == Self.hexString([0x68] + Array("Recover1".utf8)))

        let recover2 = SecretsRequest.recover2(
            version: [UInt8](repeating: 1, count: 16),
            blindedInput: [UInt8](repeating: 2, count: 32)
        ).encoded()
        // map(1), "Recover2", map(2), "version", bytes(16), "oprf_blinded_input", bytes(32)
        #expect(Array(recover2[0..<10]) == [0xa1, 0x68] + Array("Recover2".utf8))
        #expect(Array(recover2[10..<19]) == [0xa2, 0x67] + Array("version".utf8))
    }

    @Test func secretsResponseDecoding() throws {
        let recover1 = try SecretsResponse.decode(
            CBOR.map([
                    "Recover1": .map([
                            "Ok": .map([
                                    "version": .byteString([UInt8](repeating: 7, count: 16))
                                ])
                        ])
                ]).encode())
        #expect(recover1 == .recover1(.ok(version: [UInt8](repeating: 7, count: 16))))

        #expect(
            try SecretsResponse.decode(
                CBOR.map([
                        "Recover1": .textString("NotRegistered")
                    ]).encode()) == .recover1(.notRegistered))
        #expect(
            try SecretsResponse.decode(
                CBOR.map([
                        "Recover1": .textString("NoGuesses")
                    ]).encode()) == .recover1(.noGuesses))

        let signed = CBOR.map([
            "public_key": .byteString([UInt8](repeating: 1, count: 32)),
            "verifying_key": .byteString([UInt8](repeating: 2, count: 32)),
            "signature": .byteString([UInt8](repeating: 3, count: 64)),
        ])
        let proof = CBOR.map([
            "c": .byteString([UInt8](repeating: 4, count: 32)),
            "beta_z": .byteString([UInt8](repeating: 5, count: 32)),
        ])
        let recover2 = try SecretsResponse.decode(
            CBOR.map([
                    "Recover2": .map([
                            "Ok": .map([
                                    "oprf_signed_public_key": signed,
                                    "oprf_blinded_result": .byteString([UInt8](repeating: 6, count: 32)),
                                    "oprf_proof": proof,
                                    "unlock_key_commitment": .byteString([UInt8](repeating: 7, count: 32)),
                                    "num_guesses": .unsignedInt(5),
                                    "guess_count": .unsignedInt(1),
                                ])
                        ])
                ]).encode())
        #expect(
            recover2
                == .recover2(
                    .ok(
                        signedPublicKey: OPRFSignedPublicKey(
                            publicKey: [UInt8](repeating: 1, count: 32),
                            verifyingKey: [UInt8](repeating: 2, count: 32),
                            signature: [UInt8](repeating: 3, count: 64)),
                        blindedResult: [UInt8](repeating: 6, count: 32),
                        proof: OPRFProofFields(
                            c: [UInt8](repeating: 4, count: 32),
                            betaZ: [UInt8](repeating: 5, count: 32)),
                        unlockKeyCommitment: [UInt8](repeating: 7, count: 32),
                        numGuesses: 5, guessCount: 1)))

        let badTag = try SecretsResponse.decode(
            CBOR.map([
                    "Recover3": .map([
                            "BadUnlockKeyTag": .map([
                                    "guesses_remaining": .unsignedInt(2)
                                ])
                        ])
                ]).encode())
        #expect(badTag == .recover3(.badUnlockKeyTag(guessesRemaining: 2)))
    }

    @Test func paddedSecretsResponse() throws {
        let inner = CBOR.map([
                "Recover1": .map([
                        "Ok": .map([
                                "version": .byteString([UInt8](repeating: 9, count: 16))
                            ])
                    ])
            ]).encode()
        var padded = inner
        padded += [UInt8](repeating: 0, count: PaddedSecretsResponse.maximumLength - inner.count)
        let envelope = CBOR.map([
                "unpadded_length": .unsignedInt(UInt64(inner.count)),
                "padded_bytes": .byteString(padded),
            ]).encode()
        let decoded = try PaddedSecretsResponse.decode(envelope)
        #expect(decoded.unpaddedLength == UInt16(inner.count))
        #expect(try decoded.unpack() == .recover1(.ok(version: [UInt8](repeating: 9, count: 16))))
    }

    @Test func clientRequestEncodingAndResponseDecoding() throws {
        let request = ClientRequest(
            realmId: [UInt8](repeating: 1, count: 16), authToken: "token", sessionId: 7,
            kind: .secretsRequest,
            encrypted: .transport(ciphertext: [0xaa, 0xbb]))
        let value = try decodeCBOR(request.encoded())
        #expect(
            value["auth_token"] == .textString("token"))
        #expect(value["session_id"] == .unsignedInt(7))
        #expect(value["kind"] == .textString("SecretsRequest"))

        let handshakeResponse = CBOR.map([
                "Ok": .map([
                        "Handshake": .map([
                                "handshake": .map([
                                        "server_ephemeral_public": .byteString([UInt8](repeating: 2, count: 32)),
                                        "payload_ciphertext": .byteString([9, 9]),
                                    ]),
                                "session_lifetime": .map([
                                        "secs": .unsignedInt(30),
                                        "nanos": .unsignedInt(0),
                                    ]),
                            ])
                    ])
            ]).encode()
        #expect(
            try ClientResponse.decode(handshakeResponse)
                == .okHandshake(
                    ClientResponse.Handshake(
                        serverEphemeralPublic: [UInt8](repeating: 2, count: 32),
                        payloadCiphertext: [9, 9], sessionLifetimeSeconds: 30,
                        sessionLifetimeNanos: 0)))
        #expect(
            try ClientResponse.decode(CBOR.textString("InvalidAuth").encode()) == .invalidAuth)
        #expect(
            try ClientResponse.decode(
                CBOR.map([
                        "Ok": .map([
                                "Transport": .map([
                                        "ciphertext": .byteString([1, 2, 3])
                                    ])
                            ])
                    ]).encode()) == .okTransport(ciphertext: [1, 2, 3]))
    }
}
