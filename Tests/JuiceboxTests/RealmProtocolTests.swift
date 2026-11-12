import XCTest

@testable import Juicebox

/// CBOR encoding, configuration parsing, and realm message framing.
final class RealmProtocolTests: XCTestCase {
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

    func testCBORIntegers() {
        XCTAssertEqual(encodeCBOR(.unsigned(0)), [0x00])
        XCTAssertEqual(encodeCBOR(.unsigned(23)), [0x17])
        XCTAssertEqual(encodeCBOR(.unsigned(24)), [0x18, 0x18])
        XCTAssertEqual(encodeCBOR(.unsigned(255)), [0x18, 0xff])
        XCTAssertEqual(encodeCBOR(.unsigned(256)), [0x19, 0x01, 0x00])
        XCTAssertEqual(encodeCBOR(.unsigned(65535)), [0x19, 0xff, 0xff])
        XCTAssertEqual(encodeCBOR(.unsigned(65536)), [0x1a, 0x00, 0x01, 0x00, 0x00])
        XCTAssertEqual(encodeCBOR(.negative(-1)), [0x20])
        XCTAssertEqual(encodeCBOR(.negative(-24)), [0x37])
        XCTAssertEqual(encodeCBOR(.negative(-25)), [0x38, 0x18])

        for value in [UInt64(0), 1, 23, 24, 255, 256, 65535, 65536, 1 << 32, UInt64.max] {
            XCTAssertEqual(try? decodeCBOR(encodeCBOR(.unsigned(value))), .unsigned(value))
        }
        for value in [Int64(-1), -24, -25, -256, -65536, Int64.min + 1] {
            XCTAssertEqual(try? decodeCBOR(encodeCBOR(.negative(value))), .negative(value))
        }
    }

    func testCBORContainers() throws {
        let value = CBORValue.map([
            CBORPair(key: .text("a"), value: .array([.unsigned(1), .bool(true), .null])),
            CBORPair(key: .text("b"), value: .bytes([0, 1, 2])),
            CBORPair(key: .text("c"), value: .negative(-3)),
        ])
        let encoded = encodeCBOR(value)
        XCTAssertEqual(try decodeCBOR(encoded), value)
        XCTAssertEqual(encodeCBOR(try decodeCBOR(encoded)), encoded)
    }

    /// The reference implementation's serialized proof: a two-entry map of
    /// byte strings.
    func testCBORReferenceProofVector() throws {
        let bytes = Self.hex(
            "a261635820ebd3f55c1a631258d69cf7a2def9de140000000000000000000000000000001066626574615f7a"
                + "5820ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        let value = try decodeCBOR(bytes)
        XCTAssertEqual(value, .map([
            CBORPair(
                key: .text("c"),
                value: .bytes(Self.hex(
                    "ebd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"))),
            CBORPair(
                key: .text("beta_z"),
                value: .bytes(Self.hex(
                    "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"))),
        ]))
        XCTAssertEqual(encodeCBOR(value), bytes)
    }

    func testCBORRejectsMalformedInput() {
        XCTAssertThrowsError(try decodeCBOR([0x18]))  // missing argument
        XCTAssertThrowsError(try decodeCBOR([0x58, 0x05, 0x00]))  // short byte string
        XCTAssertThrowsError(try decodeCBOR([0x00, 0x00]))  // trailing byte
        XCTAssertThrowsError(try decodeCBOR([0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))
        XCTAssertThrowsError(try decodeCBOR([0xff]))
        XCTAssertThrowsError(try decodeCBOR([0x5f]))  // indefinite lengths
    }

    func testCBORTagsCountTowardNestingLimit() throws {
        XCTAssertEqual(try decodeCBOR([0xc0, 0x00]), .unsigned(0))
        let tags = [UInt8](repeating: 0xc0, count: 64)
        XCTAssertThrowsError(try decodeCBOR(tags + [0x00])) { error in
            XCTAssertEqual(error as? CBORError, .depthExceeded)
        }
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

    func testConfigurationParsing() throws {
        let configuration = try JuiceboxConfiguration.parse(
            Array(Self.configurationJSON.utf8))
        XCTAssertEqual(configuration.realms.count, 3)
        XCTAssertEqual(configuration.registerThreshold, 3)
        XCTAssertEqual(configuration.recoverThreshold, 3)
        XCTAssertEqual(configuration.pinHashingMode, .standard2019)
        XCTAssertEqual(configuration.realms[0].id, Self.hex("0102030405060708090a0b0c0d0e0f10"))
        XCTAssertNotNil(configuration.realms[0].publicKey)
        XCTAssertNil(configuration.realms[1].publicKey)
        XCTAssertEqual(configuration.shareIndex(
            for: Self.hex("0102030405060708090a0b0c0d0e0f10")), 1)
        XCTAssertEqual(configuration.shareIndex(
            for: Self.hex("3102030405060708090a0b0c0d0e0f10")), 3)
    }

    func testConfigurationRejectsBadInput() {
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
            XCTAssertThrowsError(try JuiceboxConfiguration.parse(Array(json.utf8)), json)
        }
    }

    func testConfigurationRejectsBadPublicKey() {
        let json = Self.configurationJSON.replacingOccurrences(
            of: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            with: "0102")
        XCTAssertThrowsError(try JuiceboxConfiguration.parse(Array(json.utf8)))
    }

    func testConfigurationDistinguishesNullPublicKeyFromAnInvalidType() throws {
        let key = #""0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20""#
        for value in ["42", "[]", "{}", "false"] {
            let json = Self.configurationJSON.replacingOccurrences(of: key, with: value)
            XCTAssertThrowsError(try JuiceboxConfiguration.parse(Array(json.utf8)))
        }
        let json = Self.configurationJSON.replacingOccurrences(of: key, with: "null")
        let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
        XCTAssertNil(configuration.realms[0].publicKey)
    }

    // MARK: Messages

    func testSecretsRequestEncoding() {
        XCTAssertEqual(
            Self.hexString(SecretsRequest.recover1.encoded()),
            Self.hexString([0x68] + Array("Recover1".utf8)))

        let recover2 = SecretsRequest.recover2(
            version: [UInt8](repeating: 1, count: 16),
            blindedInput: [UInt8](repeating: 2, count: 32)).encoded()
        // map(1), "Recover2", map(2), "version", bytes(16), "oprf_blinded_input", bytes(32)
        XCTAssertEqual(Array(recover2[0..<10]), [0xa1, 0x68] + Array("Recover2".utf8))
        XCTAssertEqual(Array(recover2[10..<19]), [0xa2, 0x67] + Array("version".utf8))
    }

    func testSecretsResponseDecoding() throws {
        let recover1 = try SecretsResponse.decode(encodeCBOR(.map([
            CBORPair(key: .text("Recover1"), value: .map([
                CBORPair(key: .text("Ok"), value: .map([
                    CBORPair(key: .text("version"), value: .bytes([UInt8](repeating: 7, count: 16))),
                ])),
            ])),
        ])))
        XCTAssertEqual(recover1, .recover1(.ok(version: [UInt8](repeating: 7, count: 16))))

        XCTAssertEqual(
            try SecretsResponse.decode(encodeCBOR(.map([
                CBORPair(key: .text("Recover1"), value: .text("NotRegistered")),
            ]))),
            .recover1(.notRegistered))
        XCTAssertEqual(
            try SecretsResponse.decode(encodeCBOR(.map([
                CBORPair(key: .text("Recover1"), value: .text("NoGuesses")),
            ]))),
            .recover1(.noGuesses))

        let signed = CBORValue.map([
            CBORPair(key: .text("public_key"), value: .bytes([UInt8](repeating: 1, count: 32))),
            CBORPair(key: .text("verifying_key"), value: .bytes([UInt8](repeating: 2, count: 32))),
            CBORPair(key: .text("signature"), value: .bytes([UInt8](repeating: 3, count: 64))),
        ])
        let proof = CBORValue.map([
            CBORPair(key: .text("c"), value: .bytes([UInt8](repeating: 4, count: 32))),
            CBORPair(key: .text("beta_z"), value: .bytes([UInt8](repeating: 5, count: 32))),
        ])
        let recover2 = try SecretsResponse.decode(encodeCBOR(.map([
            CBORPair(key: .text("Recover2"), value: .map([
                CBORPair(key: .text("Ok"), value: .map([
                    CBORPair(key: .text("oprf_signed_public_key"), value: signed),
                    CBORPair(
                        key: .text("oprf_blinded_result"),
                        value: .bytes([UInt8](repeating: 6, count: 32))),
                    CBORPair(key: .text("oprf_proof"), value: proof),
                    CBORPair(
                        key: .text("unlock_key_commitment"),
                        value: .bytes([UInt8](repeating: 7, count: 32))),
                    CBORPair(key: .text("num_guesses"), value: .unsigned(5)),
                    CBORPair(key: .text("guess_count"), value: .unsigned(1)),
                ])),
            ])),
        ])))
        XCTAssertEqual(
            recover2,
            .recover2(.ok(
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

        let badTag = try SecretsResponse.decode(encodeCBOR(.map([
            CBORPair(key: .text("Recover3"), value: .map([
                CBORPair(key: .text("BadUnlockKeyTag"), value: .map([
                    CBORPair(key: .text("guesses_remaining"), value: .unsigned(2)),
                ])),
            ])),
        ])))
        XCTAssertEqual(badTag, .recover3(.badUnlockKeyTag(guessesRemaining: 2)))
    }

    func testPaddedSecretsResponse() throws {
        let inner = encodeCBOR(.map([
            CBORPair(key: .text("Recover1"), value: .map([
                CBORPair(key: .text("Ok"), value: .map([
                    CBORPair(key: .text("version"), value: .bytes([UInt8](repeating: 9, count: 16))),
                ])),
            ])),
        ]))
        var padded = inner
        padded += [UInt8](repeating: 0, count: PaddedSecretsResponse.maximumLength - inner.count)
        let envelope = encodeCBOR(.map([
            CBORPair(key: .text("unpadded_length"), value: .unsigned(UInt64(inner.count))),
            CBORPair(key: .text("padded_bytes"), value: .bytes(padded)),
        ]))
        let decoded = try PaddedSecretsResponse.decode(envelope)
        XCTAssertEqual(decoded.unpaddedLength, UInt16(inner.count))
        XCTAssertEqual(try decoded.unpack(), .recover1(.ok(version: [UInt8](repeating: 9, count: 16))))
    }

    func testClientRequestEncodingAndResponseDecoding() throws {
        let request = ClientRequest(
            realmId: [UInt8](repeating: 1, count: 16), authToken: "token", sessionId: 7,
            kind: .secretsRequest,
            encrypted: .transport(ciphertext: [0xaa, 0xbb]))
        let value = try decodeCBOR(request.encoded())
        XCTAssertEqual(
            value.field("auth_token"), .text("token"))
        XCTAssertEqual(value.field("session_id"), .unsigned(7))
        XCTAssertEqual(value.field("kind"), .text("SecretsRequest"))

        let handshakeResponse = encodeCBOR(.map([
            CBORPair(key: .text("Ok"), value: .map([
                CBORPair(key: .text("Handshake"), value: .map([
                    CBORPair(key: .text("handshake"), value: .map([
                        CBORPair(
                            key: .text("server_ephemeral_public"),
                            value: .bytes([UInt8](repeating: 2, count: 32))),
                        CBORPair(
                            key: .text("payload_ciphertext"), value: .bytes([9, 9])),
                    ])),
                    CBORPair(key: .text("session_lifetime"), value: .map([
                        CBORPair(key: .text("secs"), value: .unsigned(30)),
                        CBORPair(key: .text("nanos"), value: .unsigned(0)),
                    ])),
                ])),
            ])),
        ]))
        XCTAssertEqual(
            try ClientResponse.decode(handshakeResponse),
            .okHandshake(ClientResponse.Handshake(
                serverEphemeralPublic: [UInt8](repeating: 2, count: 32),
                payloadCiphertext: [9, 9], sessionLifetimeSeconds: 30,
                sessionLifetimeNanos: 0)))
        XCTAssertEqual(
            try ClientResponse.decode(encodeCBOR(.text("InvalidAuth"))), .invalidAuth)
        XCTAssertEqual(
            try ClientResponse.decode(encodeCBOR(.map([
                CBORPair(key: .text("Ok"), value: .map([
                    CBORPair(key: .text("Transport"), value: .map([
                        CBORPair(key: .text("ciphertext"), value: .bytes([1, 2, 3])),
                    ])),
                ])),
            ]))),
            .okTransport(ciphertext: [1, 2, 3]))
    }
}
