import XCTest

@testable import Juicebox

/// BLAKE2s against RFC 7693, and the Noise NK client against the official
/// Noise test vectors (`Noise_NK_25519_ChaChaPoly_BLAKE2s`).
final class JuiceboxTests: XCTestCase {
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

    func testBlake2sKnownAnswers() {
        XCTAssertEqual(
            Self.hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
            Blake2s.hash(Array("abc".utf8)))
        XCTAssertEqual(
            Self.hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            Blake2s.hash([]))
    }

    /// The reference implementation's PIN vector (`pin.rs`): PIN "1234",
    /// registration version `[5; 16]`, user info "artemis".
    func testJuiceboxPinHashVector() throws {
        let (accessKey, seed) = try juiceboxPinHash(
            pin: Array("1234".utf8),
            registrationVersion: [UInt8](repeating: 5, count: 16),
            userInfo: Array("artemis".utf8))
        XCTAssertEqual(
            Self.hexString(accessKey),
            "2935da84c97423b37f3457231b877ce6ac2093501d7255dbee1deb09a5d8821b")
        XCTAssertEqual(
            Self.hexString(seed),
            "87c8c9b5d3ea9fea83b6ac6a64e25b97c4722ca4e40bea2523efea262125e22a")
    }

    // MARK: Noise

    /// Each vector fixes the client ephemeral and the server keys, so the
    /// handshake bytes and transport frames are checked exactly.
    func testNoiseNKVectors() throws {
        let vectors = try loadVectors()
        XCTAssertFalse(vectors.isEmpty)

        for (index, vector) in vectors.enumerated() {
            let serverStatic = Self.hex(vector.serverStaticPublic)
            let prologue = Self.hex(vector.prologue)
            let messages = vector.messages
            XCTAssertGreaterThanOrEqual(messages.count, 2, "vector \(index)")

            let (handshake, request) = try NoiseNK.Handshake.start(
                serverStaticPublic: serverStatic,
                prologue: prologue,
                payload: Self.hex(messages[0].payload),
                ephemeralSecret: Self.hex(vector.clientEphemeralSecret))

            // The first message is the client ephemeral followed by the
            // encrypted payload.
            XCTAssertEqual(
                request.clientEphemeralPublic + request.payloadCiphertext,
                Self.hex(messages[0].ciphertext), "vector \(index) message 0")

            let serverMessage = Self.hex(messages[1].ciphertext)
            let response = NoiseNK.HandshakeResponse(
                serverEphemeralPublic: Array(serverMessage[0..<32]),
                payloadCiphertext: Array(serverMessage[32...]))
            var (transport, payload) = try handshake.finish(response)
            XCTAssertEqual(payload, Self.hex(messages[1].payload), "vector \(index) message 1")

            // Messages after the handshake alternate client-to-server and
            // server-to-client, starting with the client.
            var clientSends = true
            for message in messages.dropFirst(2) {
                if clientSends {
                    XCTAssertEqual(
                        try transport.encrypt(Self.hex(message.payload)),
                        Self.hex(message.ciphertext), "vector \(index)")
                } else {
                    XCTAssertEqual(
                        try transport.decrypt(Self.hex(message.ciphertext)),
                        Self.hex(message.payload), "vector \(index)")
                }
                clientSends.toggle()
            }
        }
    }

    // MARK: Fixture

    private struct Vector: Decodable {
        struct Message: Decodable {
            let payload: String
            let ciphertext: String
        }

        let prologue: String
        let clientEphemeralSecret: String
        let serverStaticPublic: String
        let serverEphemeralSecret: String
        let messages: [Message]
    }

    private struct VectorFile: Decodable {
        let vectors: [Vector]
    }

    private func loadVectors() throws -> [Vector] {
        guard
            let url = Bundle.module.url(
                forResource: "noise_nk_vectors", withExtension: "json"),
            let data = try? Data(contentsOf: url)
        else {
            throw XCTSkip("noise_nk_vectors.json is missing from the test bundle")
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(VectorFile.self, from: data).vectors
    }
}
