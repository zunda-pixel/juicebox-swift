import Testing

@testable import Juicebox

/// The OPRF client flow against a locally played server: blinding and
/// unblinding must recover the unoblivious evaluation, and the DLEQ proof must
/// bind the result to the public key.
struct OPRFTests {
    init() throws {
        try #require(juiceboxSodiumIsReady)
    }

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

    /// Values computed modulo ℓ with plain integer arithmetic.
    @Test func scalarInverse() {
        let a = RistrettoScalar(
            canonicalBytes: Self.hex("d20a1feb8ca954ab000000000000000000000000000000000000000000000000"))!
        #expect(
            Self.hexString(a.invert().bytes)
                == "cba0dad3040690be498d79ec4da6be70902b211b7764b03a5444163bdd803b0d")
        #expect(a * a.invert() == .one)

        let b = RistrettoScalar(
            canonicalBytes: Self.hex("b10cc7e1389df8ffc2d9203f0100000000000000000000000000000000000000"))!
        #expect(
            Self.hexString(b.invert().bytes)
                == "98b81d8edb199bb35349fb2f95c3bbd3a246b91fbaf6901f263c0d3a85fbaf09")
    }

    @Test func blindEvaluateFinalizeMatchesUnoblivious() {
        let input = Array("user secret input".utf8)
        let privateKey = RistrettoScalar(
            canonicalBytes: Self.hex("d20a1feb8ca954ab000000000000000000000000000000000000000000000000"))!
        let blinding = RistrettoScalar(
            canonicalBytes: Self.hex("b10cc7e1389df8ffc2d9203f0100000000000000000000000000000000000000"))!
        let publicKey = OPRF.publicKey(for: privateKey)

        let (factor, blindedInput) = OPRF.start(input: input, blindingFactor: blinding)
        let blindedOutput = OPRF.evaluate(privateKey: privateKey, blindedInput: blindedInput)

        let nonce = RistrettoScalar.fromBytesWide(
            Self.hex("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0")
                + RistrettoScalar.zero.bytes)
        let proof = OPRF.generateProof(
            privateKey: privateKey, nonce: nonce, blindedInput: blindedInput,
            publicKey: publicKey, blindedOutput: blindedOutput)
        #expect(
            OPRF.verifyProof(
                blindedInput: blindedInput, blindedOutput: blindedOutput,
                publicKey: publicKey, proof: proof))

        let output = OPRF.finalize(
            input: input, blindingFactor: factor, blindedOutput: blindedOutput)
        #expect(output.count == 64)
        #expect(output == OPRF.unobliviousEvaluate(privateKey: privateKey, input: input))
    }

    @Test func proofRejectsWrongValues() {
        let privateKey = RistrettoScalar.random()
        let publicKey = OPRF.publicKey(for: privateKey)
        let (_, blindedInput) = OPRF.start(input: Array("input".utf8))
        let blindedOutput = OPRF.evaluate(privateKey: privateKey, blindedInput: blindedInput)
        let proof = OPRF.generateProof(
            privateKey: privateKey, nonce: .random(), blindedInput: blindedInput,
            publicKey: publicKey, blindedOutput: blindedOutput)

        #expect(
            OPRF.verifyProof(
                blindedInput: blindedInput, blindedOutput: blindedOutput,
                publicKey: publicKey, proof: proof))

        let (_, otherInput) = OPRF.start(input: Array("other".utf8))
        #expect(
            !OPRF.verifyProof(
                blindedInput: otherInput, blindedOutput: blindedOutput,
                publicKey: publicKey, proof: proof))

        let otherOutput = OPRF.evaluate(
            privateKey: .random(), blindedInput: blindedInput)
        #expect(
            !OPRF.verifyProof(
                blindedInput: blindedInput, blindedOutput: otherOutput,
                publicKey: publicKey, proof: proof))

        let otherPublicKey = OPRF.publicKey(for: .random())
        #expect(
            !OPRF.verifyProof(
                blindedInput: blindedInput, blindedOutput: blindedOutput,
                publicKey: otherPublicKey, proof: proof))

        let tampered = OPRF.Proof(c: proof.c + .one, betaZ: proof.betaZ)
        #expect(
            !OPRF.verifyProof(
                blindedInput: blindedInput, blindedOutput: blindedOutput,
                publicKey: publicKey, proof: tampered))

        #expect(
            !OPRF.verifyProof(
                blindedInput: blindedInput, blindedOutput: blindedOutput,
                publicKey: [UInt8](repeating: 0, count: 32), proof: proof))
    }

    @Test func proofWireForm() throws {
        let c = RistrettoScalar(
            canonicalBytes: Self.hex("d20a1feb8ca954ab000000000000000000000000000000000000000000000000"))!
        let betaZ = RistrettoScalar(
            canonicalBytes: Self.hex("b10cc7e1389df8ffc2d9203f0100000000000000000000000000000000000000"))!
        let proof = OPRF.Proof(c: c, betaZ: betaZ)
        #expect(proof.bytes.count == 64)
        let decoded = try OPRF.Proof(bytes: proof.bytes)
        #expect(decoded.c == c)
        #expect(decoded.betaZ == betaZ)

        let groupOrder = Self.hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        #expect(throws: OPRFError.invalidProof) { _ = try OPRF.Proof(bytes: groupOrder + betaZ.bytes) }
    }

    @Test func blindedPointsRoundTrip() throws {
        let privateKey = RistrettoScalar.random()
        let (_, input) = OPRF.start(input: Array("round trip".utf8))
        let output = OPRF.evaluate(privateKey: privateKey, blindedInput: input)
        #expect(try OPRF.BlindedInput(compressed: input.compressed).compressed == input.compressed)
        #expect(
            try OPRF.BlindedOutput(compressed: output.compressed).compressed == output.compressed)
        #expect(throws: OPRFError.self) {
            _ = try OPRF.BlindedInput(compressed: [UInt8](repeating: 0xff, count: 32))
        }
    }
}
