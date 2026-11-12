import Crypto

/// Juicebox's verifiable OPRF over Ristretto255. The client blinds its input,
/// the realm evaluates with its private key and proves the result, and the
/// client verifies the proof before unblinding.
enum OPRF {
    static let outputDomain = Array("Juicebox_OPRF_2023_1;".utf8)
    static let proofDomain = Array("Juicebox_DLEQ_2023_1;".utf8)

    struct BlindingFactor: Sendable {
        var scalar: RistrettoScalar
    }

    struct BlindedInput: Sendable {
        var point: RistrettoPoint

        var compressed: [UInt8] { point.compress() }

        init(compressed: [UInt8]) throws {
            guard let point = RistrettoPoint.decompress(compressed) else {
                throw OPRFError.invalidPoint
            }
            self.point = point
        }

        init(point: RistrettoPoint) {
            self.point = point
        }
    }

    struct BlindedOutput: Sendable {
        var point: RistrettoPoint

        var compressed: [UInt8] { point.compress() }

        init(compressed: [UInt8]) throws {
            guard let point = RistrettoPoint.decompress(compressed) else {
                throw OPRFError.invalidPoint
            }
            self.point = point
        }

        init(point: RistrettoPoint) {
            self.point = point
        }
    }

    struct Proof: Sendable {
        var c: RistrettoScalar
        var betaZ: RistrettoScalar

        /// The wire form is two 32-byte scalars.
        var bytes: [UInt8] { c.bytes + betaZ.bytes }

        init(c: RistrettoScalar, betaZ: RistrettoScalar) {
            self.c = c
            self.betaZ = betaZ
        }

        init(bytes: [UInt8]) throws {
            guard bytes.count == 64 else { throw OPRFError.invalidProof }
            guard let challenge = RistrettoScalar(canonicalBytes: Array(bytes.prefix(32))),
                let response = RistrettoScalar(canonicalBytes: Array(bytes.suffix(32)))
            else { throw OPRFError.invalidProof }
            self.init(c: challenge, betaZ: response)
        }
    }

    // MARK: Client

    /// Starts the OPRF: hashes the input to the group and blinds it.
    static func start(input: [UInt8]) -> (BlindingFactor, BlindedInput) {
        start(input: input, blindingFactor: .random())
    }

    static func start(
        input: [UInt8], blindingFactor: RistrettoScalar
    ) -> (BlindingFactor, BlindedInput) {
        let inputPoint = RistrettoPoint.hashToGroup(input)
        let blinded = inputPoint.scalarMultiply(blindingFactor)
        return (BlindingFactor(scalar: blindingFactor), BlindedInput(point: blinded))
    }

    /// Unblinds the realm's result and derives the 64-byte OPRF output.
    static func finalize(
        input: [UInt8], blindingFactor: BlindingFactor, blindedOutput: BlindedOutput
    ) -> [UInt8] {
        let result = blindedOutput.point.scalarMultiply(blindingFactor.scalar.invert())
        return hashToOutput(input: input, result: result)
    }

    /// Verifies the DLEQ proof that the realm evaluated with the private key
    /// behind `publicKey`.
    static func verifyProof(
        blindedInput: BlindedInput,
        blindedOutput: BlindedOutput,
        publicKey: [UInt8],
        proof: Proof
    ) -> Bool {
        guard let publicPoint = RistrettoPoint.decompress(publicKey) else { return false }

        let vT = RistrettoPoint.basepoint.scalarMultiply(proof.betaZ)
            - publicPoint.scalarMultiply(proof.c)
        let wT = blindedInput.point.scalarMultiply(proof.betaZ)
            - blindedOutput.point.scalarMultiply(proof.c)
        let expected = challenge(
            u: blindedInput.compressed, v: publicKey, w: blindedOutput.compressed,
            vT: vT.compress(), wT: wT.compress())
        return expected == proof.c
    }

    // MARK: Server (used by tests and non-interactive paths)

    static func publicKey(for privateKey: RistrettoScalar) -> [UInt8] {
        RistrettoPoint.basepoint.scalarMultiply(privateKey).compress()
    }

    static func evaluate(
        privateKey: RistrettoScalar, blindedInput: BlindedInput
    ) -> BlindedOutput {
        BlindedOutput(point: blindedInput.point.scalarMultiply(privateKey))
    }

    static func generateProof(
        privateKey: RistrettoScalar,
        nonce: RistrettoScalar,
        blindedInput: BlindedInput,
        publicKey: [UInt8],
        blindedOutput: BlindedOutput
    ) -> Proof {
        let vT = RistrettoPoint.basepoint.scalarMultiply(nonce)
        let wT = blindedInput.point.scalarMultiply(nonce)
        let c = challenge(
            u: blindedInput.compressed, v: publicKey, w: blindedOutput.compressed,
            vT: vT.compress(), wT: wT.compress())
        let betaZ = nonce + privateKey * c
        return Proof(c: c, betaZ: betaZ)
    }

    /// Evaluates locally, giving the same output as a full interaction.
    static func unobliviousEvaluate(
        privateKey: RistrettoScalar, input: [UInt8]
    ) -> [UInt8] {
        let result = RistrettoPoint.hashToGroup(input).scalarMultiply(privateKey)
        return hashToOutput(input: input, result: result)
    }

    // MARK: Hashing

    private static func hashToOutput(input: [UInt8], result: RistrettoPoint) -> [UInt8] {
        var data = outputDomain
        data += input
        data += result.compress()
        return Array(SHA512.hash(data: data))
    }

    private static func challenge(
        u: [UInt8], v: [UInt8], w: [UInt8], vT: [UInt8], wT: [UInt8]
    ) -> RistrettoScalar {
        var data = proofDomain
        data += u
        data += v
        data += w
        data += vT
        data += wT
        return RistrettoScalar.fromBytesWide(Array(SHA512.hash(data: data)))
    }
}

enum OPRFError: Error, Equatable {
    case invalidPoint
    case invalidProof
}
