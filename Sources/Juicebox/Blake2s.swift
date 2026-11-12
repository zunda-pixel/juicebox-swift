import BlakeHash
import Crypto
import Foundation

enum Blake2s {
    static func hash(_ data: [UInt8]) -> [UInt8] {
        Array(BLAKE2s.hash(Data(data)))
    }

    static func mac(key: [UInt8], message: [UInt8], outputLength: Int = 32) -> [UInt8] {
        Array(BLAKE2s.hash(Data(message), digestLength: outputLength, key: Data(key)))
    }
}

/// Noise uses HKDF-HMAC-BLAKE2s with the chaining key as salt and empty info.
func hkdfBlake2s(salt: [UInt8], ikm: [UInt8], length: Int) -> [UInt8] {
    let key = HKDF<Blake2sHash>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: ikm),
        salt: salt,
        info: [UInt8](),
        outputByteCount: length
    )
    return unsafe key.withUnsafeBytes { unsafe Array($0) }
}

private struct Blake2sHash: HashFunction {
    static let blockByteCount = 64

    private var hasher = BLAKE2s.Hasher()

    init() {}

    mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        hasher.update(unsafe Data(bufferPointer))
    }

    func finalize() -> Blake2sDigest {
        var copy = hasher
        return Blake2sDigest(bytes: Array(copy.finalize()))
    }
}

private struct Blake2sDigest: Digest {
    static let byteCount = 32

    var bytes: [UInt8]

    var description: String {
        bytes.map { byte in
            let hex = String(byte, radix: 16)
            return byte < 16 ? "0" + hex : hex
        }.joined()
    }

    func makeIterator() -> Array<UInt8>.Iterator {
        bytes.makeIterator()
    }

    func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
    ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
    }
}
