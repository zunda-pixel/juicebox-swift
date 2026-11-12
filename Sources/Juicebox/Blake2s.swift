import BlakeHash
import Foundation

enum Blake2s {
    static func hash(_ data: [UInt8]) -> [UInt8] {
        Array(BLAKE2s.hash(Data(data)))
    }

    static func mac(key: [UInt8], message: [UInt8], outputLength: Int = 32) -> [UInt8] {
        Array(BLAKE2s.hash(Data(message), digestLength: outputLength, key: Data(key)))
    }
}

/// HMAC-BLAKE2s-256 (RFC 2104 over BLAKE2s), which Noise's key derivation
/// uses.
func hmacBlake2s(key: [UInt8], message: [UInt8]) -> [UInt8] {
    var paddedKey = key.count > 64 ? Blake2s.hash(key) : key
    if paddedKey.count < 64 {
        paddedKey.append(contentsOf: [UInt8](repeating: 0, count: 64 - paddedKey.count))
    }
    let inner = paddedKey.map { $0 ^ 0x36 }
    let outer = paddedKey.map { $0 ^ 0x5c }
    return Blake2s.hash(outer + Blake2s.hash(inner + message))
}

/// HKDF with HMAC-BLAKE2s, as Noise instantiates it: extract with the
/// chaining key as salt, then expand without info.
func hkdfBlake2s(salt: [UInt8], ikm: [UInt8], length: Int) -> [UInt8] {
    let prk = hmacBlake2s(key: salt, message: ikm)
    var output: [UInt8] = []
    var previous: [UInt8] = []
    var counter: UInt8 = 1
    while output.count < length {
        previous = hmacBlake2s(key: prk, message: previous + [counter])
        output.append(contentsOf: previous)
        counter &+= 1
    }
    return Array(output.prefix(length))
}

extension UInt32 {
    var leBytes: [UInt8] {
        [
            UInt8(truncatingIfNeeded: self),
            UInt8(truncatingIfNeeded: self >> 8),
            UInt8(truncatingIfNeeded: self >> 16),
            UInt8(truncatingIfNeeded: self >> 24),
        ]
    }

    func rotatedRight(_ amount: UInt32) -> UInt32 {
        (self &>> amount) | (self &<< ((32 &- amount) & 31))
    }
}
