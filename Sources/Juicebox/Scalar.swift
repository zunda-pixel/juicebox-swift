import _Clibsodium

/// A canonical little-endian scalar modulo the Ristretto255 group order.
struct RistrettoScalar: Sendable, Equatable {
    let bytes: [UInt8]

    static let zero = Self(bytes: [UInt8](repeating: 0, count: 32))
    static let one = Self(bytes: [1] + [UInt8](repeating: 0, count: 31))

    private init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    init?(canonicalBytes: [UInt8]) {
        guard canonicalBytes.count == 32 else { return nil }
        let reduced = Self.fromBytesWide(canonicalBytes + Self.zero.bytes)
        guard unsafe sodium_memcmp(reduced.bytes, canonicalBytes, 32) == 0 else { return nil }
        self = reduced
    }

    static func fromBytesWide(_ bytes: [UInt8]) -> Self {
        precondition(bytes.count == 64)
        var scalar = Self.zero.bytes
        unsafe crypto_core_ristretto255_scalar_reduce(&scalar, bytes)
        return Self(bytes: scalar)
    }

    static func random() -> Self {
        var scalar = Self.zero.bytes
        unsafe crypto_core_ristretto255_scalar_random(&scalar)
        return Self(bytes: scalar)
    }

    var isZero: Bool {
        unsafe sodium_is_zero(bytes, bytes.count) == 1
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        unsafe sodium_memcmp(lhs.bytes, rhs.bytes, 32) == 0
    }

    static func + (lhs: Self, rhs: Self) -> Self {
        var result = Self.zero.bytes
        unsafe crypto_core_ristretto255_scalar_add(&result, lhs.bytes, rhs.bytes)
        return Self(bytes: result)
    }

    static func - (lhs: Self, rhs: Self) -> Self {
        var result = Self.zero.bytes
        unsafe crypto_core_ristretto255_scalar_sub(&result, lhs.bytes, rhs.bytes)
        return Self(bytes: result)
    }

    static func * (lhs: Self, rhs: Self) -> Self {
        var result = Self.zero.bytes
        unsafe crypto_core_ristretto255_scalar_mul(&result, lhs.bytes, rhs.bytes)
        return Self(bytes: result)
    }

    func invert() -> Self {
        var result = Self.zero.bytes
        let status = unsafe crypto_core_ristretto255_scalar_invert(&result, bytes)
        precondition(status == 0)
        return Self(bytes: result)
    }
}
