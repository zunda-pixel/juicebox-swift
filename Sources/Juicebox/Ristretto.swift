import Crypto
import _Clibsodium

struct RistrettoPoint: Sendable, Equatable {
    private var bytes: [UInt8]

    static let identity = Self(bytes: [UInt8](repeating: 0, count: 32))
    static let basepoint = Self.makeBasepoint()

    private static func makeBasepoint() -> Self {
        var point = identity.bytes
        let status = unsafe crypto_scalarmult_ristretto255_base(&point, RistrettoScalar.one.bytes)
        precondition(status == 0)
        return Self(bytes: point)
    }

    func compress() -> [UInt8] { bytes }

    static func decompress(_ bytes: [UInt8]) -> Self? {
        guard bytes.count == 32, bytes[31] < 0x80,
            unsafe crypto_core_ristretto255_is_valid_point(bytes) == 1
        else {
            return nil
        }
        return Self(bytes: bytes)
    }

    static func fromUniformBytes(_ bytes: [UInt8]) -> Self {
        precondition(bytes.count == 64)
        var point = identity.bytes
        let status = unsafe crypto_core_ristretto255_from_hash(&point, bytes)
        precondition(status == 0)
        return Self(bytes: point)
    }

    static func hashToGroup(_ input: [UInt8]) -> Self {
        fromUniformBytes(Array(SHA512.hash(data: input)))
    }

    static func + (lhs: Self, rhs: Self) -> Self {
        var result = identity.bytes
        let status = unsafe crypto_core_ristretto255_add(&result, lhs.bytes, rhs.bytes)
        precondition(status == 0)
        return Self(bytes: result)
    }

    static func - (lhs: Self, rhs: Self) -> Self {
        var result = identity.bytes
        let status = unsafe crypto_core_ristretto255_sub(&result, lhs.bytes, rhs.bytes)
        precondition(status == 0)
        return Self(bytes: result)
    }

    func scalarMultiply(_ scalar: RistrettoScalar) -> Self {
        // libsodium rejects the identity output. Interpolation and proof
        // verification still need multiplication by zero in the group.
        var result = Self.identity.bytes
        let status = unsafe crypto_scalarmult_ristretto255(&result, scalar.bytes, bytes)
        return status == 0 ? Self(bytes: result) : .identity
    }
}
