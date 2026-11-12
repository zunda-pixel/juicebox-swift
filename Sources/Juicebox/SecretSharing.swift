/// Shamir secret sharing over a type that supports addition and scalar
/// multiplication, matching the Juicebox share indices (1...count).
protocol SecretShareable: Sendable {
    static var additiveIdentity: Self { get }
    static func adding(_ lhs: Self, _ rhs: Self) -> Self
    static func multiplied(_ value: Self, by scalar: RistrettoScalar) -> Self
}

struct SecretShare<Secret: SecretShareable>: Sendable {
    var index: UInt32
    var secret: Secret
}

enum SecretSharingError: Error, Equatable {
    case duplicateShares
}

extension RistrettoScalar: SecretShareable {
    static var additiveIdentity: RistrettoScalar { .zero }
    static func adding(_ lhs: RistrettoScalar, _ rhs: RistrettoScalar) -> RistrettoScalar { lhs + rhs }
    static func multiplied(_ value: RistrettoScalar, by scalar: RistrettoScalar) -> RistrettoScalar { value * scalar }
}

extension RistrettoPoint: SecretShareable {
    static var additiveIdentity: RistrettoPoint { .identity }
    static func adding(_ lhs: RistrettoPoint, _ rhs: RistrettoPoint) -> RistrettoPoint {
        lhs + rhs
    }
    static func multiplied(_ value: RistrettoPoint, by scalar: RistrettoScalar) -> RistrettoPoint {
        value.scalarMultiply(scalar)
    }
}

/// The scalar for a share index: the index in the low four little-endian
/// bytes.
func shareIndexScalar(_ index: UInt32) -> RistrettoScalar {
    var bytes = [UInt8](repeating: 0, count: 32)
    bytes[0] = UInt8(truncatingIfNeeded: index)
    bytes[1] = UInt8(truncatingIfNeeded: index >> 8)
    bytes[2] = UInt8(truncatingIfNeeded: index >> 16)
    bytes[3] = UInt8(truncatingIfNeeded: index >> 24)
    return RistrettoScalar(canonicalBytes: bytes)!
}

/// Recovers the secret by Lagrange interpolation at zero.
func recoverSecret<Secret: SecretShareable>(
    _ shares: [SecretShare<Secret>]
) throws -> Secret {
    var result = Secret.additiveIdentity
    for (i, share) in shares.enumerated() {
        var numerator = RistrettoScalar.one
        var denominator = RistrettoScalar.one
        let xi = shareIndexScalar(share.index)
        for (j, other) in shares.enumerated() where j != i {
            let xj = shareIndexScalar(other.index)
            numerator = numerator * xj
            denominator = denominator * (xj - xi)
        }
        guard !denominator.isZero else { throw SecretSharingError.duplicateShares }
        let coefficient = numerator * denominator.invert()
        result = Secret.adding(result, Secret.multiplied(share.secret, by: coefficient))
    }
    return result
}
