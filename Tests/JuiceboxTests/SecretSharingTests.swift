import Testing

@testable import Juicebox

/// Shamir sharing over scalars and Ristretto points, including threshold and
/// duplicate handling.
struct SecretSharingTests {
    init() throws {
        try #require(juiceboxSodiumIsReady)
    }

    @Test func scalarSharesRoundTrip() throws {
        let secret = RistrettoScalar.random()
        for count in 2...5 {
            for threshold in 2...count {
                let shares = createShares(
                    secret: secret, threshold: threshold, count: count,
                    random: { RistrettoScalar.random() })
                #expect(shares.count == count)
                #expect(shares.allSatisfy { $0.secret != secret })

                #expect(try recoverSecret(shares) == secret)
                for subset in combinations(shares, choose: threshold) {
                    #expect(try recoverSecret(subset) == secret)
                }
                for subset in combinations(shares, choose: threshold - 1) {
                    #expect(try recoverSecret(subset) != secret)
                }
            }
        }
    }

    @Test func pointSharesRoundTrip() throws {
        let secret = RistrettoPoint.hashToGroup(Array("shared secret".utf8))
        for count in 2...4 {
            for threshold in 2...count {
                let shares = createShares(
                    secret: secret, threshold: threshold, count: count,
                    random: { RistrettoPoint.random() })
                #expect(try recoverSecret(shares) == secret)
                for subset in combinations(shares, choose: threshold) {
                    #expect(try recoverSecret(subset) == secret)
                }
            }
        }
    }

    @Test func duplicateIndicesFail() {
        let share = SecretShare(index: 1, secret: RistrettoScalar.random())
        #expect(throws: SecretSharingError.duplicateShares) { _ = try recoverSecret([share, share]) }
    }

    @Test func singleShareAtZero() throws {
        let value = RistrettoScalar.random()
        let share = SecretShare(index: 1, secret: value)
        #expect(try recoverSecret([share]) == value)
    }

    private func combinations<T>(_ items: [T], choose count: Int) -> [[T]] {
        guard count > 0, items.count >= count else {
            return count == 0 ? [[]] : []
        }
        guard let first = items.first else { return [] }
        let rest = Array(items.dropFirst())
        return combinations(rest, choose: count - 1).map { [first] + $0 }
            + combinations(rest, choose: count)
    }
}
