import XCTest

@testable import Juicebox

/// Shamir sharing over scalars and Ristretto points, including threshold and
/// duplicate handling.
final class SecretSharingTests: XCTestCase {
    func testScalarSharesRoundTrip() throws {
        let secret = RistrettoScalar.random()
        for count in 2...5 {
            for threshold in 2...count {
                let shares = createShares(
                    secret: secret, threshold: threshold, count: count,
                    random: { RistrettoScalar.random() })
                XCTAssertEqual(shares.count, count)
                XCTAssertTrue(shares.allSatisfy { $0.secret != secret })

                XCTAssertEqual(try recoverSecret(shares), secret)
                for subset in combinations(shares, choose: threshold) {
                    XCTAssertEqual(try recoverSecret(subset), secret)
                }
                for subset in combinations(shares, choose: threshold - 1) {
                    XCTAssertNotEqual(try recoverSecret(subset), secret)
                }
            }
        }
    }

    func testPointSharesRoundTrip() throws {
        let secret = RistrettoPoint.hashToGroup(Array("shared secret".utf8))
        for count in 2...4 {
            for threshold in 2...count {
                let shares = createShares(
                    secret: secret, threshold: threshold, count: count,
                    random: { RistrettoPoint.random() })
                XCTAssertEqual(try recoverSecret(shares), secret)
                for subset in combinations(shares, choose: threshold) {
                    XCTAssertEqual(try recoverSecret(subset), secret)
                }
            }
        }
    }

    func testDuplicateIndicesFail() {
        let share = SecretShare(index: 1, secret: RistrettoScalar.random())
        XCTAssertThrowsError(try recoverSecret([share, share])) { error in
            XCTAssertEqual(error as? SecretSharingError, .duplicateShares)
        }
    }

    func testSingleShareAtZero() throws {
        let value = RistrettoScalar.random()
        let share = SecretShare(index: 1, secret: value)
        XCTAssertEqual(try recoverSecret([share]), value)
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
