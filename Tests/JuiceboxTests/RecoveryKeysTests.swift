import Testing

@testable import Juicebox

/// Keyed BLAKE2s, the derived encryption key, the commitment tags, and the
/// padded ChaCha20-Poly1305 user secret. The expected values come from plain
/// hashing and from the reference implementation's fixed vectors.
struct RecoveryKeysTests {
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

  @Test func keyedBlake2s() {
    #expect(
      Self.hexString(
        Blake2s.mac(
          key: [UInt8](repeating: 8, count: 32),
          message: Array("abc".utf8), outputLength: 16)) == "08ef48662552a6519fd9f4b3011eb6d8")
  }

  @Test func userSecretEncryptionKey() {
    let scalar = Self.hex(
      "d20a1feb8ca954ab000000000000000000000000000000000000000000000000")
    let key = JuiceboxKeys.userSecretEncryptionKey(
      seed: [UInt8](repeating: 8, count: 32), scalar: scalar)
    #expect(
      Self.hexString(key) == "c92f94b62b865422b447742ab8c97a356b2bd3a331670e0ba9bd7346e55bff7e")
  }

  @Test func unlockKeyTagAndCommitment() {
    let realm = (0..<16).map { UInt8($0) }
    let key = [UInt8](repeating: 9, count: 32)
    #expect(
      Self.hexString(JuiceboxKeys.unlockKeyTag(unlockKey: key, realmId: realm))
        == "7fa2c8d60bfdb4848c6356d87d5e72d5")
    #expect(
      Self.hexString(
        JuiceboxKeys.encryptedUserSecretCommitment(
          unlockKey: key, realmId: realm,
          scalarShare: [UInt8](repeating: 1, count: 32),
          encryptedSecret: [UInt8](repeating: 2, count: 145))) == "2ff1669be5c7c40ec8909fae17074359"
    )
  }

  /// The reference implementation's fixed encrypted secret for "artemis"
  /// under the all-8 key.
  @Test func userSecretEncryptionVector() throws {
    let expected = Self.hex(
      "0186b2fb12c1f4a27ac200efff80fd27c7f991e2fc53a551322e11015e6ce08b338998b0e6cbb8ac4b"
        + "b5ce97bc166471e097443fcaa4e1549b8da931ff4b015ffa225ccb9c815410149531563ff5742452"
        + "74d788c59a7e63637f4f1d174aac9514022b661d525966e15340e5f7e8c2cf0681b72e0434cd6df0"
        + "40430fe2b9ba36a214dbfaa267a44c79578c93766d6b2307")
    #expect(expected.count == JuiceboxKeys.encryptedUserSecretLength)

    let encrypted = try #require(
      JuiceboxKeys.encryptUserSecret(Array("artemis".utf8), key: [UInt8](repeating: 8, count: 32)))
    #expect(Self.hexString(encrypted) == Self.hexString(expected))
    #expect(
      JuiceboxKeys.decryptUserSecret(encrypted, key: [UInt8](repeating: 8, count: 32))
        == Array("artemis".utf8))
  }

  @Test func userSecretPadding() {
    #expect(
      JuiceboxKeys.padUserSecret([1, 2, 3, 0, 4, 5, 0])?[0..<8] == [7, 1, 2, 3, 0, 4, 5, 0])
    #expect(
      JuiceboxKeys.padUserSecret([UInt8](repeating: 5, count: 128))?[0] == 128)
    #expect(JuiceboxKeys.padUserSecret([UInt8](repeating: 5, count: 129)) == nil)
    #expect(JuiceboxKeys.padUserSecret([])?.count == 129)

    for secret in [[], [0], [1, 2, 3], [UInt8](repeating: 0xab, count: 128)] {
      let padded = JuiceboxKeys.padUserSecret(secret)!
      #expect(JuiceboxKeys.unpadUserSecret(padded) == secret)
    }
  }

  @Test func unlockKeyDerivation() {
    let (key, commitment) = JuiceboxKeys.unlockKeyAndCommitment(
      oprfOutput: (0..<64).map { UInt8($0) })
    #expect(key != commitment)
    #expect(key.count == 32)
    #expect(commitment.count == 32)
  }

  @Test func decryptRejectsTampering() throws {
    let key = [UInt8](repeating: 8, count: 32)
    var encrypted = try #require(
      JuiceboxKeys.encryptUserSecret(Array("artemis".utf8), key: key))
    encrypted[0] ^= 1
    #expect(JuiceboxKeys.decryptUserSecret(encrypted, key: key) == nil)
  }
}
