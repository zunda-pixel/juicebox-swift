import Crypto
import Foundation

/// Key derivation and authenticated encryption around a recovered Juicebox
/// user secret: the unlock key and its commitments, the secret's encryption
/// key, and the padded ChaCha20-Poly1305 envelope.
enum JuiceboxKeys {
    static let maximumUserSecretLength = 128
    /// One length byte plus the maximum secret, then the 16-byte tag.
    static let paddedUserSecretLength = maximumUserSecretLength + 1
    static let encryptedUserSecretLength = paddedUserSecretLength + 16

    /// `SHA-512(oprf output)`: the first half commits to the unlock key, the
    /// second half is the key itself.
    static func unlockKeyAndCommitment(
        oprfOutput: [UInt8]
    ) -> (unlockKey: [UInt8], commitment: [UInt8]) {
        precondition(oprfOutput.count == 64)
        let digest = Array(SHA512.hash(data: oprfOutput))
        return (
            unlockKey: Array(digest[32..<64]),
            commitment: Array(digest[0..<32])
        )
    }

    /// Keyed BLAKE2s with the PIN-derived seed and the recovered scalar.
    static func userSecretEncryptionKey(seed: [UInt8], scalar: [UInt8]) -> [UInt8] {
        let label = Array("User Secret Encryption Key".utf8)
        var message: [UInt8] = []
        message += be32(UInt32(label.count))
        message += label
        message += be32(UInt32(scalar.count))
        message += scalar
        return Blake2s.mac(key: seed, message: message)
    }

    /// The 16-byte tag a realm releases its scalar share for.
    static func unlockKeyTag(unlockKey: [UInt8], realmId: [UInt8]) -> [UInt8] {
        let label = Array("Unlock Key Tag".utf8)
        var message: [UInt8] = []
        message += be32(UInt32(label.count))
        message += label
        message += be32(UInt32(realmId.count))
        message += realmId
        return Blake2s.mac(key: unlockKey, message: message, outputLength: 16)
    }

    /// The 16-byte commitment binding a realm's scalar share to the encrypted
    /// secret it returned.
    static func encryptedUserSecretCommitment(
        unlockKey: [UInt8], realmId: [UInt8], scalarShare: [UInt8], encryptedSecret: [UInt8]
    ) -> [UInt8] {
        let label = Array("Encrypted User Secret Commitment".utf8)
        var message: [UInt8] = []
        message += be32(UInt32(label.count))
        message += label
        message += be32(UInt32(realmId.count))
        message += realmId
        message += be32(UInt32(scalarShare.count))
        message += scalarShare
        message += be32(UInt32(encryptedSecret.count))
        message += encryptedSecret
        return Blake2s.mac(key: unlockKey, message: message, outputLength: 16)
    }

    // MARK: User secret

    /// `[length, secret, 0...]` padded to 129 bytes. The length is one byte,
    /// so the secret cannot exceed 128 bytes.
    static func padUserSecret(_ secret: [UInt8]) -> [UInt8]? {
        guard secret.count <= maximumUserSecretLength else { return nil }
        var padded = [UInt8](repeating: 0, count: paddedUserSecretLength)
        padded[0] = UInt8(secret.count)
        padded.replaceSubrange(1..<(1 + secret.count), with: secret)
        return padded
    }

    static func unpadUserSecret(_ padded: [UInt8]) -> [UInt8]? {
        guard padded.count == paddedUserSecretLength else { return nil }
        let length = Int(padded[0])
        guard length <= maximumUserSecretLength, 1 + length <= padded.count else { return nil }
        return Array(padded[1..<(1 + length)])
    }

    /// ChaCha20-Poly1305 with an all-zero nonce, which is safe because each
    /// registration encrypts under a fresh PIN-derived key.
    static func encryptUserSecret(_ secret: [UInt8], key: [UInt8]) -> [UInt8]? {
        guard let padded = padUserSecret(secret) else { return nil }
        let nonce = try? ChaChaPoly.Nonce(data: [UInt8](repeating: 0, count: 12))
        guard let nonce,
            let sealed = try? ChaChaPoly.seal(
                Data(padded), using: SymmetricKey(data: key), nonce: nonce,
                authenticating: Data())
        else { return nil }
        return Array(sealed.ciphertext) + Array(sealed.tag)
    }

    static func decryptUserSecret(_ encrypted: [UInt8], key: [UInt8]) -> [UInt8]? {
        guard encrypted.count == encryptedUserSecretLength else { return nil }
        let ciphertext = Array(encrypted[0..<(encrypted.count - 16)])
        let tag = Array(encrypted[(encrypted.count - 16)...])
        guard let nonce = try? ChaChaPoly.Nonce(data: [UInt8](repeating: 0, count: 12)),
            let box = try? ChaChaPoly.SealedBox(
                nonce: nonce, ciphertext: Data(ciphertext), tag: Data(tag)),
            let opened = try? ChaChaPoly.open(box, using: SymmetricKey(data: key),
                authenticating: Data())
        else { return nil }
        return unpadUserSecret(Array(opened))
    }
}

/// A 16-bit big-endian length, used in the signed-OPRF-key message.
func be16(_ value: UInt16) -> [UInt8] {
    [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
}
