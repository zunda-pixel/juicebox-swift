import Crypto
import Foundation

/// The Noise NK client channel (`Noise_NK_25519_ChaChaPoly_BLAKE2s`) that
/// Juicebox hardware realms speak: an ephemeral client key, the realm's
/// static public key, and a two-message handshake that yields a transport
/// cipher.
enum NoiseNK {
  static let protocolName = Array("Noise_NK_25519_ChaChaPoly_BLAKE2s".utf8)
  static let hashLength = 32

  struct HandshakeRequest {
    /// The client's ephemeral public key (32 bytes).
    var clientEphemeralPublic: [UInt8]
    /// The encrypted request payload (tag included).
    var payloadCiphertext: [UInt8]
  }

  struct HandshakeResponse {
    /// The server's ephemeral public key (32 bytes).
    var serverEphemeralPublic: [UInt8]
    /// The encrypted response payload (tag included).
    var payloadCiphertext: [UInt8]
  }

  /// The client side of an in-progress NK handshake.
  struct Handshake {
    private var clientEphemeral: Curve25519.KeyAgreement.PrivateKey
    private var h: [UInt8]
    private var ck: [UInt8]

    /// The handshake hash, which Noise test vectors name.
    var handshakeHash: [UInt8] { h }

    /// Starts a handshake to `serverStaticPublic`, sending `payload` in
    /// the first message. `ephemeralSecret` is for deterministic tests.
    static func start(
      serverStaticPublic: [UInt8],
      prologue: [UInt8] = [],
      payload: [UInt8],
      ephemeralSecret: [UInt8]? = nil
    ) throws -> (Handshake, HandshakeRequest) {
      let ephemeral: Curve25519.KeyAgreement.PrivateKey
      if let ephemeralSecret {
        ephemeral = try Curve25519.KeyAgreement.PrivateKey(
          rawRepresentation: ephemeralSecret)
      } else {
        ephemeral = Curve25519.KeyAgreement.PrivateKey()
      }
      let serverStatic: Curve25519.KeyAgreement.PublicKey
      do {
        serverStatic = try Curve25519.KeyAgreement.PublicKey(
          rawRepresentation: serverStaticPublic)
      } catch {
        throw NoiseError.invalidKey
      }
      let clientEphemeralPublic = Array(ephemeral.publicKey.rawRepresentation)

      var h = Blake2s.hash(protocolName)
      var ck = h
      h = mixHash(h, prologue)
      h = mixHash(h, serverStaticPublic)
      h = mixHash(h, clientEphemeralPublic)

      let (chainingKey, key) = hkdfPair(
        salt: ck, ikm: try sharedSecret(ephemeral, serverStatic))
      ck = chainingKey
      var cipher = CipherState(key: key)
      let payloadCiphertext = try cipher.seal(payload, authenticatedData: h)
      h = mixHash(h, payloadCiphertext)

      return (
        Handshake(clientEphemeral: ephemeral, h: h, ck: ck),
        HandshakeRequest(
          clientEphemeralPublic: clientEphemeralPublic,
          payloadCiphertext: payloadCiphertext)
      )
    }

    /// Completes the handshake, returning the transport cipher and the
    /// server's payload.
    func finish(_ response: HandshakeResponse) throws -> (Transport, [UInt8]) {
      let serverEphemeral: Curve25519.KeyAgreement.PublicKey
      do {
        serverEphemeral = try Curve25519.KeyAgreement.PublicKey(
          rawRepresentation: response.serverEphemeralPublic)
      } catch {
        throw NoiseError.invalidKey
      }
      var h = self.h
      h = mixHash(h, response.serverEphemeralPublic)
      let (chainingKey, key) = hkdfPair(
        salt: ck, ikm: try sharedSecret(clientEphemeral, serverEphemeral))

      var cipher = CipherState(key: key)
      let payload = try cipher.open(
        response.payloadCiphertext, authenticatedData: h)

      let (k1, k2) = hkdfPair(salt: chainingKey, ikm: [])
      return (
        Transport(outboundKey: k1, inboundKey: k2),
        payload
      )
    }
  }

  /// The post-handshake channel: each direction has its own key and nonce
  /// sequence.
  struct Transport {
    private var inbound: CipherState
    private var outbound: CipherState

    init(outboundKey: [UInt8], inboundKey: [UInt8]) {
      outbound = CipherState(key: outboundKey)
      inbound = CipherState(key: inboundKey)
    }

    mutating func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
      try outbound.seal(plaintext, authenticatedData: [])
    }

    mutating func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8] {
      try inbound.open(ciphertext, authenticatedData: [])
    }
  }

  enum NoiseError: Error {
    case invalidKey
    case decryption
  }
}

/// One direction of a Noise cipher: ChaCha20-Poly1305 with the protocol's
/// 12-byte nonce (four zero bytes, then a little-endian 64-bit counter).
private struct CipherState {
  private var key: SymmetricKey
  private var nonce: UInt64 = 0

  init(key: [UInt8]) {
    self.key = SymmetricKey(data: key)
  }

  mutating func seal(_ plaintext: [UInt8], authenticatedData: [UInt8]) throws -> [UInt8] {
    let nonceBytes = nonceBytes()
    let sealed = try ChaChaPoly.seal(
      plaintext, using: key,
      nonce: try ChaChaPoly.Nonce(data: nonceBytes),
      authenticating: authenticatedData)
    nonce &+= 1
    return Array(sealed.ciphertext) + Array(sealed.tag)
  }

  mutating func open(_ ciphertext: [UInt8], authenticatedData: [UInt8]) throws -> [UInt8] {
    guard ciphertext.count >= 16 else {
      throw NoiseNK.NoiseError.decryption
    }
    let split = ciphertext.count - 16
    let box: ChaChaPoly.SealedBox
    do {
      box = try ChaChaPoly.SealedBox(
        nonce: try ChaChaPoly.Nonce(data: nonceBytes()),
        ciphertext: Array(ciphertext[..<split]),
        tag: Array(ciphertext[split...]))
    } catch {
      throw NoiseNK.NoiseError.decryption
    }
    let plaintext: Data
    do {
      plaintext = try ChaChaPoly.open(box, using: key, authenticating: authenticatedData)
    } catch {
      throw NoiseNK.NoiseError.decryption
    }
    nonce &+= 1
    return Array(plaintext)
  }

  private func nonceBytes() -> [UInt8] {
    [0, 0, 0, 0] + nonce.littleEndianBytes
  }
}

/// Noise's `HKDF(chaining key, input)` split into two 32-byte keys.
private func hkdfPair(salt: [UInt8], ikm: [UInt8]) -> ([UInt8], [UInt8]) {
  let okm = hkdfBlake2s(salt: salt, ikm: ikm, length: 64)
  return (Array(okm[0..<32]), Array(okm[32..<64]))
}

/// Noise's `MixHash(h, data) = HASH(h || data)`.
private func mixHash(_ h: [UInt8], _ data: [UInt8]) -> [UInt8] {
  Blake2s.hash(h + data)
}

private func sharedSecret(
  _ privateKey: Curve25519.KeyAgreement.PrivateKey,
  _ publicKey: Curve25519.KeyAgreement.PublicKey
) throws -> [UInt8] {
  do {
    let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    return unsafe secret.withUnsafeBytes { unsafe Array($0) }
  } catch {
    throw NoiseNK.NoiseError.invalidKey
  }
}

extension UInt64 {
  var littleEndianBytes: [UInt8] {
    var value = littleEndian
    var bytes = [UInt8](repeating: 0, count: 8)
    for i in 0..<8 {
      bytes[i] = UInt8(truncatingIfNeeded: value & 0xff)
      value >>= 8
    }
    return bytes
  }
}
