import Crypto
import Foundation

@testable import Juicebox

extension OPRF {
  static func publicKey(for privateKey: RistrettoScalar) -> [UInt8] {
    RistrettoPoint.basepoint.scalarMultiply(privateKey).compress()
  }

  static func evaluate(
    privateKey: RistrettoScalar, blindedInput: BlindedInput
  ) -> BlindedOutput {
    BlindedOutput(point: blindedInput.point.scalarMultiply(privateKey))
  }

  static func generateProof(
    privateKey: RistrettoScalar,
    nonce: RistrettoScalar,
    blindedInput: BlindedInput,
    publicKey: [UInt8],
    blindedOutput: BlindedOutput
  ) -> Proof {
    let vT = RistrettoPoint.basepoint.scalarMultiply(nonce)
    let wT = blindedInput.point.scalarMultiply(nonce)
    let c = challenge(
      u: blindedInput.compressed, v: publicKey, w: blindedOutput.compressed,
      vT: vT.compress(), wT: wT.compress())
    let betaZ = nonce + privateKey * c
    return Proof(c: c, betaZ: betaZ)
  }

  /// Evaluates locally, giving the same output as a full interaction.
  static func unobliviousEvaluate(
    privateKey: RistrettoScalar, input: [UInt8]
  ) -> [UInt8] {
    let result = RistrettoPoint.hashToGroup(input).scalarMultiply(privateKey)
    return hashToOutput(input: input, result: result)
  }
}

extension OPRF.BlindedInput {
  init(compressed: [UInt8]) throws {
    guard let point = RistrettoPoint.decompress(compressed) else {
      throw OPRFError.invalidPoint
    }
    self.init(point: point)
  }
}

extension OPRF.Proof {
  /// The wire form is two 32-byte scalars.
  var bytes: [UInt8] { c.bytes + betaZ.bytes }
}

extension JuiceboxKeys {
  /// `[length, secret, 0...]` padded to 129 bytes. The length is one byte,
  /// so the secret cannot exceed 128 bytes.
  static func padUserSecret(_ secret: [UInt8]) -> [UInt8]? {
    guard secret.count <= maximumUserSecretLength else { return nil }
    var padded = [UInt8](repeating: 0, count: paddedUserSecretLength)
    padded[0] = UInt8(secret.count)
    padded.replaceSubrange(1..<(1 + secret.count), with: secret)
    return padded
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
}

extension RistrettoPoint {
  static func random() -> RistrettoPoint {
    fromUniformBytes(juiceboxRandomBytes(64))
  }
}

/// Cryptographically secure random bytes from the system random source.
private func juiceboxRandomBytes(_ length: Int) -> [UInt8] {
  var generator = SystemRandomNumberGenerator()
  return (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) }
}

/// Distributes `secret` into `count` shares; any `threshold` recover it.
func createShares<Secret: SecretShareable>(
  secret: Secret, threshold: Int, count: Int, random: () -> Secret
) -> [SecretShare<Secret>] {
  precondition(threshold > 0 && count > 0 && threshold <= count)
  var coefficients: [Secret] = []
  if threshold > 1 {
    for _ in 1..<threshold {
      coefficients.append(random())
    }
  }
  return (1...count).map { index in
    let x = shareIndexScalar(UInt32(index))
    var value = Secret.additiveIdentity
    for coefficient in coefficients {
      value = Secret.multiplied(Secret.adding(value, coefficient), by: x)
    }
    value = Secret.adding(value, secret)
    return SecretShare(index: UInt32(index), secret: value)
  }
}
