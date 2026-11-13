import Argon2

/// Juicebox's PIN stretching: Argon2id with a salt built from the
/// registration version and user info, producing the OPRF access key and the
/// seed that encrypts the recovered user secret.
func juiceboxPinHash(
  pin: [UInt8],
  registrationVersion: [UInt8],
  userInfo: [UInt8] = [],
  mode: JuiceboxPinHashingMode = .standard2019
) throws -> (accessKey: [UInt8], encryptionKeySeed: [UInt8]) {
  var salt: [UInt8] = []
  salt += be32(UInt32(registrationVersion.count))
  salt += registrationVersion
  salt += be32(UInt32(userInfo.count))
  salt += userInfo

  let parameters = mode.parameters
  do {
    let hash = try Argon2id.deriveKey(
      password: pin, salt: salt, memoryKiB: parameters.memory,
      iterations: parameters.time, parallelism: parameters.parallelism, outputByteCount: 64)
    return (Array(hash.prefix(32)), Array(hash.suffix(32)))
  } catch {
    throw JuiceboxRecoveryError.assertion
  }
}
