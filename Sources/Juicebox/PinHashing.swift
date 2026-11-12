import argon2

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
    var hash = [UInt8](repeating: 0, count: 64)
    let status = unsafe argon2id_hash_raw(
        parameters.time, parameters.memory, parameters.parallelism,
        pin, pin.count, salt, salt.count, &hash, hash.count)
    guard status == 0 else { throw JuiceboxRecoveryError.assertion }
    return (Array(hash.prefix(32)), Array(hash.suffix(32)))
}
