import CBOR
import Crypto
import Foundation
import HTTPTypes
import Synchronization
import Testing

@testable import Juicebox

/// Recovery across two Noise NK hardware realms and one plain HTTP software
/// realm, with a test-side Noise server built independently of the client.
struct HardwareRecoveryTests {
  init() throws {
    try #require(juiceboxSodiumIsReady)
  }

  private static let version = [UInt8](repeating: 5, count: 16)
  private static let pin = Array("13579".utf8)
  private static let secret =
    Array("two hardware realms".utf8)
    + [UInt8](
      repeating: 0, count: 44)

  // MARK: Server-side Noise

  private struct ServerCipher {
    private var key: SymmetricKey
    private var nonce: UInt64 = 0

    init(key: [UInt8]) {
      self.key = SymmetricKey(data: key)
    }

    mutating func seal(_ plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
      let sealed = try ChaChaPoly.seal(
        plaintext, using: key, nonce: try ChaChaPoly.Nonce(data: nonceBytes),
        authenticating: aad)
      nonce += 1
      return Array(sealed.ciphertext) + Array(sealed.tag)
    }

    mutating func open(_ ciphertext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
      guard ciphertext.count >= 16 else { throw NoiseNK.NoiseError.decryption }
      let split = ciphertext.count - 16
      let box = try ChaChaPoly.SealedBox(
        nonce: try ChaChaPoly.Nonce(data: nonceBytes),
        ciphertext: Array(ciphertext[..<split]), tag: Array(ciphertext[split...]))
      let opened = try ChaChaPoly.open(box, using: key, authenticating: aad)
      nonce += 1
      return Array(opened)
    }

    private var nonceBytes: [UInt8] {
      [0, 0, 0, 0] + littleEndianBytes(nonce)
    }
  }

  private final class ServerTransport {
    private var inbound: ServerCipher
    private var outbound: ServerCipher

    init(inboundKey: [UInt8], outboundKey: [UInt8]) {
      inbound = ServerCipher(key: inboundKey)
      outbound = ServerCipher(key: outboundKey)
    }

    func open(_ ciphertext: [UInt8]) throws -> [UInt8] {
      try inbound.open(ciphertext, aad: [])
    }

    func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
      try outbound.seal(plaintext, aad: [])
    }
  }

  private struct ServerHandshake {
    var h: [UInt8]
    var ck: [UInt8]
    var cipher: ServerCipher
    var serverEphemeralPublic: [UInt8]
    var requestPlaintext: [UInt8]

    static func begin(
      staticSecret: Curve25519.KeyAgreement.PrivateKey, clientEphemeralPublic: [UInt8],
      payloadCiphertext: [UInt8]
    ) throws -> ServerHandshake {
      let clientEphemeral = try Curve25519.KeyAgreement.PublicKey(
        rawRepresentation: clientEphemeralPublic)
      let staticPublic = Array(staticSecret.publicKey.rawRepresentation)
      var h = Blake2s.hash(Array("Noise_NK_25519_ChaChaPoly_BLAKE2s".utf8))
      var ck = h
      h = mixHash(h, [])
      h = mixHash(h, staticPublic)
      h = mixHash(h, clientEphemeralPublic)

      let (chainingKey, key) = hkdfPair(
        salt: ck,
        ikm: try sharedSecret(staticSecret, clientEphemeral))
      ck = chainingKey
      var cipher = ServerCipher(key: key)
      let requestPlaintext = try cipher.open(payloadCiphertext, aad: h)
      h = mixHash(h, payloadCiphertext)

      let serverEphemeral = Curve25519.KeyAgreement.PrivateKey()
      let serverEphemeralPublic = Array(serverEphemeral.publicKey.rawRepresentation)
      h = mixHash(h, serverEphemeralPublic)
      let (nextChainingKey, nextKey) = hkdfPair(
        salt: ck,
        ikm: try sharedSecret(serverEphemeral, clientEphemeral))

      return ServerHandshake(
        h: h, ck: nextChainingKey, cipher: ServerCipher(key: nextKey),
        serverEphemeralPublic: serverEphemeralPublic,
        requestPlaintext: requestPlaintext)
    }

    /// Returns the handshake response and the transport keys. The caller
    /// makes the `ServerTransport` where it keeps it.
    mutating func finish(payload: [UInt8]) throws -> (
      ciphertext: [UInt8], inboundKey: [UInt8], outboundKey: [UInt8]
    ) {
      let ciphertext = try cipher.seal(payload, aad: h)
      let (k1, k2) = hkdfPair(salt: ck, ikm: [])
      return (ciphertext, k1, k2)
    }
  }

  private static func mixHash(_ h: [UInt8], _ data: [UInt8]) -> [UInt8] {
    Blake2s.hash(h + data)
  }

  private static func hkdfPair(salt: [UInt8], ikm: [UInt8]) -> ([UInt8], [UInt8]) {
    let okm = hkdfBlake2s(salt: salt, ikm: ikm, length: 64)
    return (Array(okm[0..<32]), Array(okm[32..<64]))
  }

  private static func sharedSecret(
    _ privateKey: Curve25519.KeyAgreement.PrivateKey,
    _ publicKey: Curve25519.KeyAgreement.PublicKey
  ) throws -> [UInt8] {
    let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    return unsafe secret.withUnsafeBytes { unsafe Array($0) }
  }

  // MARK: Fake realms

  private struct RealmFixture {
    var id: [UInt8]
    var address: String
    var token: String
    var oprfShare: RistrettoScalar
    var scalarShare: RistrettoScalar
    var encryptedSecret: [UInt8]
    var secretCommitment: [UInt8]
    var unlockKeyCommitment: [UInt8]
    var unlockKey: [UInt8]
    var numGuesses: UInt16
    var guessCount: UInt16
    var noiseStaticSecret: Curve25519.KeyAgreement.PrivateKey?
  }

  private final class FakeNetwork: BytesHTTPClient, Sendable {
    let realms: [String: RealmFixture]
    let signer: Curve25519.Signing.PrivateKey
    /// Recovery sends a phase's requests to the realms concurrently, so the
    /// sessions are guarded by a mutex. `ServerTransport` keeps cipher state
    /// and is not Sendable, so a session is made and used only inside the lock.
    private let sessions = Mutex<[UInt32: ServerTransport]>([:])
    /// Every request, in the order the network received them.
    let requests = Mutex<[HTTPRequest]>([])

    init(realms: [RealmFixture]) {
      self.realms = Dictionary(
        uniqueKeysWithValues: realms.map { ($0.address + "req", $0) })
      self.signer = Curve25519.Signing.PrivateKey()
    }

    func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
      requests.withLock { $0.append(request) }
      guard let realm = realms[request.urlString] else {
        return (HTTPResponse(status: .notFound), [])
      }
      if realm.noiseStaticSecret == nil {
        guard request.headerFields[.authorization] == "Bearer \(realm.token)" else {
          return (HTTPResponse(status: .unauthorized), [])
        }
        return (HTTPResponse(status: .ok), try response(for: realm, request: decodeCBOR(body)))
      }

      let clientRequest = try decodeCBOR(body)
      guard let sessionId = clientRequest["session_id"]?.uint64Value,
        let encrypted = clientRequest["encrypted"]
      else { return (HTTPResponse(status: .badRequest), []) }

      if let handshake = encrypted["Handshake"]?["handshake"],
        let ephemeral = handshake["client_ephemeral_public"]?.bytesValue,
        let payloadCiphertext = handshake["payload_ciphertext"]?.bytesValue
      {
        var server = try ServerHandshake.begin(
          staticSecret: realm.noiseStaticSecret!, clientEphemeralPublic: ephemeral,
          payloadCiphertext: payloadCiphertext)
        var responsePayload: [UInt8] = []
        if !server.requestPlaintext.isEmpty {
          let inner = try response(
            for: realm, request: decodeCBOR(server.requestPlaintext))
          responsePayload = paddedEnvelope(inner)
        }
        let (ciphertext, inboundKey, outboundKey) = try server.finish(payload: responsePayload)
        sessions.withLock {
          $0[UInt32(sessionId)] = ServerTransport(inboundKey: inboundKey, outboundKey: outboundKey)
        }
        return (
          HTTPResponse(status: .ok),
          CBOR.map([
            "Ok": .map([
              "Handshake": .map([
                "handshake": .map([
                  "server_ephemeral_public": .byteString(server.serverEphemeralPublic),
                  "payload_ciphertext": .byteString(ciphertext),
                ]),
                "session_lifetime": .map([
                  "secs": .unsignedInt(30),
                  "nanos": .unsignedInt(0),
                ]),
              ])
            ])
          ]).encode()
        )
      }

      guard
        let transportCiphertext = encrypted["Transport"]?["ciphertext"]?
          .bytesValue,
        let plaintext = try sessions.withLock({ stored -> [UInt8]? in
          try stored[UInt32(sessionId)]?.open(transportCiphertext)
        })
      else { return (HTTPResponse(status: .badRequest), []) }
      // The realm's work runs outside the lock, so the realms answer concurrently.
      let inner = try response(for: realm, request: decodeCBOR(plaintext))
      guard
        let responseCiphertext = try sessions.withLock({ stored -> [UInt8]? in
          try stored[UInt32(sessionId)]?.seal(paddedEnvelope(inner))
        })
      else { return (HTTPResponse(status: .badRequest), []) }
      return (
        HTTPResponse(status: .ok),
        CBOR.map([
          "Ok": .map([
            "Transport": .map([
              "ciphertext": .byteString(responseCiphertext)
            ])
          ])
        ]).encode()
      )
    }

    private func paddedEnvelope(_ inner: [UInt8]) -> [UInt8] {
      var padded = inner
      padded += [UInt8](repeating: 0, count: PaddedSecretsResponse.maximumLength - inner.count)
      return CBOR.map([
        "unpadded_length": .unsignedInt(UInt64(inner.count)),
        "padded_bytes": .byteString(padded),
      ]).encode()
    }

    private func response(for realm: RealmFixture, request: CBOR) throws -> [UInt8] {
      if request == .textString("Recover1") {
        return CBOR.map([
          "Recover1": .map([
            "Ok": .map([
              "version": .byteString(HardwareRecoveryTests.version)
            ])
          ])
        ]).encode()
      }
      if let body = request["Recover2"] {
        return try recover2(realm: realm, body: body)
      }
      if let body = request["Recover3"] {
        return try recover3(realm: realm, body: body)
      }
      throw RealmMessageError.malformed
    }

    private func recover2(realm: RealmFixture, body: CBOR) throws -> [UInt8] {
      guard let blindedInputBytes = body["oprf_blinded_input"]?.bytesValue,
        let blindedInput = try? OPRF.BlindedInput(compressed: blindedInputBytes)
      else { return [] }
      let publicKey = OPRF.publicKey(for: realm.oprfShare)
      let blindedOutput = OPRF.evaluate(
        privateKey: realm.oprfShare, blindedInput: blindedInput)
      let proof = OPRF.generateProof(
        privateKey: realm.oprfShare, nonce: .random(), blindedInput: blindedInput,
        publicKey: publicKey, blindedOutput: blindedOutput)
      var message: [UInt8] = []
      message += be16(16)
      message += realm.id
      message += be16(32)
      message += publicKey
      let signature = try signer.signature(for: message)

      return CBOR.map([
        "Recover2": .map([
          "Ok": .map([
            "oprf_signed_public_key": .map([
              "public_key": .byteString(publicKey),
              "verifying_key": .byteString(Array(signer.publicKey.rawRepresentation)),
              "signature": .byteString(Array(signature)),
            ]),
            "oprf_blinded_result": .byteString(blindedOutput.compressed),
            "oprf_proof": .map([
              "c": .byteString(proof.c.bytes),
              "beta_z": .byteString(proof.betaZ.bytes),
            ]),
            "unlock_key_commitment": .byteString(realm.unlockKeyCommitment),
            "num_guesses": .unsignedInt(UInt64(realm.numGuesses)),
            "guess_count": .unsignedInt(UInt64(realm.guessCount)),
          ])
        ])
      ]).encode()
    }

    private func recover3(realm: RealmFixture, body: CBOR) throws -> [UInt8] {
      guard let tag = body["unlock_key_tag"]?.bytesValue else { return [] }
      let expected = JuiceboxKeys.unlockKeyTag(unlockKey: realm.unlockKey, realmId: realm.id)
      guard constantTimeEqual(tag, expected) else {
        return CBOR.map([
          "Recover3": .map([
            "BadUnlockKeyTag": .map([
              "guesses_remaining": .unsignedInt(4)
            ])
          ])
        ]).encode()
      }
      return CBOR.map([
        "Recover3": .map([
          "Ok": .map([
            "encryption_key_scalar_share": .byteString(realm.scalarShare.bytes),
            "encrypted_secret": .byteString(realm.encryptedSecret),
            "encrypted_secret_commitment": .byteString(realm.secretCommitment),
          ])
        ])
      ]).encode()
    }

    private func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
      guard lhs.count == rhs.count else { return false }
      var difference: UInt8 = 0
      for i in 0..<lhs.count { difference |= lhs[i] ^ rhs[i] }
      return difference == 0
    }
  }

  // MARK: Tests

  @Test func hardwareAndSoftwareRealmsTogether() async throws {
    let realmIds = (0..<3).map { [UInt8](repeating: UInt8($0 + 1), count: 16) }
    let tokens = Dictionary(
      uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })

    let (accessKey, seed) = try juiceboxPinHash(
      pin: Self.pin, registrationVersion: Self.version, mode: .fastInsecure)
    let masterOPRF = RistrettoScalar.random()
    let oprfShares = createShares(
      secret: masterOPRF, threshold: 2, count: 3, random: { RistrettoScalar.random() })
    let oprfOutput = OPRF.unobliviousEvaluate(privateKey: masterOPRF, input: accessKey)
    let (unlockKey, unlockCommitment) = JuiceboxKeys.unlockKeyAndCommitment(
      oprfOutput: oprfOutput)
    let scalar = RistrettoScalar.random()
    let scalarShares = createShares(
      secret: scalar, threshold: 2, count: 3, random: { RistrettoScalar.random() })
    let encryptionKey = JuiceboxKeys.userSecretEncryptionKey(
      seed: seed, scalar: scalar.bytes)
    let encryptedSecret = JuiceboxKeys.encryptUserSecret(Self.secret, key: encryptionKey)!

    var realms: [RealmFixture] = []
    for index in 0..<3 {
      let id = realmIds[index]
      let commitment = JuiceboxKeys.encryptedUserSecretCommitment(
        unlockKey: unlockKey, realmId: id,
        scalarShare: scalarShares[index].secret.bytes,
        encryptedSecret: encryptedSecret)
      realms.append(
        RealmFixture(
          id: id, address: "https://realm\(index + 1).test/",
          token: tokens[hexString(id)]!, oprfShare: oprfShares[index].secret,
          scalarShare: scalarShares[index].secret, encryptedSecret: encryptedSecret,
          secretCommitment: commitment, unlockKeyCommitment: unlockCommitment,
          unlockKey: unlockKey, numGuesses: 5, guessCount: 0,
          noiseStaticSecret: index < 2 ? Curve25519.KeyAgreement.PrivateKey() : nil))
    }

    let network = FakeNetwork(realms: realms)
    let jsonRealms = realms.enumerated().map { index, realm -> String in
      let key =
        index < 2
        ? ",\"public_key\": \"\(hexString(Array(realm.noiseStaticSecret!.publicKey.rawRepresentation)))\""
        : ""
      return """
        {"id": "\(hexString(realm.id))", "address": "\(realm.address)"\(key)}
        """
    }
    let json = """
      {
        "realms": [\(jsonRealms.joined(separator: ","))],
        "register_threshold": 3,
        "recover_threshold": 2,
        "pin_hashing_mode": "FastInsecure"
      }
      """
    let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    let secret = try await recovery.recover(pin: Self.pin, httpClient: network)
    #expect(secret == Self.secret)

    // Every request is a POST to its realm's `req` endpoint with the protocol
    // version. Only the software realm's requests carry the token in a
    // header; a hardware realm's token is in the body.
    let requests = network.requests.withLock { $0 }
    #expect(
      Set(requests.map(\.urlString))
        == ["https://realm1.test/req", "https://realm2.test/req", "https://realm3.test/req"])
    let versionField = try #require(HTTPField.Name("X-Juicebox-Version"))
    for request in requests {
      #expect(request.method == .post)
      #expect(request.headerFields[versionField] == JuiceboxRecovery.juiceboxVersion)
      let token =
        request.urlString == "https://realm3.test/req"
        ? tokens[hexString(realmIds[2])].map { "Bearer \($0)" } : nil
      #expect(request.headerFields[.authorization] == token, Comment(rawValue: request.urlString))
    }
  }

  @Test func wrongPinOnHardwareRealm() async throws {
    let realmIds = (0..<2).map { [UInt8](repeating: UInt8($0 + 1), count: 16) }
    let tokens = Dictionary(
      uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })
    let (accessKey, seed) = try juiceboxPinHash(
      pin: Self.pin, registrationVersion: Self.version, mode: .fastInsecure)
    let masterOPRF = RistrettoScalar.random()
    let oprfShares = createShares(
      secret: masterOPRF, threshold: 2, count: 2, random: { RistrettoScalar.random() })
    let oprfOutput = OPRF.unobliviousEvaluate(privateKey: masterOPRF, input: accessKey)
    let (unlockKey, unlockCommitment) = JuiceboxKeys.unlockKeyAndCommitment(
      oprfOutput: oprfOutput)
    let scalar = RistrettoScalar.random()
    let scalarShares = createShares(
      secret: scalar, threshold: 2, count: 2, random: { RistrettoScalar.random() })
    let encryptionKey = JuiceboxKeys.userSecretEncryptionKey(
      seed: seed, scalar: scalar.bytes)
    let encryptedSecret = JuiceboxKeys.encryptUserSecret(Self.secret, key: encryptionKey)!

    var realms: [RealmFixture] = []
    for index in 0..<2 {
      let id = realmIds[index]
      realms.append(
        RealmFixture(
          id: id, address: "https://realm\(index + 1).test/",
          token: tokens[hexString(id)]!, oprfShare: oprfShares[index].secret,
          scalarShare: scalarShares[index].secret, encryptedSecret: encryptedSecret,
          secretCommitment: JuiceboxKeys.encryptedUserSecretCommitment(
            unlockKey: unlockKey, realmId: id,
            scalarShare: scalarShares[index].secret.bytes,
            encryptedSecret: encryptedSecret),
          unlockKeyCommitment: unlockCommitment, unlockKey: unlockKey,
          numGuesses: 5, guessCount: 1,
          noiseStaticSecret: Curve25519.KeyAgreement.PrivateKey()))
    }
    let network = FakeNetwork(realms: realms)
    let json = """
      {
        "realms": [
          {"id": "\(hexString(realms[0].id))", "address": "\(realms[0].address)",
           "public_key": "\(hexString(Array(realms[0].noiseStaticSecret!.publicKey.rawRepresentation)))"},
          {"id": "\(hexString(realms[1].id))", "address": "\(realms[1].address)",
           "public_key": "\(hexString(Array(realms[1].noiseStaticSecret!.publicKey.rawRepresentation)))"}
        ],
        "register_threshold": 2,
        "recover_threshold": 2,
        "pin_hashing_mode": "FastInsecure"
      }
      """
    let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
    do {
      _ = try await recovery.recover(pin: Array("00000".utf8), httpClient: network)
      Issue.record("wrong PIN must fail")
    } catch let error as JuiceboxRecoveryError {
      #expect(error == .invalidPin(guessesRemaining: 4))
    }
  }
}

private func littleEndianBytes(_ value: UInt64) -> [UInt8] {
  var value = value
  var bytes = [UInt8](repeating: 0, count: 8)
  for i in 0..<8 {
    bytes[i] = UInt8(truncatingIfNeeded: value & 0xff)
    value >>= 8
  }
  return bytes
}
