# Juicebox recovery protocol

## Implemented

- BlakeHash provides BLAKE2s (RFC 7693) and keyed BLAKE2s for the Juicebox
  MACs. Noise composes HMAC and HKDF with BLAKE2s.
- `NoiseNK`: the client side of `Noise_NK_25519_ChaChaPoly_BLAKE2s`, the
  channel Juicebox hardware realms speak (handshake plus transport),
  built on swift-crypto's X25519 and ChaChaPoly.
- The PHC Argon2 reference implementation provides Argon2id (version 19).
  `juiceboxPinHash` uses `Standard2019` with `m = 16384`, `t = 32`, `p = 1`,
  and the length-prefixed salt. It splits the output into the OPRF access
  key and the user-secret encryption seed. `FastInsecure` is for test realms.
- libsodium provides Ristretto255 point and scalar arithmetic, point
  validation, the one-way map, and constant-time comparisons.
- `OPRF`: `start` / `finalize` / `unobliviousEvaluate`, the DLEQ proof
  verification and generation, and the server-side evaluation used by
  tests.
- `SecretSharing`: Shamir sharing and Lagrange recovery over scalars and
  Ristretto points.
- `CBOR` plus `RealmMessages`: the serde-compatible CBOR encoding of the
  recovery requests and responses, the padded hardware envelope, and the
  Noise `ClientRequest` / `ClientResponse` wrapper.
- `JuiceboxConfiguration` (realm endpoints, public keys, and thresholds) and
  `JuiceboxRecovery`, the three-phase driver. The app supplies a
  `JuiceboxHTTPTransport`; the SDK builds every request and parses every
  response, including the `X-Juicebox-Version` header and Bearer token.
- `JuiceboxKeys`: the unlock key and commitments, the keyed-BLAKE2s
  user-secret encryption key, and the padded ChaCha20-Poly1305 secret.

Tests: RFC 7693 vectors, the reference PIN vector, official
Noise NK vectors (`Tests/JuiceboxTests/Fixtures/noise_nk_vectors.json`),
RFC 9496 Ristretto vectors (multiples, invalid encodings, uniform bytes),
the reference secret-encryption vector, and end-to-end recovery against
fake software and Noise hardware realms, including wrong PINs, missing
tokens, and a realm outage.

On Linux, install libsodium 1.0.22 and `pkg-config`, then run
`swift test -Xcc -Wno-cpp`. CI verifies the upstream release tarball and
builds the same libsodium version bundled on Apple platforms. The extra
flag covers swift-sodium's
system-library preprocessor warning ([#3](https://github.com/zunda-pixel/xchat-swift/issues/3)).

## Protocol (from `juicebox-sdk@0.3.7`)

Recovery requires matching responses from at least `recover_threshold` realms.

1. `Recover1` → the registration `version` (16 bytes), or NotRegistered /
   NoGuesses.
2. **PIN hash**: Argon2id, version 0x13, `m_cost = 16384`, `t_cost = 32`,
   `p_cost = 1`, 64 bytes, with salt
   `be32(len(version)) ‖ version ‖ be32(len(info)) ‖ info` where
   `UserInfo` is empty by default. Output: `access_key` (32) ‖ `encryption_key_seed` (32).
   There is a fixed vector in the reference source.
3. **OPRF** (Ristretto255 over SHA-512):
   - `start`: `input_point = hash_to_group(access_key)`,
     `blinding = random Scalar`, send `input_point · blinding`.
   - Each realm answers `oprf_blinded_result` (RistrettoPoint),
     `oprf_signed_public_key`, a DLEQ `proof`, `unlock_key_commitment`,
     `num_guesses`, `guess_count`. Verify the realm's signed public key
     and the proof.
   - Combine the result shares with Shamir interpolation, unblind
     (`· blinding⁻¹`), `hash_to_output` = SHA-512(`"Juicebox_OPRF_2023_1;" ‖
     input ‖ compressed result`), derive `unlock_key` and
     `unlock_key_commitment`; a mismatch means a wrong PIN.
4. `Recover3` with `unlock_key_tag = UnlockKeyTag(unlock_key, realm id)`
   → an `encryption_key_scalar_share`, the `encrypted_secret`, and its
   commitment. Check each share's commitment, combine the scalar shares,
   derive the encryption key with keyed BLAKE2s using the PIN-derived seed and
   the length-prefixed label and scalar. Decrypt the user secret (up to 128 bytes).

Wire format: the realm RPC endpoint is `<address>/req` taking a CBOR body.
Software realms take a `SecretsRequest` directly with
`Authorization: Bearer <token>`; hardware realms (those with a `public_key`)
take a `ClientRequest` containing the token and a Noise NK message, and answer a `ClientResponse` whose
payload is a padded `SecretsResponse`. Every request carries
`X-Juicebox-Version: 0.3.7`.

Secret sharing is Shamir over `Scalar`/`RistrettoPoint`, indices `1...n` as
scalars, Lagrange interpolation with the secret as the constant term.

## Remaining

1. **Registration / deletion**: this module supports recovery. The
   registration and deletion RPCs are separate protocol paths.
2. **Session reuse**: the driver opens a new Noise session per request.
   Reusing sessions would save a round trip for phases 2 and 3.
