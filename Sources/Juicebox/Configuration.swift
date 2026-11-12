import Foundation

/// How a PIN is stretched before registration and recovery. `standard2019` is
/// the tuned production mode; `fastInsecure` exists for test realms.
public enum JuiceboxPinHashingMode: String, Sendable, Equatable {
    case standard2019 = "Standard2019"
    case fastInsecure = "FastInsecure"

    var parameters: (memory: UInt32, time: UInt32, parallelism: UInt32) {
        switch self {
        case .standard2019: return (16 * 1024, 32, 1)
        case .fastInsecure: return (8, 1, 1)
        }
    }
}

/// A realm the client talks to: its 16-byte id, base address, and, for
/// hardware realms, its X25519 public key.
public struct JuiceboxRealm: Sendable, Equatable {
    public let id: [UInt8]
    public let address: String
    public let publicKey: [UInt8]?

    public init(id: [UInt8], address: String, publicKey: [UInt8]? = nil) {
        self.id = id
        self.address = address
        self.publicKey = publicKey
    }

    /// The RPC endpoint: the realm's address with `req` appended.
    var requestURL: String {
        if address.hasSuffix("/") {
            return address + "req"
        }
        return address + "/req"
    }
}

public enum JuiceboxConfigurationError: Error, Equatable {
    case invalid
}

/// The client configuration the X API returns inside `key_store_token_map_json`.
public struct JuiceboxConfiguration: Sendable, Equatable {
    public let realms: [JuiceboxRealm]
    public let registerThreshold: Int
    public let recoverThreshold: Int
    public let pinHashingMode: JuiceboxPinHashingMode

    /// Parses the SDK configuration JSON. Realms are sorted by id, which fixes
    /// their share indices, exactly as the reference client does.
    public static func parse(_ json: [UInt8]) throws -> JuiceboxConfiguration {
        guard let root = try? JSONSerialization.jsonObject(with: Data(json)) as? [String: Any],
            let rawRealms = root["realms"] as? [[String: Any]],
            let registerThreshold = (root["register_threshold"] as? NSNumber)?.intValue,
            let recoverThreshold = (root["recover_threshold"] as? NSNumber)?.intValue,
            let modeName = root["pin_hashing_mode"] as? String,
            let mode = JuiceboxPinHashingMode(rawValue: modeName)
        else { throw JuiceboxConfigurationError.invalid }

        var realms: [JuiceboxRealm] = []
        for raw in rawRealms {
            guard let idHex = raw["id"] as? String,
                let id = hexBytes(idHex), id.count == 16,
                let address = raw["address"] as? String, !address.isEmpty
            else { throw JuiceboxConfigurationError.invalid }
            var publicKey: [UInt8]?
            if let value = raw["public_key"], !(value is NSNull) {
                guard let key = value as? String,
                    let parsed = hexBytes(key), parsed.count == 32
                else {
                    throw JuiceboxConfigurationError.invalid
                }
                publicKey = parsed
            }
            realms.append(JuiceboxRealm(id: id, address: address, publicKey: publicKey))
        }

        let count = realms.count
        guard count >= 1,
            Set(realms.map { $0.id }).count == count,
            recoverThreshold >= 1,
            recoverThreshold <= count,
            recoverThreshold * 2 > count,
            registerThreshold >= 1,
            registerThreshold <= count
        else { throw JuiceboxConfigurationError.invalid }

        realms.sort { $0.id.lexicographicallyPrecedes($1.id) }
        return JuiceboxConfiguration(
            realms: realms, registerThreshold: registerThreshold,
            recoverThreshold: recoverThreshold, pinHashingMode: mode)
    }

    /// The 1-based share index of a realm, in sorted-id order.
    func shareIndex(for realmId: [UInt8]) -> UInt32? {
        guard let position = realms.firstIndex(where: { $0.id == realmId }) else { return nil }
        return UInt32(position + 1)
    }
}

func hexBytes(_ text: String) -> [UInt8]? {
    guard text.count % 2 == 0 else { return nil }
    var out: [UInt8] = []
    out.reserveCapacity(text.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
        out.append(byte)
        index = next
    }
    return out
}

/// Lowercase hex for a byte string.
func hexString(_ bytes: [UInt8]) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var chars: [UInt8] = []
    chars.reserveCapacity(bytes.count * 2)
    for byte in bytes {
        chars.append(digits[Int(byte >> 4)])
        chars.append(digits[Int(byte & 0x0f)])
    }
    return String(decoding: chars, as: UTF8.self)
}
