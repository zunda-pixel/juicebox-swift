import Foundation

/// A small subset of CBOR (RFC 8949) matching how the Juicebox realm API
/// serializes serde types: structs and externally tagged enum variants are
/// maps, unit variants are text, byte arrays are byte strings, and options are
/// encoded as the value or `null`.
indirect enum CBORValue: Equatable, Sendable {
    case unsigned(UInt64)
    /// A negative integer, stored as its actual value (not `-1 - n`).
    case negative(Int64)
    case bytes([UInt8])
    case text(String)
    case array([CBORValue])
    case map([CBORPair])
    case bool(Bool)
    case null
}

struct CBORPair: Equatable, Sendable {
    let key: CBORValue
    let value: CBORValue
}

enum CBORError: Error, Equatable {
    case truncated
    case invalid
    case depthExceeded
}

/// Encodes a value with definite lengths and the shortest integer form, which
/// is what ciborium emits for these types.
func encodeCBOR(_ value: CBORValue) -> [UInt8] {
    var output: [UInt8] = []
    appendCBOR(value, to: &output)
    return output
}

private func appendCBOR(_ value: CBORValue, to output: inout [UInt8]) {
    switch value {
    case .unsigned(let number):
        appendHeader(major: 0, value: number, to: &output)
    case .negative(let number):
        precondition(number < 0)
        appendHeader(major: 1, value: UInt64(-1 - number), to: &output)
    case .bytes(let bytes):
        appendHeader(major: 2, value: UInt64(bytes.count), to: &output)
        output += bytes
    case .text(let text):
        let bytes = Array(text.utf8)
        appendHeader(major: 3, value: UInt64(bytes.count), to: &output)
        output += bytes
    case .array(let items):
        appendHeader(major: 4, value: UInt64(items.count), to: &output)
        for item in items {
            appendCBOR(item, to: &output)
        }
    case .map(let pairs):
        appendHeader(major: 5, value: UInt64(pairs.count), to: &output)
        for pair in pairs {
            appendCBOR(pair.key, to: &output)
            appendCBOR(pair.value, to: &output)
        }
    case .bool(let flag):
        output.append(flag ? 0xf5 : 0xf4)
    case .null:
        output.append(0xf6)
    }
}

private func appendHeader(major: UInt8, value: UInt64, to output: inout [UInt8]) {    let prefix = major << 5
    if value < 24 {
        output.append(prefix | UInt8(value))
    } else if value <= UInt64(UInt8.max) {
        output.append(prefix | 24)
        output.append(UInt8(value))
    } else if value <= UInt64(UInt16.max) {
        output.append(prefix | 25)
        output += be16(UInt16(value))
    } else if value <= UInt64(UInt32.max) {
        output.append(prefix | 26)
        output += be32(UInt32(value))
    } else {
        output.append(prefix | 27)
        output += be64(value)
    }
}

/// Decodes one complete CBOR value, rejecting trailing bytes.
func decodeCBOR(_ bytes: [UInt8]) throws -> CBORValue {
    var cursor = CBORCursor(bytes: bytes, offset: 0, depth: 0)
    let value = try cursor.readValue()
    guard cursor.offset == bytes.count else { throw CBORError.invalid }
    return value
}

private struct CBORCursor {
    let bytes: [UInt8]
    var offset: Int
    var depth: Int

    static let maximumDepth = 32

    mutating func readValue() throws -> CBORValue {
        guard depth < Self.maximumDepth else { throw CBORError.depthExceeded }
        let initial = try readByte()
        let major = initial >> 5
        let additional = initial & 0x1f

        switch major {
        case 0:
            return .unsigned(try readLength(additional))
        case 1:
            let value = try readLength(additional)
            guard value <= UInt64(Int64.max) else { throw CBORError.invalid }
            return .negative(-1 - Int64(value))
        case 2:
            let count = try readLength(additional)
            return .bytes(try readBytes(count))
        case 3:
            let count = try readLength(additional)
            let raw = try readBytes(count)
            guard let string = String(bytes: raw, encoding: .utf8) else { throw CBORError.invalid }
            return .text(string)
        case 4:
            let count = try readLength(additional)
            guard count <= UInt64(bytes.count - offset) else { throw CBORError.truncated }
            depth += 1
            var items: [CBORValue] = []
            items.reserveCapacity(Int(count))
            for _ in 0..<count {
                items.append(try readValue())
            }
            depth -= 1
            return .array(items)
        case 5:
            let count = try readLength(additional)
            guard count <= UInt64((bytes.count - offset) / 2) else { throw CBORError.truncated }
            depth += 1
            var pairs: [CBORPair] = []
            pairs.reserveCapacity(Int(count))
            for _ in 0..<count {
                let key = try readValue()
                let value = try readValue()
                pairs.append(CBORPair(key: key, value: value))
            }
            depth -= 1
            return .map(pairs)
        case 6:
            _ = try readLength(additional)
            depth += 1
            defer { depth -= 1 }
            return try readValue()
        case 7:
            switch additional {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            default: throw CBORError.invalid
            }
        default:
            throw CBORError.invalid
        }
    }

    private mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw CBORError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    private mutating func readLength(_ additional: UInt8) throws -> UInt64 {
        switch additional {
        case 0..<24:
            return UInt64(additional)
        case 24:
            return UInt64(try readByte())
        case 25:
            let raw = try readBytes(2)
            return UInt64(raw[0]) << 8 | UInt64(raw[1])
        case 26:
            let raw = try readBytes(4)
            return UInt64(raw[0]) << 24 | UInt64(raw[1]) << 16 | UInt64(raw[2]) << 8 | UInt64(raw[3])
        case 27:
            let raw = try readBytes(8)
            var value: UInt64 = 0
            for byte in raw {
                value = value << 8 | UInt64(byte)
            }
            return value
        default:
            throw CBORError.invalid
        }
    }

    private mutating func readBytes(_ count: UInt64) throws -> [UInt8] {
        guard count <= UInt64(bytes.count - offset) else { throw CBORError.truncated }
        let end = offset + Int(count)
        defer { offset = end }
        return Array(bytes[offset..<end])
    }
}

// MARK: Accessors
extension CBORValue {
    /// The value for a text key in a map.
    func field(_ name: String) -> CBORValue? {
        guard case .map(let pairs) = self else { return nil }
        for pair in pairs where pair.key == .text(name) {
            return pair.value
        }
        return nil
    }

    var bytesValue: [UInt8]? {
        guard case .bytes(let bytes) = self else { return nil }
        return bytes
    }

    var textValue: String? {
        guard case .text(let text) = self else { return nil }
        return text
    }

    var unsignedValue: UInt64? {
        guard case .unsigned(let number) = self else { return nil }
        return number
    }

    var arrayValue: [CBORValue]? {
        guard case .array(let items) = self else { return nil }
        return items
    }
}

/// Big-endian 64-bit bytes for CBOR integer heads.
func be64(_ value: UInt64) -> [UInt8] {
    (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> (8 * UInt64($0))) }
}

func be32(_ value: UInt32) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
    ]
}
