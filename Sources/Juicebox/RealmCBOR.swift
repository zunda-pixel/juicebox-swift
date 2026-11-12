import CBOR

private let realmCBOROptions = CBOROptions(maximumDepth: 31, rejectDuplicateMapKeys: true)

func decodeCBOR(_ bytes: [UInt8]) throws -> CBOR {
    guard bytes.count <= 64 * 1024 else { throw RealmMessageError.malformed }
    return try withoutTags(CBOR.decode(bytes, options: realmCBOROptions))
}

/// The realm protocol reads the value inside a CBOR tag. Check keys again
/// after stripping tags so two representations cannot name the same field.
private func withoutTags(_ value: CBOR) throws -> CBOR {
    switch value {
    case .tagged(_, let item):
        return try withoutTags(item)
    case .array(let items):
        return .array(try items.map(withoutTags))
    case .map(let fields):
        var untagged: [CBOR: CBOR] = [:]
        for (key, item) in fields {
            let key = try withoutTags(key)
            guard untagged[key] == nil else { throw CBORError.duplicateMapKey }
            untagged[key] = try withoutTags(item)
        }
        return .map(untagged)
    default:
        return value
    }
}
