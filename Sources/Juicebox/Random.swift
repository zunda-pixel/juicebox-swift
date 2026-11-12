/// Cryptographically secure random bytes from the system random source.
func juiceboxRandomBytes(_ length: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<length).map { _ in UInt8.random(in: 0...255, using: &generator) }
}
