# juicebox-swift

A Swift package for recovering PIN-protected secrets with the Juicebox protocol. The `Juicebox` module supports software realms and Noise NK hardware realms.

Supply the realm configuration and authentication tokens to `JuiceboxRecovery`, implement `JuiceboxHTTPTransport`, and call `recover(pin:transport:)` to recover the secret. The transport sends each realm request, an `HTTPRequest` from [swift-http-types](https://github.com/apple/swift-http-types) with its body, and returns the `HTTPResponse` with its body, whatever the status. With `HTTPTypesFoundation`, `URLSession` can send it:

```swift
import Foundation
import HTTPTypes
import HTTPTypesFoundation
import Juicebox

struct RealmTransport: JuiceboxHTTPTransport {
  func send(_ request: HTTPRequest, body: [UInt8]) async throws -> (HTTPResponse, [UInt8]) {
    let (data, response) = try await URLSession.shared.upload(for: request, from: Data(body))
    return (response, Array(data))
  }
}

let configuration = try JuiceboxConfiguration.parse(configurationJSON)
let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
let secret = try await recovery.recover(pin: pin, transport: RealmTransport())
```

`URLSession.shared` follows redirects, which can send a request's body, and with it a hardware realm's token, to another host; a transport for an app may use a session whose delegate refuses them.

Recovery calls the transport's `send` concurrently: each phase asks all of its realms at once (the OPRF and unlock phases ask the realms that reported the chosen registration version; within one recovery, one request in flight per realm; for a hardware realm, the OPRF and unlock phases send the Noise handshake and then the request), so the transport must handle several requests at a time. An error the transport throws, including a cancellation, is a failure of that realm unless the caller cancelled recovery; `recover` throws `CancellationError` only for the caller's cancellation. Each phase waits for all of its requests, so recovery stops promptly when the caller cancels only if `send` responds to its task's cancellation (as `URLSession`'s async methods do). A cancellation that arrives while the PIN is being hashed takes effect once the hashing ends.

Run the Swift Testing suite with `swift test` on macOS.
