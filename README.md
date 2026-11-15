# juicebox-swift

A Swift package for recovering PIN-protected secrets with the Juicebox protocol. The `Juicebox` module supports software realms and Noise NK hardware realms.

Supply the realm configuration and authentication tokens to `JuiceboxRecovery`, implement `JuiceboxHTTPTransport`, and call `recover(pin:transport:)` to recover the secret. Recovery calls the transport's `send` concurrently: each phase sends one request to every realm at once, so the transport must handle several requests at a time. An error the transport throws, including a cancellation, is a failure of that realm unless the caller cancelled recovery; `recover` throws `CancellationError` only for the caller's cancellation.

Run the Swift Testing suite with `swift test` on macOS.
