# juicebox-swift

A Swift package for recovering PIN-protected secrets with the Juicebox protocol. The `Juicebox` module supports software realms and Noise NK hardware realms.

Supply the realm configuration and authentication tokens to `JuiceboxRecovery`, implement `JuiceboxHTTPTransport`, and call `recover(pin:transport:)` to recover the secret.

The implementation and interoperability vectors originated in the [Juicebox target in xchat-swift](https://github.com/zunda-pixel/xchat-swift/tree/a2b630ab0568c9472e132fe63e8f3743117e8814/Sources/Juicebox). See [the protocol notes](docs/JUICEBOX.md) for wire details and Linux test setup.

Run the Swift Testing suite with `swift test` on macOS.
