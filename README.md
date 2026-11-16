# juicebox-swift

A Swift package for recovering PIN-protected secrets with the Juicebox protocol. The `Juicebox` module supports software realms and Noise NK hardware realms.

Supply the realm configuration and authentication tokens to `JuiceboxRecovery`, and call `recover(pin:httpClient:)` with an HTTP client to recover the secret. The HTTP client is an `HTTPClientProtocol` from [http-client](https://github.com/zunda-pixel/http-client), which `URLSession` conforms to, so you can pass `URLSession.shared` as it is:

```swift
import Foundation
import Juicebox

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

let configuration = try JuiceboxConfiguration.parse(configurationJSON)
let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)
let secret = try await recovery.recover(pin: pin, httpClient: URLSession.shared)
```

`URLSession.shared` follows redirects, which can carry a realm's token to another host; see [Redirects](#redirects).

juicebox-swift depends on http-client, so passing a `URLSession` needs no other dependency. On Linux, `URLSession` is in FoundationNetworking, so import it to name `URLSession`.

Each realm request is a POST of a CBOR message, an `HTTPRequest` from [swift-http-types](https://github.com/apple/swift-http-types) with a body. Recovery reads a realm's error from the body of a non-2xx response when there is one, and from the status otherwise, so the HTTP client must return the response whatever its status, as `HTTPClientProtocol` requires.

## AsyncHTTPClient

To send the requests with AsyncHTTPClient, enable http-client's `AsyncHTTPClient` trait. juicebox-swift leaves the trait off, so that apps that use `URLSession` don't fetch or build SwiftNIO. SwiftPM enables a trait for the whole package graph when any package enables it, so add http-client to your own dependencies with the trait:

```swift
// Package.swift (swift-tools-version: 6.4 or later)
dependencies: [
  .package(url: "https://github.com/zunda-pixel/juicebox-swift", from: "0.3.1"),
  .package(
    url: "https://github.com/zunda-pixel/http-client",
    from: "0.5.0",
    traits: ["AsyncHTTPClient"]
  ),
  .package(url: "https://github.com/swift-server/async-http-client", from: "1.33.0"),
],
targets: [
  .target(
    name: "App",
    dependencies: [
      .product(name: "Juicebox", package: "juicebox-swift"),
      .product(name: "HTTPClient", package: "http-client"),
      .product(name: "AsyncHTTPClient", package: "async-http-client"),
    ]
  )
]
```

```swift
import AsyncHTTPClient
import HTTPClient
import Juicebox

let secret = try await recovery.recover(pin: pin, httpClient: .asyncHTTPClient(.shared))
```

## Redirects

`URLSession.shared` and AsyncHTTPClient's `HTTPClient.shared` follow redirects, which can carry a realm's token to wherever the redirect points. On a 307 or 308 redirect to another host, `URLSession` on Apple platforms and AsyncHTTPClient send the request's body again, and with it a hardware realm's token, which is in the body. `URLSession` on Linux (FoundationNetworking) does not send the body again, but sends the `Authorization` header again on every redirect it follows (301, 302, 303, 307 and 308), to another host too, and with it a software realm's token. To keep the tokens on the realm's host, pass a client that refuses redirects. A refused redirect is a failure of that realm (`transient`). With `URLSession`, refuse them in the session's delegate:

```swift
final class RefuseRedirects: NSObject, URLSessionTaskDelegate {
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}

let session = URLSession(configuration: .default, delegate: RefuseRedirects(), delegateQueue: nil)
let secret = try await recovery.recover(pin: pin, httpClient: session)
```

Make the session once and reuse it for every recovery: a session keeps a strong reference to its delegate until it is invalidated.

With AsyncHTTPClient, start from the configuration of `HTTPClient.shared` and refuse redirects in it. That configuration has a read timeout, which `HTTPClient.Configuration(redirectConfiguration: .disallow)` does not: without one, a realm that takes a request and never answers holds recovery until the caller cancels (see [Concurrency and cancellation](#concurrency-and-cancellation)). Make this client once too, and shut it down when the app no longer needs it.

```swift
var configuration = AsyncHTTPClient.HTTPClient.Configuration.singletonConfiguration
configuration.redirectConfiguration = .disallow
let client = AsyncHTTPClient.HTTPClient(configuration: configuration)
let secret = try await recovery.recover(pin: pin, httpClient: client)
```

## Concurrency and cancellation

Recovery calls the HTTP client's `execute(for:from:)` concurrently: each phase asks all of its realms at once (the OPRF and unlock phases ask the realms that reported the chosen registration version; within one recovery, one request in flight per realm; for a hardware realm, the OPRF and unlock phases send the Noise handshake and then the request). An error the HTTP client throws, including a cancellation, is a failure of that realm unless the caller cancelled recovery; `recover` throws `CancellationError` only for the caller's cancellation. Each phase waits for all of its requests, so recovery stops promptly when the caller cancels only if `execute(for:from:)` responds to its task's cancellation (as `URLSession` and AsyncHTTPClient do). For the same reason, each phase takes as long as its slowest realm, and what ends a request to a realm that stops answering is the HTTP client's timeout: with a client that has none, a realm that takes a request and never answers holds recovery until the caller cancels. Those timeouts (`URLSession`'s `timeoutIntervalForRequest`, AsyncHTTPClient's read timeout) count the time without data, so they do not cut off a realm that keeps answering slowly. To limit the whole recovery, cancel the caller's task after a deadline; with `URLSession`, `timeoutIntervalForResource` also limits each request as a whole. A cancellation that arrives while the PIN is being hashed takes effect once the hashing ends.

Run the Swift Testing suite with `swift test` on macOS, and in a release build with `swift test -c release -Xswiftc -enable-testing`, which can catch optimizer bugs that a debug build hides. CI runs both on Linux.
