import CBOR
import Foundation
import Synchronization
import Testing

@testable import Juicebox

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// Recovery through a real `URLSession`, whose requests a `URLProtocol`
/// answers in place of the realms, so the requests and answers go through
/// http-client's `URLSession` conformance.
struct URLSessionRecoveryTests {
  init() throws {
    try #require(juiceboxSodiumIsReady)
  }

  /// A request as the URL loading system hands it to a `URLProtocol`.
  struct SeenRequest: Sendable {
    var method: String?
    var url: String?
    var version: String?
    var authorization: String?
    var body: [UInt8]?
  }

  /// Answers each request with the status and body of the scenario that its
  /// host is registered with, and records the request under its host.
  final class RealmStub: URLProtocol {
    /// The scenario each realm host answers with. Each test registers hosts
    /// of its own, so runs that overlap, or repeat in the same process, do not
    /// see each other's requests.
    static let scenarios = Mutex<[String: Scenario]>([:])
    /// The requests each host received.
    static let seen = Mutex<[String: [SeenRequest]]>([:])

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
      let request = self.request
      guard let url = request.url, let host = url.host(),
        let scenario = Self.scenarios.withLock({ $0[host] }),
        let response = HTTPURLResponse(
          url: url, statusCode: scenario.status, httpVersion: "HTTP/1.1", headerFields: [:])
      else {
        client?.urlProtocol(self, didFailWithError: URLError(.badURL))
        return
      }
      Self.seen.withLock {
        $0[host, default: []].append(
          SeenRequest(
            method: request.httpMethod, url: url.absoluteString,
            version: request.value(forHTTPHeaderField: "X-Juicebox-Version"),
            authorization: request.value(forHTTPHeaderField: "Authorization"),
            body: Self.body(of: request)))
      }
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      client?.urlProtocol(self, didLoad: Data(scenario.body))
      client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    /// The body, which an upload hands over as a stream.
    private static func body(of request: URLRequest) -> [UInt8]? {
      if let body = request.httpBody { return Array(body) }
      guard let stream = request.httpBodyStream else { return nil }
      stream.open()
      defer { stream.close() }
      var bytes: [UInt8] = []
      var buffer = [UInt8](repeating: 0, count: 1024)
      while true {
        let count = unsafe stream.read(&buffer, maxLength: buffer.count)
        guard count > 0 else { break }
        bytes += buffer[..<count]
      }
      return bytes
    }
  }

  /// What every realm of a test answers.
  enum Scenario: CaseIterable, Sendable {
    /// 401 with no body: an error status that the HTTP client returns
    /// instead of throwing, so recovery reads it as `invalidAuth`.
    case unauthorized
    /// 200 with a realm answer in the body, `NotRegistered`.
    case notRegistered
    /// 500 with a realm answer in the body, `NotRegistered`: recovery reads
    /// the body of a non-2xx answer too, so the HTTP client must return it.
    case serverErrorWithAnAnswer

    /// A realm's answer that the version phase reads as `notRegistered`.
    static let notRegisteredAnswer = CBOR.map(["Recover1": .textString("NotRegistered")])
      .encode()

    var status: Int {
      switch self {
      case .unauthorized: 401
      case .notRegistered: 200
      case .serverErrorWithAnAnswer: 500
      }
    }

    var body: [UInt8] {
      switch self {
      case .unauthorized: []
      case .notRegistered, .serverErrorWithAnAnswer: Self.notRegisteredAnswer
      }
    }

    var expectedError: JuiceboxRecoveryError {
      switch self {
      case .unauthorized: .invalidAuth
      case .notRegistered, .serverErrorWithAnAnswer: .notRegistered
      }
    }
  }

  /// Each realm gets one POST to its `req` endpoint with the protocol version
  /// and its token, and recovery reads the status and body that `URLSession`
  /// returns: a 401 without a body is `invalidAuth`, not a thrown error
  /// (`transient`), and the body of a 200 or a 500 is the realm's answer.
  @Test(.timeLimit(.minutes(1)), arguments: Scenario.allCases)
  func recoveryReadsTheRealmsAnswersThroughURLSession(scenario: Scenario) async throws {
    #expect(try SecretsResponse.decode(Scenario.notRegisteredAnswer) == .recover1(.notRegistered))
    let realmIds = (1...3).map { [UInt8](repeating: UInt8($0), count: 16) }
    let tokens = Dictionary(
      uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })
    let run = UUID().uuidString.lowercased()
    let hosts = (1...3).map { "realm\($0)-\(run).test" }
    RealmStub.scenarios.withLock { scenarios in
      for host in hosts { scenarios[host] = scenario }
    }
    defer {
      RealmStub.scenarios.withLock { scenarios in
        for host in hosts { scenarios[host] = nil }
      }
      RealmStub.seen.withLock { seen in
        for host in hosts { seen[host] = nil }
      }
    }
    let realms = zip(realmIds, hosts).map { id, host in
      #"{"id": "\#(hexString(id))", "address": "https://\#(host)/"}"#
    }
    let json = """
      {
        "realms": [\(realms.joined(separator: ","))],
        "register_threshold": 3,
        "recover_threshold": 2,
        "pin_hashing_mode": "FastInsecure"
      }
      """
    let configuration = try JuiceboxConfiguration.parse(Array(json.utf8))
    let recovery = JuiceboxRecovery(configuration: configuration, tokens: tokens)

    let sessionConfiguration = URLSessionConfiguration.ephemeral
    sessionConfiguration.protocolClasses = [RealmStub.self]
    let session = URLSession(configuration: sessionConfiguration)
    defer { session.invalidateAndCancel() }
    await #expect(throws: scenario.expectedError) {
      try await recovery.recover(pin: Array("1234".utf8), httpClient: session)
    }

    // The version phase fails, so each realm gets only its Recover1 request.
    let seen = RealmStub.seen.withLock { seen in hosts.map { seen[$0] ?? [] } }
    for ((id, host), requests) in zip(zip(realmIds, hosts), seen) {
      #expect(requests.count == 1, Comment(rawValue: host))
      for request in requests {
        #expect(request.method == "POST")
        #expect(request.url == "https://\(host)/req")
        #expect(request.version == JuiceboxRecovery.juiceboxVersion)
        #expect(request.authorization == "Bearer token-\(hexString(id))")
        // swift-corelibs-foundation does not hand an upload's body to a
        // URLProtocol, so the body can be checked only on Apple platforms.
        #if canImport(Darwin)
          #expect(request.body == SecretsRequest.recover1.encoded())
        #endif
      }
    }
  }
}
