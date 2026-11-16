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

  /// Answers every request with the status and body that its host's scenario
  /// gives, and records the request.
  final class RealmStub: URLProtocol {
    static let seen = Mutex<[SeenRequest]>([])

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
      let request = self.request
      Self.seen.withLock {
        $0.append(
          SeenRequest(
            method: request.httpMethod, url: request.url?.absoluteString,
            version: request.value(forHTTPHeaderField: "X-Juicebox-Version"),
            authorization: request.value(forHTTPHeaderField: "Authorization"),
            body: Self.body(of: request)))
      }
      guard let url = request.url, let host = url.host(),
        let scenario = Scenario.allCases.first(where: { host.hasPrefix($0.rawValue) }),
        let response = HTTPURLResponse(
          url: url, statusCode: scenario.status, httpVersion: "HTTP/1.1", headerFields: [:])
      else {
        client?.urlProtocol(self, didFailWithError: URLError(.badURL))
        return
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

  /// What every realm answers, chosen by the realms' host names.
  enum Scenario: String, CaseIterable, Sendable {
    /// 401 with no body: an error status that the HTTP client returns
    /// instead of throwing, so recovery reads it as `invalidAuth`.
    case unauthorized = "unauthorized"
    /// 200 with a realm answer in the body, `NotRegistered`.
    case notRegistered = "notregistered"

    var status: Int {
      switch self {
      case .unauthorized: 401
      case .notRegistered: 200
      }
    }

    var body: [UInt8] {
      switch self {
      case .unauthorized: []
      case .notRegistered: CBOR.map(["Recover1": .textString("NotRegistered")]).encode()
      }
    }

    var expectedError: JuiceboxRecoveryError {
      switch self {
      case .unauthorized: .invalidAuth
      case .notRegistered: .notRegistered
      }
    }
  }

  /// Each realm gets one POST to its `req` endpoint with the protocol version
  /// and its token, and recovery reads the status and body that `URLSession`
  /// returns: a 401 without a body is `invalidAuth`, not a thrown error
  /// (`transient`), and a 200's body is the realm's answer.
  @Test(arguments: Scenario.allCases)
  func recoveryReadsTheRealmsAnswersThroughURLSession(scenario: Scenario) async throws {
    #expect(
      try SecretsResponse.decode(Scenario.notRegistered.body) == .recover1(.notRegistered))
    let realmIds = (1...3).map { [UInt8](repeating: UInt8($0), count: 16) }
    let tokens = Dictionary(
      uniqueKeysWithValues: realmIds.map { (hexString($0), "token-\(hexString($0))") })
    let realms = realmIds.enumerated().map { index, id in
      #"{"id": "\#(hexString(id))", "address": "https://\#(scenario.rawValue)\#(index + 1).test/"}"#
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
    let authorizations = Dictionary(
      uniqueKeysWithValues: realmIds.enumerated().map { index, id in
        ("https://\(scenario.rawValue)\(index + 1).test/req", "Bearer token-\(hexString(id))")
      })
    let seen = RealmStub.seen.withLock { requests in
      requests.filter { $0.url?.hasPrefix("https://\(scenario.rawValue)") == true }
    }
    #expect(seen.compactMap(\.url).sorted() == authorizations.keys.sorted())
    for request in seen {
      #expect(request.method == "POST")
      #expect(request.version == JuiceboxRecovery.juiceboxVersion)
      #expect(request.authorization == authorizations[request.url ?? ""])
      // swift-corelibs-foundation does not hand an upload's body to a
      // URLProtocol, so the body can be checked only on Apple platforms.
      #if canImport(Darwin)
        #expect(request.body == SecretsRequest.recover1.encoded())
      #endif
    }
  }
}
