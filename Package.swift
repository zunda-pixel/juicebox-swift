// swift-tools-version:6.4
import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ImmutableWeakCaptures"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .defaultIsolation(nil),
    .strictMemorySafety(),
    .treatAllWarnings(as: .error),
]

let package = Package(
    name: "Juicebox",
    platforms: [.macOS(.v27), .iOS(.v27)],
    products: [
        .library(name: "Juicebox", targets: ["Juicebox"]),
    ],
    dependencies: [
        .package(url: "https://github.com/brokenhandsio/swift-cbor.git", exact: "0.2.0", traits: []),
        .package(url: "https://github.com/P-H-C/phc-winner-argon2.git", revision: "f57e61e19229e23c4445b85494dbf7c07de721cb"),
        .package(url: "https://github.com/trancee/blake-hash.git", exact: "1.1.1"),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.1"),
    ],
    targets: [
        .target(
            name: "Juicebox",
            dependencies: [
                .product(name: "CBOR", package: "swift-cbor"),
                .product(name: "argon2", package: "phc-winner-argon2"),
                .product(name: "BlakeHash", package: "blake-hash"),
                .product(name: "Clibsodium", package: "swift-sodium"),
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JuiceboxTests",
            dependencies: [
                .target(name: "Juicebox"),
                .product(name: "CBOR", package: "swift-cbor")
            ],
            resources: [.copy("Fixtures/noise_nk_vectors.json")],
            swiftSettings: swiftSettings
        ),
    ],
    swiftLanguageModes: [.v6]
)
