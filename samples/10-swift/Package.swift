// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PKISample",
    platforms: [
        .macOS(.v13)   // URLSessionWebSocketTask + Security RSA require macOS 13+
    ],
    targets: [
        .executableTarget(
            name: "PKISample",
            path: "Sources/PKISample",
            swiftSettings: [
                .unsafeFlags(["-I../../"])  // include SDK root for bridging headers
            ]
        )
    ]
)
