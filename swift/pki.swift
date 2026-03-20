import Foundation
import CryptoKit

struct PKI {
    private static let fileURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("pki_keys.json")
    private static var signingPrivateKey: P256.Signing.PrivateKey?
    private static var encryptingPrivateKey: RSA.PrivateKey?

    static func init() throws {
        if FileManager.default.fileExists(atPath: fileURL.path) {
            let data = try Data(contentsOf: fileURL)
            let decoder = JSONDecoder()
            let keys = try decoder.decode(StoredKeys.self, from: data)
            signingPrivateKey = try P256.Signing.PrivateKey(jsonWebKey: keys.signingPrivateJWK)
            encryptingPrivateKey = try RSA.PrivateKey(jsonWebKey: keys.encryptingPrivateJWK)
        } else {
            signingPrivateKey = P256.Signing.PrivateKey()
            encryptingPrivateKey = try RSA.PrivateKey(keySize: 2048, e: 65537)

            let signingPrivateJWK = try signingPrivateKey!.jsonWebKey()
            let encryptingPrivateJWK = try encryptingPrivateKey!.jsonWebKey()

            let keys = StoredKeys(signingPrivateJWK: signingPrivateJWK, encryptingPrivateJWK: encryptingPrivateJWK)
            let encoder = JSONEncoder()
            let data = try encoder.encode(keys)
            try data.write(to: fileURL)
        }
    }

    static func sign(_ message: String) throws -> String {
        try init()
        guard let key = signingPrivateKey else { throw NSError(domain: "PKI", code: 1, userInfo: [NSLocalizedDescriptionKey: "Keys not initialized"]) }
        let data = Data(message.utf8)
        let signature = try key.signature(for: SHA256.hash(data: data))
        return signature.base64EncodedString()
    }

    static func verify(_ message: String, signature: String) throws -> Bool {
        try init()
        guard let key = signingPrivateKey else { throw NSError(domain: "PKI", code: 1, userInfo: [NSLocalizedDescriptionKey: "Keys not initialized"]) }
        let publicKey = key.publicKey
        let data = Data(message.utf8)
        let sigData = Data(base64Encoded: signature)!
        return publicKey.isValidSignature(sigData, for: SHA256.hash(data: data))
    }

    static func encrypt(_ message: String) throws -> String {
        try init()
        guard let key = encryptingPrivateKey else { throw NSError(domain: "PKI", code: 1, userInfo: [NSLocalizedDescriptionKey: "Keys not initialized"]) }
        let publicKey = key.publicKey
        let data = Data(message.utf8)
        let ciphertext = try publicKey.encrypt(data, padding: .oaep(with: .sha256))
        return ciphertext.base64EncodedString()
    }

    static func decrypt(_ ciphertext: String) throws -> String {
        try init()
        guard let key = encryptingPrivateKey else { throw NSError(domain: "PKI", code: 1, userInfo: [NSLocalizedDescriptionKey: "Keys not initialized"]) }
        let ctData = Data(base64Encoded: ciphertext)!
        let plaintext = try key.decrypt(ctData, padding: .oaep(with: .sha256))
        return String(data: plaintext, encoding: .utf8) ?? ""
    }
}

struct StoredKeys: Codable {
    let signingPrivateJWK: JSONWebKey
    let encryptingPrivateJWK: JSONWebKey
}

// Usage example (in a Swift script or playground):
do {
    try PKI.init()
    let sig = try PKI.sign("Hello World")
    print("Signature: \(sig)")
    print("Verify: \(try PKI.verify("Hello World", signature: sig))")
    let enc = try PKI.encrypt("Secret message")
    print("Encrypted: \(enc)")
    print("Decrypted: \(try PKI.decrypt(enc))")
} catch {
    print("Error: \(error)")
}
