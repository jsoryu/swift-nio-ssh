//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto
import _CryptoExtras
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    private init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = .ecdsaP384(key)
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = .ecdsaP521(key)
    }

    /// Create a private key from an RSA key.
    ///
    /// RSA support exists for interoperability with existing deployments. Signatures
    /// use rsa-sha2-256/rsa-sha2-512 only (RFC 8332); ssh-rsa/SHA-1 is never produced.
    /// For new deployments prefer Ed25519 or ECDSA keys.
    public init(rsaKey key: _RSA.Signing.PrivateKey) {
        self.backingKey = .rsa(key)
    }

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = .secureEnclaveP256(key)
    }
    #endif

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        switch self.backingKey {
        case .ed25519:
            return ["ssh-ed25519"]
        case .ecdsaP256:
            return ["ecdsa-sha2-nistp256"]
        case .ecdsaP384:
            return ["ecdsa-sha2-nistp384"]
        case .ecdsaP521:
            return ["ecdsa-sha2-nistp521"]
        case .rsa:
            // rsa-sha2-512 preferred over rsa-sha2-256 (RFC 8332). Deliberately no
            // ssh-rsa (SHA-1) entry: we never offer or accept SHA-1 RSA.
            return ["rsa-sha2-512", "rsa-sha2-256"]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)
        case rsa(_RSA.Signing.PrivateKey)

        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        #endif
    }
}

extension NIOSSHPrivateKey {
    func sign<DigestBytes: Digest>(digest: DigestBytes) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        case .rsa:
            // RSA host-key signing is deliberately NOT reachable through this generic
            // digest overload — doing so is the RFC 8332 non-conformance this fork fixes.
            //
            // RFC 8332 requires the RSA signature hash to be the one bound to the
            // *negotiated* rsa-sha2 algorithm (rsa-sha2-512 → SHA-512, rsa-sha2-256 →
            // SHA-256), treating the exchange hash H as the message. That negotiated
            // algorithm is independent of the KEX exchange-hash's own width: e.g. an
            // ecdh-sha2-nistp384 exchange yields a SHA-384 `Digest` here, which must NOT
            // dictate the RSA hash. This overload only sees the `Digest` (whose *type* is
            // the KEX curve's hash), so it cannot know the negotiated algorithm — signing
            // here would derive the PKCS#1 DigestInfo OID from the wrong hash and mis-tag
            // the wire signature (self-consistent fork↔fork but rejected by OpenSSH).
            //
            // Fail closed: RSA host-key signatures MUST go through
            // `signForHostKeyExchange(digest:rsaAlgorithm:)`, which re-hashes the exchange
            // hash with the negotiated SHA-2 variant. ed25519/ECDSA are unaffected.
            throw NIOSSHError.invalidHostKeyForKeyExchange(
                expected: "rsa-sha2-512 or rsa-sha2-256",
                got: self.publicKey.keyPrefix
            )

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    func sign(_ payload: UserAuthSignablePayload, rsaSignatureAlgorithm: RSASignatureAlgorithm = .sha512) throws
        -> NIOSSHSignature
    {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        case .rsa(let key):
            // Hash the signable payload with the negotiated SHA-2 variant, then sign
            // with PKCS#1 v1.5 padding (RFC 8332). Only rsa-sha2-256/512 are reachable;
            // there is no SHA-1 path.
            let bytesView = payload.bytes.readableBytesView
            switch rsaSignatureAlgorithm {
            case .sha512:
                let digest = SHA512.hash(data: bytesView)
                let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
                return NIOSSHSignature(backingSignature: .rsaSHA512(signature))
            case .sha256:
                let digest = SHA256.hash(data: bytesView)
                let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
                return NIOSSHSignature(backingSignature: .rsaSHA256(signature))
            }
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// Signs the key-exchange exchange hash for **host-key** authentication (the server
    /// side of the KEX signature), applying RFC 8332 correctly for RSA.
    ///
    /// This is the dedicated host-key signing seam used by the key-exchange machinery.
    ///
    /// - For ed25519 and ECDSA (incl. Secure Enclave) this is byte-for-byte identical to
    ///   the generic ``sign(digest:)`` — the exchange hash is signed as-is.
    /// - For **RSA** it implements RFC 8332: the exchange hash `H` is treated as the
    ///   *message* and re-hashed with the SHA-2 variant bound to the **negotiated**
    ///   `rsa-sha2-*` algorithm (rsa-sha2-512 → `SHA-512(H)`, rsa-sha2-256 → `SHA-256(H)`).
    ///   The signature is then produced with PKCS#1 v1.5 padding, so the DigestInfo carries
    ///   the SHA-512/SHA-256 OID as required, and the wire signature is tagged by the
    ///   negotiated algorithm — never by the width of the KEX curve's hash. `ssh-rsa`/SHA-1
    ///   is unreachable.
    ///
    /// - Parameters:
    ///   - digest: The KEX exchange hash `H`. Its *type* is the KEX curve's hash (e.g.
    ///     SHA-384 for ecdh-sha2-nistp384), which may differ from the RSA signature hash —
    ///     that difference is exactly what RFC 8332 resolves by re-hashing `H`.
    ///   - rsaAlgorithm: The negotiated RSA signature algorithm. It MUST be non-nil for an
    ///     RSA host key (negotiation guarantees this); it is ignored for ed25519/ECDSA.
    ///     Fail-closed: a nil value with an RSA host key throws rather than guessing a hash.
    func signForHostKeyExchange<DigestBytes: Digest>(
        digest: DigestBytes,
        rsaAlgorithm: RSASignatureAlgorithm?
    ) throws -> NIOSSHSignature {
        guard case .rsa(let key) = self.backingKey else {
            // ed25519 / ECDSA (incl. Secure Enclave): unchanged generic digest signature.
            return try self.sign(digest: digest)
        }

        guard let rsaAlgorithm else {
            // Fail closed: an RSA host key must carry a negotiated rsa-sha2-* algorithm.
            throw NIOSSHError.invalidHostKeyForKeyExchange(
                expected: "rsa-sha2-512 or rsa-sha2-256",
                got: self.publicKey.keyPrefix
            )
        }

        // RFC 8332: re-hash the exchange-hash BYTES with the negotiated SHA-2 variant so
        // the PKCS#1 DigestInfo OID matches the wire tag, then sign. PKCS#1 v1.5 is
        // deterministic, so this is byte-identical to a swift-crypto reference signature
        // over the same re-hashed digest.
        let exchangeHashBytes = Array(digest)
        switch rsaAlgorithm {
        case .sha512:
            let rehashed = SHA512.hash(data: exchangeHashBytes)
            let signature = try key.signature(for: rehashed, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA512(signature))
        case .sha256:
            let rehashed = SHA256.hash(data: exchangeHashBytes)
            let signature = try key.signature(for: rehashed, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA256(signature))
        }
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        case .ecdsaP384(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP384(privateKey.publicKey))
        case .ecdsaP521(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP521(privateKey.publicKey))
        case .rsa(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsa(privateKey.publicKey))
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        }
    }
}
