//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import _CryptoExtras
import NIOCore
import XCTest

@testable import NIOSSH

/// Focused coverage for the vendored rsa-sha2-256/512 support (RFC 8332):
/// client-sign + server-verify at the crypto layer, wire round-trips, the
/// algorithm-name/key-prefix decoupling, and the SHA-1/ssh-rsa refusal.
final class RSASHA2SignVerifyTests: XCTestCase {

    private func makeSessionID() -> ByteBuffer {
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)
        return sessionID
    }

    // MARK: - client-sign + server-verify over the user-auth payload

    private func assertSignAndVerify(_ algorithm: RSASignatureAlgorithm) throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        let payload = UserAuthSignablePayload(
            sessionIdentifier: self.makeSessionID(),
            userName: "testuser",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: algorithm
        )

        // Client signs; server verifies via the isValidSignature payload overload.
        let signature = try sshKey.sign(payload, rsaSignatureAlgorithm: algorithm)
        XCTAssertTrue(
            sshKey.publicKey.isValidSignature(signature, for: payload),
            "\(algorithm) signature should verify against its own key"
        )

        // The signature must carry the algorithm we asked for.
        switch (algorithm, signature.backingSignature) {
        case (.sha256, .rsaSHA256), (.sha512, .rsaSHA512):
            break
        default:
            XCTFail("Signature backing does not match requested algorithm \(algorithm)")
        }

        // Round-trip the signature through the wire and re-verify.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)
        guard let roundTripped = try buffer.readSSHSignature() else {
            XCTFail("Failed to read back \(algorithm) signature")
            return
        }
        XCTAssertEqual(signature, roundTripped)
        XCTAssertTrue(
            sshKey.publicKey.isValidSignature(roundTripped, for: payload),
            "round-tripped \(algorithm) signature should still verify"
        )

        // A different key must NOT verify.
        let otherKey = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        XCTAssertFalse(
            otherKey.publicKey.isValidSignature(signature, for: payload),
            "\(algorithm) signature must not verify under an unrelated key"
        )
    }

    func testSignAndVerifyRSASHA256() throws {
        try self.assertSignAndVerify(.sha256)
    }

    func testSignAndVerifyRSASHA512() throws {
        try self.assertSignAndVerify(.sha512)
    }

    // MARK: - algorithm-name vs key-prefix decoupling (RFC 8332)

    func testAlgorithmNameDecouplesFromKeyPrefix() throws {
        let sshKey = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        let publicKey = sshKey.publicKey

        // The key-blob prefix stays "ssh-rsa" ...
        XCTAssertTrue(publicKey.keyPrefix.elementsEqual("ssh-rsa".utf8))

        // ... while the user-auth algorithm name is rsa-sha2-256/512.
        XCTAssertTrue(publicKey.algorithmName(forRSA: .sha512).elementsEqual("rsa-sha2-512".utf8))
        XCTAssertTrue(publicKey.algorithmName(forRSA: .sha256).elementsEqual("rsa-sha2-256".utf8))
    }

    func testRSAPublicKeyWireRoundTrip() throws {
        let sshKey = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        let publicKey = sshKey.publicKey

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHHostKey(publicKey)

        guard let readBack = try buffer.readSSHHostKey() else {
            XCTFail("Failed to read back RSA public key")
            return
        }
        XCTAssertEqual(publicKey, readBack)
    }

    /// End-to-end within the fork: a full user-auth request message with an RSA key and
    /// an rsa-sha2 algorithm name must survive write→read (exercises the knownAlgorithms
    /// gate and the relaxed algorithm/key consistency guard), and still verify.
    func testUserAuthRequestMessageRoundTripAndVerify() throws {
        let sshKey = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))

        let payload = UserAuthSignablePayload(
            sessionIdentifier: self.makeSessionID(),
            userName: "test",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey,
            rsaSignatureAlgorithm: .sha512
        )
        let signature = try sshKey.sign(payload, rsaSignatureAlgorithm: .sha512)

        let message = SSHMessage.userAuthRequest(
            .init(
                username: "test",
                service: "ssh-connection",
                method: .publicKey(.known(key: sshKey.publicKey, signature: signature, rsaSignatureAlgorithm: .sha512))
            )
        )

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    // MARK: - SHA-1 / ssh-rsa refusal

    func testSHA1AlgorithmNameIsRefused() {
        // "ssh-rsa" (SHA-1) is never mapped to an RSASignatureAlgorithm.
        XCTAssertNil(RSASignatureAlgorithm(algorithmName: "ssh-rsa".utf8))
        // Garbage is also refused; the valid SHA-2 names are accepted.
        XCTAssertNil(RSASignatureAlgorithm(algorithmName: "rsa-sha2-384".utf8))
        XCTAssertEqual(RSASignatureAlgorithm(algorithmName: "rsa-sha2-256".utf8), .sha256)
        XCTAssertEqual(RSASignatureAlgorithm(algorithmName: "rsa-sha2-512".utf8), .sha512)
    }

    func testSSHRSASignatureBlobIsRefusedOnRead() {
        // An "ssh-rsa" (SHA-1) signature blob on the wire has no reader arm and must be
        // rejected as an unknown signature, never silently accepted.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writeSSHString(Array("not-a-real-signature".utf8))

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownSignature)
        }
    }

    // MARK: - minimum RSA modulus floor on the host-key read path

    /// Defense-in-depth: a well-formed "ssh-rsa" wire blob whose modulus is below the
    /// 2048-bit floor (here 1024 bits) must be rejected by the host-key reader, while a
    /// normal 2048-bit key still round-trips. This keeps the min-modulus guard in
    /// `readRSAPublicKey` live.
    func testRSAPublicKeyBelowMinimumModulusIsRejectedOnRead() throws {
        // Build a genuine 1024-bit "ssh-rsa" blob with the fork's own writer, which
        // applies no size floor, so only the reader's guard can reject it.
        let weakKey = try _RSA.Signing.PrivateKey(unsafeKeySize: _RSA.Signing.KeySize(bitCount: 1024))
        let weakPublicKey = NIOSSHPrivateKey(rsaKey: weakKey).publicKey
        XCTAssertTrue(
            weakPublicKey.keyPrefix.elementsEqual("ssh-rsa".utf8),
            "the weak key must serialize under the ssh-rsa key prefix"
        )

        var weakBuffer = ByteBufferAllocator().buffer(capacity: 1024)
        weakBuffer.writeSSHHostKey(weakPublicKey)
        XCTAssertNil(
            try weakBuffer.readSSHHostKey(),
            "a 1024-bit RSA host key is below the 2048-bit floor and must be rejected on read"
        )

        // A normal 2048-bit key must still be accepted.
        let strongKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let strongPublicKey = NIOSSHPrivateKey(rsaKey: strongKey).publicKey

        var strongBuffer = ByteBufferAllocator().buffer(capacity: 1024)
        strongBuffer.writeSSHHostKey(strongPublicKey)
        XCTAssertEqual(
            try strongBuffer.readSSHHostKey(),
            strongPublicKey,
            "a 2048-bit RSA host key must still be accepted on read"
        )
    }

    // MARK: - advertised host-key algorithm list

    /// The client advertises rsa-sha2-512 and rsa-sha2-256 for host-key verification,
    /// at the lowest preference (ed25519/ECDSA ahead of RSA, 512 ahead of 256), and never
    /// advertises ssh-rsa (SHA-1).
    func testAdvertisedHostKeyAlgorithmsContainRSASHA2ButNotSHA1() {
        let algorithms = SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms

        XCTAssertTrue(algorithms.contains("rsa-sha2-512"), "rsa-sha2-512 must be advertised")
        XCTAssertTrue(algorithms.contains("rsa-sha2-256"), "rsa-sha2-256 must be advertised")

        // ssh-rsa (SHA-1) must never appear.
        XCTAssertFalse(algorithms.contains("ssh-rsa"), "ssh-rsa (SHA-1) must never be advertised")

        // RSA is lowest preference: every non-RSA algorithm precedes both rsa-sha2 names.
        guard
            let idx512 = algorithms.firstIndex(of: "rsa-sha2-512"),
            let idx256 = algorithms.firstIndex(of: "rsa-sha2-256")
        else {
            XCTFail("rsa-sha2-512/256 must both be present")
            return
        }
        XCTAssertLessThan(idx512, idx256, "rsa-sha2-512 must be preferred over rsa-sha2-256")

        let nonRSA = ["ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521"]
        for name in nonRSA {
            guard let idx = algorithms.firstIndex(of: Substring(name)) else {
                XCTFail("expected \(name) to be advertised")
                continue
            }
            XCTAssertLessThan(idx, idx512, "\(name) must be preferred over RSA")
        }
    }

    // MARK: - RFC 8332 conformance: RSA host-key signature over the exchange hash
    //
    // These tests pin the fork's RSA host-key sign/verify to an INDEPENDENT swift-crypto
    // reference. A fork↔fork round-trip cannot catch the RFC 8332 non-conformance — it is
    // self-consistent by construction — so the oracle here is swift-crypto's own
    // deterministic PKCS#1 v1.5 signature over the *correctly re-hashed* exchange hash:
    // rsa-sha2-512 ⇒ RSA(SHA-512-OID, SHA-512(H)), rsa-sha2-256 ⇒ RSA(SHA-256-OID, SHA-256(H)),
    // where H is the KEX exchange hash treated as the message.

    /// The raw PKCS#1 v1.5 signature bytes carried by an RSA `NIOSSHSignature`, plus its
    /// on-the-wire rsa-sha2 tag (`true` == rsa-sha2-512). `nil` if the backing is not RSA.
    private func rsaSignatureBytesAndTag(_ signature: NIOSSHSignature) -> (bytes: Data, isSHA512: Bool)? {
        switch signature.backingSignature {
        case .rsaSHA512(let sig):
            return (sig.rawRepresentation, true)
        case .rsaSHA256(let sig):
            return (sig.rawRepresentation, false)
        default:
            return nil
        }
    }

    /// Builds a `NIOSSHSignature` from raw PKCS#1 v1.5 bytes tagged for `algorithm`.
    private func rsaSignature(rawBytes: Data, tagged algorithm: RSASignatureAlgorithm) -> NIOSSHSignature {
        switch algorithm {
        case .sha512:
            return NIOSSHSignature(backingSignature: .rsaSHA512(.init(rawRepresentation: rawBytes)))
        case .sha256:
            return NIOSSHSignature(backingSignature: .rsaSHA256(.init(rawRepresentation: rawBytes)))
        }
    }

    /// The swift-crypto RFC 8332 reference signature bytes: re-hash `H` with the SHA-2
    /// variant bound to `algorithm`, then sign with deterministic PKCS#1 v1.5.
    private func referenceSignatureBytes<D: Digest>(
        key: _RSA.Signing.PrivateKey,
        exchangeHash: D,
        algorithm: RSASignatureAlgorithm
    ) throws -> Data {
        let hBytes = Array(exchangeHash)
        switch algorithm {
        case .sha512:
            return try key.signature(for: SHA512.hash(data: hBytes), padding: .insecurePKCS1v1_5).rawRepresentation
        case .sha256:
            return try key.signature(for: SHA256.hash(data: hBytes), padding: .insecurePKCS1v1_5).rawRepresentation
        }
    }

    /// Core RFC 8332 conformance assertion for one (exchange-hash, negotiated rsa-sha2)
    /// pairing. `exchangeHash`'s *type* is the KEX curve's hash and is deliberately allowed
    /// to differ from the RSA hash — that divergence is exactly what RFC 8332 resolves.
    private func assertRFC8332Conformance<D: Digest>(
        exchangeHash: D,
        tamperedHash: D,
        negotiated: RSASignatureAlgorithm
    ) throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let hostKey = NIOSSHPrivateKey(rsaKey: rsaKey)

        // The fork's host-key signature over H under the negotiated algorithm.
        let signature = try hostKey.signForHostKeyExchange(digest: exchangeHash, rsaAlgorithm: negotiated)

        guard let (forkBytes, forkIsSHA512) = self.rsaSignatureBytesAndTag(signature) else {
            XCTFail("host-key signature must be an RSA signature")
            return
        }

        // (1) Wire tag follows the NEGOTIATED algorithm, never the exchange-hash width.
        XCTAssertEqual(
            forkIsSHA512, negotiated == .sha512,
            "wire tag must match the negotiated rsa-sha2 algorithm, not the KEX hash width"
        )

        // (2) BYTE-IDENTICAL to the independent swift-crypto RFC 8332 reference.
        let referenceBytes = try self.referenceSignatureBytes(
            key: rsaKey, exchangeHash: exchangeHash, algorithm: negotiated
        )
        XCTAssertEqual(
            forkBytes, referenceBytes,
            "fork RSA host-key signature must be byte-identical to the swift-crypto RFC 8332 reference"
        )

        // (3) The fork's verify accepts the independent reference signature.
        let referenceSignature = self.rsaSignature(rawBytes: referenceBytes, tagged: negotiated)
        XCTAssertTrue(
            hostKey.publicKey.isValidHostKeySignature(referenceSignature, for: exchangeHash, rsaAlgorithm: negotiated),
            "fork verify must accept the swift-crypto RFC 8332 reference signature"
        )

        // (4) The fork also verifies its own signature (sign/verify agree).
        XCTAssertTrue(
            hostKey.publicKey.isValidHostKeySignature(signature, for: exchangeHash, rsaAlgorithm: negotiated),
            "the fork's own RFC 8332 signature must verify"
        )

        // (5) A tampered exchange hash must NOT verify.
        XCTAssertFalse(
            hostKey.publicKey.isValidHostKeySignature(signature, for: tamperedHash, rsaAlgorithm: negotiated),
            "a tampered exchange hash must not verify"
        )

        // (6) An unrelated host key must NOT verify the signature.
        let otherKey = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        XCTAssertFalse(
            otherKey.publicKey.isValidHostKeySignature(signature, for: exchangeHash, rsaAlgorithm: negotiated),
            "an unrelated RSA host key must not verify the signature"
        )
    }

    /// The canonical divergent case: an ecdh-sha2-nistp384 exchange yields a SHA-384 hash,
    /// which under rsa-sha2-512 must be re-hashed with SHA-512 (NOT signed under the SHA-384
    /// OID). This is the exact scenario the fork's old passthrough got wrong.
    func testRFC8332_SHA384ExchangeHash_negotiatedRSASHA512() throws {
        try self.assertRFC8332Conformance(
            exchangeHash: SHA384.hash(data: Array("genuine-nistp384-exchange-hash".utf8)),
            tamperedHash: SHA384.hash(data: Array("tampered-nistp384-exchange-hash".utf8)),
            negotiated: .sha512
        )
    }

    /// Same divergent SHA-384 exchange hash, negotiated rsa-sha2-256 ⇒ re-hash with SHA-256.
    func testRFC8332_SHA384ExchangeHash_negotiatedRSASHA256() throws {
        try self.assertRFC8332Conformance(
            exchangeHash: SHA384.hash(data: Array("genuine-nistp384-exchange-hash".utf8)),
            tamperedHash: SHA384.hash(data: Array("tampered-nistp384-exchange-hash".utf8)),
            negotiated: .sha256
        )
    }

    /// Matched-width cases still exercise the fix: the old passthrough signed H directly
    /// under the SHA-512/256 OID, whereas RFC 8332 requires SHA-512(H)/SHA-256(H). The
    /// byte-identity check against the reference catches the difference.
    func testRFC8332_SHA512ExchangeHash_negotiatedRSASHA512() throws {
        try self.assertRFC8332Conformance(
            exchangeHash: SHA512.hash(data: Array("genuine-exchange-hash".utf8)),
            tamperedHash: SHA512.hash(data: Array("tampered-exchange-hash".utf8)),
            negotiated: .sha512
        )
    }

    func testRFC8332_SHA256ExchangeHash_negotiatedRSASHA256() throws {
        try self.assertRFC8332Conformance(
            exchangeHash: SHA256.hash(data: Array("genuine-exchange-hash".utf8)),
            tamperedHash: SHA256.hash(data: Array("tampered-exchange-hash".utf8)),
            negotiated: .sha256
        )
    }

    /// Negative control (the whole point): reconstruct the fork's OLD non-conformant form
    /// with an independent oracle — RSA over the exchange hash H *directly*, so the PKCS#1
    /// DigestInfo carries the SHA-384 OID of the KEX curve hash — mislabeled rsa-sha2-512.
    /// The fixed verify MUST reject it, while the correctly re-hashed signature is accepted.
    func testNegativeControl_legacyPassthroughFormIsRejected() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let hostKey = NIOSSHPrivateKey(rsaKey: rsaKey)
        let exchangeHash = SHA384.hash(data: Array("nistp384-exchange-hash".utf8))

        // OLD passthrough: sign H directly (SHA-384-OID DigestInfo), tag as rsa-sha2-512.
        let passthroughBytes = try rsaKey.signature(
            for: exchangeHash, padding: .insecurePKCS1v1_5
        ).rawRepresentation
        let mislabeled = self.rsaSignature(rawBytes: passthroughBytes, tagged: .sha512)
        XCTAssertFalse(
            hostKey.publicKey.isValidHostKeySignature(mislabeled, for: exchangeHash, rsaAlgorithm: .sha512),
            "the legacy passthrough form (RSA over H under the KEX-hash OID) must be rejected"
        )

        // The RFC 8332-conformant signature over the same H IS accepted — proving the
        // rejection above is specific to the non-conformant form, not a blanket failure.
        let conformantBytes = try self.referenceSignatureBytes(
            key: rsaKey, exchangeHash: exchangeHash, algorithm: .sha512
        )
        XCTAssertNotEqual(
            passthroughBytes, conformantBytes,
            "the passthrough and RFC 8332 signatures must genuinely differ"
        )
        let conformant = self.rsaSignature(rawBytes: conformantBytes, tagged: .sha512)
        XCTAssertTrue(
            hostKey.publicKey.isValidHostKeySignature(conformant, for: exchangeHash, rsaAlgorithm: .sha512),
            "the RFC 8332-conformant signature must verify"
        )
    }

    /// The verify seam is fail-closed on any disagreement between the wire signature tag and
    /// the negotiated algorithm, and on a nil negotiated algorithm for an RSA host key.
    func testVerifyRejectsTagOrAlgorithmMismatch() throws {
        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let hostKey = NIOSSHPrivateKey(rsaKey: rsaKey)
        let exchangeHash = SHA384.hash(data: Array("exchange-hash".utf8))

        // A genuine rsa-sha2-256 host-key signature ...
        let sig256 = try hostKey.signForHostKeyExchange(digest: exchangeHash, rsaAlgorithm: .sha256)

        // ... must NOT verify when rsa-sha2-512 was negotiated (tag ≠ negotiated).
        XCTAssertFalse(
            hostKey.publicKey.isValidHostKeySignature(sig256, for: exchangeHash, rsaAlgorithm: .sha512),
            "a rsa-sha2-256 signature must not verify under negotiated rsa-sha2-512"
        )

        // ... and a nil negotiated algorithm (unreachable for RSA post-negotiation) fails closed.
        XCTAssertFalse(
            hostKey.publicKey.isValidHostKeySignature(sig256, for: exchangeHash, rsaAlgorithm: nil),
            "a nil negotiated algorithm must fail closed for an RSA host key"
        )

        // Signing an RSA host key with a nil negotiated algorithm must throw (fail closed).
        XCTAssertThrowsError(
            try hostKey.signForHostKeyExchange(digest: exchangeHash, rsaAlgorithm: nil)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidHostKeyForKeyExchange)
        }
    }

    /// The generic digest overloads must fail closed for RSA (they cannot know the negotiated
    /// algorithm), while ed25519/ECDSA continue to work through them unchanged.
    func testGenericDigestOverloadsFailClosedForRSA() throws {
        let hostKey = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        let exchangeHash = SHA384.hash(data: Array("exchange-hash".utf8))

        // Generic sign(digest:) must refuse RSA host keys.
        XCTAssertThrowsError(try hostKey.sign(digest: exchangeHash)) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidHostKeyForKeyExchange)
        }

        // Generic isValidSignature(_:for digest:) must reject any RSA signature, even a
        // genuine RFC 8332 one — RSA host-key verification only happens via the dedicated seam.
        let goodSignature = try hostKey.signForHostKeyExchange(digest: exchangeHash, rsaAlgorithm: .sha512)
        XCTAssertFalse(
            hostKey.publicKey.isValidSignature(goodSignature, for: exchangeHash),
            "the generic digest verify overload must fail closed for RSA"
        )

        // Sanity: ed25519 still works through the generic overloads.
        let edKey = NIOSSHPrivateKey(ed25519Key: .init())
        let edSignature = try edKey.sign(digest: exchangeHash)
        XCTAssertTrue(
            edKey.publicKey.isValidSignature(edSignature, for: exchangeHash),
            "ed25519 signing/verification through the generic overloads must be unchanged"
        )
    }
}
