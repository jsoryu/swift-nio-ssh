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
}
