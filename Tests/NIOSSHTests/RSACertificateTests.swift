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
import Foundation
import NIOCore
import XCTest
import _CryptoExtras

@testable import NIOSSH

/// Coverage for RSA USER certificate support (`ssh-rsa-cert-v01@openssh.com`, RFC 8332 +
/// OpenSSH PROTOCOL.certkeys), mirroring the ed25519/ecdsa user-cert tests:
///
/// - PARSE of a genuine `ssh-keygen`-produced RSA certificate (base key + fields).
/// - CA-signature trust: an RSA-CA-signed cert verifies; a tampered cert is rejected
///   (non-vacuous — the untampered form passes).
/// - user-auth produces the RFC-8332 cert-variant `rsa-sha2-{256,512}-cert-v01@openssh.com`
///   name while the base-key signature verifies.
/// - the SHA-1 `ssh-rsa-cert-v01@openssh.com` name is refused as a signature algorithm.
final class RSACertificateTests: XCTestCase {
    private enum Fixtures {
        // Generated with OpenSSH ssh-keygen:
        //   ssh-keygen -t ecdsa -b 384 -f ca               (ECDSA CA)
        //   ssh-keygen -t rsa   -b 2048 -f rsaca           (RSA CA)
        //   ssh-keygen -t rsa   -b 2048 -f rsauser         (RSA user base key)
        //   ssh-keygen -s ca    -I rsa-user-cert       -n alice,bob -V -1d:+2600w -z 7 rsauser.pub
        //   ssh-keygen -s rsaca -I rsa-user-cert-rsaca -n alice,bob -V -1d:+2600w -z 8 rsauser.pub

        /// ECDSA-P384 certificate authority public key.
        static let ecdsaCAPublicKey =
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBAdOnKKnt4pa7LkT+lkrFsd1z37CTEMIw1YK5SuT6UABqGBHp60HPW4lRtE/Go9xm7PTxycCwcnB1vRApy1iA+CwOuSsyEycqPdqBHkjdCZeFQ3I04J6BAWPgqXws61eWQ== rsa-cert-ca"

        /// RSA certificate authority public key.
        static let rsaCAPublicKey =
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDf9XIIfW8BSdH5V23Lc7YWSoVdKC5RbNmzvEyeH5xA0rp0b3izQhTxaY2veeCl5t4a3/4ERh/+ve+yNaqV90/wVVrS/kERyOw8rZMfTGgZVNxh25aq8Yy3j0a9wFYNTqfsuE6eIo0nhp33rwFC6nXZGmOMktL8UYA1hZnvl2NOXGONgEeCpfATSHuUulp35N+H/O823j4LV1gT9g1H444dnnWJqrlEB4V/Tfp9TCuAXHAPqRwmqAtBjcOCt+xP3QvlSMrtXjRUiZij+kZypijkNmrTIhqZ27kN6sqlBAiTg5bNdBoqrkgmusSC1iW2TyoSYGXclYkGyvhSEAwa3SHb rsa-ca"

        /// The RSA user base public key (`ssh-rsa`).
        static let rsaUserBase =
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJHhJiZ+23KDkaVLxqWfFQTXlKPMFY220CBzdbdovO/MWvwz1Pb1O69J7ng15B/z8ExjpU7zI7c08rxTGFR+oKdxhLLdFONas8QAcNA/JEeOjxhDvn0iwir1gS7qfLE3Mqy4X5oMUEt1hft5BF5rBawqkKcRRXAfE0Oiw54YzfUmTKsTFbzRNFJy/kiwiPas14K9Y4Kc8EOuzuup/LmpHnq4+4xTdzT529rOBPE5oiYgIDTZOZaiMzbzQIGBl2pcZ/KeSXYxgPBa1/aq4UE6FEWft0af+e36YJZOlpqc/rTemrI4Ho0eT7WTzgRahUVlTNAopISzht7nI3P1Aid2mN rsa-user"

        /// RSA user certificate signed by the ECDSA CA (serial 7, principals alice/bob).
        static let rsaUserCertEcdsaCA =
            "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgQEwDu2h56MdcsA3lkfP+740s6v1QI4SUM7UOJSCHuFsAAAADAQABAAABAQDJHhJiZ+23KDkaVLxqWfFQTXlKPMFY220CBzdbdovO/MWvwz1Pb1O69J7ng15B/z8ExjpU7zI7c08rxTGFR+oKdxhLLdFONas8QAcNA/JEeOjxhDvn0iwir1gS7qfLE3Mqy4X5oMUEt1hft5BF5rBawqkKcRRXAfE0Oiw54YzfUmTKsTFbzRNFJy/kiwiPas14K9Y4Kc8EOuzuup/LmpHnq4+4xTdzT529rOBPE5oiYgIDTZOZaiMzbzQIGBl2pcZ/KeSXYxgPBa1/aq4UE6FEWft0af+e36YJZOlpqc/rTemrI4Ho0eT7WTzgRahUVlTNAopISzht7nI3P1Aid2mNAAAAAAAAAAcAAAABAAAADXJzYS11c2VyLWNlcnQAAAAQAAAABWFsaWNlAAAAA2JvYgAAAABqYpGsAAAAAMgeBywAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAiAAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQQHTpyip7eKWuy5E/pZKxbHdc9+wkxDCMNWCuUrk+lAAahgR6etBz1uJUbRPxqPcZuz08cnAsHJwdb0QKctYgPgsDrkrMhMnKj3agR5I3QmXhUNyNOCegQFj4Kl8LOtXlkAAACDAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABoAAAAMEXALFKqivDkwURL6NAIyarlB3bC2dNFnnLrhFfNr/t/DKyPPDu7G0fm458Q2KA52QAAADAXJhfjazXrn/HPeyXmSk7PJC4RMERUvpi/NXDaY4VyxrMb+iXgN0Zms4f64ECdcWk= rsa-user"

        /// RSA user certificate signed by the RSA CA using rsa-sha2-512 (serial 8, principals alice/bob).
        static let rsaUserCertRsaCA =
            "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgnh5xHGMZNSGsJ7oWIvXT1eAIf4OCZBXVAfyrQXhACiMAAAADAQABAAABAQDJHhJiZ+23KDkaVLxqWfFQTXlKPMFY220CBzdbdovO/MWvwz1Pb1O69J7ng15B/z8ExjpU7zI7c08rxTGFR+oKdxhLLdFONas8QAcNA/JEeOjxhDvn0iwir1gS7qfLE3Mqy4X5oMUEt1hft5BF5rBawqkKcRRXAfE0Oiw54YzfUmTKsTFbzRNFJy/kiwiPas14K9Y4Kc8EOuzuup/LmpHnq4+4xTdzT529rOBPE5oiYgIDTZOZaiMzbzQIGBl2pcZ/KeSXYxgPBa1/aq4UE6FEWft0af+e36YJZOlpqc/rTemrI4Ho0eT7WTzgRahUVlTNAopISzht7nI3P1Aid2mNAAAAAAAAAAgAAAABAAAAE3JzYS11c2VyLWNlcnQtcnNhY2EAAAAQAAAABWFsaWNlAAAAA2JvYgAAAABqYpGsAAAAAMgeBywAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEA3/VyCH1vAUnR+Vdty3O2FkqFXSguUWzZs7xMnh+cQNK6dG94s0IU8WmNr3ngpebeGt/+BEYf/r3vsjWqlfdP8FVa0v5BEcjsPK2TH0xoGVTcYduWqvGMt49GvcBWDU6n7LhOniKNJ4ad968BQup12RpjjJLS/FGANYWZ75djTlxjjYBHgqXwE0h7lLpad+Tfh/zvNt4+C1dYE/YNR+OOHZ51iaq5RAeFf036fUwrgFxwD6kcJqgLQY3DgrfsT90L5UjK7V40VImYo/pGcqYo5DZq0yIamdu5DerKpQQIk4OWzXQaKq5IJrrEgtYltk8qEmBl3JWJBsr4UhAMGt0h2wAAARQAAAAMcnNhLXNoYTItNTEyAAABAF1Pq0hzkyUt2m78YFCoHnfgIBp0MRt/9N1n/Xa5mmw4wlFSZyTj5W8tYEHQqwLiUALBA242NuN58OUcHIMJnYa3cTIjCyXK9z/coJVUoVs49z6AHoqLdCOxToqN0PNSguMOXbxko08zbDG+FjrjMnsfE8kkeGdKUWfIFWZMljXa/5OZb5ugQr9J2HDAi2tb6rv57hWtH7vQqWVyHm6ZFOWgtLkLUR4VRahfqYtweN8sxQNuG++xiCszG89UGJBvgmeneuaAawjl+Z6AJ89+9cL30k8zORO0LEHAR8/EkF+o0/lzjdoIlf9To2UvpKhCXjj526KjS4Klf4Qlxx80SN0= rsa-user"
    }

    // MARK: - (a) PARSE

    func testParseRSACertificateBaseKeyAndFields() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaUserCertEcdsaCA)
        guard let cert = NIOSSHCertifiedPublicKey(key) else {
            XCTFail("RSA certificate did not unwrap as a certified key")
            return
        }

        // The certificate's key-blob prefix is ssh-rsa-cert-v01@openssh.com...
        XCTAssertTrue(cert.keyPrefix.elementsEqual("ssh-rsa-cert-v01@openssh.com".utf8))
        // ...and the (public) NIOSSHPublicKey keyPrefix agrees.
        XCTAssertTrue(key.keyPrefix.elementsEqual("ssh-rsa-cert-v01@openssh.com".utf8))

        // The base key is the plain ssh-rsa key, byte-identical to the standalone user key.
        guard case .rsa = cert.key.backingKey else {
            XCTFail("base key of RSA certificate is not RSA")
            return
        }
        let standaloneBase = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaUserBase)
        XCTAssertEqual(cert.key, standaloneBase)

        // Standard certificate fields.
        XCTAssertEqual(cert.serial, 7)
        XCTAssertEqual(cert.type, .user)
        XCTAssertEqual(cert.keyID, "rsa-user-cert")
        XCTAssertEqual(cert.validPrincipals, ["alice", "bob"])
        XCTAssertEqual(cert.criticalOptions, [:])
        XCTAssertEqual(Set(cert.extensions.keys), [
            "permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding",
            "permit-pty", "permit-user-rc",
        ])

        // The signing (CA) key is the ECDSA CA.
        XCTAssertEqual(cert.signatureKey, try NIOSSHPublicKey(openSSHPublicKey: Fixtures.ecdsaCAPublicKey))
    }

    func testRSACertificateRoundTripsThroughWire() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaUserCertRsaCA)
        let cert = try XCTUnwrap(NIOSSHCertifiedPublicKey(key))

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeCertifiedKey(cert)

        // The blob begins with the ssh-rsa-cert-v01 key-format string.
        var peek = buffer
        let prefix = try XCTUnwrap(peek.readSSHStringAsString())
        XCTAssertEqual(prefix, "ssh-rsa-cert-v01@openssh.com")

        let reparsed = try XCTUnwrap(try buffer.readCertifiedKey())
        XCTAssertEqual(reparsed, cert)

        // Drip-feed: a truncated buffer must never mis-parse.
        var whole = ByteBufferAllocator().buffer(capacity: 1024)
        whole.writeSSHHostKey(NIOSSHPublicKey(cert))
        for i in 0..<whole.readableBytes {
            var slice = whole.getSlice(at: 0, length: i)!
            XCTAssertNil(try slice.readCertifiedKey())
        }
    }

    // MARK: - (b) CA-signature trust anchor

    func testRSACACertificateVerifies() throws {
        // Trust anchor path: NIOSSHCertifiedPublicKey.validate ->
        // signatureKey.isValidSignature(signature, for: signableBytes). With an RSA CA the
        // signature carries the rsa-sha2-512 tag, so verification routes into the RSA
        // ByteBuffer overload (SHA-512 over the certificate body) in NIOSSHPublicKey.
        let rsaCA = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaCAPublicKey)
        let cert = try XCTUnwrap(
            NIOSSHCertifiedPublicKey(try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaUserCertRsaCA))
        )

        // Directly exercise the CA signature verification (independent of time/type checks).
        XCTAssertTrue(
            cert.signatureKey.isValidSignature(cert.signature, for: cert.signableBytes),
            "validly-signed RSA-CA certificate must verify"
        )

        // And through the full validation entry point.
        XCTAssertNoThrow(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [rsaCA])
        )
        XCTAssertNoThrow(
            try cert.validate(principal: "bob", type: .user, allowedAuthoritySigningKeys: [rsaCA])
        )
    }

    func testTamperedRSACertificateIsRejected() throws {
        let rsaCA = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaCAPublicKey)
        let original = try XCTUnwrap(
            NIOSSHCertifiedPublicKey(try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaUserCertRsaCA))
        )

        // Sanity: the pristine certificate verifies (non-vacuous tamper test below).
        XCTAssertTrue(original.signatureKey.isValidSignature(original.signature, for: original.signableBytes))

        // Mutate a signed cert-body field (the serial). This changes signableBytes but
        // keeps the original CA signature, which must therefore no longer verify.
        var tampered = original
        tampered.serial = original.serial &+ 1
        XCTAssertNotEqual(tampered.signableBytes, original.signableBytes)
        XCTAssertFalse(
            tampered.signatureKey.isValidSignature(tampered.signature, for: tampered.signableBytes),
            "tampering with a signed field must invalidate the CA signature"
        )
        XCTAssertThrowsError(
            try tampered.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [rsaCA])
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }

        // A cert not signed by the presented CA is also rejected.
        let unrelatedCA = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048)).publicKey
        XCTAssertThrowsError(
            try original.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [unrelatedCA])
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }

    func testEcdsaCACertificateStillVerifies() throws {
        // No-regression: an RSA cert signed by an ECDSA CA verifies through the generic path.
        let ecdsaCA = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.ecdsaCAPublicKey)
        let cert = try XCTUnwrap(
            NIOSSHCertifiedPublicKey(try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsaUserCertEcdsaCA))
        )
        XCTAssertNoThrow(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [ecdsaCA])
        )
    }

    // MARK: - (c) user-auth signature over an RSA certificate

    /// Builds an RSA user certificate around `userPrivate`'s public key, signed by `caPrivate`
    /// with rsa-sha2-512 over the certificate body.
    private func makeRSACertificate(
        userPrivate: _RSA.Signing.PrivateKey,
        caPrivate: _RSA.Signing.PrivateKey,
        keyID: String = "programmatic-rsa-user",
        principals: [String] = ["alice"]
    ) throws -> NIOSSHCertifiedPublicKey {
        let userPub = NIOSSHPrivateKey(rsaKey: userPrivate).publicKey
        let caPub = NIOSSHPrivateKey(rsaKey: caPrivate).publicKey

        var nonce = ByteBufferAllocator().buffer(capacity: 32)
        nonce.writeBytes((0..<32).map { UInt8($0) })

        // Placeholder signature: signableBytes does not depend on the signature field.
        let placeholder = NIOSSHSignature(
            backingSignature: .rsaSHA512(_RSA.Signing.RSASignature(rawRepresentation: Data(repeating: 0, count: 256)))
        )
        let unsigned = try NIOSSHCertifiedPublicKey(
            nonce: nonce,
            serial: 42,
            type: .user,
            key: userPub,
            keyID: keyID,
            validPrincipals: principals,
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPub,
            signature: placeholder
        )

        // CA signs SHA-512 of the certificate body, matching the ByteBuffer verify overload.
        let body = Array(unsigned.signableBytes.readableBytesView)
        let caSig = try caPrivate.signature(for: SHA512.hash(data: body), padding: .insecurePKCS1v1_5)
        let signature = NIOSSHSignature(backingSignature: .rsaSHA512(caSig))

        return try NIOSSHCertifiedPublicKey(
            nonce: nonce,
            serial: 42,
            type: .user,
            key: userPub,
            keyID: keyID,
            validPrincipals: principals,
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPub,
            signature: signature
        )
    }

    private func makeSessionID() -> ByteBuffer {
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)
        return sessionID
    }

    private func assertUserAuthCertSignature(_ algorithm: RSASignatureAlgorithm, expectedName: String) throws {
        let userPrivate = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let caPrivate = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let cert = try self.makeRSACertificate(userPrivate: userPrivate, caPrivate: caPrivate)
        let certPublic = NIOSSHPublicKey(cert)

        // The wire "public key algorithm name" is the cert-variant signature name.
        XCTAssertTrue(
            certPublic.algorithmName(forRSA: algorithm).elementsEqual(expectedName.utf8),
            "expected user-auth algorithm name \(expectedName)"
        )
        XCTAssertTrue(cert.algorithmName(forRSA: algorithm).elementsEqual(expectedName.utf8))

        let payload = UserAuthSignablePayload(
            sessionIdentifier: self.makeSessionID(),
            userName: "alice",
            serviceName: "ssh-connection",
            publicKey: certPublic,
            rsaSignatureAlgorithm: algorithm
        )

        // The base (user) key signs the payload; verification delegates to the base RSA key.
        let signature = try NIOSSHPrivateKey(rsaKey: userPrivate).sign(payload, rsaSignatureAlgorithm: algorithm)
        XCTAssertTrue(
            certPublic.isValidSignature(signature, for: payload),
            "RSA certificate user-auth signature must verify via the base key"
        )

        // The signature blob itself carries the plain rsa-sha2-* tag (RFC 8332): the
        // cert-variant name is only the user-auth algorithm-name field.
        var sigBuffer = ByteBufferAllocator().buffer(capacity: 512)
        sigBuffer.writeSSHSignature(signature)
        let sigTag = try XCTUnwrap(sigBuffer.readSSHStringAsString())
        XCTAssertEqual(sigTag, algorithm.algorithmName)

        // An unrelated user key must not verify.
        let otherCert = try self.makeRSACertificate(
            userPrivate: try _RSA.Signing.PrivateKey(keySize: .bits2048),
            caPrivate: caPrivate
        )
        XCTAssertFalse(NIOSSHPublicKey(otherCert).isValidSignature(signature, for: payload))
    }

    func testUserAuthRSACertificateSHA256() throws {
        try self.assertUserAuthCertSignature(.sha256, expectedName: "rsa-sha2-256-cert-v01@openssh.com")
    }

    func testUserAuthRSACertificateSHA512() throws {
        try self.assertUserAuthCertSignature(.sha512, expectedName: "rsa-sha2-512-cert-v01@openssh.com")
    }

    // MARK: - (d) SHA-1 refusal

    func testSSHRSACertV01IsNotAnAcceptedSignatureName() throws {
        // The bare ssh-rsa-cert-v01 key-blob prefix must NOT be usable as a user-auth
        // signature-algorithm name: only the rsa-sha2-*-cert-v01 names are.
        XCTAssertNil(
            NIOSSHCertifiedPublicKey.rsaCertSignatureAlgorithm(algorithmName: "ssh-rsa-cert-v01@openssh.com".utf8)
        )
        XCTAssertEqual(
            NIOSSHCertifiedPublicKey.rsaCertSignatureAlgorithm(algorithmName: "rsa-sha2-256-cert-v01@openssh.com".utf8),
            .sha256
        )
        XCTAssertEqual(
            NIOSSHCertifiedPublicKey.rsaCertSignatureAlgorithm(algorithmName: "rsa-sha2-512-cert-v01@openssh.com".utf8),
            .sha512
        )

        // knownAlgorithms registers the cert-variant signature names but never the SHA-1
        // ssh-rsa-cert-v01 key prefix.
        func known(_ name: String) -> Bool {
            NIOSSHPublicKey.knownAlgorithms.contains { $0.elementsEqual(name.utf8) }
        }
        XCTAssertTrue(known("rsa-sha2-256-cert-v01@openssh.com"))
        XCTAssertTrue(known("rsa-sha2-512-cert-v01@openssh.com"))
        XCTAssertFalse(known("ssh-rsa-cert-v01@openssh.com"))
        XCTAssertFalse(known("ssh-rsa"))
    }
}
