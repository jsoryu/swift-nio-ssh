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

@testable import NIOSSH

/// Regression coverage for the certificate validity-window check in
/// ``NIOSSHCertifiedPublicKey/validate(principal:type:allowedAuthoritySigningKeys:acceptableCriticalOptions:)``.
///
/// `ssh-keygen` writes `validBefore == UInt64.max` ("forever") for a certificate with no
/// expiry. Historically that bound was fed straight into `DispatchWallTime(secondsSinceEpoch:)`,
/// where the `UInt64 -> time_t` (`Int64`) conversion overflowed and TRAPPED the process — a
/// crash on ordinary forever-certificates and a client-side denial of service when validating a
/// hostile host certificate with maximal validity. These tests pin the fixed behaviour:
///
/// - a forever-cert (validBefore == UInt64.max) validates WITHOUT trapping and is not-expired;
/// - validAfter == 0 is "valid from the epoch";
/// - values near/at `time_t` max do not trap;
/// - genuinely-expired and not-yet-valid certificates are still rejected (semantics preserved).
final class CertificateValidityWindowTests: XCTestCase {
    /// Builds an ed25519 user (or host) certificate around a fresh subject key, signed for real by
    /// `caPrivate`, with a caller-chosen validity window. The signature is genuine so `validate`
    /// exercises the real time-window check rather than failing earlier on the signature.
    private func makeCertificate(
        caPrivate: Curve25519.Signing.PrivateKey,
        validAfter: UInt64,
        validBefore: UInt64,
        type: NIOSSHCertifiedPublicKey.CertificateType = .user,
        principals: [String] = ["alice"]
    ) throws -> NIOSSHCertifiedPublicKey {
        let subjectPublic = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey()).publicKey
        let caPublic = NIOSSHPrivateKey(ed25519Key: caPrivate).publicKey

        var nonce = ByteBufferAllocator().buffer(capacity: 32)
        nonce.writeBytes((0..<32).map { UInt8($0) })

        // Placeholder signature: `signableBytes` does not include the signature field.
        let placeholder = NIOSSHSignature(backingSignature: .ed25519(.data(Data(repeating: 0, count: 64))))
        let unsigned = try NIOSSHCertifiedPublicKey(
            nonce: nonce,
            serial: 1,
            type: type,
            key: subjectPublic,
            keyID: "validity-window-test",
            validPrincipals: principals,
            validAfter: validAfter,
            validBefore: validBefore,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPublic,
            signature: placeholder
        )

        let body = Array(unsigned.signableBytes.readableBytesView)
        let caSignature = try caPrivate.signature(for: body)
        let signature = NIOSSHSignature(backingSignature: .ed25519(.data(caSignature)))

        return try NIOSSHCertifiedPublicKey(
            nonce: nonce,
            serial: 1,
            type: type,
            key: subjectPublic,
            keyID: "validity-window-test",
            validPrincipals: principals,
            validAfter: validAfter,
            validBefore: validBefore,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPublic,
            signature: signature
        )
    }

    // MARK: - (a) forever-cert: validBefore == UInt64.max

    func testForeverCertificateValidatesWithoutTrapping() throws {
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey
        let cert = try self.makeCertificate(caPrivate: ca, validAfter: 0, validBefore: .max)

        // Before the fix this call trapped (SIGILL) inside DispatchWallTime; reaching the
        // assertion at all proves the process did not crash.
        XCTAssertNoThrow(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [caPublic])
        )
    }

    func testForeverHostCertificateWithMaxValidityDoesNotDenialOfService() throws {
        // The DoS vector: a server presenting a host certificate whose validBefore is UInt64.max.
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey
        let cert = try self.makeCertificate(
            caPrivate: ca,
            validAfter: 0,
            validBefore: .max,
            type: .host,
            principals: ["host.example.com"]
        )

        XCTAssertNoThrow(
            try cert.validate(
                principal: "host.example.com",
                type: .host,
                allowedAuthoritySigningKeys: [caPublic]
            )
        )
    }

    // MARK: - (b) validAfter == 0 is valid-from-epoch

    func testValidAfterZeroIsValidFromEpoch() throws {
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey
        // validBefore ~ year 2070 (in-range), validAfter == 0.
        let cert = try self.makeCertificate(caPrivate: ca, validAfter: 0, validBefore: 3_163_683_075)

        XCTAssertNoThrow(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [caPublic])
        )
    }

    // MARK: - (c) edge values near time_t max do not trap

    func testEdgeValidBeforeValuesDoNotTrap() throws {
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey

        // Each of these previously overflowed time_t (or its nanosecond product) and trapped.
        // All are far-future -> not expired -> validate must succeed with validAfter == 0.
        let edgeBounds: [UInt64] = [
            UInt64(Int64.max),        // exactly time_t.max on a 64-bit time_t
            UInt64(Int64.max) - 1,
            UInt64.max - 1,
            0xFFFF_FFFF_FFFF_0000,    // near the top of the UInt64 range
            .max,
        ]

        for validBefore in edgeBounds {
            let cert = try self.makeCertificate(caPrivate: ca, validAfter: 0, validBefore: validBefore)
            XCTAssertNoThrow(
                try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [caPublic]),
                "validBefore == \(validBefore) should be treated as unbounded (not expired)"
            )
        }
    }

    /// Deterministic exercise of the time-window helper with a caller-supplied "now": proves the
    /// full UInt64 range is handled without trapping and that the boundary semantics match the
    /// original `validAfter <= now < validBefore` check (inclusive lower, exclusive upper).
    func testIsValidWindowSemanticsAcrossFullRange() throws {
        let ca = Curve25519.Signing.PrivateKey()

        // Forever cert: validAfter == 0 ("from the epoch"), validBefore == UInt64.max.
        let forever = try self.makeCertificate(caPrivate: ca, validAfter: 0, validBefore: .max)
        XCTAssertTrue(forever.isValid(nowSeconds: 0))                   // valid from the epoch
        XCTAssertTrue(forever.isValid(nowSeconds: 1_700_000_000))       // a real "now"
        XCTAssertTrue(forever.isValid(nowSeconds: UInt64(Int64.max)))   // time_t max: no trap
        XCTAssertTrue(forever.isValid(nowSeconds: UInt64.max - 1))      // near the top: no trap
        XCTAssertFalse(forever.isValid(nowSeconds: .max))               // now == validBefore -> expired

        // Bounded window [100, 200]: inclusive lower bound, exclusive upper bound.
        let bounded = try self.makeCertificate(caPrivate: ca, validAfter: 100, validBefore: 200)
        XCTAssertFalse(bounded.isValid(nowSeconds: 99))                 // before validAfter -> not yet valid
        XCTAssertTrue(bounded.isValid(nowSeconds: 100))                 // == validAfter -> valid (inclusive)
        XCTAssertTrue(bounded.isValid(nowSeconds: 199))
        XCTAssertFalse(bounded.isValid(nowSeconds: 200))               // == validBefore -> expired (exclusive)
        XCTAssertFalse(bounded.isValid(nowSeconds: 201))
    }

    // MARK: - (d) semantics preserved: expired and not-yet-valid still reject

    func testGenuinelyExpiredCertificateIsRejected() throws {
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey
        // validBefore ~ 1970 (well in the past), validAfter == 0.
        let cert = try self.makeCertificate(caPrivate: ca, validAfter: 0, validBefore: 1_000)

        XCTAssertThrowsError(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [caPublic])
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }

    func testNotYetValidCertificateIsRejected_inRangeFutureValidAfter() throws {
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey
        // validAfter ~ year 2096 (in-range but in the future), validBefore == forever.
        let cert = try self.makeCertificate(caPrivate: ca, validAfter: 4_000_000_000, validBefore: .max)

        XCTAssertThrowsError(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [caPublic])
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }

    func testNotYetValidCertificateIsRejected_outOfRangeFutureValidAfter() throws {
        let ca = Curve25519.Signing.PrivateKey()
        let caPublic = NIOSSHPrivateKey(ed25519Key: ca).publicKey
        // validAfter == UInt64.max saturates to the far future: not-yet-valid, must reject (no trap).
        let cert = try self.makeCertificate(caPrivate: ca, validAfter: .max, validBefore: .max)

        XCTAssertThrowsError(
            try cert.validate(principal: "alice", type: .user, allowedAuthoritySigningKeys: [caPublic])
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }
}
