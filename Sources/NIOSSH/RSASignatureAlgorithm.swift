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

/// The RSA signature algorithm to use for public-key authentication.
///
/// Per RFC 8332, RSA public-key authentication uses the SHA-2 based signature
/// algorithms `rsa-sha2-256` and `rsa-sha2-512`. Note that the RSA *key* format
/// identifier remains `ssh-rsa` on the wire (it is the key-blob tag, per RFC 4253);
/// it is only the *signature*/user-auth algorithm name that becomes `rsa-sha2-*`.
///
/// The legacy `ssh-rsa` *signature* algorithm (RSASSA-PKCS1-v1_5 with SHA-1) is
/// intentionally NOT representable here. NIOSSH refuses SHA-1 RSA signatures: the
/// failable initializer below returns `nil` for `ssh-rsa`, so it is rejected at the
/// negotiation edge rather than silently downgraded.
public enum RSASignatureAlgorithm: Hashable, Sendable {
    /// RSA signature using SHA-512 (`rsa-sha2-512`). Recommended default (RFC 8332).
    case sha512

    /// RSA signature using SHA-256 (`rsa-sha2-256`) (RFC 8332).
    case sha256

    /// The algorithm name as used in the SSH wire protocol.
    public var algorithmName: String {
        switch self {
        case .sha512: return "rsa-sha2-512"
        case .sha256: return "rsa-sha2-256"
        }
    }

    /// The algorithm name as UTF-8 bytes for the wire protocol.
    internal var wireBytes: String.UTF8View { self.algorithmName.utf8 }

    /// Initialize from a wire-protocol algorithm name.
    ///
    /// Returns `nil` for any unrecognized name. In particular the legacy `ssh-rsa`
    /// (SHA-1) name returns `nil`: SHA-1 is refused here, never mapped to a case.
    public init?<Bytes: Collection>(algorithmName bytes: Bytes) where Bytes.Element == UInt8 {
        if bytes.elementsEqual("rsa-sha2-512".utf8) {
            self = .sha512
        } else if bytes.elementsEqual("rsa-sha2-256".utf8) {
            self = .sha256
        } else {
            return nil
        }
    }
}
