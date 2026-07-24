//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore

/// The user authentication modes available at this point in time.
///
/// User authentication in SSH proceeds in a dynamic fashion, and it is possible to require multiple forms
/// of authentication sequentially, or to be able to accept one of many forms.
public struct NIOSSHAvailableUserAuthenticationMethods: OptionSet, Sendable {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Public key authentication is acceptable.
    public static let publicKey: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 0)

    /// Password-based authentication is acceptable.
    public static let password: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 1)

    /// Host-based authentication is acceptable.
    public static let hostBased: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 2)

    /// Keyboard-interactive (RFC 4256) authentication is acceptable.
    public static let keyboardInteractive: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 3)

    /// A short-hand for all supported authentication types.
    ///
    /// - Note: `.keyboardInteractive` is deliberately excluded. The client offers it only when the
    ///     server explicitly advertises it (via a `USERAUTH_FAILURE` re-offer), mirroring upstream
    ///     PR #242, so that a server that does not support it is never sent a keyboard-interactive
    ///     request speculatively.
    public static let all: NIOSSHAvailableUserAuthenticationMethods = [.publicKey, .password, .hostBased]
}

extension NIOSSHAvailableUserAuthenticationMethods {
    internal init(_ message: SSHMessage.UserAuthFailureMessage) {
        self = .init()

        for message in message.authentications {
            switch message {
            case "publickey":
                self.insert(.publicKey)
            case "password":
                self.insert(.password)
            case "hostbased":
                self.insert(.hostBased)
            case "keyboard-interactive":
                self.insert(.keyboardInteractive)
            default:
                // This is an unknown method, which we ignore.
                break
            }
        }
    }

    internal var strings: [Substring] {
        guard self != .init() else {
            return []
        }

        // We need an array.
        var methods = [Substring]()
        methods.reserveCapacity(4)

        if self.contains(.password) {
            methods.append("password")
        }
        if self.contains(.publicKey) {
            methods.append("publickey")
        }
        if self.contains(.hostBased) {
            methods.append("hostbased")
        }
        if self.contains(.keyboardInteractive) {
            methods.append("keyboard-interactive")
        }

        return methods
    }
}

extension NIOSSHAvailableUserAuthenticationMethods: Hashable {}

/// A specific request for user authentication. This type is the one observed from the server side. The
/// associated client side type is ``NIOSSHUserAuthenticationOffer``.
public struct NIOSSHUserAuthenticationRequest: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication request.
    public var request: Request

    public init(username: String, serviceName: String, request: Request) {
        self.username = username
        self.request = request
    }
}

extension NIOSSHUserAuthenticationRequest {
    /// ``NIOSSHUserAuthenticationRequest/Request-swift.enum`` describes the kind of authentication attempt the client is making.
    public enum Request: Sendable {
        /// The client would like to perform public key authentication.
        case publicKey(PublicKey)

        /// The client would like to perform password authentication.
        case password(Password)

        /// The client would like to perform host-based authentication.
        ///
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)

        /// The client believes it does not need authentication.
        case none
    }
}

extension NIOSSHUserAuthenticationRequest.Request {
    /// Information provided by the client when attempting to perform a public-key authentication.
    public struct PublicKey: Sendable {
        /// The user's public key.
        public var publicKey: NIOSSHPublicKey

        public init(publicKey: NIOSSHPublicKey) {
            self.publicKey = publicKey
        }
    }

    /// Information provided by the client when attempting to perform password-based authentication.
    public struct Password: Sendable {
        /// The user's password.
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    /// Information provided by the client when attempting to perform host-based authentication.
    ///
    /// This method is currently unsupported by ``NIOSSH``.
    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension NIOSSHUserAuthenticationRequest: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.PublicKey: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.Password: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.HostBased: Hashable {}

/// A specific offer of user authentication. This type is the one used on the client side. The
/// associated server side type is ``NIOSSHUserAuthenticationRequest``.
public struct NIOSSHUserAuthenticationOffer: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication offer.
    public var offer: Offer

    public init(username: String, serviceName: String, offer: Offer) {
        self.username = username
        self.offer = offer
    }
}

extension NIOSSHUserAuthenticationOffer {
    /// ``NIOSSHUserAuthenticationOffer/Offer-swift.enum`` describes the kind of authentication offer the client is making.
    public enum Offer: Sendable {
        /// The client would like to perform private key authentication.
        case privateKey(PrivateKey)

        /// The client would like to perform password authentication.
        case password(Password)

        /// The client would like to perform host-based authentication.
        ///
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)

        /// The client would like to perform keyboard-interactive (RFC 4256) authentication.
        ///
        /// The actual challenge responses are supplied later, via the client delegate's
        /// ``NIOSSHClientUserAuthenticationDelegate/respondToKeyboardInteractiveChallenge(_:responsePromise:)``.
        case keyboardInteractive(KeyboardInteractive)

        /// The client believes it does not need authentication.
        case none
    }
}

extension NIOSSHUserAuthenticationOffer.Offer {
    /// Information provided by the client when attempting to perform private key authentication.
    public struct PrivateKey: Sendable {
        /// The client's private key.
        ///
        /// This is not sent to the server, but is used by ``NIOSSH`` to respond to auth challenges.
        public var privateKey: NIOSSHPrivateKey

        /// The client's public key.
        ///
        /// This is sent to the server.
        public var publicKey: NIOSSHPublicKey

        /// The RSA signature algorithm to use (RFC 8332). Applies only to RSA keys;
        /// for other key types this value is ignored.
        public var rsaSignatureAlgorithm: RSASignatureAlgorithm

        public init(privateKey: NIOSSHPrivateKey, rsaSignatureAlgorithm: RSASignatureAlgorithm = .sha512) {
            self.privateKey = privateKey
            self.publicKey = privateKey.publicKey
            self.rsaSignatureAlgorithm = rsaSignatureAlgorithm
        }

        public init(
            privateKey: NIOSSHPrivateKey,
            certifiedKey: NIOSSHCertifiedPublicKey,
            rsaSignatureAlgorithm: RSASignatureAlgorithm = .sha512
        ) {
            self.privateKey = privateKey
            self.publicKey = NIOSSHPublicKey(certifiedKey)
            self.rsaSignatureAlgorithm = rsaSignatureAlgorithm
        }
    }

    /// Information provided by the client when attempting to perform password-based authentication.
    public struct Password: Sendable {
        /// The client's password.
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    /// Information provided by the client when attempting to perform host-based authentication.
    ///
    /// This method is currently unsupported by ``NIOSSH``.
    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }

    /// Information provided by the client when offering keyboard-interactive (RFC 4256) authentication.
    ///
    /// This is a pure data carrier for the initial `USERAUTH_REQUEST`; the interactive challenge
    /// responses are delivered separately by the client delegate.
    public struct KeyboardInteractive: Sendable {
        /// The RFC 3066 language tag hint sent to the server. Commonly empty.
        public var languageTag: String

        /// A comma-separated hint of preferred submethods (RFC 4256 § 3.1). Commonly empty.
        public var submethods: String

        public init(languageTag: String = "", submethods: String = "") {
            self.languageTag = languageTag
            self.submethods = submethods
        }
    }
}

extension SSHMessage.UserAuthRequestMessage {
    init(request: NIOSSHUserAuthenticationOffer, sessionID: ByteBuffer) throws {
        // We only ever ask for the ssh-connection service.
        self.username = request.username
        self.service = "ssh-connection"

        switch request.offer {
        case .privateKey(let privateKeyRequest):
            let rsaAlgorithm = privateKeyRequest.rsaSignatureAlgorithm
            let dataToSign = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: self.username,
                serviceName: self.service,
                publicKey: privateKeyRequest.publicKey,
                rsaSignatureAlgorithm: rsaAlgorithm
            )
            let signature = try privateKeyRequest.privateKey.sign(dataToSign, rsaSignatureAlgorithm: rsaAlgorithm)
            self.method = .publicKey(
                .known(key: privateKeyRequest.publicKey, signature: signature, rsaSignatureAlgorithm: rsaAlgorithm)
            )
        case .password(let passwordRequest):
            self.method = .password(passwordRequest.password)
        case .keyboardInteractive(let keyboardInteractive):
            // RFC 4256: the initial request is unsigned (unlike publickey). The interactive
            // challenge/response loop happens afterwards, driven by the client delegate.
            self.method = .keyboardInteractive(
                languageTag: keyboardInteractive.languageTag,
                submethods: keyboardInteractive.submethods
            )
        case .hostBased:
            fatalError("Unsupported")
        case .none:
            self.method = .none
        }
    }
}

/// The outcome of a user authentication attempt.
public enum NIOSSHUserAuthenticationOutcome: Sendable {
    /// The authentication attempt succeeded and the client is authenticated.
    case success

    /// The authentication attempt partially succeeded, but additional authentication is required.
    ///
    /// The additional authentication requirements are described in `remainingMethods`.
    case partialSuccess(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)

    /// The authentication attempt failed.
    case failure
}

enum NIOSSHUserAuthenticationResponseMessage {
    case success
    case failure(SSHMessage.UserAuthFailureMessage)
    case publicKeyOK(SSHMessage.UserAuthPKOKMessage)
    // Server-side keyboard-interactive: issue an INFO_REQUEST challenge to the client.
    case infoRequest(SSHMessage.UserAuthInfoRequestMessage)
}

extension NIOSSHUserAuthenticationResponseMessage {
    init(_ outcome: NIOSSHUserAuthenticationOutcome, supportedMethods: NIOSSHAvailableUserAuthenticationMethods) {
        switch outcome {
        case .success:
            self = .success
        case .partialSuccess(remainingMethods: let remaining):
            let message = SSHMessage.UserAuthFailureMessage(authentications: remaining.strings, partialSuccess: true)
            self = .failure(message)
        case .failure:
            let message = SSHMessage.UserAuthFailureMessage(
                authentications: supportedMethods.strings,
                partialSuccess: false
            )
            self = .failure(message)
        }
    }
}
