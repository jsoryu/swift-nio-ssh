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

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentication methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Called when the server issues a keyboard-interactive (RFC 4256) challenge that the client must
    /// answer.
    ///
    /// The delegate must complete `responsePromise` with one response per prompt in `challenge`, in
    /// order (RFC 4256 § 3.4). A challenge with zero prompts is informational and must be answered
    /// with an empty array. Prompts with `echo == false` are secret (for example passwords or
    /// one-time codes) and must be handled with credential-grade care.
    ///
    /// Failing the promise declines/aborts the exchange and terminates the attempt.
    ///
    /// A default implementation is provided that fails the promise, so keyboard-interactive is opt-in:
    /// only delegates that implement this method can answer keyboard-interactive challenges.
    ///
    /// - parameters:
    ///     - challenge: The challenge issued by the server.
    ///     - responsePromise: An `EventLoopPromise` to be completed with the ordered responses.
    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    )
}

extension NIOSSHClientUserAuthenticationDelegate {
    public func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        // Default: this delegate does not support keyboard-interactive authentication.
        responsePromise.fail(NIOSSHError.unsupportedUserAuthenticationMethod)
    }
}
