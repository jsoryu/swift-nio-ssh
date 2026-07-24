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

// MARK: - Public model (RFC 4256, aligned with upstream swift-nio-ssh PR #242)

/// A single prompt within a keyboard-interactive (RFC 4256) challenge.
///
/// The server sends one of these for each piece of information it wishes to collect from the
/// user (for example a password, a one-time code, or an acknowledgement).
public struct NIOSSHKeyboardInteractivePrompt: Sendable, Hashable {
    /// The prompt text to display to the user, for example `"Password: "`.
    ///
    /// - Warning: This string is attacker-influenced (it originates from the remote server). Callers
    ///     that render it to a terminal MUST sanitise control characters before display (RFC 4256 § 6).
    public var prompt: String

    /// Whether the user's typed response should be echoed.
    ///
    /// When `false`, the response is secret (for example a password or OTP) and MUST be collected
    /// with echo disabled and handled with the same care as any other credential.
    public var echo: Bool

    public init(prompt: String, echo: Bool) {
        self.prompt = prompt
        self.echo = echo
    }
}

/// A keyboard-interactive (RFC 4256) challenge issued by the server.
///
/// A challenge may carry zero or more prompts. A challenge with zero prompts is a purely
/// informational message (for example a banner) and requires an empty response.
public struct NIOSSHKeyboardInteractiveChallenge: Sendable, Hashable {
    /// The name of the challenge, which may be displayed as a title.
    ///
    /// - Warning: Attacker-influenced. Sanitise control characters before terminal display.
    public var name: String

    /// Instruction text describing the challenge.
    ///
    /// - Warning: Attacker-influenced. Sanitise control characters before terminal display.
    public var instruction: String

    /// The RFC 3066 language tag for `name`/`instruction`/prompt text. Often empty.
    public var languageTag: String

    /// The prompts to be answered, in order. Responses MUST be index-aligned to this array.
    public var prompts: [NIOSSHKeyboardInteractivePrompt]

    public init(
        name: String,
        instruction: String,
        languageTag: String = "",
        prompts: [NIOSSHKeyboardInteractivePrompt]
    ) {
        self.name = name
        self.instruction = instruction
        self.languageTag = languageTag
        self.prompts = prompts
    }
}

// MARK: - Server-side keyboard-interactive (minimal, test-scoped)

/// The next step a server wishes to take in a keyboard-interactive (RFC 4256) exchange.
public enum NIOSSHKeyboardInteractiveServerStep: Sendable {
    /// Issue another INFO_REQUEST challenge to the client.
    case challenge(NIOSSHKeyboardInteractiveChallenge)

    /// Terminate the exchange with a final outcome (success or failure).
    case outcome(NIOSSHUserAuthenticationOutcome)
}

/// An optional companion to ``NIOSSHServerUserAuthenticationDelegate`` that adds server-side
/// keyboard-interactive (RFC 4256) support.
///
/// This is intentionally minimal: the client is the product path, and this exists primarily so a
/// full client<->server keyboard-interactive handshake can be exercised in-process. A server
/// delegate opts in by also conforming to this protocol; NIOSSH probes for the conformance and,
/// when absent, keyboard-interactive requests fail like any other unsupported method.
public protocol NIOSSHServerKeyboardInteractiveAuthenticationDelegate {
    /// Produce the next step of a keyboard-interactive exchange.
    ///
    /// - parameters:
    ///     - username: The username the client is authenticating as.
    ///     - previousResponses: `nil` for the initial call (right after the keyboard-interactive
    ///         `USERAUTH_REQUEST`), or the client's index-aligned answers to the previously issued
    ///         challenge on subsequent calls.
    ///     - promise: A promise to be completed with the next ``NIOSSHKeyboardInteractiveServerStep``.
    func nextKeyboardInteractiveStep(
        username: String,
        previousResponses: [String]?,
        promise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    )
}

// MARK: - DoS caps (net-new hardening over PR #242)

/// Safety limits applied to keyboard-interactive (RFC 4256) exchanges.
///
/// A hostile or spoofed server must not be able to force unbounded prompt UI, unbounded exchange
/// rounds, or unbounded allocation. Breaching any of these limits results in a thrown
/// ``NIOSSHError`` (never a trap), terminating the connection cleanly.
enum KeyboardInteractiveLimits {
    /// Maximum number of prompts permitted in a single INFO_REQUEST.
    static let maximumPrompts = 100

    /// Maximum number of responses permitted in a single INFO_RESPONSE.
    static let maximumResponses = 100

    /// Maximum number of INFO_REQUEST rounds permitted within a single authentication attempt.
    static let maximumRounds = 50

    /// Maximum length, in bytes, of any single string field (name, instruction, prompt, response).
    static let maximumFieldByteLength = 8 * 1024
}
