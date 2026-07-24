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

struct UserAuthenticationStateMachine {
    private var state: State
    private var delegate: UserAuthDelegate
    private let loop: EventLoop
    private var sessionID: ByteBuffer

    /// Client side: `true` while a keyboard-interactive attempt is live (from sending the
    /// keyboard-interactive `USERAUTH_REQUEST` until the terminal SUCCESS/FAILURE). This is the
    /// source of truth for the id-60 decode gate.
    private var clientKeyboardInteractiveInProgress: Bool = false

    /// Client side: the number of INFO_REQUEST rounds seen in the current keyboard-interactive
    /// attempt, capped to defend against a malicious server driving an unbounded loop.
    private var keyboardInteractiveRounds: Int = 0

    /// Client side: `true` while an INFO_RESPONSE for a received INFO_REQUEST is still outstanding
    /// (delegate promise not yet resolved and serialized). Enforces a single in-flight response so a
    /// server cannot pipeline INFO_REQUESTs and race our replies.
    private var clientKeyboardInteractiveResponseOutstanding: Bool = false

    /// Server side: when non-`nil`, the server has issued an INFO_REQUEST with this many prompts and
    /// is awaiting the client's INFO_RESPONSE. Used to enforce num-responses == num-prompts and to
    /// distinguish a legitimate INFO_RESPONSE from a stray one.
    private var serverKeyboardInteractivePendingPromptCount: Int?

    /// Server side: the username of the in-flight keyboard-interactive exchange, captured from the
    /// initial `USERAUTH_REQUEST` so it can be supplied to the delegate on each subsequent round.
    private var serverKeyboardInteractiveUsername: String?

    // TODO: The server SHOULD limit the number of authentication attempts the client may make.
    init(role: SSHConnectionRole, loop: EventLoop, sessionID: ByteBuffer) {
        self.state = .idle
        self.delegate = UserAuthDelegate(role: role)
        self.loop = loop
        self.sessionID = sessionID
    }

    /// Whether this side currently expects to decode an incoming message id 60 as an RFC 4256
    /// `USERAUTH_INFO_REQUEST` (rather than `USERAUTH_PK_OK`). Only a client mid keyboard-interactive
    /// attempt ever does. This drives ``SSHPacketParser/keyboardInteractiveInProgress``.
    var isExpectingKeyboardInteractiveInfoRequest: Bool {
        if case .client = self.delegate {
            return self.clientKeyboardInteractiveInProgress
        }
        return false
    }

    fileprivate static let serviceName: String = "ssh-userauth"

    fileprivate static let nextServiceName: String = "ssh-connection"
}

extension UserAuthenticationStateMachine {
    fileprivate enum State {
        /// In this state, we have not received any user auth messages yet
        case idle
        case awaitingServiceAcceptance
        case awaitingNextRequest
        case awaitingResponses(Int)
        case authenticationSucceeded
        case authenticationFailed
    }
}

extension UserAuthenticationStateMachine {
    fileprivate static let protocolName = "userauth"
}

// MARK: Receiving Messages

extension UserAuthenticationStateMachine {
    /// A ServiceRequest message was received from the remote peer.
    mutating func receiveServiceRequest(
        _ message: SSHMessage.ServiceRequestMessage
    ) throws -> SSHMessage.ServiceAcceptMessage? {
        switch (self.delegate, self.state) {
        case (.server, .idle):
            guard message.service == Self.serviceName else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "unexpected service request: \(message)"
                )
            }

            self.state = .awaitingServiceAcceptance
            return .init(service: Self.serviceName)

        case (.server, .awaitingServiceAcceptance),
            (.server, .awaitingNextRequest),
            (.server, .awaitingResponses):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unexpected state for service request: \(message)"
            )

        case (.server, .authenticationSucceeded):
            // We ignore messages after authentication succeeded.
            return nil

        case (.server, .authenticationFailed):
            // TODO(cory): We should be limiting the maximum number of authentication attempts.
            preconditionFailure("Servers cannot enter authentication failed")

        case (.client, _):
            // Clients may never receive user service request messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent service request: \(message)"
            )
        }
    }

    /// A ServiceAccept message was received from the remote peer.
    mutating func receiveServiceAccept(
        _ message: SSHMessage.ServiceAcceptMessage
    ) throws -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?>? {
        switch (self.delegate, self.state) {
        case (.client(let delegate), .awaitingServiceAcceptance):
            guard message.service == Self.serviceName else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "unexpected service accept: \(message)"
                )
            }

            // Cool, we can begin the auth dance.
            self.state = .awaitingNextRequest
            return self.requestNextAuthRequest(methods: .all, delegate: delegate)
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            return nil
        case (.client, .idle):
            // Server sent a service accept but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited service accept message: \(message)"
            )
        case (.client, .awaitingNextRequest),
            (.client, .awaitingResponses),
            (.client, .authenticationFailed):
            // In these states we aren't expecting a service accept message
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited service accept message: \(message)"
            )
        case (.server, _):
            // Servers may never receive user auth success messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth success"
            )
        }
    }

    /// A UserAuthRequest message was received from the remote peer.
    mutating func receiveUserAuthRequest(
        _ message: SSHMessage.UserAuthRequestMessage
    ) throws -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage>? {
        guard message.service == Self.nextServiceName else {
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "requested unsupported service: \(message.service)"
            )
        }

        switch (self.delegate, self.state) {
        case (.server(let delegate), .awaitingNextRequest):
            self.state = .awaitingResponses(1)
            return self.nextAuthResponse(request: message, delegate: delegate)

        case (.server(let delegate), .awaitingResponses(let pending)):
            self.state = .awaitingResponses(pending + 1)
            return self.nextAuthResponse(request: message, delegate: delegate)

        case (.server, .idle), (.server, .awaitingServiceAcceptance):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "user auth request before service accepted"
            )

        case (.server, .authenticationSucceeded):
            // We ignore messages after authentication succeeded.
            return nil

        case (.server, .authenticationFailed):
            // TODO(cory): We should be limiting the maximum number of authentication attempts.
            preconditionFailure("Servers cannot enter authentication failed")

        case (.client, _):
            // Clients may never receive user auth request messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent user auth request"
            )
        }
    }

    /// We've received a user auth success message.
    ///
    /// If this method completes without throwing, user auth has completed.
    mutating func receiveUserAuthSuccess() throws {
        switch (self.delegate, self.state) {
        case (.client, .awaitingResponses):
            // Great, we got a response, and it's a success! Disregard all future responses.
            // A keyboard-interactive attempt (if any) is over: clear every bit of its loop state so
            // that a delegate answering future which resolves *after* this terminal SUCCESS becomes a
            // safe no-op instead of a trap. In particular, clearing the "response outstanding" flag is
            // what turns a late `sendUserAuthInfoResponse` into a graceful drop (see that method). A
            // malicious server can pipeline INFO_REQUEST then SUCCESS to exploit exactly this window.
            self.clientKeyboardInteractiveInProgress = false
            self.keyboardInteractiveRounds = 0
            self.clientKeyboardInteractiveResponseOutstanding = false
            self.state = .authenticationSucceeded
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            break
        case (.client, .idle), (.client, .awaitingServiceAcceptance):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited auth success message"
            )
        case (.client, .awaitingNextRequest), (.client, .authenticationFailed):
            // In these states we believe we received all our auth responses, so this is wrong.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited auth success message"
            )
        case (.server, _):
            // Servers may never receive user auth success messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth success"
            )
        }
    }

    mutating func receiveUserAuthFailure(
        _ message: SSHMessage.UserAuthFailureMessage
    ) throws -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?>? {
        switch (self.delegate, self.state) {
        case (.client(let delegate), .awaitingResponses(let responseCount)):
            // Ok, the server didn't like that much. Let's try another one.
            // A keyboard-interactive attempt (if any) is over; clear its loop state so the id-60
            // decode gate closes and the next attempt starts fresh. Crucially, clear the
            // "response outstanding" flag as well: the server may have pipelined INFO_REQUEST then
            // FAILURE, parking our answering delegate. When that delegate resolves later, the
            // resulting `sendUserAuthInfoResponse` must find no outstanding challenge and drop the
            // late response gracefully rather than trapping.
            self.clientKeyboardInteractiveInProgress = false
            self.keyboardInteractiveRounds = 0
            self.clientKeyboardInteractiveResponseOutstanding = false
            self.state = .awaitingNextRequest
            precondition(responseCount == 1, "We don't support parallel authentication attempts yet!")
            return self.requestNextAuthRequest(methods: .init(message), delegate: delegate)
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            return nil
        case (.client, .idle), (.client, .awaitingServiceAcceptance):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent user auth failure unprompted"
            )
        case (.client, .awaitingNextRequest), (.client, .authenticationFailed):
            // In these states we believe we received all our auth responses, so this is wrong.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited auth failure message"
            )
        case (.server, _):
            // Servers may never receive user auth failure messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth failure"
            )
        }
    }

    mutating func receiveUserAuthBanner(_: SSHMessage.UserAuthBannerMessage) throws {
        switch (self.delegate, self.state) {
        case (.client, .idle), (.client, .authenticationSucceeded):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent user auth banner at the wrong time"
            )
        case (.server, _):
            // Servers may never receive user auth banner messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth banner"
            )
        default:
            // In all other instances, receiving user auth banner is legal and must be dealt with by client
            return
        }
    }

    /// Client side: a keyboard-interactive INFO_REQUEST (RFC 4256 § 3.2) was received.
    ///
    /// Valid only while a keyboard-interactive attempt is live. Invokes the client delegate's
    /// answering promise, enforces num-responses == num-prompts, and remains in `.awaitingResponses`
    /// so the challenge→response loop continues within the same authentication attempt (no attempt
    /// budget is consumed per round).
    mutating func receiveUserAuthInfoRequest(
        _ message: SSHMessage.UserAuthInfoRequestMessage
    ) throws -> EventLoopFuture<SSHMessage.UserAuthInfoResponseMessage>? {
        switch (self.delegate, self.state) {
        case (.client(let delegate), .awaitingResponses):
            guard self.clientKeyboardInteractiveInProgress else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "received INFO_REQUEST outside a keyboard-interactive exchange"
                )
            }
            guard !self.clientKeyboardInteractiveResponseOutstanding else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "received INFO_REQUEST while a prior INFO_RESPONSE is still outstanding"
                )
            }

            self.keyboardInteractiveRounds += 1
            guard self.keyboardInteractiveRounds <= KeyboardInteractiveLimits.maximumRounds else {
                throw NIOSSHError.keyboardInteractiveLimitsExceeded(
                    reason: "keyboard-interactive exchange exceeded \(KeyboardInteractiveLimits.maximumRounds) rounds"
                )
            }

            self.clientKeyboardInteractiveResponseOutstanding = true
            return self.answerKeyboardInteractiveChallenge(message, delegate: delegate)

        case (.client, .authenticationSucceeded):
            // Auth already succeeded; ignore trailing messages.
            return nil

        case (.client, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "received INFO_REQUEST at an unexpected time"
            )

        case (.server, _):
            // Servers never decode id 60 as INFO_REQUEST (the gate is client-only), so this is a
            // protocol violation if it ever arrives.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client received INFO_REQUEST on the server side"
            )
        }
    }

    /// Server side: a keyboard-interactive INFO_RESPONSE (RFC 4256 § 3.4) was received.
    ///
    /// Valid only while the server has an outstanding INFO_REQUEST. Enforces
    /// num-responses == num-prompts, then asks the delegate for the next step (another challenge or a
    /// terminal outcome).
    mutating func receiveUserAuthInfoResponse(
        _ message: SSHMessage.UserAuthInfoResponseMessage
    ) throws -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage>? {
        switch (self.delegate, self.state) {
        case (.server(let delegate), .awaitingResponses):
            guard let expectedCount = self.serverKeyboardInteractivePendingPromptCount else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "received INFO_RESPONSE without an outstanding INFO_REQUEST"
                )
            }
            guard message.responses.count == expectedCount else {
                throw NIOSSHError.invalidKeyboardInteractiveResponse(
                    reason: "expected \(expectedCount) response(s), client provided \(message.responses.count)"
                )
            }

            self.serverKeyboardInteractivePendingPromptCount = nil

            guard let kiDelegate = delegate as? NIOSSHServerKeyboardInteractiveAuthenticationDelegate else {
                throw NIOSSHError.unsupportedUserAuthenticationMethod
            }

            let username = self.serverKeyboardInteractiveUsername ?? ""
            return self.serverKeyboardInteractiveStep(
                username: username,
                previousResponses: message.responses,
                delegate: kiDelegate,
                supportedMethods: delegate.supportedAuthenticationMethods
            )

        case (.server, .authenticationSucceeded):
            return nil

        case (.server, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "received INFO_RESPONSE at an unexpected time"
            )

        case (.client, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent INFO_RESPONSE to a client"
            )
        }
    }
}

// MARK: Sending Messages

extension UserAuthenticationStateMachine {
    mutating func sendServiceRequest(_ message: SSHMessage.ServiceRequestMessage) {
        switch (self.delegate, self.state) {
        case (.client, .idle):
            precondition(message.service == Self.serviceName)
            self.state = .awaitingServiceAcceptance
        case (.client, .awaitingServiceAcceptance):
            preconditionFailure("Duplicate service request")
        case (.client, .awaitingNextRequest),
            (.client, .awaitingResponses),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            preconditionFailure("May not send service request in \(self.state)")
        case (.server, _):
            preconditionFailure("Servers may not send service requests")
        }
    }

    mutating func sendServiceAccept(_ message: SSHMessage.ServiceAcceptMessage) {
        switch (self.delegate, self.state) {
        case (.server, .awaitingServiceAcceptance):
            precondition(message.service == Self.serviceName)
            self.state = .awaitingNextRequest
        case (.server, .idle):
            preconditionFailure("Cannot accept a service that hasn't been requested")
        case (.server, .awaitingNextRequest),
            (.server, .awaitingResponses),
            (.server, .authenticationSucceeded),
            (.server, .authenticationFailed):
            preconditionFailure("May not send service request in \(self.state)")
        case (.client, _):
            preconditionFailure("Clients may not send service acceptance")
        }
    }

    mutating func sendUserAuthRequest(_ message: SSHMessage.UserAuthRequestMessage) {
        switch (self.delegate, self.state) {
        case (.client, .awaitingNextRequest):
            // Record whether this is a keyboard-interactive attempt. This both opens the id-60
            // decode gate (so the next id 60 is an INFO_REQUEST) and starts a fresh round counter.
            if case .keyboardInteractive = message.method {
                self.clientKeyboardInteractiveInProgress = true
                self.keyboardInteractiveRounds = 0
                self.clientKeyboardInteractiveResponseOutstanding = false
            } else {
                self.clientKeyboardInteractiveInProgress = false
            }
            self.state = .awaitingResponses(1)
        case (.client, .idle),
            (.client, .awaitingServiceAcceptance):
            preconditionFailure("Sent an auth request without asking us first")
        case (.client, .awaitingResponses):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure(
                "Attempted to send a user auth request while we were waiting for a response to the last one."
            )
        case (.client, .authenticationSucceeded):
            preconditionFailure("Attempted to send a user auth request after auth succeeded")
        case (.client, .authenticationFailed):
            preconditionFailure("Attempted to send a user auth request after auth failed")
        case (.server, _):
            // Servers may never send user auth request messages.
            preconditionFailure("Servers may not authenticate")
        }
    }

    mutating func sendUserAuthPKOK(_: SSHMessage.UserAuthPKOKMessage) {
        switch (self.delegate, self.state) {
        case (.server, .idle),
            (.server, .awaitingServiceAcceptance):
            preconditionFailure("Server sent an auth response prior to receiving an auth request")
        case (.server, .awaitingNextRequest):
            preconditionFailure("Too many auth responses sent")
        case (.server, .awaitingResponses(let responseCount)):
            if responseCount > 1 {
                self.state = .awaitingResponses(responseCount - 1)
            } else {
                self.state = .awaitingNextRequest
            }
        case (.server, .authenticationSucceeded):
            preconditionFailure("Authentication already succeeded, further messages are unnecessary.")
        case (.server, .authenticationFailed):
            preconditionFailure("Servers can never enter authenticationFailed")
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }

    /// Server side: we are emitting a keyboard-interactive INFO_REQUEST challenge.
    mutating func sendUserAuthInfoRequest(_ message: SSHMessage.UserAuthInfoRequestMessage) {
        switch (self.delegate, self.state) {
        case (.server, .awaitingResponses):
            // Remain awaiting responses; record the prompt count so the matching INFO_RESPONSE can
            // be validated (num-responses == num-prompts) and distinguished from a stray one.
            self.serverKeyboardInteractivePendingPromptCount = message.prompts.count
        case (.server, .idle),
            (.server, .awaitingServiceAcceptance):
            preconditionFailure("Server sent an INFO_REQUEST prior to receiving an auth request")
        case (.server, .awaitingNextRequest):
            preconditionFailure("Server sent an INFO_REQUEST with no auth request in flight")
        case (.server, .authenticationSucceeded):
            preconditionFailure("Authentication already succeeded, further messages are unnecessary.")
        case (.server, .authenticationFailed):
            preconditionFailure("Servers can never enter authenticationFailed")
        case (.client, _):
            preconditionFailure("Clients never send INFO_REQUEST")
        }
    }

    /// Client side: we are emitting a keyboard-interactive INFO_RESPONSE answering a challenge.
    ///
    /// Returns `true` when the response should actually be serialized and sent, and `false` when it
    /// must be dropped because the keyboard-interactive exchange it belonged to has already
    /// terminated. The latter is not a bug in our own code: a malicious server can pipeline an
    /// INFO_REQUEST immediately followed by a terminal SUCCESS/FAILURE (or a different method), so
    /// that our asynchronous answering delegate resolves *after* the exchange is already over. When
    /// that happens the server-decided auth outcome stands and the stale response is simply dropped —
    /// never a `preconditionFailure`, because that would be a remotely triggerable client crash (DoS).
    @discardableResult
    mutating func sendUserAuthInfoResponse(_: SSHMessage.UserAuthInfoResponseMessage) -> Bool {
        switch (self.delegate, self.state) {
        case (.client, .awaitingResponses):
            guard self.clientKeyboardInteractiveInProgress, self.clientKeyboardInteractiveResponseOutstanding else {
                // We are back in `.awaitingResponses`, but not for the challenge this response
                // answers: either the keyboard-interactive attempt was terminated by the server and a
                // *different* method is now in flight (`inProgress == false`), or its challenge was
                // already answered / cleared (`responseOutstanding == false`). Drop the stale response.
                return false
            }
            // The response is now serialized; a new INFO_REQUEST may follow. Stay in the loop.
            self.clientKeyboardInteractiveResponseOutstanding = false
            return true
        case (.client, .awaitingNextRequest),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            // The exchange already reached a terminal / next-method transition (the server drained a
            // SUCCESS/FAILURE ahead of our delegate resolving). Drop the late response gracefully;
            // never trap on server-controlled message ordering.
            return false
        case (.client, .idle),
            (.client, .awaitingServiceAcceptance):
            // Genuine internal invariant, unreachable via server input: an INFO_RESPONSE is only ever
            // produced in reply to an INFO_REQUEST, which itself requires having advanced past service
            // acceptance into `.awaitingResponses`. The state machine can never walk backwards to
            // these states, so reaching here means a local bug, not a hostile server.
            preconditionFailure("Sent an INFO_RESPONSE without an outstanding challenge")
        case (.server, _):
            preconditionFailure("Servers never send INFO_RESPONSE")
        }
    }

    mutating func sendUserAuthSuccess() {
        self.sendUserAuthResponseMessage(success: true)
    }

    mutating func sendUserAuthFailure(_: SSHMessage.UserAuthFailureMessage) {
        self.sendUserAuthResponseMessage(success: false)
    }

    mutating func sendUserAuthBanner(_: SSHMessage.UserAuthBannerMessage) {
        // Relevant passage from RFC 4252:
        //
        // The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
        // time after this authentication protocol starts and before
        // authentication is successful.  This message contains text to be
        // displayed to the client user before authentication is attempted.  The
        // format is as follows:
        switch (self.delegate, self.state) {
        case (.server, .idle):
            preconditionFailure("Banner sent before authentication protocol start")
        case (.server, .authenticationSucceeded):
            preconditionFailure("Banner sent after authentication suceeded")
        case (.server, _):
            break
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }

    private mutating func sendUserAuthResponseMessage(success: Bool) {
        switch (self.delegate, self.state) {
        case (.server, .idle),
            (.server, .awaitingServiceAcceptance):
            preconditionFailure("Server sent an auth response prior to receiving an auth request")
        case (.server, .awaitingNextRequest):
            preconditionFailure("Too many auth responses sent")
        case (.server, .awaitingResponses(let responseCount)):
            if success {
                self.state = .authenticationSucceeded
            } else if responseCount > 1 {
                self.state = .awaitingResponses(responseCount - 1)
            } else {
                self.state = .awaitingNextRequest
            }
        case (.server, .authenticationSucceeded):
            preconditionFailure("Authentication already succeeded, further messages are unnecessary.")
        case (.server, .authenticationFailed):
            preconditionFailure("Servers can never enter authenticationFailed")
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }
}

// MARK: Client authentication methods

extension UserAuthenticationStateMachine {
    /// Called to begin authentication in the state machine.
    func beginAuthentication() -> SSHMessage.ServiceRequestMessage? {
        switch (self.delegate, self.state) {
        case (.client, .idle):
            return SSHMessage.ServiceRequestMessage(service: Self.serviceName)
        case (.client, .awaitingServiceAcceptance),
            (.client, .awaitingNextRequest),
            (.client, .awaitingResponses),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Cannot start authentication twice, state: \(self.state)")
        case (.server, _):
            return nil
        }
    }

    /// Called when the last call to obtain an authentication request returned nil.
    mutating func noFurtherMethods() {
        switch (self.delegate, self.state) {
        case (.client, .awaitingNextRequest):
            self.state = .authenticationFailed
        case (.client, .idle),
            (.client, .awaitingServiceAcceptance):
            preconditionFailure("Ran out of auth methods before asking for any")
        case (.client, .awaitingResponses),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Request for further auth failed when no such request should be outstanding")
        case (.server, _):
            preconditionFailure("Servers may not authenticate")
        }
    }
}

// MARK: Interacting with client delegate

extension UserAuthenticationStateMachine {
    fileprivate func requestNextAuthRequest(
        methods: NIOSSHAvailableUserAuthenticationMethods,
        delegate: NIOSSHClientUserAuthenticationDelegate
    ) -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?> {
        let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        delegate.nextAuthenticationType(availableMethods: methods, nextChallengePromise: promise)

        // The explicit capture list is here to force a copy of the buffer, rather than capturing self.
        return promise.futureResult.flatMapThrowing { [sessionID = self.sessionID] request in
            try request.map { try SSHMessage.UserAuthRequestMessage(request: $0, sessionID: sessionID) }
        }
    }
}

// MARK: Interacting with server delegate

extension UserAuthenticationStateMachine {
    fileprivate mutating func nextAuthResponse(
        request: SSHMessage.UserAuthRequestMessage,
        delegate: NIOSSHServerUserAuthenticationDelegate
    ) -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage> {
        switch request.method {
        case .password(let password):
            let request = NIOSSHUserAuthenticationRequest(
                username: request.username,
                serviceName: request.service,
                request: .password(.init(password: password))
            )
            let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
            delegate.requestReceived(request: request, responsePromise: promise)
            let supportedMethods = delegate.supportedAuthenticationMethods

            return promise.futureResult.map { outcome in
                .init(outcome, supportedMethods: supportedMethods)
            }

        case .publicKey(.known(key: let key, signature: .some(let signature), rsaSignatureAlgorithm: let rsaAlgorithm)):
            // This is a direct request to auth, just pass it through.
            // Server-side verify: reconstruct the signable payload with the wire-parsed
            // RSA algorithm so the "public key algorithm name" field matches what the
            // client signed (rsa-sha2-256/512, RFC 8332). Getting this wrong would make
            // every RSA signature fail to verify.
            let dataToSign = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: request.username,
                serviceName: request.service,
                publicKey: key,
                rsaSignatureAlgorithm: rsaAlgorithm
            )
            let supportedMethods = delegate.supportedAuthenticationMethods

            guard key.isValidSignature(signature, for: dataToSign) else {
                // Whoops, signature not valid.
                return self.loop.makeSucceededFuture(
                    .failure(.init(authentications: supportedMethods.strings, partialSuccess: false))
                )
            }

            // Signature is valid, ask if the delegate is happy.
            let request = NIOSSHUserAuthenticationRequest(
                username: request.username,
                serviceName: request.service,
                request: .publicKey(.init(publicKey: key))
            )
            let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
            delegate.requestReceived(request: request, responsePromise: promise)

            return promise.futureResult.map { outcome in
                .init(outcome, supportedMethods: supportedMethods)
            }

        case .publicKey(.known(key: let key, signature: .none, rsaSignatureAlgorithm: _)):
            // This is a weird wrinkle in public key auth: it's a request to ask whether a given key is valid, but not to validate that key itself.
            // For now we do a shortcut: we just say that all keys are acceptable, rather than ask the delegate.
            return self.loop.makeSucceededFuture(.publicKeyOK(.init(key: key)))

        case .publicKey(.unknown):
            // We don't known the algorithm, the auth attempt has failed.
            return self.loop.makeSucceededFuture(
                .failure(.init(authentications: delegate.supportedAuthenticationMethods.strings, partialSuccess: false))
            )

        case .keyboardInteractive:
            // RFC 4256: begin (or, for a re-offer, restart) a keyboard-interactive exchange. If the
            // delegate does not support it, fail like any other unsupported method.
            let supportedMethods = delegate.supportedAuthenticationMethods
            guard let kiDelegate = delegate as? NIOSSHServerKeyboardInteractiveAuthenticationDelegate else {
                return self.loop.makeSucceededFuture(
                    .failure(.init(authentications: supportedMethods.strings, partialSuccess: false))
                )
            }

            self.serverKeyboardInteractiveUsername = request.username
            self.serverKeyboardInteractivePendingPromptCount = nil
            return self.serverKeyboardInteractiveStep(
                username: request.username,
                previousResponses: nil,
                delegate: kiDelegate,
                supportedMethods: supportedMethods
            )

        case .none:
            let request = NIOSSHUserAuthenticationRequest(
                username: request.username,
                serviceName: request.service,
                request: .none
            )
            let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
            delegate.requestReceived(request: request, responsePromise: promise)
            let supportedMethods = delegate.supportedAuthenticationMethods

            return promise.futureResult.map { outcome in
                .init(outcome, supportedMethods: supportedMethods)
            }
        }
    }

    /// Server side: ask the keyboard-interactive delegate for its next step and map it to a wire
    /// response (an INFO_REQUEST challenge, or a terminal success/failure).
    fileprivate func serverKeyboardInteractiveStep(
        username: String,
        previousResponses: [String]?,
        delegate: NIOSSHServerKeyboardInteractiveAuthenticationDelegate,
        supportedMethods: NIOSSHAvailableUserAuthenticationMethods
    ) -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage> {
        let promise = self.loop.makePromise(of: NIOSSHKeyboardInteractiveServerStep.self)
        delegate.nextKeyboardInteractiveStep(
            username: username,
            previousResponses: previousResponses,
            promise: promise
        )

        return promise.futureResult.map { step in
            switch step {
            case .challenge(let challenge):
                let prompts = challenge.prompts.map {
                    SSHMessage.UserAuthInfoRequestMessage.Prompt(prompt: $0.prompt, echo: $0.echo)
                }
                return .infoRequest(
                    .init(
                        name: challenge.name,
                        instruction: challenge.instruction,
                        languageTag: challenge.languageTag,
                        prompts: prompts
                    )
                )
            case .outcome(let outcome):
                return .init(outcome, supportedMethods: supportedMethods)
            }
        }
    }
}

// MARK: Keyboard-interactive (client answering)

extension UserAuthenticationStateMachine {
    /// Client side: hand the challenge to the delegate and build the INFO_RESPONSE from its answers.
    ///
    /// Enforces num-responses == num-prompts (RFC 4256 § 3.4). Note that echo=false answers are
    /// credentials: they are never logged here, and are held only as long as needed to serialize the
    /// response. Deeper zeroization of the collected buffers is the responsibility of the application
    /// layer that gathers the answers.
    fileprivate func answerKeyboardInteractiveChallenge(
        _ message: SSHMessage.UserAuthInfoRequestMessage,
        delegate: NIOSSHClientUserAuthenticationDelegate
    ) -> EventLoopFuture<SSHMessage.UserAuthInfoResponseMessage> {
        let challenge = NIOSSHKeyboardInteractiveChallenge(
            name: message.name,
            instruction: message.instruction,
            languageTag: message.languageTag,
            prompts: message.prompts.map { NIOSSHKeyboardInteractivePrompt(prompt: $0.prompt, echo: $0.echo) }
        )
        let promptCount = message.prompts.count

        let promise = self.loop.makePromise(of: [String].self)
        delegate.respondToKeyboardInteractiveChallenge(challenge, responsePromise: promise)

        return promise.futureResult.flatMapThrowing { responses in
            guard responses.count == promptCount else {
                throw NIOSSHError.invalidKeyboardInteractiveResponse(
                    reason: "expected \(promptCount) response(s), delegate provided \(responses.count)"
                )
            }
            return SSHMessage.UserAuthInfoResponseMessage(responses: responses)
        }
    }
}
