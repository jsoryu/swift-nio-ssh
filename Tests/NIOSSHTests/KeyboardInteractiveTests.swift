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

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

// MARK: - Test error

private enum KITestError: Error {
    case futureNotResolved
}

// MARK: - Test delegates

/// A client delegate that offers keyboard-interactive exactly once, and answers challenges by
/// invoking a supplied closure. The closure lets individual tests control the responses (including
/// deliberately wrong counts).
final class ScriptedKIClientDelegate: NIOSSHClientUserAuthenticationDelegate {
    private var offered = false
    private let username: String
    private let respond: (NIOSSHKeyboardInteractiveChallenge) -> [String]

    init(username: String = "foo", respond: @escaping (NIOSSHKeyboardInteractiveChallenge) -> [String]) {
        self.username = username
        self.respond = respond
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard !self.offered else {
            nextChallengePromise.succeed(nil)
            return
        }
        self.offered = true
        nextChallengePromise.succeed(
            .init(username: self.username, serviceName: "ssh-connection", offer: .keyboardInteractive(.init()))
        )
    }

    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        responsePromise.succeed(self.respond(challenge))
    }
}

/// A client delegate that offers keyboard-interactive once but does **not** answer challenges
/// synchronously: it parks each answering promise so a test can resolve it *late* — modelling a real
/// user who is still typing their OTP while a malicious server pipelines a terminal message. Resolving
/// the parked promise is what reproduces the late-INFO_RESPONSE DoS window.
final class DeferredKIClientDelegate: NIOSSHClientUserAuthenticationDelegate {
    private var offered = false
    private let username: String
    private let answers: [String]
    private var pending: [EventLoopPromise<[String]>] = []

    init(username: String = "foo", answers: [String]) {
        self.username = username
        self.answers = answers
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard !self.offered else {
            nextChallengePromise.succeed(nil)
            return
        }
        self.offered = true
        nextChallengePromise.succeed(
            .init(username: self.username, serviceName: "ssh-connection", offer: .keyboardInteractive(.init()))
        )
    }

    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        // Deliberately do not resolve now — the test resolves this promise later, after a terminal
        // SUCCESS/FAILURE has already been processed.
        self.pending.append(responsePromise)
    }

    /// Resolve the oldest parked challenge, as if the user just finished typing.
    func resolveOldestPending() {
        self.pending.removeFirst().succeed(self.answers)
    }
}

/// A server delegate that drives a keyboard-interactive exchange by invoking a supplied closure for
/// each step.
final class ScriptedKIServerDelegate: NIOSSHServerUserAuthenticationDelegate,
    NIOSSHServerKeyboardInteractiveAuthenticationDelegate
{
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .keyboardInteractive

    private let step: (String, [String]?) -> NIOSSHKeyboardInteractiveServerStep

    init(step: @escaping (String, [String]?) -> NIOSSHKeyboardInteractiveServerStep) {
        self.step = step
    }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        // Any non-keyboard-interactive request is rejected.
        responsePromise.succeed(.failure)
    }

    func nextKeyboardInteractiveStep(
        username: String,
        previousResponses: [String]?,
        promise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        promise.succeed(self.step(username, previousResponses))
    }
}

// MARK: - Tests

final class KeyboardInteractiveTests: XCTestCase {
    var loop: EmbeddedEventLoop!
    var sessionID: ByteBuffer!

    override func setUp() {
        self.loop = EmbeddedEventLoop()
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        buffer.writeBytes(0..<32)
        self.sessionID = buffer
    }

    override func tearDown() {
        try! self.loop.syncShutdownGracefully()
        self.loop = nil
        self.sessionID = nil
    }

    private func resolve<T>(_ future: EventLoopFuture<T>) throws -> T {
        let box = NIOLoopBoundBox<Result<T, Error>?>(nil, eventLoop: future.eventLoop)
        future.whenComplete { box.value = $0 }
        self.loop.run()
        guard let result = box.value else { throw KITestError.futureNotResolved }
        return try result.get()
    }

    // MARK: (1) Codec round-trip — exact RFC 4256 wire format

    func testInfoRequestRoundTrips() throws {
        let message = SSHMessage.userAuthInfoRequest(
            .init(
                name: "PAM Authentication",
                instruction: "Please authenticate",
                languageTag: "",
                prompts: [
                    .init(prompt: "Password: ", echo: false),
                    .init(prompt: "Username echo: ", echo: true),
                ]
            )
        )

        var buffer = ByteBufferAllocator().buffer(capacity: 128)
        buffer.writeSSHMessage(message)

        // Must be decoded as INFO_REQUEST only while keyboard-interactive is in progress.
        var decodeBuffer = buffer
        XCTAssertEqual(try decodeBuffer.readSSHMessage(keyboardInteractiveInProgress: true), message)
    }

    func testInfoRequestExactWireFormat() throws {
        // Hand-computed RFC 4256 § 3.2 wire bytes: id, string name, string instruction, string
        // lang-tag, uint32 num-prompts, {string prompt, bool echo}*.
        let message = SSHMessage.userAuthInfoRequest(
            .init(name: "n", instruction: "in", languageTag: "en", prompts: [.init(prompt: "P?", echo: false)])
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)

        var expected = ByteBufferAllocator().buffer(capacity: 64)
        expected.writeInteger(UInt8(60))  // SSH_MSG_USERAUTH_INFO_REQUEST
        expected.writeInteger(UInt32(1))  // name length
        expected.writeString("n")
        expected.writeInteger(UInt32(2))  // instruction length
        expected.writeString("in")
        expected.writeInteger(UInt32(2))  // lang-tag length
        expected.writeString("en")
        expected.writeInteger(UInt32(1))  // num-prompts
        expected.writeInteger(UInt32(2))  // prompt length
        expected.writeString("P?")
        expected.writeInteger(UInt8(0))  // echo == false

        XCTAssertEqual(buffer, expected)
    }

    func testInfoResponseRoundTrips() throws {
        let message = SSHMessage.userAuthInfoResponse(.init(responses: ["secret", "123456"]))
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)
        var decodeBuffer = buffer
        XCTAssertEqual(try decodeBuffer.readSSHMessage(), message)
    }

    func testInfoResponseExactWireFormat() throws {
        let message = SSHMessage.userAuthInfoResponse(.init(responses: ["ab"]))
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        buffer.writeSSHMessage(message)

        var expected = ByteBufferAllocator().buffer(capacity: 32)
        expected.writeInteger(UInt8(61))  // SSH_MSG_USERAUTH_INFO_RESPONSE
        expected.writeInteger(UInt32(1))  // num-responses
        expected.writeInteger(UInt32(2))  // response length
        expected.writeString("ab")

        XCTAssertEqual(buffer, expected)
    }

    func testZeroPromptInfoRequestRoundTrips() throws {
        let message = SSHMessage.userAuthInfoRequest(
            .init(name: "Banner", instruction: "Welcome", languageTag: "", prompts: [])
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)
        var decodeBuffer = buffer
        XCTAssertEqual(try decodeBuffer.readSSHMessage(keyboardInteractiveInProgress: true), message)
    }

    func testKeyboardInteractiveRequestRoundTrips() throws {
        let message = SSHMessage.userAuthRequest(
            .init(
                username: "foo",
                service: "ssh-connection",
                method: .keyboardInteractive(languageTag: "en-US", submethods: "otp")
            )
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)
        var decodeBuffer = buffer
        XCTAssertEqual(try decodeBuffer.readSSHMessage(), message)
    }

    // MARK: (2) id-60 disambiguation, BOTH directions

    func testId60DecodesAsPKOKWhenNotInKeyboardInteractive() throws {
        let key = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        let pkok = SSHMessage.userAuthPKOK(.init(key: key))

        var buffer = ByteBufferAllocator().buffer(capacity: 128)
        buffer.writeSSHMessage(pkok)

        // Correct flag (false): decodes as PK_OK.
        var b1 = buffer
        XCTAssertEqual(try b1.readSSHMessage(keyboardInteractiveInProgress: false), pkok)

        // Wrong flag (true): id 60 is interpreted as INFO_REQUEST, so it must NOT decode as PK_OK.
        var b2 = buffer
        let wrong = try? b2.readSSHMessage(keyboardInteractiveInProgress: true)
        if case .some(.userAuthPKOK) = wrong {
            XCTFail("id 60 must not decode as PK_OK while keyboard-interactive is in progress")
        }
    }

    func testId60DecodesAsInfoRequestWhenInKeyboardInteractive() throws {
        let infoRequest = SSHMessage.userAuthInfoRequest(
            .init(name: "n", instruction: "i", languageTag: "", prompts: [.init(prompt: "P: ", echo: false)])
        )

        var buffer = ByteBufferAllocator().buffer(capacity: 128)
        buffer.writeSSHMessage(infoRequest)

        // Correct flag (true): decodes as INFO_REQUEST.
        var b1 = buffer
        XCTAssertEqual(try b1.readSSHMessage(keyboardInteractiveInProgress: true), infoRequest)

        // Wrong flag (false): id 60 is interpreted as PK_OK, so it must NOT decode as INFO_REQUEST.
        var b2 = buffer
        let wrong = try? b2.readSSHMessage(keyboardInteractiveInProgress: false)
        if case .some(.userAuthInfoRequest) = wrong {
            XCTFail("id 60 must not decode as INFO_REQUEST outside a keyboard-interactive exchange")
        }
    }

    // MARK: (5) num-responses != num-prompts rejected (client side)

    func testMismatchedResponseCountIsRejected() throws {
        // Client delegate answers with the wrong number of responses.
        let delegate = ScriptedKIClientDelegate { _ in ["only-one", "too-many"] }
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false)]  // exactly one prompt
        )

        let future = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(infoRequest))
        XCTAssertThrowsError(try self.resolve(future)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidKeyboardInteractiveResponse)
        }
    }

    func testMatchedResponseCountProducesInfoResponse() throws {
        let delegate = ScriptedKIClientDelegate { _ in ["the-password"] }
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false)]
        )

        let future = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(infoRequest))
        let response = try self.resolve(future)
        XCTAssertEqual(response.responses, ["the-password"])
    }

    // MARK: (4) Zero-prompt informational INFO_REQUEST -> empty response, loop continues

    func testZeroPromptProducesEmptyResponseAndLoopContinues() throws {
        let delegate = ScriptedKIClientDelegate { challenge in
            // Answer with one response per prompt; zero prompts -> empty array.
            Array(repeating: "x", count: challenge.prompts.count)
        }
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        // Round 1: informational (zero prompts).
        let informational = SSHMessage.UserAuthInfoRequestMessage(
            name: "MOTD",
            instruction: "Welcome",
            languageTag: "",
            prompts: []
        )
        let firstFuture = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(informational))
        let firstResponse = try self.resolve(firstFuture)
        XCTAssertEqual(firstResponse.responses, [])
        stateMachine.sendUserAuthInfoResponse(firstResponse)

        // Round 2: a real prompt still works — the loop continued within the same attempt.
        let real = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false)]
        )
        let secondFuture = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(real))
        let secondResponse = try self.resolve(secondFuture)
        XCTAssertEqual(secondResponse.responses, ["x"])
    }

    // MARK: (6) DoS caps -> thrown, never trap

    func testTooManyPromptsIsRejected() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeInteger(UInt8(60))  // INFO_REQUEST id
        buffer.writeSSHString("n".utf8)
        buffer.writeSSHString("i".utf8)
        buffer.writeSSHString("".utf8)
        buffer.writeInteger(UInt32(KeyboardInteractiveLimits.maximumPrompts + 1))  // over cap

        XCTAssertThrowsError(try buffer.readSSHMessage(keyboardInteractiveInProgress: true)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyboardInteractiveLimitsExceeded)
        }
    }

    func testTooManyResponsesIsRejected() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeInteger(UInt8(61))  // INFO_RESPONSE id
        buffer.writeInteger(UInt32(KeyboardInteractiveLimits.maximumResponses + 1))  // over cap

        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyboardInteractiveLimitsExceeded)
        }
    }

    func testOversizedFieldIsRejected() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeInteger(UInt8(60))  // INFO_REQUEST id
        // Declare a name field larger than the cap. The length prefix is inspected before the body
        // is read, so this is rejected without allocating the oversized field.
        buffer.writeInteger(UInt32(KeyboardInteractiveLimits.maximumFieldByteLength + 1))

        XCTAssertThrowsError(try buffer.readSSHMessage(keyboardInteractiveInProgress: true)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyboardInteractiveLimitsExceeded)
        }
    }

    func testTooManyRoundsIsRejected() throws {
        let delegate = ScriptedKIClientDelegate { challenge in
            Array(repeating: "x", count: challenge.prompts.count)
        }
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false)]
        )

        // The cap is inclusive: `maximumRounds` rounds succeed.
        for _ in 0..<KeyboardInteractiveLimits.maximumRounds {
            let future = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(infoRequest))
            let response = try self.resolve(future)
            stateMachine.sendUserAuthInfoResponse(response)
        }

        // One more round exceeds the cap and must throw (never trap).
        XCTAssertThrowsError(try stateMachine.receiveUserAuthInfoRequest(infoRequest)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyboardInteractiveLimitsExceeded)
        }
    }

    // MARK: (7) Late-INFO_RESPONSE DoS — a terminal message drains before we answer

    /// Attack (a): server pipelines INFO_REQUEST then USERAUTH_FAILURE. The client's answering delegate
    /// resolves *late* (the user finishes typing after the failure has already been processed). The
    /// resulting INFO_RESPONSE must be dropped gracefully — never a `preconditionFailure` — and auth
    /// must have failed cleanly, proceeding toward the next method / `.authenticationFailed`.
    func testLateInfoResponseAfterFailureIsDroppedNotTrap() throws {
        let delegate = DeferredKIClientDelegate(answers: ["123456"])
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "One-time Code: ", echo: false)]
        )

        // INFO_REQUEST parks our answering delegate (response now outstanding)...
        let answeringFuture = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(infoRequest))

        // ...and a terminal FAILURE is drained from the same read before we could answer. This must
        // not throw, and it clears the keyboard-interactive loop state.
        let failureFuture = try XCTUnwrap(
            try stateMachine.receiveUserAuthFailure(.init(authentications: [], partialSuccess: false))
        )
        // No further methods remain, so the client gives up cleanly.
        XCTAssertNil(try self.resolve(failureFuture))
        stateMachine.noFurtherMethods()

        // NOW the user finishes typing: the answering delegate resolves late.
        delegate.resolveOldestPending()
        let lateResponse = try self.resolve(answeringFuture)

        // The stale INFO_RESPONSE is a graceful no-op (dropped), not a trap.
        XCTAssertFalse(stateMachine.sendUserAuthInfoResponse(lateResponse))

        // The server-decided failure stands: a subsequent SUCCESS would now be unsolicited.
        XCTAssertThrowsError(try stateMachine.receiveUserAuthSuccess()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    /// Attack (b): server pipelines INFO_REQUEST then USERAUTH_SUCCESS. The client's answering delegate
    /// resolves *late*. The stale INFO_RESPONSE must be dropped gracefully and the authenticated state
    /// must stand — no `preconditionFailure`, no session teardown.
    func testLateInfoResponseAfterSuccessIsDroppedNotTrap() throws {
        let delegate = DeferredKIClientDelegate(answers: ["123456"])
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        let infoRequest = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "One-time Code: ", echo: false)]
        )

        let answeringFuture = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(infoRequest))

        // Terminal SUCCESS drained before we answer — must not throw.
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())

        // Late resolution of the parked challenge.
        delegate.resolveOldestPending()
        let lateResponse = try self.resolve(answeringFuture)

        // Dropped gracefully; authenticated state stands.
        XCTAssertFalse(stateMachine.sendUserAuthInfoResponse(lateResponse))

        // Still authenticated: a repeated SUCCESS is ignored, and trailing INFO_REQUESTs are ignored.
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
        XCTAssertNil(try stateMachine.receiveUserAuthInfoRequest(infoRequest))
    }

    /// Regression guard (c): the fix must not disturb the normal multi-round flow. Each timely
    /// INFO_RESPONSE is actually sent (`sendUserAuthInfoResponse` returns `true`), the loop continues,
    /// and a terminal SUCCESS is accepted.
    func testNormalMultiRoundThenSuccessStillSends() throws {
        let delegate = ScriptedKIClientDelegate { challenge in
            Array(repeating: "x", count: challenge.prompts.count)
        }
        var stateMachine = self.makeClientInKeyboardInteractive(delegate: delegate)

        let prompt = SSHMessage.UserAuthInfoRequestMessage(
            name: "n",
            instruction: "i",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false)]
        )

        // Round 1: timely answer is actually sent.
        let f1 = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(prompt))
        let r1 = try self.resolve(f1)
        XCTAssertTrue(stateMachine.sendUserAuthInfoResponse(r1))

        // Round 2: still in the loop, still sends.
        let f2 = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(prompt))
        let r2 = try self.resolve(f2)
        XCTAssertTrue(stateMachine.sendUserAuthInfoResponse(r2))

        // Terminal SUCCESS accepted.
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    // MARK: (3) Full client<->server multi-round handshake via the in-process emitter

    func testEndToEndMultiRoundHandshakeReachesSuccess() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        // Client answers a password prompt then an OTP prompt.
        let clientDelegate = ScriptedKIClientDelegate { challenge in
            if challenge.prompts.first?.prompt.contains("Password") == true {
                return ["hunter2"]
            } else if challenge.prompts.first?.prompt.contains("Code") == true {
                return ["654321"]
            }
            return Array(repeating: "", count: challenge.prompts.count)
        }

        // Server: password round -> OTP round -> success.
        let serverDelegate = ScriptedKIServerDelegate { _, previousResponses in
            switch previousResponses {
            case .none:
                return .challenge(
                    .init(
                        name: "PAM",
                        instruction: "Step 1",
                        prompts: [.init(prompt: "Password: ", echo: false)]
                    )
                )
            case .some(["hunter2"]):
                return .challenge(
                    .init(
                        name: "PAM",
                        instruction: "Step 2",
                        prompts: [.init(prompt: "One-time Code: ", echo: false)]
                    )
                )
            case .some(["654321"]):
                return .outcome(.success)
            default:
                return .outcome(.failure)
            }
        }

        var harness = TestHarness()
        harness.clientAuthDelegate = clientDelegate
        harness.serverAuthDelegate = serverDelegate

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        // Auth completing is proven by the connection reaching the active state: a child channel can
        // now be opened and confirmed by the server.
        let clientChannel = try channel.createNewChannel()
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertTrue(clientChannel.isActive)
        XCTAssertEqual(channel.activeServerChannels.count, 1)
    }

    func testEndToEndWrongAnswerFailsAuth() throws {
        let channel = BackToBackEmbeddedChannel()
        defer { try? channel.finish() }

        let clientDelegate = ScriptedKIClientDelegate { challenge in
            Array(repeating: "wrong", count: challenge.prompts.count)
        }

        let serverDelegate = ScriptedKIServerDelegate { _, previousResponses in
            switch previousResponses {
            case .none:
                return .challenge(
                    .init(name: "PAM", instruction: "", prompts: [.init(prompt: "Password: ", echo: false)])
                )
            case .some(["correct"]):
                return .outcome(.success)
            default:
                return .outcome(.failure)
            }
        }

        var harness = TestHarness()
        harness.clientAuthDelegate = clientDelegate
        harness.serverAuthDelegate = serverDelegate

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        // Auth never succeeded: no active server channel exists.
        XCTAssertEqual(channel.activeServerChannels.count, 0)
    }

    // MARK: Helpers

    /// Drives a fresh client state machine to the point where a keyboard-interactive attempt is live
    /// (state `.awaitingResponses`, keyboard-interactive in progress), ready to receive INFO_REQUESTs.
    private func makeClientInKeyboardInteractive(
        delegate: NIOSSHClientUserAuthenticationDelegate
    ) -> UserAuthenticationStateMachine {
        var stateMachine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: self.loop,
            sessionID: self.sessionID
        )

        _ = stateMachine.beginAuthentication()
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        let future = try! XCTUnwrap(try! stateMachine.receiveServiceAccept(.init(service: "ssh-userauth")))
        let request = try! self.resolve(future)
        let message = try! XCTUnwrap(request)
        XCTAssertEqual(message.method, .keyboardInteractive(languageTag: "", submethods: ""))
        stateMachine.sendUserAuthRequest(message)

        return stateMachine
    }
}
