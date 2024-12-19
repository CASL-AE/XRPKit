//
//  connection.swift
//
//
//  Created by Denis Angell on 7/27/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/client/connection.ts

import Foundation
import NIO
import WebSocketKit
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CoreFoundation)
import CoreFoundation
#endif

// ----------------------------------------------------------------------------------

protocol ConsoleLogDelegate: AnyObject {
    func onUpdate(id: Int, message: String)
}

class ConsoleLog {
    var trace: [[String: AnyObject]] = []
    func push(id: Int, _ message: String) {
        self.trace.append([
            "id": id,
            "message": message
        ] as? [String: AnyObject] ?? [:])
    }
}

// ----------------------------------------------------------------------------------

private let connEventGroup = MultiThreadedEventLoopGroup(numberOfThreads: 4)

private let SECONDS_PER_MINUTE: Int = 60 // swiftlint:disable:this identifier_name
private let TIMEOUT: Int = 20
private let CONNECTION_TIMEOUT: Int = 5 // swiftlint:disable:this identifier_name

public enum WebsocketState: String {
    case closed
    case closing
    case open
}

/**
 ConnectionOptions is the configuration for the Connection class.
 */
public class ConnectionOptions {
    //  trace: Bool? | ((id: string, message: string) => void)
    internal var trace: ConsoleLog?
    public var proxy: String?
    public var proxyAuthorization: String?
    public var authorization: String?
    public var trustedCertificates: [String]?
    public var key: String?
    public var passphrase: String?
    public var certificate: String?
    public var timeout: Int?
    public var connectionTimeout: Int = 3600
    public var headers: [String: [String: String]]?
}

/**
 ConnectionUserOptions is the user-provided configuration object. All configuration
 is optional, so any ConnectionOptions configuration that has a default value is
 still optional at the point that the user provides it.
 */
public class ConnectionUserOptions: ConnectionOptions {}

/**
 Represents an intentionally triggered web-socket disconnect code.
 WebSocket spec allows 4xxx codes for app/library specific codes.
 See: https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent
 */
public let INTENTIONAL_DISCONNECT_CODE = 4000 // swiftlint:disable:this identifier_name

// typealias WebsocketState: Int = 0 | 1 | 2 | 3

// func getAgent(url: String, config: ConnectionOptions) -> Agent? {
//  if config.proxy == nil {
//    return nil
//  }
//
//  let parsedURL = URL(url)
//    let parsedProxyURL = URL(config.proxy)
//
//  let proxyOptions = _.omitBy(
//    {
//      secureEndpoint: parsedURL.protocol === "wss:",
//      secureProxy: parsedProxyURL.protocol === "https:",
//      auth: config.proxyAuthorization,
//      ca: config.trustedCertificates,
//      key: config.key,
//      passphrase: config.passphrase,
//      cert: config.certificate,
//      href: parsedProxyURL.href,
//      origin: parsedProxyURL.origin,
//      protocol: parsedProxyURL.protocol,
//      username: parsedProxyURL.username,
//      password: parsedProxyURL.password,
//      host: parsedProxyURL.host,
//      hostname: parsedProxyURL.hostname,
//      port: parsedProxyURL.port,
//      pathname: parsedProxyURL.pathname,
//      search: parsedProxyURL.search,
//      hash: parsedProxyURL.hash,
//    },
//    (value) => value == null,
//  )
//
//  let HttpsProxyAgent: new (opt: typeof proxyOptions) => Agent
//  do {
//    /* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-require-imports,
//      node/global-require, global-require, -- Necessary for the `require` */
//    HttpsProxyAgent = require("https-proxy-agent")
//    /* eslint-enable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-require-imports,
//      node/global-require, global-require, */
//  } catch (_error) {
//    throw new Error(""proxy" option is not supported in the browser")
//  }
//  return new HttpsProxyAgent(proxyOptions)
// }

/**
 Create a new websocket given your URL and optional proxy/certificate configuration.
 - parameters:
 - url: The URL to connect to.
 - config: The configuration options for the WebSocket.
 - returns:
 A Websocket that fits the given configuration parameters.
 */
public func createWebSocket(
    url: String,
    config: ConnectionOptions
) -> WebSocketClient? {
    //    let options: WebSocket.ClientOptions = [:]
    //    options.agent = getAgent(url, config)
    //    if config.headers != nil {
    //        options.headers = config.headers
    //    }
    //    if config.authorization != nil {
    //        let base64 = Data(from: config.authorization).base64EncodedString()
    //        options.headers = [
    //            ...options.headers,
    //            "Authorization": "Basic \(base64)"
    //        ]
    //    }
    let optionsOverrides = [
        "ca": config.trustedCertificates,
        "key": config.key,
        "passphrase": config.passphrase,
        "cert": config.certificate
    ] as [String: Any]
    let websocketOptions = optionsOverrides
    let client = WebSocketClient(eventLoopGroupProvider: .shared(connEventGroup))
    /*
     * we will have a listener for each outstanding request,
     * so we have to raise the limit (the default is 10)
     */
    //    if typeof websocket.setMaxListeners == "function" {
    //        websocket.setMaxListeners(1000000)
    //    }
    return client
}

/**
 Ws.send(), but promisified.
 - parameters:
 - ws: Websocket to send with.
 - message: Message to send.
 - returns:
 When the message has been sent.
 */
public func websocketSendAsync(
    ws: WebSocket,
    message: String
) async -> EventLoopFuture<Void> {
    let promise = connEventGroup.next().makePromise(of: Void.self)
    ws.send(message, promise: promise)
    return promise.futureResult
}

public protocol ConnectionDelegate: AnyObject {
    func error(code: Int, message: Any, data: Data)
    func connected()
    func disconnected(code: Int)
    func ledgerClosed(ledger: Any)
    func transaction(tx: Any)
    func validationReceived(validation: Any)
    func manifestReceived(manifest: Any)
    func peerStatusChange(status: Any)
    func consensusPhase(consensus: Any)
    func pathFind(path: Any)
}

/**
 The main Connection class. Responsible for connecting to & managing
 an active WebSocket connection to a XRPL node.
 */
public class Connection {
    var delegate: ConnectionDelegate?

    internal var trace: ConsoleLog?

    internal let url: String?
    public var ws: WebSocket?
    private var reconnectTimeoutID: Timer?
    private var heartbeatIntervalID: Timer?
    private let retryConnectionBackoff = ExponentialBackoff(
        opts: ExponentialBackoffOptions(min: 100, max: SECONDS_PER_MINUTE * 1000)
    )

    internal let config: ConnectionOptions
    private let requestManager = RequestManager()
    private let connectionManager = ConnectionManager()

    /**
     Creates a new Connection object.
     - parameters:
     - ws: URL to connect to.
     - options: Options for the Connection object.
     */
    public init(url: String?, options: ConnectionUserOptions? = nil) {
        //    super()
        //        ws.setMaxListeners(1000000)
        self.url = url
        self.config = ConnectionOptions()
        self.config.timeout = TIMEOUT * 1000
        self.config.connectionTimeout = CONNECTION_TIMEOUT * 1000
        //        self.config = {
        //            self.timeout: TIMEOUT * 1000,
        //        connectionTimeout: CONNECTION_TIMEOUT * 1000,
        //            ...options,
        //        }
        //        if (typeof options.trace === "function") {
        //            self.trace = options.trace
        //        } else if (options.trace) {
        //            // eslint-disable-next-line no-console -- Used for tracing only
        //            self.trace = console.log
        //        }
    }

    /**
     Returns whether the websocket is connected.
     - returns:
     Whether the websocket connection is open.
     */
    public func isConnected() -> Bool {
        return self.ws?.isClosed == false
    }

    /**
     Connects the websocket to the provided URL.
     - returns:
     When the websocket is connected.
     - throws:
     ConnectionError if there is a connection error, RippleError if there is already a WebSocket in existence.
     */
    public func connect() async throws -> EventLoopFuture<Any> {
        //        let promise = connEventGroup.next().makePromise(of: Any.self)
        //        if self.isConnected() {
        //            return promise.futureResult
        //        }
        //        if self.state == .closed {
        //            return await self.connectionManager.awaitConnection()
        //        }
        //        if self.url!.isEmpty {
        //            promise.fail(XrplError("Cannot connect because no server was specified"))
        //        }
        //        if self.ws != nil {
        //            // missing state
        //            promise.fail(XrplError("Websocket connection never cleaned up."))
        //        }

        let connectionTimeoutID = Timer.scheduledTimer(withTimeInterval: TimeInterval(self.config.connectionTimeout), repeats: false) { _ in
            Task {
                // swiftlint:disable:next line_length
                self.onConnectionFailed(errorOrCode: ConnectionError("Error: connect() timed out after \(self.config.connectionTimeout)ms. If your internet connection is working, the rippled server may be blocked or inaccessible. You can also try setting the `connectionTimeout` option in the Client constructor.")
                )
            }
        }
        // Create the connection timeout, in case the connection hangs longer than expected.
        // Connection listeners: these stay attached only until a connection is done/open.
        guard let url = url, let uri = URL(string: url), let isport = uri.port, let isscheme = uri.scheme, let ishost = uri.host else {
            throw ConnectionError("Connection: invalid url")
        }
        let client: WebSocketClient = createWebSocket(url: url, config: self.config)!
        try client.connect(scheme: isscheme, host: ishost, port: isport, onUpgrade: { ws -> Void in
            self.ws = ws
            Task {
                // TODO: This goes after client.connect in js, but swift doesnt(verify) return the ws. we would .wait
                // But if we .wait(), then the await connection func is hit after the onceOpen func
                if self.ws == nil {
                    throw ConnectionError("Connect: created null websocket")
                }
                try await self.onceOpen(connectionTimeoutID: connectionTimeoutID)
            }
        })

        //        this.ws.on('error', (error) => this.onConnectionFailed(error))
        //        this.ws.on('error', () => clearTimeout(connectionTimeoutID))

        self.ws?.eventLoop.execute {
            self.ws?.onClose.whenFailure({ error in
                self.onConnectionFailed(errorOrCode: error)
            })
            self.ws?.onClose.whenSuccess({ _ in
                connectionTimeoutID.invalidate()
            })
        }
        
        return await self.connectionManager.awaitConnection()
    }

    /**
     Disconnect the websocket connection.
     We never expect this method to reject. Even on "bad" disconnects, the websocket
     should still successfully close with the relevant error code returned.
     See https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent for the full list.
     If no open websocket connection exists, resolve with no code (`undefined`).
     - returns:
     A promise containing either `undefined` or a disconnected code, that resolves when the connection is destroyed.
     */
    public func disconnect() async -> EventLoopFuture<Any?> {
        let promise = connEventGroup.next().makePromise(of: Any?.self)
        //            self.clearHeartbeatInterval()
        if self.reconnectTimeoutID != nil {
            self.reconnectTimeoutID?.invalidate()
            self.reconnectTimeoutID = nil
        }
        if self.state == WebsocketState.closed {
            promise.succeed(nil)
        }
        if self.ws == nil {
            promise.succeed(nil)
        }

        if self.ws == nil {
            promise.succeed(nil)
        }
        if self.ws != nil {
            promise.succeed(1000)
            //            self.ws.once("close", (code) => resolve(code))
        }
        /*
         * Connection already has a disconnect handler for the disconnect logic.
         * Just close the websocket manually (with our "intentional" code) to
         * trigger that.
         */
        if self.ws != nil && self.state != WebsocketState.closing {
            _ = try? await self.ws?.close(code: .normalClosure)
        }

        return promise.futureResult
    }

    /**
     Disconnect the websocket, then connect again.
     */
    public func reconnect() async throws {
        /*
         * NOTE: We currently have a "reconnecting" event, but that only triggers
         * through an unexpected connection retry logic.
         * See: https://github.com/XRPLF/xrpl.js/pull/1101#issuecomment-565360423
         */
        //        self.emit("reconnect")
        _ = await self.disconnect()
        _ = try await self.connect()
    }

    /**
     Sends a request to the rippled server.
     - parameters:
     - request: The request to send to the server.
     - timeout: How long the Connection instance should wait before assuming that there will not be a response.
     - returns:
     The response from the rippled server.
     - throws:
     NotConnectedError if the Connection isn"t connected to a server.
     */
    public func request<R: BaseRequest>(
        request: R,
        timeout: Int? = nil
    ) async throws -> EventLoopFuture<Any> {
        guard self.shouldBeConnected, let ws = self.ws else {
            throw NotConnectedError("Not Connected")
        }
        let (id, message, responsePromise) = try! self.requestManager.createRequest(
            request: request,
            //            timeout: timeout ?? self.config.timeout,
            timeout: 10
        )
        //        self.trace("send", message)
        _ = await websocketSendAsync(ws: ws, message: message)
        return responsePromise
    }

    /**
     Get the Websocket connection URL.
     - returns:
     The Websocket connection URL.
     */
    public func getUrl() -> String {
        return self.url ?? ""
    }

    /**
     Handler for when messages are received from the server.
     - parameters:
     - message: The message received from the server.
     */
    private func onMessage(data: Data) {
        //        self.trace("receive", message)
        var dict: [String: AnyObject] = [:]
        do {
            dict = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves) as! [String: AnyObject]
        } catch {
            print(error.localizedDescription)
            //            if (error instanceof Error) {
            //                self.emit("error", "badMessage", error.message, message)
            //            }
            return
        }
        //        guard let br = br else {
        //            return
        //        }
        //        if br.type == nil && br.error != nil {
        //            // e.g. slowDown
        ////            self.emit("error", data.error, data.error_message, data)
        //            return
        //        }
        //        if (br.type.isEmpty) {
        //            // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- Should be true
        ////            self.emit(data.type as string, data)
        //        }
        if dict["type"] as! String == "response" {
            do {
                try self.requestManager.handleResponse(response: dict)
            } catch {
                print(error)
                // eslint-disable-next-line max-depth -- okay here
                //                if (error instanceof Error) {
                //                    self.emit("error", "badMessage", error.message, message)
                //                } else {
                //                    self.emit("error", "badMessage", error, error)
                //                }
            }
        }
    }

    /**
     Handler for when messages are received from the server.
     - parameters:
     - message: The message received from the server.
     */
    private func onMessage(message: String) {
        let data: Data = message.data(using: .utf8)!
        self.onMessage(data: data)
    }

    /**
     Gets the state of the websocket.
     - returns:
     The Websocket"s ready state.
     */
    private var state: WebsocketState {
        return self.ws != nil ? WebsocketState.open : WebsocketState.closed
    }

    /**
     Returns whether the server should be connected.
     - returns:
     Whether the server should be connected.
     */
    private var shouldBeConnected: Bool {
        return self.ws != nil
    }

    /**
     Handler for what to do once the connection to the server is open.
     - parameters:
     - connectionTimeoutID: Timeout in case the connection hangs longer than expected.
     - returns:
     A promise that resolves to void when the connection is fully established.
     - throws:
     Error if the websocket initialized is somehow null.
     */
    private func onceOpen(connectionTimeoutID: Timer) async throws {
        if self.ws == nil {
            throw ConnectionError("onceOpen: ws is nil")
        }

        // Once the connection completes successfully, remove all old listeners
        //        self.ws.removeAllListeners()
        connectionTimeoutID.invalidate()
        // Add new, long-term connected listeners for messages and errors
        
        self.ws?.eventLoop.execute {
            self.ws?.onText({ _, message in
                self.onMessage(message: message)
            })
            
            
            // TESTING ONLY
            // TODO: This function is only used in the MockRippled Testing Response
            
            self.ws?.onBinary({ _, message in
                let data = Data(buffer: message)
                self.onMessage(data: data)
            })
            
            //        self.ws.on("error", (error) =>
            //            self.emit("error", "websocket", error.message, error),
            //        )
            // Handle a closed connection: reconnect if it was unexpected
            _ = self.ws?.onClose.map { _ in
                let reason: String = "none"
                let code: Int? = 0
                if self.ws == nil {
                    NSLog("UNMPLEMENTED")
                    return
                }
                self.clearHeartbeatInterval()
                try? self.requestManager.rejectAll(error: DisconnectedError("websocket was closed, \(reason)"))
                //            self.ws.removeAllListeners()
                self.ws = nil
                
                if code == nil {
                    let reasonText = reason
                    // swiftlint:disable:next line_length
                    NSLog("Disconnected but the disconnect code was undefined (The given reason was \(reasonText)). This could be caused by an exception being thrown during a `connect` callback. Disconnecting with code 1011 to indicate an internal error has occurred.")
                    
                    /*
                     * Error code 1011 represents an Internal Error according to
                     * https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
                     */
                    let internalErrorCode = 1011
                    //                self.emit("disconnected", internalErrorCode)
                    print("disconnected: \(internalErrorCode)")
                } else {
                    //                self.emit("disconnected", code)
                    guard let code = code else { return }
                    print("disconnected: \(code)")
                }
                
                /*
                 * If this wasn"t a manual disconnect, then lets reconnect ASAP.
                 * Code can be undefined if there"s an exception while connecting.
                 */
                if code != INTENTIONAL_DISCONNECT_CODE && code != nil {
                    self.intentionalDisconnect()
                }
            }
        }
        
        // Finalize the connection and resolve all awaiting connect() requests
        do {
            self.retryConnectionBackoff.reset()
            self.startHeartbeatInterval()
            self.connectionManager.resolveAllAwaiting()
            //                self.emit("connected")
            NSLog("connected")
        } catch {
            print(error.localizedDescription)
            if error is Error {
                self.connectionManager.rejectAllAwaiting(error: error)
                // Ignore this error, propagate the root cause.
                await self.disconnect()
            }
        }
    }

    /**
     Handler for what to do once the connection to the server is open.
     - parameters:
     - connectionTimeoutID: Timeout in case the connection hangs longer than expected.
     - returns:
     A promise that resolves to void when the connection is fully established.
     - throws:
     Error if the websocket initialized is somehow null.
     */
    private func intentionalDisconnect() {
        let retryTimeout: Int = self.retryConnectionBackoff.duration()
        //            self.trace("reconnect", "Retrying connection in \(retryTimeout)ms.")
        //            self.emit("reconnecting", self.retryConnectionBackoff.attempts)
        NSLog("reconnecting: \(String(describing: self.retryConnectionBackoff.attempts)))")
        /*
         * Start the reconnect timeout, but set it to `this.reconnectTimeoutID`
         * so that we can cancel one in-progress on disconnect.
         */
        self.reconnectTimeoutID = Timer.scheduledTimer(withTimeInterval: TimeInterval(retryTimeout), repeats: false) { _ in
            Task {
                try await self.reconnect()
            }
        }
    }

    /**
     Clears the heartbeat connection interval.
     */
    private func clearHeartbeatInterval() {
        if self.heartbeatIntervalID != nil {
            self.heartbeatIntervalID?.invalidate()
        }
    }

    /**
     Starts a heartbeat to check the connection with the server.
     */
    private func startHeartbeatInterval() {
        self.clearHeartbeatInterval()
        self.heartbeatIntervalID = Timer.scheduledTimer(withTimeInterval: TimeInterval(self.config.timeout!), repeats: false) { _ in
            Task {
                await self.heartbeat()
            }
        }
    }

    /**
     A heartbeat is just a "ping" command, sent on an interval.
     If this succeeds, we"re good. If it fails, disconnect so that the consumer can reconnect, if desired.
     - returns:
     A Promise that resolves to void when the heartbeat returns successfully.
     */
    private func heartbeat() async -> EventLoopPromise<Void> {
        let promise = connEventGroup.next().makePromise(of: Void.self)
        let response = try! await self.request(request: BaseRequest(command: "ping"))
        response.whenFailure { error in
            Task {
                do {
                    try await self.reconnect()
                } catch {
                    //                    self.emit("error", "reconnect", error.message, error)
                    NSLog("error: reconnect: \(error.localizedDescription)")
                }
            }
        }
        return promise
    }

    /**
     Process a failed connection.
     - parameters:
     - errorOrCode: (Optional) Error or code for connection failure.
     */
    private func onConnectionFailed(errorOrCode: Error) {
        if self.ws != nil {
            //            self.ws.removeAllListeners()
            _ = self.ws?.close()
            self.ws = nil
        }
        if !errorOrCode.localizedDescription.isEmpty {
            //            self.connectionManager.rejectAllAwaiting(error: NotConnectedError.connection(errorOrCode.localizedDescription, errorOrCode))
            self.connectionManager.rejectAllAwaiting(error: NotConnectedError(errorOrCode.localizedDescription))
        } else {
            self.connectionManager.rejectAllAwaiting(error: NotConnectedError("Connection failed."))
        }
    }

    /**
     Process a failed connection.
     - parameters:
     - errorOrCode: (Optional) Error or code for connection failure.
     */
    private func onConnectionFailed(errorOrCode: Int) {
        if self.ws != nil {
            //            self.ws.removeAllListeners()
            _ = self.ws?.close()
            self.ws = nil
        }
        self.connectionManager.rejectAllAwaiting(
            //            error: NotConnectedError("Connection failed with code \(errorOrCode).", code: errorOrCode),
            error: NotConnectedError("Connection failed with code \(errorOrCode).")
        )
    }
}
