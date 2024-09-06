//
//  File.swift
//
//
//  Created by Denis Angell on 7/27/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/client/RequestManager.ts

import Foundation
import NIO

struct RequestMap<T> {
    public var timer: Timer
    public var promise: EventLoopPromise<Any>
    public var requestType: T
}

/**
 * Manage all the requests made to the websocket, and their async responses
 * that come in from the WebSocket. Responses come in over the WS connection
 * after-the-fact, so this manager will tie that response to resolve the
 * original request.
 */
public class RequestManager {
    private var nextId = 0
    private var promisesAwaitingResponse = SafeDict<Int, RequestMap<Any>>()

    /**
     * Successfully resolves a request.
     *
     * @param id - ID of the request.
     * @param response - Response to return.
     * @throws Error if no existing promise with the given ID.
     */
    public func resolve(_ id: Int, _ response: Any?, _ error: Error?) throws {
        guard let index = self.promisesAwaitingResponse.firstIndex(id) else {
            throw XrplError("No existing promise with id \(id)")
        }
        
        guard let map = self.promisesAwaitingResponse.getByIndex(index) else { return }
        
        map.timer.invalidate()
        map.promise.succeed(response!)
        self.deletePromise(id: id)
    }

    public func resolve(id: Int, error: Any) throws {
        guard let index = self.promisesAwaitingResponse.firstIndex(id) else {
            throw XrplError("No existing promise with id \(id)")
        }
        
        guard let map = self.promisesAwaitingResponse.getByIndex(index) else {
            return
        }

        map.timer.invalidate()
        map.promise.succeed(error)
        self.deletePromise(id: id)
    }

    /**
     * Rejects a request.
     *
     * @param id - ID of the request.
     * @param error - Error to throw with the reject.
     * @throws Error if no existing promise with the given ID.
     */
    public func reject(id: Int, error: Error) throws {
        guard let index = self.promisesAwaitingResponse.firstIndex(id) else {
            throw XrplError("No existing promise with id \(id)")
        }
        
        guard let map = self.promisesAwaitingResponse.getByIndex(index) else { return }
            
        map.timer.invalidate()
        // TODO: figure out how to have a better stack trace for an error
        map.promise.fail(error)
        self.deletePromise(id: id)
    }

    /**
     * Reject all pending requests.
     *
     * @param error - Error to throw with the reject.
     */
    public func rejectAll(error: Error) throws {
        try? self.promisesAwaitingResponse.keys().forEach { (key: Int) in
            try self.reject(id: key, error: error)
//            self.deletePromise(id: key)
        }
    }

    /**
     * Creates a new WebSocket request. This sets up a timeout timer to catch
     * hung responses, and a promise that will resolve with the response once
     * the response is seen & handled.
     *
     * @param request - Request to create.
     * @param timeout - Timeout length to catch hung responses.
     * @returns Request ID, new request form, and the promise for resolving the request.
     * @throws XrplError if request with the same ID is already pending.
     */
//    @objc func resolveTimer(_ sender: Timer) {
//        guard let id = sender.userInfo as? Int else { return }
//        try! resolve(id: id, error: XrplError1.timeout())
//    }

    public func createRequest<R: BaseRequest>(
        request: R,
        timeout: Int
    ) throws -> (Int, String, EventLoopFuture<Any>) {
        var newId = 0
        if request.id == nil {
            newId = self.nextId
            self.nextId += 1
        } else {
            newId = request.id!
        }
        request.id = newId

        let encoder = JSONEncoder()
        guard let newRequest = try? encoder.encode(request).to(type: String.self) else {
            throw XrplError("request encoding error on `\(newId)`")
        }

        let timer = Timer.scheduledTimer(withTimeInterval: Double(timeout), repeats: false) { _ in
            Task {
                try! self.reject(id: self.nextId, error: TimeoutError("Timeout Error"))
            }
        }
        //    /*
        //     * Node.js won"t exit if a timer is still running, so we tell Node to ignore.
        //     * (Node will still wait for the request to complete).
        //     */
        //    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Reason above.
        //    if (timer.unref) {
        //      timer.unref()
        //    }

        if self.promisesAwaitingResponse.contains(key: newId) {
            throw XrplError("Response with id `\(newId)` is already pending")
        }

        let newPromise = eventGroup.next().makePromise(of: Any.self)
        let reqMap = RequestMap<Any>(timer: timer, promise: newPromise, requestType: R.self)
        self.promisesAwaitingResponse.set(key: newId, value: reqMap)
        
        return (newId, newRequest, newPromise.futureResult)
    }

    /**
     * Handle a "response". Responses match to the earlier request handlers,
     * and resolve/reject based on the data received.
     *
     * @param response - The response to handle.
     * @throws ResponseFormatError if the response format is invalid, RippledError if rippled returns an error.
     */
    // swiftlint:disable:next cyclomatic_complexity
    public func handleResponse(response: [String: AnyObject]?) throws {
//        NSLog("RESPONSE: \(response)")
        let decoder = JSONDecoder()
        let baseData = try JSONSerialization.data(withJSONObject: response!, options: .prettyPrinted)
        let baseResponse = try RippleBaseResponse(data: baseData)

        var isIndexInited = false
        guard let index = self.promisesAwaitingResponse.firstIndex(baseResponse.id) else { return }

        if baseResponse.status == nil {
            let error: XrplError = ValidationError("valid id not found in response")
            try self.reject(id: baseResponse.id, error: error)
            return
        }
        if baseResponse.status == "error" {
            let errorData = try JSONSerialization.data(withJSONObject: response!, options: .prettyPrinted)
            let returnedDecodable = try decoder.decode(ErrorResponse.self, from: errorData)
            if let errorMessage = returnedDecodable.errorMessage {
                try self.reject(id: baseResponse.id, error: XrplError(errorMessage))
                return
            }
            if let errorException = returnedDecodable.errorException {
                try self.reject(id: baseResponse.id, error: RippledError(errorException))
                return
            }
            let error = returnedDecodable.error
            try self.reject(id: baseResponse.id, error: XrplError(error))
            return
        }
        if baseResponse.status != "success" {
            let error = ResponseFormatError("unrecognized response.status: \(baseResponse.status ?? "")")
            try self.reject(id: baseResponse.id, error: error)
            return
        }

        guard let map = self.promisesAwaitingResponse.getByIndex(index) else { return }
        
        let jsonData = try JSONSerialization.data(
            withJSONObject: response!["result"] as! [String: AnyObject],
            options: .prettyPrinted
        )
        if map.requestType.self is AccountChannelsRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountChannelsResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountCurrenciesRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountCurrenciesResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountInfoRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountInfoResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountLinesRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountLinesResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountNFTsRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountNFTsResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountObjectsRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountObjectsResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountOffersRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountOffersResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is AccountTxRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(AccountTxResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is BookOffersRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(BookOffersResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is ChannelVerifyRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(ChannelVerifyResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is DepositAuthorizedRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(DepositAuthorizedResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is FeeRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(FeeResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is GatewayBalancesRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(GatewayBalancesResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is LedgerRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(LedgerResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is LedgerClosedRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(LedgerClosedResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is LedgerCurrentRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(LedgerCurrentResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is LedgerDataRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(LedgerDataResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        //        if map.requestType.self is LedgerEntryRequest.Type {
        //            let responseObj = BaseResponse(
        //                response: baseResponse,
        //                result: CodableHelper.decode(LedgerEntryResponse.self, from: jsonData).decodableObj
        //            )
        //            try self.resolve(responseObj.id, responseObj, nil)
        //            return
        //        }
        //        if map.requestType.self is ManifestRequest.Type {
        //            let responseObj = BaseResponse(
        //                response: baseResponse,
        //                result: CodableHelper.decode(ManifestReseponse.self, from: jsonData).decodableObj
        //            )
        //            try self.resolve(responseObj.id, responseObj, nil)
        //            return
        //        }
        if map.requestType.self is NFTBuyOffersRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(NFTBuyOffersResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is NFTSellOffersRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(NFTSellOffersResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is NoRippleCheckRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(NoRippleCheckResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        //        if map.requestType.self is PathFindRequest.Type {
        //            let responseObj = BaseResponse(
        //                response: baseResponse,
        //                result: CodableHelper.decode(PathFindRequest.self, from: jsonData).decodableObj
        //            )
        //            try self.resolve(responseObj.id, responseObj, nil)
        //            return
        //        }
        if map.requestType.self is PingRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(PingResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is RandomRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(RandomResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is RipplePathFindRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(RipplePathFindResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is ServerInfoRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(ServerInfoResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is ServerStateRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(ServerStateResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is SubmitRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(SubmitResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is SubmitMultisignedRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(SubmitMultisignedResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        //        if map.requestType.self is SubscribeRequest.Type {
        //            let responseObj = BaseResponse(
        //                response: baseResponse,
        //                result: CodableHelper.decode(SubscribeResponse.self, from: jsonData).decodableObj
        //            )
        //            try self.resolve(responseObj.id, responseObj, nil)
        //            return
        //        }
        //        if map.requestType.self is UnsubscribeRequest.Type {
        //            let responseObj = BaseResponse(
        //                response: baseResponse,
        //                result: CodableHelper.decode(UnsubscribeResponse.self, from: jsonData).decodableObj
        //            )
        //            try self.resolve(responseObj.id, responseObj, nil)
        //            return
        //        }
        if map.requestType.self is TransactionEntryRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(TransactionEntryResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        if map.requestType.self is TxRequest.Type {
            let responseObj = BaseResponse(
                response: baseResponse,
                result: CodableHelper.decode(TxResponse.self, from: jsonData).decodableObj
            )
            try self.resolve(responseObj.id, responseObj, nil)
            return
        }
        let error = ConnectionError("The request \(map.requestType) has not been mapped")
        try self.reject(id: baseResponse.id, error: error)
    }

    /**
     * Delete a promise after it has been returned.
     *
     * @param id - ID of the request.
     */
    private func deletePromise(id: Int) {
        self.promisesAwaitingResponse.remove(key: id)
    }
}
