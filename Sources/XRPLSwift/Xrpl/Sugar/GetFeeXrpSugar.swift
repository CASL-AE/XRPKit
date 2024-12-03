//
//  GetFeeXrpSugar.swift
//
//
//  Created by Denis Angell on 8/21/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/sugar/getFeeXrp.ts

import Foundation

let NUM_DECIMAL_PLACES: Int = 6 // swiftlint:disable:this identifier_name
let BASE_10: Int = 10 // swiftlint:disable:this identifier_name

/**
 Calculates the current transaction fee for the ledger.
 Note: This is a public API that can be called directly.
 - parameters:
    - client: The Client used to connect to the ledger.
    - cushion: The fee cushion to use.
 - returns:
 The transaction fee.
 */
public func getFeeXrp(
    _ client: XrplClient,
    _ cushion: Double? = nil
) async throws -> String {
    let feeCushion = cushion ?? client.feeCushion

    let request = try ServerInfoRequest(["command": "server_info"] as [String: AnyObject])
    let response = try await client.request(request).get()
    guard let response = response as? BaseResponse<ServerInfoResponse> else { throw XrplError("Invalid Response, getFeeXrp") }
    guard let result = response.result else {
        throw XrplError("Invalid Result, getFeeXrp")
    }

    let serverInfo = result.info
    guard let baseFee = serverInfo.validatedLedger?.baseFeeXrp else {
        throw XrplError("Xrp: Could not get base_fee_xrp from server_info")
    }

    let baseFeeXrp = Double(baseFee)
    var loadFactor = serverInfo.loadFactor ?? 1
    var fee = baseFeeXrp * Double(loadFactor) * feeCushion
    // Cap fee to `client.maxFeeXRP`
    fee = min(fee, Double(client.maxFeeXRP)!)
    // Round fee to 6 decimal places
    return fee.description
}
