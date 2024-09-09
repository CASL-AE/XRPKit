//
//  AutoFill.swift
//
//
//  Created by Denis Angell on 7/31/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/sugar/autofill.ts

import Foundation
import NIO

private let autofillEventGroup = MultiThreadedEventLoopGroup(numberOfThreads: 4)

public class AutoFillSugar {
    /// Expire unconfirmed transactions after 20 ledger versions, approximately 1 minute, by default
    let LEDGER_OFFSET = 20 // swiftlint:disable:this identifier_name
    public struct ClassicAccountAndTag {
        public let classicAccount: String
        public let tag: Int? // JM: Int | Bool only false?
    }
    
    public init() {}

    /**
     Autofills fields in a transaction. This will set `Sequence`, `Fee`,
     `lastLedgerSequence` according to the current state of the server this Client
     is connected to. It also converts all X-Addresses to classic addresses and
     flags interfaces into numbers.
     - parameters:
        - client: A client.
        - transaction: A {@link Transaction} in JSON format
        - signersCount: The expected number of signers for this transaction. Only used for multisigned transactions.
     - returns
     The autofilled transaction.
     */
    public func autofill(
        _ client: XrplClient,
        _ transaction: [String: AnyObject],
        _ signersCount: Int?
    ) async throws -> EventLoopFuture<[String: AnyObject]> {
        var tx = transaction

        try setValidAddresses(&tx)

        try setTransactionFlagsToNumber(tx: &tx)

        var promises: [Void] = []
        if tx["Sequence"] == nil {
            await promises.append(self.setNextValidSequenceNumber(client, &tx))
        }
        if tx["Fee"] == nil {
            await promises.append(try self.calculateFeePerTransactionType(client, &tx, signersCount))
        }
        if tx["LastLedgerSequence"] == nil {
            await promises.append(try self.setLatestValidatedLedgerSequence(client, &tx))
        }
        if tx["TransactionType"] as! String == "AccountDelete" {
            await promises.append(try self.checkAccountDeleteBlockers(client, &tx))
        }
        let promise = autofillEventGroup.next().makePromise(of: [String: AnyObject].self)
        _ = promises.compactMap({ $0 })
        promise.succeed(tx)
        return promise.futureResult
    }
    
    public func autofill(
        _ client: XrplClient,
        _ transaction: Transaction,
        _ signersCount: Int?
    ) async throws -> EventLoopFuture<[String: AnyObject]> {
        let encodedTx = try! transaction.toJson()
        return try await self.autofill(client, encodedTx, signersCount)
    }

    func setValidAddresses(_ tx: inout [String: AnyObject]) throws {
        try validateAccountAddress(&tx, "Account", "SourceTag")
        // eslint-disable-next-line @typescript-eslint/dot-notation -- Destination can exist on Transaction
        if tx["Destination"] != nil {
            try validateAccountAddress(&tx, "Destination", "DestinationTag")
        }

        // DepositPreauth:
        try convertToClassicAddress(&tx, "Authorize")
        try convertToClassicAddress(&tx, "Unauthorize")
        // EscrowCancel, EscrowFinish:
        try convertToClassicAddress(&tx, "Owner")
        // SetRegularKey:
        try convertToClassicAddress(&tx, "RegularKey")
    }

    func validateAccountAddress(
        _ tx: inout [String: AnyObject],
        _ accountField: String,
        _ tagField: String
    ) throws {
        // if X-address is given, convert it to classic address
        let accountAndTag = try getClassicAccountAndTag(tx[accountField] as! String)
        tx[accountField] = accountAndTag.classicAccount as AnyObject

        if accountAndTag.tag != nil {
            if tx[tagField] != nil && tx[tagField] as! Int != accountAndTag.tag {
                throw ValidationError("The \(tagField), if present, must match the tag of the \(accountField) X-address")
            }
            tx[tagField] = accountAndTag.tag as AnyObject?
        }
    }

    func getClassicAccountAndTag(
        _ account: String,
        _ expectedTag: Int? = nil
    ) throws -> ClassicAccountAndTag {
        if AddressCodec.isValidXAddress(account) {
            let classic = try AddressCodec.xAddressToClassicAddress(account)
            if expectedTag != nil && classic.tag! != expectedTag! {
                throw ValidationError("address includes a tag that does not match the tag specified in the transaction")
            }
            return ClassicAccountAndTag(
                classicAccount: classic.classicAddress,
                tag: classic.tag as? Int
            )
        }
        return ClassicAccountAndTag(
            classicAccount: account,
            tag: expectedTag
        )
    }

    func convertToClassicAddress(_ tx: inout [String: AnyObject], _ fieldName: String) throws {
        let account = tx[fieldName] as? String
        if account != nil {
            let classicAndTag = try getClassicAccountAndTag(account!)
            tx[fieldName] = classicAndTag.classicAccount as AnyObject
        }
    }

    func setNextValidSequenceNumber(
        _ client: XrplClient,
        _ tx: inout [String: AnyObject]
    ) async {
        let request = AccountInfoRequest(account: tx["Account"] as! String, ledgerIndex: .string("current"))
        let response = try! await client.request(r: request).get() as? BaseResponse<AccountInfoResponse>
        tx["Sequence"] = response!.result?.accountData.sequence as AnyObject
    }

    func fetchAccountDeleteFee(_ client: XrplClient) async -> Double {
        let request = ServerStateRequest()
        guard let response = try? await client.request(request).get() as? BaseResponse<ServerStateResponse> else {
            return 2 * 1000000
        }
        
        let fee = response.result?.state.validatedLedger?.reserveIncXrp
        if fee == nil {
            return 2 * 1000000
        }
        return Double(fee!)
    }

    func calculateFeePerTransactionType(
        _ client: XrplClient,
        _ tx: inout [String: AnyObject],
        _ signersCount: Int? = 0
    ) async throws {
        // netFee is usually 0.00001 XRP (10 drops)
        let netFeeXRP = try await getFeeXrp(client)
        let netFeeDrops = try xrpToDrops(netFeeXRP)
        var baseFee = Double(netFeeDrops)

        // EscrowFinish Transaction with Fulfillment
        if tx["TransactionType"] as! String == "EscrowFinish" && tx["Fulfillment"] != nil {
            let fulfillmentBytesSize = Int(ceil(Double((tx["Fulfillment"] as! String).count / 2)))
            // 10 drops × (33 + (Fulfillment size in bytes / 16))
            let product = Double(scaleValue(netFeeDrops, 33 + fulfillmentBytesSize / 16))
            baseFee = ceil(Double(product!))
        }

        // AccountDelete Transaction
        if tx["TransactionType"] as! String == "AccountDelete" {
            baseFee = await fetchAccountDeleteFee(client)
        }

        /*
         * Multi-signed Transaction
         * 10 drops × (1 + Number of Signatures Provided)
         */
        if signersCount! > 0 {
            baseFee = baseFee! + Double(scaleValue(netFeeDrops, 1 + signersCount!))!
        }

        let maxFeeDrops = try xrpToDrops(client.maxFeeXRP)
        let totalFee = tx["TransactionType"] as! String == "AccountDelete" ? baseFee : min(baseFee!, Double(maxFeeDrops)!)
        //        Round up baseFee and return it as a string
        tx["Fee"] = String(Int(ceil(totalFee!))) as AnyObject
    }

    func scaleValue(_ value: String, _ multiplier: Int) -> String {
        return String(Int(value)! * multiplier)
    }

    func setLatestValidatedLedgerSequence(
        _ client: XrplClient,
        _ tx: inout [String: AnyObject]
    ) async throws {
        let ledgerSequence = try await client.getLedgerIndex()
        tx["LastLedgerSequence"] = (ledgerSequence + LEDGER_OFFSET) as AnyObject
    }

    func checkAccountDeleteBlockers(
        _ client: XrplClient,
        _ tx: inout [String: AnyObject]
    ) async throws {
        let request = try AccountObjectsRequest([
            "command": "account_objects",
            "account": tx["Account"] as! String,
            "ledger_index": "validated",
            "deletion_blockers_only": true
        ] as [String: AnyObject])
        let response = try await client.request(request).wait() as? BaseResponse<AccountObjectsResponse>
        if let result = response?.result, result.accountObjects.count > 0 {
            throw XrplError(
                "Account \(tx["Account"]) cannot be deleted; there are Escrows, PayChannels, RippleStates, or Checks associated with the account."
            )
        }
    }
}
