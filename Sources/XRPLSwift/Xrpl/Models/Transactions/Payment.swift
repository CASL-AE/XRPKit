//
//  Payment.swift
//  AnyCodable
//
//  Created by Mitch Lang on 2/4/20.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/transactions/payment.ts

import Foundation

public enum PaymentFlags: Int {
    /*
     Transactions of the Payment type support additional values in the Flags field.
     This enum represents those options.
     `See Payment Flags <https://xrpl.org/payment.html#payment-flags>`_
     */

    case tfNoDirectRipple = 0x00010000
    /*
     Do not use the default path; only use paths included in the Paths field.
     This is intended to force the transaction to take arbitrage opportunities.
     Most clients do not need this.
     */

    case tfPartialPayment = 0x00020000
    /*
     If the specified Amount cannot be sent without spending more than SendMax,
     reduce the received amount instead of failing outright.
     See `Partial Payments <https://xrpl.org/partial-payments.html>`_ for more details.
     */

    case tfLimitQuality = 0x00040000
    /*
     Only take paths where all the conversions have an input:output ratio
     that is equal or better than the ratio of Amount:SendMax.
     See `Limit <https://xrpl.org/payment.html#limit-quality>`_ Quality for details.
     */
}

extension Array where Element == PaymentFlags {
    var interface: [PaymentFlags: Bool] {
        var flags: [PaymentFlags: Bool] = [:]
        for flag in self {
            if flag == .tfNoDirectRipple {
                flags[flag] = true
            }
            if flag == .tfPartialPayment {
                flags[flag] = true
            }
            if flag == .tfLimitQuality {
                flags[flag] = true
            }
        }
        return flags
    }
}

public class Payment: BaseTransaction, XrplTransaction {
    func from(from json: [String: AnyObject]) async throws -> Payment {
        return try Payment(json: [:])
    }

    typealias Model = Payment

    /*
     Represents a Payment <https://xrpl.org/payment.html>`_ transaction, which
     sends value from one account to another. (Depending on the path taken, this
     can involve additional exchanges of value, which occur atomically.) This
     transaction type can be used for several `types of payments
     <http://xrpl.local/payment.html#types-of-payments>`_.
     Payments are also the only way to `create accounts
     <http://xrpl.local/payment.html#creating-accounts>`_.
     */

    public var amount: Amount?
    /*
     The amount of currency to deliver. If the Partial Payment flag is set,
     deliver *up to* this amount instead. This field is required.
     :meta hide-value:
     */

    public var destination: String
    /*
     The address of the account receiving the payment. This field is required.
     :meta hide-value:
     */

    public var destinationTag: Int?
    /*
     An arbitrary `destination tag
     <https://xrpl.org/source-and-destination-tags.html>`_ that
     identifies the reason for the Payment, or a hosted recipient to pay.
     */

    public var invoiceId: String?
    /*
     Arbitrary 256-bit hash representing a specific reason or identifier for
     this Check.
     */

    public var paths: [Path]?
    /*
     Array of payment paths to be used (for a cross-currency payment). Must be
     omitted for XRP-to-XRP transactions.
     */

    public var sendMax: Amount?
    /*
     Maximum amount of source currency this transaction is allowed to cost,
     including `transfer fees <http://xrpl.local/transfer-fees.html>`_,
     exchange rates, and slippage. Does not include the XRP destroyed as a
     cost for submitting the transaction. Must be supplied for cross-currency
     or cross-issue payments. Must be omitted for XRP-to-XRP payments.
     */

    public var deliverMin: Amount?
    /*
     Minimum amount of destination currency this transaction should deliver.
     Only valid if this is a partial payment. If omitted, any positive amount
     is considered a success.
     */
    
    public var deliverMax: Amount?
    
    public var date: Int?
    public var hash: String?

    enum CodingKeys: String, CodingKey {
        case amount = "Amount"
        case destination = "Destination"
        case destinationTag = "DestinationTag"
        case invoiceId = "InvoiceID"
        case paths = "Paths"
        case sendMax = "SendMax"
        case deliverMin = "DeliverMin"
        case deliverMax = "DeliverMax"
        case date = "date"
        case hash = "hash"
    }

    public init(
        amount: Amount,
        destination: String,
        destinationTag: Int? = nil,
        invoiceId: String? = nil,
        paths: [Path]? = nil,
        sendMax: Amount? = nil,
        deliverMin: Amount? = nil,
        deliverMax: Amount? = nil
    ) {
        self.amount = amount
        self.destination = destination
        self.destinationTag = destinationTag
        self.invoiceId = invoiceId
        self.paths = paths
        self.sendMax = sendMax
        self.deliverMin = deliverMin
        self.deliverMax = deliverMax
        super.init(account: "", transactionType: "Payment")
    }

    override public init(json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(Payment.self, from: data)
        self.amount = decoded.amount
        self.destination = decoded.destination
        self.destinationTag = decoded.destinationTag
        self.invoiceId = decoded.invoiceId
        self.paths = decoded.paths
        self.sendMax = decoded.sendMax
        self.deliverMin = decoded.deliverMin
        self.deliverMax = decoded.deliverMax
        self.date = decoded.date
        self.hash = decoded.hash
        try super.init(json: json)
        try validateAmount()
    }
    
    func validateAmount() throws {
        if self.amount == nil && self.deliverMax == nil {
            throw Transaction.TransactionCodingError.decoding("Invalid Transaction Type")
        }
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        amount = try values.decodeIfPresent(Amount.self, forKey: .amount)
        destination = try values.decode(String.self, forKey: .destination)
        destinationTag = try values.decodeIfPresent(Int.self, forKey: .destinationTag)
        invoiceId = try values.decodeIfPresent(String.self, forKey: .invoiceId)
        paths = try values.decodeIfPresent([Path].self, forKey: .paths)
        sendMax = try values.decodeIfPresent(Amount.self, forKey: .sendMax)
        deliverMin = try values.decodeIfPresent(Amount.self, forKey: .deliverMin)
        deliverMax = try values.decodeIfPresent(Amount.self, forKey: .deliverMax)
        date = try values.decodeIfPresent(Int.self, forKey: .date)
        hash = try values.decodeIfPresent(String.self, forKey: .hash)
        try super.init(from: decoder)
        try validateAmount()
    }

    override public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try super.encode(to: encoder)
        try values.encode(amount, forKey: .amount)
        try values.encode(destination, forKey: .destination)
        if let destinationTag = destinationTag { try values.encode(destinationTag, forKey: .destinationTag) }
        if let invoiceId = invoiceId { try values.encode(invoiceId, forKey: .invoiceId) }
        if let paths = paths { try values.encode(paths, forKey: .paths) }
        if let sendMax = sendMax { try values.encode(sendMax, forKey: .sendMax) }
        if let deliverMin = deliverMin { try values.encode(deliverMin, forKey: .deliverMin) }
        if let deliverMax = deliverMax { try values.encode(deliverMax, forKey: .deliverMax) }
    }
}

/**
 Verify the form and type of an Payment at runtime.
 - parameters:
 - tx: An Payment Transaction.
 - throws:
 When the Payment is Malformed.
 */
public func validatePayment(tx: [String: AnyObject]) throws {
    try validateBaseTransaction(common: tx)

    if tx["Amount"] == nil {
        throw ValidationError("Payment: missing field Amount")
    }

    if !isAmount(amount: tx["Amount"] as Any) {
        throw ValidationError("Payment: invalid Amount")
    }

    if tx["Destination"] == nil {
        throw ValidationError("Payment: missing field Destination")
    }

    if !isAmount(amount: tx["Destination"] as Any) {
        throw ValidationError("Payment: invalid Destination")
    }

    if tx["DestinationTag"] != nil && !(tx["DestinationTag"] is Int) {
        throw ValidationError("Payment: DestinationTag must be a number")
    }

    if tx["InvoiceID"] != nil && !(tx["InvoiceID"] is String) {
        throw ValidationError("Payment: InvoiceID must be a string")
    }

    if tx["Paths"] != nil && !isPaths(paths: tx["Paths"] as! [[[String: AnyObject]]]) {
        throw ValidationError("Payment: invalid Paths")
    }

    if tx["SendMax"] != nil && !isAmount(amount: tx["SendMax"] as Any) {
        throw ValidationError("Payment: invalid SendMax")
    }
    try checkPartialPayment(tx: tx)
}

func checkPartialPayment(tx: [String: AnyObject]) throws {
    if tx["DeliverMin"] != nil {
        if tx["Flags"] == nil {
            throw ValidationError("Payment: tfPartialPayment flag required with DeliverMin")
        }
        if let flags = tx["Flags"] as? Int {
            let isTfPartialPayment = isFlagEnabled(flags: flags, checkFlag: PaymentFlags.tfPartialPayment.rawValue)
            if !isTfPartialPayment {
                throw ValidationError("Payment: tfPartialPayment flag required with DeliverMin")
            }

            if !isAmount(amount: tx["DeliverMin"] as Any) {
                throw ValidationError("Payment: invalid DeliverMin")
            }
        }
        // For Flags Interface
        //        if let flags = tx["Flags"] as? Int {
        //            let isTfPartialPayment = flags.rawValue == PaymentFlags.tfPartialPayment.rawValue
        //
        //            if !isTfPartialPayment {
        //                throw ValidationError("Payment: tfPartialPayment flag required with DeliverMin")
        //            }
        //
        //            if !isAmount(amount: tx["DeliverMin"] as Any) {
        //                throw ValidationError("Payment: invalid DeliverMin")
        //            }
        //        }
    }
}

func isPathStep(pathStep: [String: AnyObject]) -> Bool {
    if pathStep["account"] != nil && !(pathStep["account"] is String) {
        return false
    }
    if pathStep["currency"] != nil && !(pathStep["currency"] is String) {
        return false
    }
    if pathStep["issuer"] != nil && !(pathStep["issuer"] is String) {
        return false
    }
    if pathStep["account"] != nil && pathStep["currency"] == nil && pathStep["issuer"] == nil {
        return true
    }
    if pathStep["currency"] != nil || pathStep["issuer"] != nil {
        return true
    }
    return false
}

func isPath(path: [[String: AnyObject]]) -> Bool {
    for pathStep in path {
        if !isPathStep(pathStep: pathStep) {
            return false
        }
    }
    return true
}

func isPaths(paths: [[[String: AnyObject]]]) -> Bool {
    //    if !(paths is Array) || paths.count == 0 {
    if paths.isEmpty {
        return false
    }

    for path in paths {
        //        if !(path is Array || path.count == 0 {
        if path.isEmpty {
            return false
        }

        if !isPath(path: path) {
            return false
        }
    }

    return true
}
