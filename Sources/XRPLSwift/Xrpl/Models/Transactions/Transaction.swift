//
//  Transaction.swift
//
//
//  Created by Denis Angell on 7/27/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/transactions/transaction.ts

import Foundation

protocol XrplTransaction {
    associatedtype Model
    func from(from json: [String: AnyObject]) async throws -> Model
}

/**

 */
public enum Transaction: Codable {
    case accountDelete(AccountDelete)
    case accountSet(AccountSet)
    case checkCancel(CheckCancel)
    case checkCash(CheckCash)
    case checkCreate(CheckCreate)
    case depositPreauth(DepositPreauth)
    case escrowCancel(EscrowCancel)
    case escrowCreate(EscrowCreate)
    case escrowFinish(EscrowFinish)
    case nfTokenAcceptOffer(NFTokenAcceptOffer)
    case nfTokenBurn(NFTokenBurn)
    case nfTokenCancelOffer(NFTokenCancelOffer)
    case nfTokenCreateOffer(NFTokenCreateOffer)
    case nfTokenMint(NFTokenMint)
    case offerCancel(OfferCancel)
    case offerCreate(OfferCreate)
    case payment(Payment)
    case paymentChannelClaim(PaymentChannelClaim)
    case paymentChannelCreate(PaymentChannelCreate)
    case paymentChannelFund(PaymentChannelFund)
    case setRegularKey(SetRegularKey)
    case signerListSet(SignerListSet)
    case ticketCreate(TicketCreate)
    case trustSet(TrustSet)
}

extension Transaction {
    enum CodingKeys: String, CodingKey {
        case tt = "TransactionType"
    }

    enum TransactionCodingError: Error {
        case decoding(String)
    }

    public func toData() throws -> Data {
        return try JSONEncoder().encode(self)
    }

    // swiftlint:disable:next cyclomatic_complexity
    public init?(_ json: [String: AnyObject]) throws {
        guard let transactionType: String = json["TransactionType"] as? String else {
            throw TransactionCodingError.decoding("Missing Transaction Type")
        }
        if transactionType == "AccountDelete", let value = try? AccountDelete(json: json) {
            self = .accountDelete(value)
            return
        }
        if transactionType == "AccountSet", let value = try? AccountSet(json: json) {
            self = .accountSet(value)
            return
        }
        if transactionType == "CheckCancel", let value = try? CheckCancel(json: json) {
            self = .checkCancel(value)
            return
        }
        if transactionType == "CheckCreate", let value = try? CheckCreate(json: json) {
            self = .checkCreate(value)
            return
        }
        if transactionType == "CheckCash", let value = try? CheckCash(json: json) {
            self = .checkCash(value)
            return
        }
        if transactionType == "DepositPreauth", let value = try? DepositPreauth(json: json) {
            self = .depositPreauth(value)
            return
        }
        if transactionType == "EscrowFinish", let value = try? EscrowFinish(json: json) {
            self = .escrowFinish(value)
            return
        }
        if transactionType == "NFTokenAcceptOffer", let value = try? NFTokenAcceptOffer(json: json) {
            self = .nfTokenAcceptOffer(value)
            return
        }
        if transactionType == "NFTokenBurn", let value = try? NFTokenBurn(json: json) {
            self = .nfTokenBurn(value)
            return
        }
        if transactionType == "NFTokenCancelOffer", let value = try? NFTokenCancelOffer(json: json) {
            self = .nfTokenCancelOffer(value)
            return
        }
        if transactionType == "NFTokenCreateOffer", let value = try? NFTokenCreateOffer(json: json) {
            self = .nfTokenCreateOffer(value)
            return
        }
        if transactionType == "NFTokenMint", let value = try? NFTokenMint(json: json) {
            self = .nfTokenMint(value)
            return
        }
        if transactionType == "OfferCancel", let value = try? OfferCancel(json: json) {
            self = .offerCancel(value)
            return
        }
        if transactionType == "OfferCreate", let value = try? OfferCreate(json: json) {
            self = .offerCreate(value)
            return
        }
        if transactionType == "Payment", let value = try? Payment(json: json) {
            self = .payment(value)
            return
        }
        if transactionType == "PaymentChannelClaim", let value = try? PaymentChannelClaim(json: json) {
            self = .paymentChannelClaim(value)
            return
        }
        if transactionType == "PaymentChannelCreate", let value = try? PaymentChannelCreate(json: json) {
            self = .paymentChannelCreate(value)
            return
        }
        if transactionType == "PaymentChannelFund", let value = try? PaymentChannelFund(json: json) {
            self = .paymentChannelFund(value)
            return
        }
        if transactionType == "SetRegularKey", let value = try? SetRegularKey(json: json) {
            self = .setRegularKey(value)
            return
        }
        if transactionType == "SignerListSet", let value = try? SignerListSet(json: json) {
            self = .signerListSet(value)
            return
        }
        if transactionType == "TicketCreate", let value = try? TicketCreate(json: json) {
            self = .ticketCreate(value)
            return
        }
        if transactionType == "TrustSet", let value = try? TrustSet(json: json) {
            self = .trustSet(value)
            return
        }
        throw TransactionCodingError.decoding("Invalid Transaction Type")
    }

    public func toJson() throws -> [String: AnyObject] {
        let data = try JSONEncoder().encode(self)
        let jsonResult = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves)
        return jsonResult as! [String: AnyObject]
    }

    public func toAny() throws -> Any {
        switch self {
        case .accountDelete(let value):
            return value
        case .accountSet(let value):
            return value
        case .checkCancel(let value):
            return value
        case .checkCreate(let value):
            return value
        case .checkCash(let value):
            return value
        case .depositPreauth(let value):
            return value
        case .escrowFinish(let value):
            return value
        case .escrowCancel(let value):
            return value
        case .escrowCreate(let value):
            return value
        case .nfTokenAcceptOffer(let value):
            return value
        case .nfTokenBurn(let value):
            return value
        case .nfTokenCancelOffer(let value):
            return value
        case .nfTokenCreateOffer(let value):
            return value
        case .nfTokenMint(let value):
            return value
        case .offerCancel(let value):
            return value
        case .offerCreate(let value):
            return value
        case .payment(let value):
            return value
        case .paymentChannelClaim(let value):
            return value
        case .paymentChannelCreate(let value):
            return value
        case .paymentChannelFund(let value):
            return value
        case .setRegularKey(let value):
            return value
        case .signerListSet(let value):
            return value
        case .ticketCreate(let value):
            return value
        case .trustSet(let value):
            return value
        }
    }

    // swiftlint:disable:next cyclomatic_complexity
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let tt = try values.decode(String.self, forKey: .tt)
        if tt == "AccountDelete", let value = try? AccountDelete(from: decoder) {
            self = .accountDelete(value)
            return
        }
        if tt == "AccountSet", let value = try? AccountSet(from: decoder) {
            self = .accountSet(value)
            return
        }
        if tt == "CheckCancel", let value = try? CheckCancel(from: decoder) {
            self = .checkCancel(value)
            return
        }
        if tt == "CheckCreate", let value = try? CheckCreate(from: decoder) {
            self = .checkCreate(value)
            return
        }
        if tt == "CheckCash", let value = try? CheckCash(from: decoder) {
            self = .checkCash(value)
            return
        }
        if tt == "DepositPreauth", let value = try? DepositPreauth(from: decoder) {
            self = .depositPreauth(value)
            return
        }
        if tt == "EscrowFinish", let value = try? EscrowFinish(from: decoder) {
            self = .escrowFinish(value)
            return
        }
        if tt == "NFTokenAcceptOffer", let value = try? NFTokenAcceptOffer(from: decoder) {
            self = .nfTokenAcceptOffer(value)
            return
        }
        if tt == "NFTokenBurn", let value = try? NFTokenBurn(from: decoder) {
            self = .nfTokenBurn(value)
            return
        }
        if tt == "NFTokenCancelOffer", let value = try? NFTokenCancelOffer(from: decoder) {
            self = .nfTokenCancelOffer(value)
            return
        }
        if tt == "NFTokenCreateOffer", let value = try? NFTokenCreateOffer(from: decoder) {
            self = .nfTokenCreateOffer(value)
            return
        }
        if tt == "NFTokenMint", let value = try? NFTokenMint(from: decoder) {
            self = .nfTokenMint(value)
            return
        }
        if tt == "OfferCancel", let value = try? OfferCancel(from: decoder) {
            self = .offerCancel(value)
            return
        }
        if tt == "OfferCreate", let value = try? OfferCreate(from: decoder) {
            self = .offerCreate(value)
            return
        }
        if tt == "Payment", let value = try? Payment(from: decoder) {
            self = .payment(value)
            return
        }
        if tt == "PaymentChannelClaim", let value = try? PaymentChannelClaim(from: decoder) {
            self = .paymentChannelClaim(value)
            return
        }
        if tt == "PaymentChannelCreate", let value = try? PaymentChannelCreate(from: decoder) {
            self = .paymentChannelCreate(value)
            return
        }
        if tt == "PaymentChannelFund", let value = try? PaymentChannelFund(from: decoder) {
            self = .paymentChannelFund(value)
            return
        }
        if tt == "SetRegularKey", let value = try? SetRegularKey(from: decoder) {
            self = .setRegularKey(value)
            return
        }
        if tt == "SignerListSet", let value = try? SignerListSet(from: decoder) {
            self = .signerListSet(value)
            return
        }
        if tt == "TicketCreate", let value = try? TicketCreate(from: decoder) {
            self = .ticketCreate(value)
            return
        }
        if tt == "TrustSet", let value = try? TrustSet(from: decoder) {
            self = .trustSet(value)
            return
        }
        throw TransactionCodingError.decoding("DENIS!!!")
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .accountDelete(let value):
            try value.encode(to: encoder)
        case .accountSet(let value):
            try value.encode(to: encoder)
        case .checkCancel(let value):
            try value.encode(to: encoder)
        case .checkCreate(let value):
            try value.encode(to: encoder)
        case .checkCash(let value):
            try value.encode(to: encoder)
        case .depositPreauth(let value):
            try value.encode(to: encoder)
        case .escrowFinish(let value):
            try value.encode(to: encoder)
        case .escrowCancel(let value):
            try value.encode(to: encoder)
        case .escrowCreate(let value):
            try value.encode(to: encoder)
        case .nfTokenAcceptOffer(let value):
            try value.encode(to: encoder)
        case .nfTokenBurn(let value):
            try value.encode(to: encoder)
        case .nfTokenCancelOffer(let value):
            try value.encode(to: encoder)
        case .nfTokenCreateOffer(let value):
            try value.encode(to: encoder)
        case .nfTokenMint(let value):
            try value.encode(to: encoder)
        case .offerCancel(let value):
            try value.encode(to: encoder)
        case .offerCreate(let value):
            try value.encode(to: encoder)
        case .payment(let value):
            try value.encode(to: encoder)
        case .paymentChannelClaim(let value):
            try value.encode(to: encoder)
        case .paymentChannelCreate(let value):
            try value.encode(to: encoder)
        case .paymentChannelFund(let value):
            try value.encode(to: encoder)
        case .setRegularKey(let value):
            try value.encode(to: encoder)
        case .signerListSet(let value):
            try value.encode(to: encoder)
        case .ticketCreate(let value):
            try value.encode(to: encoder)
        case .trustSet(let value):
            try value.encode(to: encoder)
        }
    }

    static func all() -> [String] {
        return [
            "AccountDelete",
            "AccountSet",
            "CheckCancel",
            "CheckCash",
            "CheckCreate",
            "DepositPreauth",
            "EscrowCancel",
            "EscrowCreate",
            "EscrowFinish",
            "NFTokenAcceptOffer",
            "NFTokenBurn",
            "NFTokenCancelOffer",
            "NFTokenCreateOffer",
            "NFTokenMint",
            "OfferCancel",
            "OfferCreate",
            "Payment",
            "PaymentChannelClaim",
            "PaymentChannelCreate",
            "PaymentChannelFund",
            "SetRegularKey",
            "SignerListSet",
            "TicketCreate",
            "TrustSet"
        ]
    }
}

/**
 * @category Transaction Models
 */
public class TransactionAndMetadata: Codable {
    public var transaction: Transaction
    public var metadata: TransactionMetadata

    //    enum CodingKeys: String, CodingKey {
    //        case transaction = "transaction"
    //        case metadata = "metadata"
    //    }
    //
    //    required public init(from decoder: Decoder) throws {
    //        let values = try decoder.container(keyedBy: CodingKeys.self)
    //        transaction = try values.decode(Transaction.self, forKey: .transaction)
    //        metadata = try values.decode(TransactionMetadata.self, forKey: .metadata)
    //    }
}

/**
 Verifies various Transaction Types.
 Encode/decode and individual type validation.
 - parameters:
 - transaction: A Transaction.
 - throws:
 ValidationError When the Transaction is malformed.
 */
public func validate(transaction: [String: AnyObject]) throws {
    var tx: [String: AnyObject] = transaction
    guard let tt = transaction["TransactionType"] as? String else {
        throw ValidationError("Object's `TransactionType` is not a string")
    }
    try setTransactionFlagsToNumber(tx: &tx)
    switch tt {
    case "AccountDelete":
        try validateAccountDelete(tx: tx)
    case "AccountSet":
        try validateAccountSet(tx: tx)
    case "CheckCancel":
        try validateCheckCancel(tx: tx)
    case "CheckCash":
        try validateCheckCash(tx: tx)
    case "CheckCreate":
        try validateCheckCreate(tx: tx)
    case "DepositPreauth":
        try validateDepositPreauth(tx: tx)
    case "EscrowCancel":
        try validateEscrowCancel(tx: tx)
    case "EscrowCreate":
        try validateEscrowCreate(tx: tx)
    case "EscrowFinish":
        try validateEscrowFinish(tx: tx)
    case "NFTokenAcceptOffer":
        try validateNFTokenAcceptOffer(tx: tx)
    case "NFTokenBurn":
        try validateNFTokenBurn(tx: tx)
    case "NFTokenCancelOffer":
        try validateNFTokenCancelOffer(tx: tx)
    case "NFTokenCreateOffer":
        try validateNFTokenCreateOffer(tx: tx)
    case "NFTokenMint":
        try validateNFTokenMint(tx: tx)
    case "OfferCancel":
        try validateOfferCancel(tx: tx)
    case "OfferCreate":
        try validateOfferCreate(tx: tx)
    case "Payment":
        try validatePayment(tx: tx)
    case "PaymentChannelClaim":
        try validatePaymentChannelClaim(tx: tx)
    case "PaymentChannelCreate":
        try validatePaymentChannelCreate(tx: tx)
    case "PaymentChannelFund":
        try validatePaymentChannelFund(tx: tx)
    case "SetRegularKey":
        try validateSetRegularKey(tx: tx)
    case "SignerListSet":
        try validateSignerListSet(tx: tx)
    case "TicketCreate":
        try validateTicketCreate(tx: tx)
    case "TrustSet":
        try validateTrustSet(tx: tx)
    default:
        throw ValidationError("Invalid field TransactionType: \(tt)")
    }
    //    if (
    //        !_.isEqual(
    //            decode(encode(tx)),
    //            _.omitBy(tx, (value) => value == null),
    //        )
    //    ) {
    //        throw new ValidationError(`Invalid Transaction: ${tx.TransactionType}`)
    //    }
}

extension Payment {
    public var asTx: Transaction {
        return Transaction.payment(self)
    }
}
