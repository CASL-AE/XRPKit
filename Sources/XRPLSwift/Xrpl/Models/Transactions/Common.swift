//
//  Common.swift
//
//
//  Created by Denis Angell on 8/1/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/transactions/common.ts

import Foundation

public typealias GlobalFlags = Any

// swiftlint:disable:next identifier_name
let MEMO_SIZE: Int = 3

func isMemo(obj: [ String: AnyObject? ]) -> Bool {
    if obj["Memo"] == nil {
        return false
    }
    // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- Only used by JS
    guard let memo = obj["Memo"] as? [String: AnyObject] else {
        return false
    }
    let size = memo.count
    // MARK: Need review here.
    let validData = memo["MemoData"] == nil || memo["MemoData"] is String
    let validFormat = memo["MemoFormat"] == nil || memo["MemoFormat"] is String
    let validType = memo["MemoType"] == nil || memo["MemoType"] is String

    return (
        size >= 1 &&
            size <= MEMO_SIZE &&
            validData &&
            validFormat &&
            validType &&
            onlyHasFields(obj: memo, fields: ["MemoFormat", "MemoData", "MemoType"])
    )
}

// swiftlint:disable:next identifier_name
let SIGNER_SIZE: Int = 3

func isSigner(obj: [ String: AnyObject? ]) -> Bool {
    // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- Only used by JS
    if obj["Signer"] == nil {
        return false
    }
    // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- Only used by JS and Signer is previously unknown
    guard let signer = obj["Signer"] as? [String: AnyObject] else {
        return false
    }
    return (
        signer.count == SIGNER_SIZE &&
            signer["Account"] is String &&
            signer["TxnSignature"] is String &&
            signer["SigningPubKey"] is String
    )
}

// swiftlint:disable:next identifier_name
let ISSUED_CURRENCY_SIZE: Int = 3

func isRecord(value: Any) -> Bool {
    guard value is [String: AnyObject] else {
        return false
    }
    return true
}

/**
 Verify the form and type of an IssuedCurrencyAmount at runtime.
 - parameters:
    - input: The input to check the form and type of.
 - returns:
 Whether the IssuedCurrencyAmount is malformed.
 */
public func isIssuedCurrency(input: Any) -> Bool {
    guard let input = input as? [String: AnyObject] else {
        return false
    }
    guard input.count == ISSUED_CURRENCY_SIZE else {
        return false
    }
    guard input["value"] is String else {
        return false
    }
    guard input["issuer"] is String else {
        return false
    }
    guard input["currency"] is String else {
        return false
    }
    return true
}

/**
 Verify the form and type of an Amount at runtime.
 - parameters:
    - amount: The object to check the form and type of.
 - returns:
 Whether the Amount is malformed.
 */
public func isAmount(amount: Any) -> Bool {
    if amount is String {
        return true
    }
    return isIssuedCurrency(input: amount)
}

/**
 Every transaction has the same set of common fields.
 */
public class BaseTransaction: Codable {
   /// The unique address of the account that initiated the transaction.
   public var account: String
   /**
    The type of transaction. Valid types include: `Payment`, `OfferCreate`,
    `SignerListSet`, `EscrowCreate`, `EscrowFinish`, `EscrowCancel`,
    `PaymentChannelCreate`, `PaymentChannelFund`, `PaymentChannelClaim`, and
    `DepositPreauth`.
    */
   public var transactionType: String
   /**
    Integer amount of XRP, in drops, to be destroyed as a cost for
    distributing this transaction to the network. Some transaction types have
    different minimum requirements.
    */
   public var fee: String?
   /**
    The sequence number of the account sending the transaction. A transaction
    is only valid if the Sequence number is exactly 1 greater than the previous
    transaction from the same account. The special case 0 means the transaction
    is using a Ticket instead.
    */
   public var sequence: Int?
   /**
    Hash value identifying another transaction. If provided, this transaction
    is only valid if the sending account's previously-sent transaction matches
    the provided hash.
    */
   public var accountTxnId: String?
   /// Set of bit-flags for this transaction.
   //    public var Flags: Int? | GlobalFlags
   public var flags: Int?
   /**
    Highest ledger index this transaction can appear in. Specifying this field
    places a strict upper limit on how long the transaction can wait to be
    validated or rejected.
    */
   public var lastLedgerSequence: Int?
   /**
    Additional arbitrary information used to identify this transaction.
    */
   public var memos: [MemoWrapper]?
   /**
    Array of objects that represent a multi-signature which authorizes this
    transaction.
    */
   public var signers: [Signer]?
   /**
    Arbitrary integer used to identify the reason for this payment, or a sender
    on whose behalf this transaction is made. Conventionally, a refund should
    specify the initial payment's SourceTag as the refund payment's
    DestinationTag.
    */
   public var sourceTag: Int?
   /**
    Hex representation of the public key that corresponds to the private key
    used to sign this transaction. If an empty string, indicates a
    multi-signature is present in the Signers field instead.
    */
   public var signingPubKey: String?
   /**
    The sequence number of the ticket to use in place of a Sequence number. If
    this is provided, Sequence must be 0. Cannot be used with AccountTxnID.
    */
   public var ticketSequence: Int?
   /**
    The signature that verifies this transaction as originating from the
    account it says it is from.
    */
   public var txnSignature: String?
   
   /// The hash of the transaction
   public var hash: String?

   enum CodingKeys: String, CodingKey {
       case account = "Account"
       case transactionType = "TransactionType"
       case fee = "Fee"
       case sequence = "Sequence"
       case accountTxnId = "AccountTxnID"
       case flags = "Flags"
       case lastLedgerSequence = "LastLedgerSequence"
       case memos = "Memos"
       case signers = "Signers"
       case sourceTag = "SourceTag"
       case signingPubKey = "SigningPubKey"
       case ticketSequence = "TicketSequence"
       case txnSignature = "TxnSignature"
       case hash = "hash"
   }

   public init(
       // Required
       account: String,
       transactionType: String,
       // Optional
       fee: String? = nil,
       sequence: Int? = nil,
       accountTxnId: String? = nil,
       flags: Int? = nil,
       lastLedgerSequence: Int? = nil,
       memos: [MemoWrapper]? = nil,
       signers: [Signer]? = nil,
       sourceTag: Int? = nil,
       signingPubKey: String? = nil,
       ticketSequence: Int? = nil,
       txnSignature: String? = nil,
       hash: String? = nil
   ) {
       // Required
       self.account = account
       self.transactionType = transactionType
       // Optional
       self.fee = fee
       self.sequence = sequence
       self.accountTxnId = accountTxnId
       self.flags = flags
       self.lastLedgerSequence = lastLedgerSequence
       self.memos = memos
       self.signers = signers
       self.sourceTag = sourceTag
       self.signingPubKey = signingPubKey
       self.ticketSequence = ticketSequence
       self.txnSignature = txnSignature
       self.hash = hash
   }

   public init(json: [String: AnyObject]) throws {
       let decoder = JSONDecoder()
       let data: Data = try! JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
       let decoded = try decoder.decode(BaseTransaction.self, from: data)
       // Required
       self.account = decoded.account
       self.transactionType = decoded.transactionType
       // Optional
       self.fee = decoded.fee
       self.sequence = decoded.sequence
       self.accountTxnId = decoded.accountTxnId
       self.flags = decoded.flags
       self.lastLedgerSequence = decoded.lastLedgerSequence
       self.memos = decoded.memos
       self.signers = decoded.signers
       self.sourceTag = decoded.sourceTag
       self.signingPubKey = decoded.signingPubKey
       self.ticketSequence = decoded.ticketSequence
       self.txnSignature = decoded.txnSignature
       self.hash = decoded.hash
   }

   public required init(from decoder: Decoder) throws {
       let values = try decoder.container(keyedBy: CodingKeys.self)
       account = try values.decode(String.self, forKey: .account)
       transactionType = try values.decode(String.self, forKey: .transactionType)
       fee = try? values.decodeIfPresent(String.self, forKey: .fee)
       sequence = try? values.decodeIfPresent(Int.self, forKey: .sequence)
       accountTxnId = try? values.decodeIfPresent(String.self, forKey: .accountTxnId)
       flags = try? values.decodeIfPresent(Int.self, forKey: .flags)
       lastLedgerSequence = try? values.decodeIfPresent(Int.self, forKey: .lastLedgerSequence)
       memos = try? values.decodeIfPresent([MemoWrapper].self, forKey: .memos)
       signers = try? values.decodeIfPresent([Signer].self, forKey: .signers)
       sourceTag = try? values.decodeIfPresent(Int.self, forKey: .sourceTag)
       signingPubKey = try? values.decodeIfPresent(String.self, forKey: .signingPubKey)
       ticketSequence = try? values.decodeIfPresent(Int.self, forKey: .ticketSequence)
       txnSignature = try? values.decodeIfPresent(String.self, forKey: .txnSignature)
       hash = try? values.decodeIfPresent(String.self, forKey: .hash)
   }

   public func encode(to encoder: Encoder) throws {
       var values = encoder.container(keyedBy: CodingKeys.self)
       try values.encode(account, forKey: .account)
       try values.encode(transactionType, forKey: .transactionType)
       if let fee = fee { try values.encode(fee, forKey: .fee) }
       if let sequence = sequence { try values.encode(sequence, forKey: .sequence) }
       if let accountTxnId = accountTxnId { try values.encode(accountTxnId, forKey: .accountTxnId) }
       if let flags = flags { try values.encode(flags, forKey: .flags) }
       if let lastLedgerSequence = lastLedgerSequence { try values.encode(lastLedgerSequence, forKey: .lastLedgerSequence) }
       if let memos = memos { try values.encode(memos, forKey: .memos) }
       if let signers = signers { try values.encode(signers, forKey: .signers) }
       if let sourceTag = sourceTag { try values.encode(sourceTag, forKey: .sourceTag) }
       if let signingPubKey = signingPubKey { try values.encode(signingPubKey, forKey: .signingPubKey) }
       if let ticketSequence = ticketSequence { try values.encode(ticketSequence, forKey: .ticketSequence) }
       if let txnSignature = txnSignature { try values.encode(txnSignature, forKey: .txnSignature) }
       if let hash = hash { try values.encode(hash, forKey: .hash) }
   }
}

extension BaseTransaction {
   func toJson() throws -> [String: AnyObject] {
       let data = try JSONEncoder().encode(self)
       let jsonResult = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves)
       return jsonResult as! [String: AnyObject]
   }
}

/**
 Verify the common fields of a transaction. The validate functionality will be
 optional, and will check transaction form at runtime. This should be called
 any time a transaction will be verified.
 - parameters:
 - common: An interface w/ common transaction fields.
 - throws:
 When the common param is malformed.
 */
public func validateBaseTransaction(common: [String: AnyObject]) throws {
    if common["Account"] == nil {
        throw ValidationError("BaseTransaction: missing field Account")
    }

    if !(common["Account"] is String) {
        throw ValidationError("BaseTransaction: Account not string")
    }

    if common["TransactionType"] == nil {
        throw ValidationError("BaseTransaction: missing field TransactionType")
    }

    if !(common["TransactionType"] is String) {
        throw ValidationError("BaseTransaction: TransactionType not string")
    }

    if !Transaction.all().contains(common["TransactionType"] as! String) {
        throw ValidationError("BaseTransaction: Unknown TransactionType")
    }

    if common["Fee"] != nil && !(common["Fee"] is String) {
        throw ValidationError("BaseTransaction: invalid Fee")
    }

    if common["Sequence"] != nil && !(common["Sequence"] is Int) {
        throw ValidationError("BaseTransaction: invalid Sequence")
    }

    if common["AccountTxnID"] != nil && !(common["AccountTxnID"] is String) {
        throw ValidationError("BaseTransaction: invalid AccountTxnID")
    }

    if common["LastLedgerSequence"] != nil && !(common["LastLedgerSequence"] is Int) {
        throw ValidationError("BaseTransaction: invalid LastLedgerSequence")
    }

    let memos = common["Memos"] as? [[String: AnyObject]]
    if memos != nil && !(memos?.allSatisfy({ result in
        isMemo(obj: result)
    }))! {
        throw ValidationError("BaseTransaction: invalid Memos")
    }

    let signers = common["Signers"] as? [[String: AnyObject]]

    if signers != nil && (signers!.isEmpty || !(signers?.allSatisfy({ result in
        isSigner(obj: result)
    }))!) {
        throw ValidationError("BaseTransaction: invalid Signers")
    }

    if common["SourceTag"] != nil && !(common["SourceTag"] is Int) {
        throw ValidationError("BaseTransaction: invalid SourceTag")
    }

    if common["SigningPubKey"] != nil && !(common["SigningPubKey"] is String) {
        throw ValidationError("BaseTransaction: invalid SigningPubKey")
    }

    if common["TicketSequence"] != nil && !(common["TicketSequence"] is Int) {
        throw ValidationError("BaseTransaction: invalid TicketSequence")
    }

    if common["TxnSignature"] != nil && !(common["TxnSignature"] is String) {
        throw ValidationError("BaseTransaction: invalid TxnSignature")
    }
}

/**
 Parse the value of an amount, expressed either in XRP or as an Issued Currency, into a number.
 - parameters:
    - amount: An Amount to parse for its value.
 - returns:
 The parsed amount value, or NaN if the amount count not be parsed.
 */
public func parseAmountValue(amount: Any) -> Double? {
    if !isAmount(amount: amount) {
        return nil
    }
    if let amount = amount as? String {
        return Double(amount)
    }
    return amount as? Double
}
