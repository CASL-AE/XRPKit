//
//  CommonModels.swift
//
//
//  Created by Denis Angell on 7/26/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/common/index.ts

import Foundation

public enum AccountObjectType: String, Codable {
    case check = "check"
    case depositPreauth = "deposit_preauth"
    case escrow = "escrow"
    case offer = "offer"
    case paymentChannel = "paymentChannel"
    case signerList = "signerList"
    case ticket = "ticket"
    case state = "state"
    case nftOffer = "nft_offer"
}

public enum LedgerIndex: Codable {
    case string(String) // ('validated' | 'closed' | 'current')
    case number(Int)
}

extension LedgerIndex {
    enum LedgerIndexCodingError: Error {
        case decoding(String)
    }

    public init(from decoder: Decoder) throws {
        if let value = try? String(from: decoder) {
            self = .string(value)
            return
        }
        if let value = try? Int(from: decoder) {
            self = .number(value)
            return
        }
        throw LedgerIndexCodingError.decoding("LedgerIndex not mapped")
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .string(let string):
            try string.encode(to: encoder)
        case .number(let number):
            try number.encode(to: encoder)
        }
    }
}

struct XRP: Codable {
    var currency: String = "XRP"
}

protocol IssuedCurrency: Codable {
    var currency: String { get set }
    var issuer: String { get set }
}

enum Currency {
    case xrp (XRP)
    case issuedCurrency (IssuedCurrency)
}

public struct IssuedCurrencyAmount: IssuedCurrency, Codable {
    public var currency: String
    public var issuer: String
    public var value: String

    enum CodingKeys: String, CodingKey {
        case currency
        case issuer
        case value
    }

    public init(value: String, issuer: String, currency: String) {
        self.value = value
        self.issuer = issuer
        self.currency = currency
    }

    public init(_ json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(IssuedCurrencyAmount.self, from: data)
        self.currency = decoded.currency
        self.issuer = decoded.issuer
        self.value = decoded.value
    }
}

enum AmountType {
    case string
    case ic
}

public enum Amount: Codable {
    case string(String)
    case ic(IssuedCurrencyAmount)
}
extension Amount {
    enum AmountCodingError: Error {
        case decoding(String)
    }
    public var value: Any {
        switch self {
        case .string(let string):
            return string
        case .ic(let ic):
            return ic
        }
    }
    public init(from decoder: Decoder) throws {
        if let value = try? String(from: decoder) {
            self = .string(value)
            return
        }
        if let value = try? IssuedCurrencyAmount(from: decoder) {
            self = .ic(value)
            return
        }
        throw AmountCodingError.decoding("Invalid Amount: Amount should be string or dict")
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .string(let string):
            try string.encode(to: encoder)
        case .ic(let ic):
            try ic.encode(to: encoder)
        }
    }

    public init(value: String, issuer: String, currency: String) {
        self = .ic(IssuedCurrencyAmount(
            value: value,
            issuer: issuer,
            currency: currency
        ))
    }

    public init(_ value: IssuedCurrencyAmount) throws {
        self = .ic(value)
    }

    public init(_ value: String) throws {
        self = .string(value)
    }
}

public class BaseSigner: Codable {
    public var account: String
    public var txnSignature: String
    public var signingPubKey: String

    enum CodingKeys: String, CodingKey {
        case account = "Account"
        case txnSignature = "TxnSignature"
        case signingPubKey = "SigningPubKey"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account = try values.decode(String.self, forKey: .account)
        txnSignature = try values.decode(String.self, forKey: .txnSignature)
        signingPubKey = try values.decode(String.self, forKey: .signingPubKey)
    }
}

public class Signer: Codable {
    enum CodingKeys: String, CodingKey {
        case signer = "Signer"
    }

    public var signer: BaseSigner

    public init(json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(Signer.self, from: data)
        self.signer = decoded.signer
    }
}

public class Memo: Codable {
    public var memoData: String?
    public var memoType: String?
    public var memoFormat: String?

    enum CodingKeys: String, CodingKey {
        case memoData = "MemoData"
        case memoType = "MemoType"
        case memoFormat = "MemoFormat"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        memoData = try values.decodeIfPresent(String.self, forKey: .memoData)
        memoType = try values.decodeIfPresent(String.self, forKey: .memoType)
        memoFormat = try values.decodeIfPresent(String.self, forKey: .memoFormat)
    }
    
    public init(_ memoData: String?, _ memoType: String?, _ memoFormat: String?) {
        self.memoData = memoData
        self.memoType = memoType
        self.memoFormat = memoFormat
    }
}

public class MemoWrapper: Codable {
    public var memo: Memo
    enum CodingKeys: String, CodingKey {
        case memo = "Memo"
    }
    
    public init(_ memo: Memo) {
        self.memo = memo
    }
}

// export type StreamType =
//  | 'consensus'
//  | 'ledger'
//  | 'manifests'
//  | 'peer_status'
//  | 'transactions'
//  | 'transactions_proposed'
//  | 'server'
//  | 'validations'
//
public struct PathStep: Codable {
    public var account: String?
    public var currency: String?
    public var issuer: String
}

public typealias Path = [PathStep]

// export interface SignerEntry {
//  SignerEntry: {
//    Account: string
//    SignerWeight: number
//  }
// }
//
/// **
// * This information is added to Transactions in request responses, but is not part
// * of the canonical Transaction information on ledger. These fields are denoted with
// * lowercase letters to indicate this in the rippled responses.
// */
// export interface ResponseOnlyTxInfo {
//  /**
//   * The date/time when this transaction was included in a validated ledger.
//   */
//  date?: number
//  /**
//   * An identifying hash value unique to this transaction, as a hex string.
//   */
//  hash?: string
//  /**
//   * The sequence number of the ledger that included this transaction.
//   */
//  ledger_index?: number
// }
//
/**
 One offer that might be returned from either an {@link NFTBuyOffersRequest}
 or an {@link NFTSellOffersRequest}.
 */
public struct NFTOffer: Codable {
    public var amount: Amount
    public var flags: Int
    public var nftOfferIndex: String
    public var owner: String
    public var destination: String?
    public var expiration: Int?

    enum CodingKeys: String, CodingKey {
        case amount = "amount"
        case flags = "flags"
        case nftOfferIndex = "nft_offer_index"
        case owner = "owner"
        case destination = "destination"
        case expiration = "expiration"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        amount = try values.decode(Amount.self, forKey: .amount)
        flags = try values.decode(Int.self, forKey: .flags)
        nftOfferIndex = try values.decode(String.self, forKey: .nftOfferIndex)
        owner = try values.decode(String.self, forKey: .owner)
        destination = try values.decodeIfPresent(String.self, forKey: .destination)
        expiration = try values.decodeIfPresent(Int.self, forKey: .expiration)
    }
}

import AnyCodable

public struct XRPLWebSocketResponse: Codable {
    public var id: String
    public var status: String
    public var type: String
    private let rresult: AnyCodable
    public var result: [String: AnyObject] {
        return rresult.value as! [String: AnyObject]
    }

    enum CodingKeys: String, CodingKey {
        case id
        case status
        case type
        case rresult = "result"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        status = try values.decode(String.self, forKey: .status)
        type = try values.decode(String.self, forKey: .type)
        rresult = try values.decode(AnyCodable.self, forKey: .rresult)
    }
}

public struct JsonRpcResponse<T> {
    public var result: T
}
