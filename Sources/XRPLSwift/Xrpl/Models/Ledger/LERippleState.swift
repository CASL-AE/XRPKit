//
//  LERippleState.swift
//
//
//  Created by Denis Angell on 7/30/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/ledger/RippleState.ts

import Foundation

/**
 The RippleState object type connects two accounts in a single currency.
 */
public class LERippleState: BaseLedgerEntry {
    public var ledgerEntryType: String = "RippleState"
    /// A bit-map of boolean options enabled for this object.
    public var flags: Int
    /**
     The balance of the trust line, from the perspective of the low account. A
     negative balance indicates that the low account has issued currency to the
     high account. The issuer is always the neutral value ACCOUNT_ONE.
     */
    public var balance: IssuedCurrencyAmount
    /**
     The limit that the low account has set on the trust line. The issuer is
     the address of the low account that set this limit.
     */
    public var lowLimit: IssuedCurrencyAmount
    /**
     The limit that the high account has set on the trust line. The issuer is
     the address of the high account that set this limit.
     */
    public var highLimit: IssuedCurrencyAmount
    /**
     The identifying hash of the transaction that most recently modified this
     object.
     */
    public var previousTxnId: String
    /**
     The index of the ledger that contains the transaction that most recently
     modified this object.
     */
    public var previousTxnLgrSeq: Int
    /**
     A hint indicating which page of the low account's owner directory links to
     this object, in case the directory consists of multiple pages.
     */
    public var lowNode: String?
    /**
     A hint indicating which page of the high account's owner directory links
     to this object, in case the directory consists of multiple pages.
     */
    public var highNode: String?
    /**
     The inbound quality set by the low account, as an integer in the implied
     ratio LowQualityIn:1,000,000,000. As a special case, the value 0 is
     equivalent to 1 billion, or face value.
     */
    public var lowQualityIn: Int?
    /**
     The outbound quality set by the low account, as an integer in the implied
     ratio LowQualityOut:1,000,000,000. As a special case, the value 0 is
     equivalent to 1 billion, or face value.
     */
    public var lowQualityOut: Int?
    /**
     The inbound quality set by the high account, as an integer in the implied
     ratio HighQualityIn:1,000,000,000. As a special case, the value 0 is
     equivalent to 1 billion, or face value.
     */
    public var highQualityIn: Int?
    /**
     The outbound quality set by the high account, as an integer in the implied
     ratio HighQualityOut:1,000,000,000. As a special case, the value 0 is
     equivalent to 1 billion, or face value.
     */
    public var highQualityOut: Int?

    enum CodingKeys: String, CodingKey {
        case flags = "Flags"
        case balance = "Balance"
        case lowLimit = "LowLimit"
        case highLimit = "HighLimit"
        case previousTxnId = "PreviousTxnID"
        case previousTxnLgrSeq = "PreviousTxnLgrSeq"
        case lowNode = "LowNode"
        case highNode = "HighNode"
        case lowQualityIn = "LowQualityIn"
        case lowQualityOut = "LowQualityOut"
        case highQualityIn = "HighQualityIn"
        case highQualityOut = "HighQualityOut"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        flags = try values.decode(Int.self, forKey: .flags)
        balance = try values.decode(IssuedCurrencyAmount.self, forKey: .balance)
        lowLimit = try values.decode(IssuedCurrencyAmount.self, forKey: .lowLimit)
        highLimit = try values.decode(IssuedCurrencyAmount.self, forKey: .highLimit)
        previousTxnId = try values.decode(String.self, forKey: .previousTxnId)
        previousTxnLgrSeq = try values.decode(Int.self, forKey: .previousTxnLgrSeq)
        lowNode = try values.decodeIfPresent(String.self, forKey: .lowNode)
        highNode = try values.decodeIfPresent(String.self, forKey: .highNode)
        lowQualityIn = try values.decodeIfPresent(Int.self, forKey: .lowQualityIn)
        lowQualityOut = try values.decodeIfPresent(Int.self, forKey: .lowQualityOut)
        highQualityIn = try values.decodeIfPresent(Int.self, forKey: .highQualityIn)
        highQualityOut = try values.decodeIfPresent(Int.self, forKey: .highQualityOut)
        try super.init(from: decoder)
    }

    override public init(json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(LERippleState.self, from: data)
        flags = decoded.flags
        balance = decoded.balance
        lowLimit = decoded.lowLimit
        highLimit = decoded.highLimit
        previousTxnId = decoded.previousTxnId
        previousTxnLgrSeq = decoded.previousTxnLgrSeq
        lowNode = decoded.lowNode
        highNode = decoded.highNode
        lowQualityIn = decoded.lowQualityIn
        lowQualityOut = decoded.lowQualityOut
        highQualityIn = decoded.highQualityIn
        highQualityOut = decoded.highQualityOut
        try super.init(json: json)
    }
}

enum RippleStateFlags: Int {
    // True, if entry counts toward reserve.
    case lsfLowReserve = 0x00010000
    case lsfHighReserve = 0x00020000
    case lsfLowAuth = 0x00040000
    case lsfHighAuth = 0x00080000
    case lsfLowNoRipple = 0x00100000
    case lsfHighNoRipple = 0x00200000
    // True, low side has set freeze flag
    case lsfLowFreeze = 0x00400000
    // True, high side has set freeze flag
    case lsfHighFreeze = 0x00800
}
