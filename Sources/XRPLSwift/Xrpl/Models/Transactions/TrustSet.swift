//
//  TrustSet.swift
//  AnyCodable
//
//  Created by Mitch Lang on 2/4/20.
//

import Foundation

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/transactions/trustSet.ts

public enum TrustSetFlag: Int {
    /*
     Transactions of the TrustSet type support additional values in the Flags field.
     This enum represents those options.
     */

    case tfSetfAuth = 0x00010000
    /*
     Authorize the other party to hold
     `currency issued by this account <https:xrpl.org/tokens.html>`_.
     (No effect unless using the `asfRequireAuth AccountSet flag
     <https://xrpl.org/accountset.html#accountset-flags>`_.) Cannot be unset.
     */

    case tfSetNoRipple = 0x00020000
    /*
     Enable the No Ripple flag, which blocks
     `rippling <https://xrpl.org/rippling.html>`_ between two trust
     lines of the same currency if this flag is enabled on both.
     */

    case tfClearNoRipple = 0x00040000
    // Disable the No Ripple flag, allowing rippling on this trust line.

    case tfSetFreeze = 0x00100000
    // Freeze the trust line.

    case tfClearFreeze = 0x00200000
    // Unfreeze the trust line.
}

extension Array where Element == TrustSetFlag {
    var interface: [TrustSetFlag: Bool] {
        var flags: [TrustSetFlag: Bool] = [:]
        for flag in self {
            if flag == .tfSetfAuth {
                flags[flag] = true
            }
            if flag == .tfSetNoRipple {
                flags[flag] = true
            }
            if flag == .tfClearNoRipple {
                flags[flag] = true
            }
            if flag == .tfSetFreeze {
                flags[flag] = true
            }
            if flag == .tfClearFreeze {
                flags[flag] = true
            }
        }
        return flags
    }
}

// public struct TrustSetFlagsInterface: GlobalFlags {
public struct TrustSetFlagsInterface {
    /**
     * Authorize the other party to hold currency issued by this account. (No
     * effect unless using the asfRequireAuth AccountSet flag.) Cannot be unset.
     */
    public var tfSetfAuth: Bool?
    /**
     * Enable the No Ripple flag, which blocks rippling between two trust lines
     * of the same currency if this flag is enabled on both.
     */
    public var tfSetNoRipple: Bool?
    /** Disable the No Ripple flag, allowing rippling on this trust line. */
    public var tfClearNoRipple: Bool?
    /** Freeze the trust line. */
    public var tfSetFreeze: Bool?
    /** Unfreeze the trust line. */
    public var tfClearFreeze: Bool?
    
    public init(
        tfSetAuth: Bool? = nil,
        tfSetNoRipple: Bool? = nil,
        tfClearNoRipple: Bool? = nil,
        tfSetFreeze: Bool? = nil,
        tfClearFreeze: Bool? = nil
    ) {
        if self.tfSetfAuth != nil {
            self.tfSetfAuth = tfSetAuth
        }
        
        if self.tfSetNoRipple != nil {
            self.tfSetNoRipple = tfSetNoRipple
        }
        
        if self.tfClearNoRipple != nil {
            self.tfClearNoRipple = tfClearNoRipple
        }
        
        if self.tfSetFreeze != nil {
            self.tfSetFreeze = tfSetFreeze
        }
        
        if self.tfClearFreeze != nil {
            self.tfClearFreeze = tfClearFreeze
        }
    }
}

public class TrustSet: BaseTransaction {
    /*
     Represents a TrustSet transaction on the XRP Ledger.
     Creates or modifies a trust line linking two accounts.
     `See TrustSet <https://xrpl.org/trustset.html>`_
     */
    public var limitAmount: IssuedCurrencyAmount
    /*
     This field is required.
     :meta hide-value:
     */

    public var qualityIn: Int?

    public var qualityOut: Int?

    enum CodingKeys: String, CodingKey {
        case limitAmount = "LimitAmount"
        case qualityIn = "QualityIn"
        case qualityOut = "QualityOut"
    }

    public init(
        limitAmount: IssuedCurrencyAmount,
        qualityIn: Int? = nil,
        qualityOut: Int? = nil,
        flags: TrustSetFlagsInterface
    ) {
        self.limitAmount = limitAmount
        self.qualityIn = qualityIn
        self.qualityOut = qualityOut
        super.init(account: "", transactionType: "TrustSet")
    }

    override public init(json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(TrustSet.self, from: data)
        self.limitAmount = decoded.limitAmount
        self.qualityIn = decoded.qualityIn
        self.qualityOut = decoded.qualityOut
        try super.init(json: json)
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        limitAmount = try values.decode(IssuedCurrencyAmount.self, forKey: .limitAmount)
        qualityIn = try values.decodeIfPresent(Int.self, forKey: .qualityIn)
        qualityOut = try values.decodeIfPresent(Int.self, forKey: .qualityOut)
        try super.init(from: decoder)
    }

    override public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try super.encode(to: encoder)
        try values.encode(limitAmount, forKey: .limitAmount)
        if let qualityIn = qualityIn { try values.encode(qualityIn, forKey: .qualityIn) }
        if let qualityOut = qualityOut { try values.encode(qualityOut, forKey: .qualityOut) }
    }
}

/**
 Verify the form and type of an TrustSet at runtime.
 - parameters:
 - tx: An TrustSet Transaction.
 - throws:
 When the TrustSet is Malformed.
 */
public func validateTrustSet(tx: [String: AnyObject]) throws {
    try validateBaseTransaction(common: tx)

    if tx["LimitAmount"] == nil {
        throw ValidationError("TrustSet: missing field LimitAmount")
    }

    if !isAmount(amount: tx["LimitAmount"] as Any) {
        throw ValidationError("TrustSet: invalid LimitAmount")
    }

    if tx["QualityIn"] != nil && !(tx["QualityIn"] is Int) {
        throw ValidationError("TrustSet: QualityIn must be a number")
    }

    if tx["QualityOut"] != nil && !(tx["QualityOut"] is Int) {
        throw ValidationError("TrustSet: QualityOut must be a number")
    }
}
