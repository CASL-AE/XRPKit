//
//  LENFTOffer.swift
//
//
//  Created by Bryan on 7/15/24.
//

import Foundation

public class LENFTOffer: BaseLedgerEntry {
    public var ledgerEntryType: String = "NFTokenOffer"
    
    public var amount: Amount
    public var destination: String?
    public var flags: Int?
    public var nfTokenId: String
    public var nfTokenOfferNode: String?
    public var owner: String
    public var ownerNode: String?
    public var previousTxnId: String
    public var previousTxnLgrSeq: Int?
    
    enum CodingKeys: String, CodingKey {
        case amount = "Amount"
        case destination = "Destination"
        case flags = "Flags"
        case nfTokenId = "NFTokenID"
        case nfTokenOfferNode = "NFTokenOfferNode"
        case owner = "Owner"
        case ownerNode = "OwnerNode"
        case previousTxnId = "PreviousTxnID"
        case previousTxnLgrSeq = "PreviousTxnLgrSeq"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        amount = try values.decode(Amount.self, forKey: .amount)
        destination = try values.decodeIfPresent(String.self, forKey: .destination)
        flags = try values.decodeIfPresent(Int.self, forKey: .flags)
        nfTokenId = try values.decode(String.self, forKey: .nfTokenId)
        nfTokenOfferNode = try values.decodeIfPresent(String.self, forKey: .nfTokenOfferNode)
        owner = try values.decode(String.self, forKey: .owner)
        ownerNode = try values.decodeIfPresent(String.self, forKey: .ownerNode)
        previousTxnId = try values.decode(String.self, forKey: .previousTxnId)
        previousTxnLgrSeq = try values.decodeIfPresent(Int.self, forKey: .previousTxnLgrSeq)
        
        try super.init(from: decoder)
    }

    override public init(json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(LENFTOffer.self, from: data)
        
        amount = decoded.amount
        destination = decoded.destination
        flags = decoded.flags
        nfTokenId = decoded.nfTokenId
        nfTokenOfferNode = decoded.nfTokenOfferNode
        owner = decoded.owner
        ownerNode = decoded.ownerNode
        previousTxnId = decoded.previousTxnId
        previousTxnLgrSeq = decoded.previousTxnLgrSeq
        
        try super.init(json: json)
    }
}
