//
//  AccountObjects.swift
//
//
//  Created by Denis Angell on 7/30/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/methods/accountObjects.ts

import AnyCodable
import Foundation

/**
 Account Objects can be a Check, a DepositPreauth, an Escrow, an Offer, a
 PayChannel, a SignerList, a Ticket, or a RippleState.
 */
public enum AccountObject: Codable {
    case check(LECheck)
    case depositPreauth(LEDepositPreauth)
    case escrow(LEEscrow)
    case offer(LEOffer)
    case paymentChannel(LEPayChannel)
    case signerList(LESignerList)
    case ticket(LETicket)
    case rippleState(LERippleState)
    case nftOffer(LENFTOffer)
    
    public func toAny() -> Any {
        switch self {
        case .check(let check):
            return check
        case .depositPreauth(let depositPreauth):
            return depositPreauth
        case .escrow(let escrow):
            return escrow
        case .offer(let offer):
            return offer
        case .paymentChannel(let paymentChannel):
            return paymentChannel
        case .signerList(let signerList):
            return signerList
        case .ticket(let ticket):
            return ticket
        case .rippleState(let rippleState):
            return rippleState
        case .nftOffer(let nftOffer):
            return nftOffer
        }
    }
}

extension AccountObject {
    enum AccountObjectCodingError: Error {
        case decoding(String)
    }
    public init(from decoder: Decoder) throws {
        if let value = try? LECheck(from: decoder) {
            self = .check(value)
            return
        }
        if let value = try? LEDepositPreauth(from: decoder) {
            self = .depositPreauth(value)
            return
        }
        if let value = try? LEEscrow(from: decoder) {
            self = .escrow(value)
            return
        }
        if let value = try? LEOffer(from: decoder) {
            self = .offer(value)
            return
        }
        if let value = try? LEPayChannel(from: decoder) {
            self = .paymentChannel(value)
            return
        }
        if let value = try? LESignerList(from: decoder) {
            self = .signerList(value)
            return
        }
        if let value = try? LETicket(from: decoder) {
            self = .ticket(value)
            return
        }
        if let value = try? LERippleState(from: decoder) {
            self = .rippleState(value)
            return
        }
        if let value = try? LENFTOffer(from: decoder) {
            self = .nftOffer(value)
            return
        }
        throw AccountObjectCodingError.decoding("AccountObject has not been mapped")
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .check(let check):
            try check.encode(to: encoder)
        case .depositPreauth(let depositPreauth):
            try depositPreauth.encode(to: encoder)
        case .escrow(let escrow):
            try escrow.encode(to: encoder)
        case .offer(let offer):
            try offer.encode(to: encoder)
        case .paymentChannel(let paymentChannel):
            try paymentChannel.encode(to: encoder)
        case .signerList(let signerList):
            try signerList.encode(to: encoder)
        case .ticket(let ticket):
            try ticket.encode(to: encoder)
        case .rippleState(let rippleState):
            try rippleState.encode(to: encoder)
        case .nftOffer(let nftOffer):
            try nftOffer.encode(to: encoder)
        }
    }
}

/**
 The account_objects command returns the raw ledger format for all objects
 owned by an account. For a higher-level view of an account's trust lines and
 balances, see the account_lines method instead. Expects a response in the
 form of an {@link AccountObjectsResponse}.
 */
public class AccountObjectsRequest: BaseRequest {
    /// A unique identifier for the account, most commonly the account's address.
    public var account: String
    /**
     If included, filter results to include only this type of ledger object.
     The valid types are: Check , DepositPreauth, Escrow, Offer, PayChannel,
     SignerList, Ticket, and RippleState (trust line).
     */
    public var type: AccountObjectType?
    /**
     If true, the response only includes objects that would block this account
     from being deleted. The default is false.
     */
    public var deletionBlockersOnly: Bool?
    /// A 20-byte hex string for the ledger version to use.
    public var ledgerHash: String?
    /**
     The ledger index of the ledger to use, or a shortcut string to choose a
     Ledger automatically.
     */
    public var ledgerIndex: LedgerIndex?
    /**
     The maximum number of objects to include in the results. Must be within
     the inclusive range 10 to 400 on non-admin connections. The default is 200.
     */
    public var limit: Int?
    /**
     Value from a previous paginated response. Resume retrieving data where
     that response left off.
     */
    public var marker: AnyCodable?

    enum CodingKeys: String, CodingKey {
        case account = "account"
        case type = "type"
        case deletionBlockersOnly = "deletion_blockers_only"
        case ledgerHash = "ledger_hash"
        case ledgerIndex = "ledger_index"
        case limit = "limit"
        case marker = "marker"
    }

    public init(
        // Required
        account: String,
        // Base
        id: Int? = nil,
        apiVersion: Int? = nil,
        // Optional
        type: AccountObjectType? = nil,
        deletionBlockersOnly: Bool? = nil,
        ledgerHash: String? = nil,
        ledgerIndex: LedgerIndex? = nil,
        limit: Int? = nil,
        marker: AnyCodable? = nil
    ) {
        // Required
        self.account = account
        // Optional
        self.type = type
        self.deletionBlockersOnly = deletionBlockersOnly
        self.ledgerHash = ledgerHash
        self.ledgerIndex = ledgerIndex
        self.limit = limit
        self.marker = marker
        super.init(id: id, command: "account_objects", apiVersion: apiVersion)
    }

    override public init(_ json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(AccountObjectsRequest.self, from: data)
        // Required
        self.account = decoded.account
        // Optional
        self.type = decoded.type
        self.deletionBlockersOnly = decoded.deletionBlockersOnly
        self.ledgerHash = decoded.ledgerHash
        self.ledgerIndex = decoded.ledgerIndex
        self.limit = decoded.limit
        self.marker = decoded.marker
        try super.init(json)
    }

    required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account = try values.decode(String.self, forKey: .account)
        type = try values.decodeIfPresent(AccountObjectType.self, forKey: .type)
        deletionBlockersOnly = try values.decodeIfPresent(Bool.self, forKey: .deletionBlockersOnly)
        ledgerHash = try values.decodeIfPresent(String.self, forKey: .ledgerHash)
        ledgerIndex = try values.decodeIfPresent(LedgerIndex.self, forKey: .ledgerIndex)
        limit = try? values.decodeIfPresent(Int.self, forKey: .limit)
        marker = try? values.decodeIfPresent(AnyCodable.self, forKey: .marker)
        try super.init(from: decoder)
    }

    override public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try super.encode(to: encoder)
        try values.encode(account, forKey: .account)
        if let type = type { try values.encode(type, forKey: .type) }
        if let deletionBlockersOnly = deletionBlockersOnly { try values.encode(deletionBlockersOnly, forKey: .deletionBlockersOnly) }
        if let ledgerHash = ledgerHash { try values.encode(ledgerHash, forKey: .ledgerHash) }
        if let ledgerIndex = ledgerIndex { try values.encode(ledgerIndex, forKey: .ledgerIndex) }
        if let limit = limit { try values.encode(limit, forKey: .limit) }
        if let marker = marker { try values.encode(marker, forKey: .marker) }
    }
}

/**
 Response expected from an {@link AccountObjectsRequest}.
 */
public class AccountObjectsResponse: Codable {
    /// Unique Address of the account this request corresponds to.
    public var account: String
    /**
     Array of objects owned by this account. Each object is in its raw
     ledger format.
     */
    public var accountObjects: [AccountObject]
    /**
     The identifying hash of the ledger that was used to generate this
     response.
     */
    public var ledgerHash: String?
    /**
     The ledger index of the ledger version that was used to generate this
     response.
     */
    public var ledgerIndex: Int?
    /**
     The ledger index of the current in-progress ledger version, which was
     used to generate this response.
     */
    public var ledgerCurrentIndex: Int?
    /// The limit that was used in this request, if any.
    public var limit: Int?
    /**
     Server-defined value indicating the response is paginated. Pass this to
     the next call to resume where this call left off. Omitted when there are
     no additional pages after this one.
     */
    public var marker: AnyCodable?
    /**
     If included and set to true, the information in this response comes from
     a validated ledger version. Otherwise, the information is subject to
     change.
     */
    public var validated: Bool?

    enum CodingKeys: String, CodingKey {
        case account = "account"
        case accountObjects = "account_objects"
        case ledgerHash = "ledger_hash"
        case ledgerIndex = "ledger_index"
        case ledgerCurrentIndex = "ledger_current_index"
        case limit = "limit"
        case marker = "marker"
        case validated = "validated"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account = try values.decode(String.self, forKey: .account)
        accountObjects = try values.decode([AccountObject].self, forKey: .accountObjects)
        ledgerHash = try? values.decodeIfPresent(String.self, forKey: .ledgerHash)
        ledgerIndex = try? values.decodeIfPresent(Int.self, forKey: .ledgerIndex)
        ledgerCurrentIndex = try? values.decodeIfPresent(Int.self, forKey: .ledgerCurrentIndex)
        limit = try? values.decodeIfPresent(Int.self, forKey: .limit)
        marker = try? values.decodeIfPresent(AnyCodable.self, forKey: .marker)
        validated = try? values.decodeIfPresent(Bool.self, forKey: .validated)
        //        try super.init(from: decoder)
    }

    func toJson() throws -> [String: AnyObject] {
        let data = try JSONEncoder().encode(self)
        let jsonResult = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves)
        return jsonResult as? [String: AnyObject] ?? [:]
    }
}
