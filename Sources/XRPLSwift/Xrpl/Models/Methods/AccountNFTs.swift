//
//  AccountNFTs.swift
//
//
//  Created by Denis Angell on 7/30/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/methods/accountNFTs.ts

import AnyCodable
import Foundation

/**
 The `account_nfts` method retrieves all of the NFTs currently owned by the
 specified account.
 */
public class AccountNFTsRequest: BaseRequest {
    /**
     The unique identifier of an account, typically the account's address. The
     request returns NFTs owned by this account.
     */
    public var account: String
    /**
     Limit the number of NFTokens to retrieve.
     */
    public var limit: Int?
    /**
     Value from a previous paginated response. Resume retrieving data where
     that response left off.
     */
    public var marker: AnyCodable?

    enum CodingKeys: String, CodingKey {
        case account
        case limit
        case marker
    }

    public init(
        // Required
        account: String,
        // Base
        id: Int? = nil,
        apiVersion: Int? = nil,
        // Optional
        limit: Int? = nil,
        marker: AnyCodable? = nil
    ) {
        // Required
        self.account = account
        // Optional
        self.limit = limit
        self.marker = marker
        super.init(id: id, command: "account_nfts", apiVersion: apiVersion)
    }

    override public init(_ json: [String: AnyObject]) throws {
        let decoder = JSONDecoder()
        let data: Data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
        let decoded = try decoder.decode(AccountLinesRequest.self, from: data)
        self.account = decoded.account
        self.limit = decoded.limit
        self.marker = decoded.marker
        try super.init(json)
    }

    required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account = try values.decode(String.self, forKey: .account)
        limit = try? values.decodeIfPresent(Int.self, forKey: .limit)
        marker = try? values.decodeIfPresent(AnyCodable.self, forKey: .marker)
        try super.init(from: decoder)
    }

    override public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try super.encode(to: encoder)
        try values.encode(account, forKey: .account)
        if let limit = limit { try values.encode(limit, forKey: .limit) }
        if let marker = marker { try values.encode(marker, forKey: .marker) }
    }
}

/**
 One NFToken that might be returned from an {@link AccountNFTsRequest}.
 */
public struct AccountNFToken: Codable {
    public var flags: Int
    public var issuer: String
    public var nfTokenID: String
    public var nfTokenTaxon: Int
    public var uri: String?
    public var nftSerial: Int

    enum CodingKeys: String, CodingKey {
        case flags = "Flags"
        case issuer = "Issuer"
        case nfTokenID = "NFTokenID"
        case nfTokenTaxon = "NFTokenTaxon"
        case uri = "URI"
        case nftSerial = "nft_serial"
    }
}

/**
 Response expected from an {@link AccountNFTsRequest}.
 */
public class AccountNFTsResponse: Codable {
    /**
     The account requested.
     */
    public var account: String
    /**
     A list of NFTs owned by the specified account.
     */
    public var accountNfts: [AccountNFToken]
    /**
     The ledger index of the current open ledger, which was used when
     retrieving this information.
     */
    public var ledgerHash: String
    public var ledgerIndex: Int
    /// If true, this data comes from a validated ledger.
    public var validated: Bool
    /// The limit that was used to fulfill this request.
    public var limit: Int?
    /**
     Server-defined value indicating the response is paginated. Pass this to
     the next call to resume where this call left off. Omitted when there are
     No additional pages after this one.
     */
    public var marker: AnyCodable?

    enum CodingKeys: String, CodingKey {
        case account = "account"
        case accountNfts = "account_nfts"
        case ledgerHash = "ledger_hash"
        case ledgerIndex = "ledger_index"
        case validated = "validated"
        case limit = "limit"
        case marker = "marker"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account = try values.decode(String.self, forKey: .account)
        accountNfts = try values.decode([AccountNFToken].self, forKey: .accountNfts)
        ledgerHash = try values.decode(String.self, forKey: .ledgerHash)
        ledgerIndex = try values.decode(Int.self, forKey: .ledgerIndex)
        validated = try values.decode(Bool.self, forKey: .validated)
        limit = try values.decodeIfPresent(Int.self, forKey: .limit)
        marker = try values.decodeIfPresent(AnyCodable.self, forKey: .marker)
        //        try super.init(from: decoder)
    }

    func toJson() throws -> [String: AnyObject] {
        let data = try JSONEncoder().encode(self)
        let jsonResult = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves)
        return jsonResult as? [String: AnyObject] ?? [:]
    }
}
