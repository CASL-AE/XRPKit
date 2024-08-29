//
//  Metadata.swift
//
//
//  Created by Denis Angell on 7/27/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/transactions/metadata.ts

import AnyCodable
import Foundation

public struct AccountRootNodeField: Codable {
    public var account: String?
    public var balance: Amount?
    public var flags: Int?
    public var ownerCount: Int?
    public var sequence: Int?
    public var previousTxnID: String?
    public var previousTxnLgrSeq: Int?

    enum CodingKeys: String, CodingKey {
        case account = "Account"
        case balance = "Balance"
        case flags = "Flags"
        case ownerCount = "OwnerCount"
        case sequence = "Sequence"
        case previousTxnID = "PreviousTxnID"
        case previousTxnLgrSeq = "PreviousTxnLgrSeq"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account = try values.decodeIfPresent(String.self, forKey: .account)
        balance = try values.decodeIfPresent(Amount.self, forKey: .balance)
        flags = try values.decodeIfPresent(Int.self, forKey: .flags)
        ownerCount = try values.decodeIfPresent(Int.self, forKey: .ownerCount)
        sequence = try values.decodeIfPresent(Int.self, forKey: .sequence)
        previousTxnID = try values.decodeIfPresent(String.self, forKey: .previousTxnID)
        previousTxnLgrSeq = try values.decodeIfPresent(Int.self, forKey: .previousTxnLgrSeq)
    }
}

public struct DirectoryNodeField: Codable {
    public var owner: String
    public var rootIndex: String
}

public struct PayChannelNodeField: Codable {
    public var account: String
    public var amount: String
    public var destination: String
    public var publicKey: String
    public var settleDelay: Int
}

public typealias LedgerEntryType = String
// public enum LedgerEntryType: Codable {
//    case accountRoot
//    case directory
//    case paychannel
//    case unknown
// }

public enum NewField: Codable {
    case account(AccountRootNodeField)
    case directory(DirectoryNodeField)
    case paychannel(PayChannelNodeField)
    case unknown

    enum NewFieldCodingError: Error {
        case decoding(String)
    }

    public init(from decoder: Decoder) throws {
        if let value = try? AccountRootNodeField(from: decoder) {
            self = .account(value)
            return
        }
        if let value = try? DirectoryNodeField(from: decoder) {
            self = .directory(value)
            return
        }
        if let value = try? PayChannelNodeField(from: decoder) {
            self = .paychannel(value)
            return
        }
        throw NewFieldCodingError.decoding("The New Field has not been mapped.")
    }
}

public struct CreatedNodeData: Codable {
    public var ledgerEntryType: LedgerEntryType
    public var ledgerIndex: String
    public var newFields: NewField?

    enum CodingKeys: String, CodingKey {
        case ledgerEntryType = "LedgerEntryType"
        case ledgerIndex = "LedgerIndex"
        case newFields = "NewFields"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        ledgerEntryType = try values.decode(LedgerEntryType.self, forKey: .ledgerEntryType)
        ledgerIndex = try values.decode(String.self, forKey: .ledgerIndex)
        newFields = try values.decodeIfPresent(NewField.self, forKey: .newFields)
    }
}

public struct CreatedNode: Codable {
    public var createdNode: CreatedNodeData

    enum CodingKeys: String, CodingKey {
        case createdNode = "CreatedNode"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        createdNode = try values.decode(CreatedNodeData.self, forKey: .createdNode)
    }
}

public enum FinalField: Codable {
    case account(AccountRootNodeField)
    case directory(DirectoryNodeField)
    case paychannel(PayChannelNodeField)
    case unknown

    enum FinalFieldCodingError: Error {
        case decoding(String)
    }

    public init(from decoder: Decoder) throws {
        if let value = try? AccountRootNodeField(from: decoder) {
            self = .account(value)
            return
        }
        if let value = try? DirectoryNodeField(from: decoder) {
            self = .directory(value)
            return
        }
        if let value = try? PayChannelNodeField(from: decoder) {
            self = .paychannel(value)
            return
        }
        throw FinalFieldCodingError.decoding("The Final Field has not been mapped.")
    }
}

public struct ModifiedNodeData: Codable {
    public var ledgerEntryType: LedgerEntryType
    public var ledgerIndex: String
    public var finalFields: FinalField?
    public var previousFields: FinalField?
    public var previoudTxnId: String?
    public var previoudTxnLgrSeq: Int?

    enum CodingKeys: String, CodingKey {
        case ledgerEntryType = "LedgerEntryType"
        case ledgerIndex = "LedgerIndex"
        case finalFields = "FinalFields"
        case previousFields = "PreviousFields"
        case previoudTxnId = "PrevioudTxnID"
        case previoudTxnLgrSeq = "PrevioudTxnLgrSeq"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        ledgerEntryType = try values.decode(LedgerEntryType.self, forKey: .ledgerEntryType)
        ledgerIndex = try values.decode(String.self, forKey: .ledgerIndex)
        finalFields = try values.decodeIfPresent(FinalField.self, forKey: .finalFields)
        previousFields = try values.decodeIfPresent(FinalField.self, forKey: .previousFields)
        previoudTxnId = try values.decodeIfPresent(String.self, forKey: .previoudTxnId)
        previoudTxnLgrSeq = try values.decodeIfPresent(Int.self, forKey: .previoudTxnLgrSeq)
    }
}

public struct ModifiedNode: Codable {
    public var modifiedNode: ModifiedNodeData

    enum CodingKeys: String, CodingKey {
        case modifiedNode = "ModifiedNode"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        modifiedNode = try values.decode(ModifiedNodeData.self, forKey: .modifiedNode)
    }
}

public struct DeletedNodeData: Codable {
    public var ledgerEntryType: LedgerEntryType
    public var ledgerIndex: String
    public var finalFields: FinalField?
    public var previousFields: FinalField?

    enum CodingKeys: String, CodingKey {
        case ledgerEntryType = "LedgerEntryType"
        case ledgerIndex = "LedgerIndex"
        case finalFields = "FinalFields"
        case previousFields = "PreviousFields"
    }
    
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        ledgerEntryType = try values.decode(LedgerEntryType.self, forKey: .ledgerEntryType)
        ledgerIndex = try values.decode(String.self, forKey: .ledgerIndex)
        finalFields = try values.decodeIfPresent(FinalField.self, forKey: .finalFields)
        previousFields = try values.decodeIfPresent(FinalField.self, forKey: .previousFields)
    }
}

public struct DeletedNode: Codable {
    public var deletedNode: DeletedNodeData

    enum CodingKeys: String, CodingKey {
        case deletedNode = "DeletedNode"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        deletedNode = try values.decode(DeletedNodeData.self, forKey: .deletedNode)
    }
}

public enum Node: Codable {
    case modified(ModifiedNode)
    case created(CreatedNode)
    case deleted(DeletedNode)
}

extension Node {
    enum NodeCodingError: Error {
        case decoding(String)
    }

    public init(from decoder: Decoder) throws {
        if let value = try? ModifiedNode(from: decoder) {
            self = .modified(value)
            return
        }
        if let value = try? CreatedNode(from: decoder) {
            self = .created(value)
            return
        }
        if let value = try? DeletedNode(from: decoder) {
            self = .deleted(value)
            return
        }

        throw NodeCodingError.decoding("The Node has not been mapped.")
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .modified(let value):
            try value.encode(to: encoder)
        case .created(let value):
            try value.encode(to: encoder)
        case .deleted(let value):
            try value.encode(to: encoder)
        }
    }
}

public class TransactionMetadata: Codable {
    public var affectedNodes: [Node]?
    public var deliveredAmount: Amount?
    public var transactionResult: String
    public var transactionIndex: Int

    init(
        affectedNodes: [Node]? = nil,
        transactionResult: String,
        transactionIndex: Int
    ) {
        self.affectedNodes = affectedNodes
        self.transactionResult = transactionResult
        self.transactionIndex = transactionIndex
    }

    enum CodingKeys: String, CodingKey {
        case affectedNodes = "AffectedNodes"
        case transactionResult = "TransactionResult"
        case transactionIndex = "TransactionIndex"
        case deliveredAmount = "delivered_amount"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        affectedNodes = try values.decodeIfPresent([Node].self, forKey: .affectedNodes)
        transactionResult = try values.decode(String.self, forKey: .transactionResult)
        transactionIndex = try values.decode(Int.self, forKey: .transactionIndex)
        deliveredAmount = try values.decodeIfPresent(Amount.self, forKey: .deliveredAmount)
    }
}
