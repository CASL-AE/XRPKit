//
//  WalletSigner.swift
//
//
//  Created by Denis Angell on 8/6/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/Wallet/signer.ts

import BigInt
import Foundation

public class WalletSigner: Wallet {
    /**
     Takes several transactions with Signer fields (in object or blob form) and creates a
     single transaction with all Signers that then gets signed and returned.
     - parameters:
        - transactions: An array of signed Transactions (in object or blob form) to combine into a single signed Transaction.
     - returns:
     A single signed Transaction which has all Signers from transactions within it.
     - throws:
     ValidationError if:
     - There were no transactions given to sign
     - The SigningPubKey field is not the empty string in any given transaction
     - Any transaction is missing a Signers field.
     */
    //    public func multisign(transactions: [Transaction] | [String]) -> String {
    public static func multisign(_ transactions: [Transaction]) throws -> String {
        if transactions.isEmpty {
            throw ValidationError("There were 0 transactions to multisign")
        }

        for txOrBlob in transactions {
            let tx: Transaction = getDecodedTransaction(txOrBlob)
            let jsonTx: [String: AnyObject] = try tx.toJson()
            /*
             This will throw a more clear error for JS users if any of the supplied transactions has incorrect formatting
             */
            // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- validate does not accept Transaction type
            try validate(transaction: jsonTx)
            if jsonTx["Signers"] == nil || (jsonTx["Signers"] as! [String: AnyObject]).isEmpty {
                // swiftlint:disable:next line_length
                throw ValidationError("For multisigning all transactions must include a Signers field containing an array of signatures. You may have forgotten to pass the 'forMultisign' parameter when signing.")
            }

            if jsonTx["SigningPubKey"] as! String != "" {
                throw ValidationError("SigningPubKey must be an empty string for all transactions when multisigning.")
            }
        }

        let decodedTransactions: [Transaction] = transactions.map { tx in
            return getDecodedTransaction(tx)
        }

        try validateTransactionEquivalence(decodedTransactions)

        return try BinaryCodec.encode(getTransactionWithAllSigners(decodedTransactions).toJson())
    }

    /**
     Creates a signature that can be used to redeem a specific amount of XRP from a payment channel.
     - parameters:
        - wallet: The account that will sign for this payment channel.
        - channelId: An id for the payment channel to redeem XRP from.
        - amount: The amount in drops to redeem.
     - returns:
     A signature that can be used to redeem a specific amount of XRP from a payment channel.
     */
    public static func authorizeChannel(
        _ wallet: Wallet,
        _ channelId: String,
        _ amount: String
    ) throws -> String {
        let channelClaim = ChannelClaim(amount: try xrpToDrops(amount), channel: channelId)
        let signingData = try BinaryCodec.encodeForSigningClaim(channelClaim)
        return try Keypairs.sign(Data(hex: signingData).bytes, wallet.privateKey).toHex
    }

    /**
     Verifies that the given transaction has a valid signature based on public-key encryption.
     - parameters:
        - tx: A transaction to verify the signature of. (Can be in object or encoded string format).
     - returns:
     Returns true if tx has a valid signature, and returns false otherwise.
     */
    public static func verifySignature(_ tx: String) throws -> Bool {
        let decodedTx: Transaction = self.getDecodedTransaction(tx)
        let json: [String: AnyObject] = try decodedTx.toJson()
        return try! Keypairs.verify(
            Data(hex: json["TxnSignature"] as! String).bytes,
            Data(hex: try BinaryCodec.encodeForSigning(json)).bytes,
            json["SigningPubKey"] as! String
        )
    }
    public static func verifySignature(_ tx: Transaction) throws -> Bool {
        let decodedTx: Transaction = WalletSigner.getDecodedTransaction(tx)
        let json: [String: AnyObject] = try decodedTx.toJson()
        return try! Keypairs.verify(
            try BinaryCodec.encodeForSigning(json).bytes,
            (json["TxnSignature"] as! String).bytes,
            json["SigningPubKey"] as! String
        )
    }

    /**
     The transactions should all be equal except for the 'Signers' field.
     - parameters:
        - transactions: An array of Transactions which are expected to be equal other than 'Signers'.
     - throws:
     ValidationError if the transactions are not equal in any field other than 'Signers'.
     */
    static func validateTransactionEquivalence(_ transactions: [Transaction]) throws {
        //        let exampleTransaction = JSON.stringify({
        //            ...transactions[0],
        //        Signers: null,
        //        })
        var exampleTx = try transactions[0].toJson()
        exampleTx["Signers"] = nil
        guard try transactions.allSatisfy({ tx in
            var cloneTx = try tx.toJson()
            cloneTx["Signers"] = nil
            //            return (exampleTx === cloneTx)
            return true
        }) else {
            throw ValidationError("txJSON is not the same for all signedTransactions")
        }
    }

    static func getTransactionWithAllSigners(_ transactions: [Transaction]) -> Transaction {
        // Signers must be sorted in the combined transaction - See compareSigners' documentation for more details
        let sortedSigners: [Signer] = transactions.compactMap { tx in
            let cloneTx = try! tx.toJson()
            return cloneTx["Signers"] as? Signer
            //        }.sorted(by: compareSigners)
        }
        //        return { ...transactions[0], Signers: sortedSigners }
        return transactions[0]
    }

    /**
     If presented in binary form, the Signers array must be sorted based on
     the numeric value of the signer addresses, with the lowest value first.
     (If submitted as JSON, the submit_multisigned method handles this automatically.)
     https://xrpl.org/multi-signing.html.
     - parameters:
        - left: A Signer to compare with.
        - right: A second Signer to compare with.
     - returns:
     1 if left \> right, 0 if left = right, -1 if left \< right, and null if left or right are NaN.
     */
    // TODO: Refactor this
    static func compareSigners(_ left: Signer, _ right: Signer) -> Int {
        if addressToBigNumber(left.signer.account) > addressToBigNumber(right.signer.account) {
            return 1
        }
        if addressToBigNumber(left.signer.account) == addressToBigNumber(right.signer.account) {
            return 0
        }
        if addressToBigNumber(left.signer.account) < addressToBigNumber(right.signer.account) {
            return -1
        }
        return 0
    }

    static func addressToBigNumber(_ address: String) -> BigUInt {
        let hex: String = try! XrplCodec.decodeClassicAddress(address).toHex
        let numberOfBitsInHex: Int = 16
        return BigUInt(hex, radix: numberOfBitsInHex)!
    }

    public static func getDecodedTransaction(_ tx: String) -> Transaction {
        let decoded: [String: AnyObject] = BinaryCodec.decode(tx)
        return try! Transaction(decoded)!
    }

    public static func getDecodedTransaction(_ tx: Transaction) -> Transaction {
        let encoded = try! BinaryCodec.encode(tx.toJson())
        let decoded: [String: AnyObject] = BinaryCodec.decode(encoded)
        return try! Transaction(decoded)!
    }
}
