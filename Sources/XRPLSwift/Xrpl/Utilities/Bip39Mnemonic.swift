//
//  Mnemonic.swift
//  WalletKit
//
//  Created by yuzushioh on 2018/02/11.
//  Copyright © 2018 yuzushioh. All rights reserved.
//
import CryptoSwift
import CryptoKit
import Foundation

// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

enum MnemonicsError: Error, Equatable {
    case notInDictionary(word: String)
    case checksumMismatch
}

public final class Bip39Mnemonic {
    public enum Strength: Int {
        case normal = 128
        case hight = 256
    }

    public static func create(strength: Strength = .normal, language: WordList = .english) throws -> String {
        let byteCount = strength.rawValue / 8
        let bytes = try Data(URandom().bytes(count: byteCount))
        return create(entropy: bytes, language: language)
    }

    public static func create(entropy: Data, language: WordList = .english) -> String {
        let entropybits = String(entropy.flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let hashBits = String(entropy.sha256().flatMap { ("00000000" + String($0, radix: 2)).suffix(8) })
        let checkSum = String(hashBits.prefix((entropy.count * 8) / 32))

        let words = language.words
        let concatenatedBits = entropybits + checkSum

        var mnemonic: [String] = []
        for index in 0..<(concatenatedBits.count / 11) {
            let startIndex = concatenatedBits.index(concatenatedBits.startIndex, offsetBy: index * 11)
            let endIndex = concatenatedBits.index(startIndex, offsetBy: 11)
            let wordIndex = Int(strtoul(String(concatenatedBits[startIndex..<endIndex]), nil, 2))
            mnemonic.append(String(words[wordIndex]))
        }

        return mnemonic.joined(separator: " ")
    }

    public static func createSeed(mnemonic: String, withPassphrase passphrase: String = "", language: WordList = .english) throws -> Data {
        try self.validateMnemonics(mnemonic, language)
        
        guard let password = mnemonic.decomposedStringWithCompatibilityMapping.data(using: .utf8) else {
            fatalError("Nomalizing password failed in \(self)")
        }

        guard let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.data(using: .utf8) else {
            fatalError("Nomalizing salt failed in \(self)")
        }

        return PBKDF2SHA512(password: password.bytes, salt: salt.bytes)
    }
    
    static func validateMnemonics(_ mnemonics: String, _ language: WordList = .english) throws {
        var decodedMnemonics = [Bit]()
        
        // 1. All words are in the mnemonic dictionary

        var mnemonicWordsDictionary = [String: UInt16]()
        for (idx, word) in language.words.enumerated() {
            mnemonicWordsDictionary[word] = UInt16(idx)
        }
        
        let mnemonicWords = mnemonics.split(separator: " ").map { String($0) }
        for mnemonic in mnemonicWords {
            if mnemonicWordsDictionary[mnemonic] == nil {
                throw MnemonicsError.notInDictionary(word: mnemonic)
            }
            
            // organize entropy data
            let unitBits = to11Bits(fromByte: mnemonicWordsDictionary[mnemonic]!)
            decodedMnemonics.append(contentsOf: unitBits)
        }

        // 2. Checksum correctness

        let entropyLen = decodedMnemonics.count * 32 / 33

        let entropy = toData(fromBits: [Bit](decodedMnemonics[..<entropyLen]))
        let checksum = [Bit](decodedMnemonics[entropyLen...])

        let checksumFromEntropy = toBits(fromByte: entropy.sha256())

        for i in 0..<checksum.count {
            if checksum[i] != checksumFromEntropy[i] {
                throw MnemonicsError.checksumMismatch
            }
        }
    }
}

func to11Bits(fromByte byte: UInt16) -> [Bit] {
    var byte = byte
    let count = 11
    
    var bits = [Bit](repeating: .zero, count: count)

    for i in 0..<count {
        let currentBit = byte & 0x01
        if currentBit != 0 {
            bits[count - 1 - i] = .one
        }

        byte >>= 1
    }

    return bits
}

func toBits(fromByte: Data) -> [Bit] {
    var bits = [Bit]()

    for i in 0..<fromByte.count {
        var unitByte = fromByte[i]
        var convertedBits = [Bit](repeating: .zero, count: 8)

        for bitIdx in 0..<8 {
            let currentBit = unitByte & 0x01
            if currentBit != 0 {
                convertedBits[7 - bitIdx] = .one
            }

            unitByte >>= 1
        }
        
        bits.append(contentsOf: convertedBits)
    }

    return bits
}

func toData(fromBits: [Bit]) -> Data {
    var resultData = [UInt8]()
    
    for byteIdx in 0..<(fromBits.count / 8) {
        var unitByte: UInt8 = 0
        for bitIdx in 0..<8 {
            let bit = fromBits[byteIdx * 8 + bitIdx]
            if bit == .one {
                unitByte |= (0x01 << (7 - bitIdx))
            }
        }
        resultData.append(unitByte)
    }
    
    return Data(resultData)
}

public func PBKDF2SHA512(password: [UInt8], salt: [UInt8]) -> Data {
    let output: [UInt8]
    do {
        output = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 2048, variant: .sha512).calculate()
    } catch {
        fatalError("PKCS5.PBKDF2 faild: \(error.localizedDescription)")
    }
    return Data(output)
}
