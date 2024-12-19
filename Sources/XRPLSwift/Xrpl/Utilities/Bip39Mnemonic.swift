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
    case noWordListOfLanguage(language: WordList)
    case notInDictionary(word: String)
    case checksumMismatch
}

public final class Bip39Mnemonic {
    public enum Strength: Int {
        case normal = 128
        case hight = 256
    }
    
    static let mnemonicWordsDictionaryWholeList = [
        WordList.english: Dictionary(uniqueKeysWithValues: zip(WordList.english.words, 0..<UInt16.max)),
        WordList.french: Dictionary(uniqueKeysWithValues: zip(WordList.french.words, 0..<UInt16.max)),
        WordList.italian: Dictionary(uniqueKeysWithValues: zip(WordList.italian.words, 0..<UInt16.max)),
        WordList.japanese: Dictionary(uniqueKeysWithValues: zip(WordList.japanese.words, 0..<UInt16.max)),
        WordList.korean: Dictionary(uniqueKeysWithValues: zip(WordList.korean.words, 0..<UInt16.max)),
        WordList.simplifiedChinese: Dictionary(uniqueKeysWithValues: zip(WordList.simplifiedChinese.words, 0..<UInt16.max)),
        WordList.spanish: Dictionary(uniqueKeysWithValues: zip(WordList.spanish.words, 0..<UInt16.max)),
        WordList.traditionalChinese: Dictionary(uniqueKeysWithValues: zip(WordList.traditionalChinese.words, 0..<UInt16.max)),
    ]

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
    
    public static func validateMnemonics(_ mnemonics: String, _ language: WordList = .english) throws {
        // 1. All words are in the mnemonic dictionary
        guard let mnemonicWordsDictionary = mnemonicWordsDictionaryWholeList[language] else {
            throw MnemonicsError.noWordListOfLanguage(language: language)
        }
        
        let mnemonicWords = mnemonics.split(separator: " ").map(String.init)
        let fullBitLength = mnemonicWords.count * 11
        let entropyBitLength = fullBitLength * 32 / 33
        let checksumBitLength = fullBitLength - entropyBitLength

        var entropyBits = Data()
        var expectedChecksumBits = Data()
        
        // bitIdx: an index of the whole bit (0 ~ mnemonicWords.count * 11)
        // unitByteIdx: a bit index of the unit byte (1 ~ 8)
        // unitByte: a unit member of the data ([UInt8])
        var bitIdx = 0
        var unitByteIdx = 0
        var unitByte: UInt8 = 0
        
        // streaming bits to entropy & checksum
        for word in mnemonicWords {
            guard let index = mnemonicWordsDictionary[word] else {
                throw MnemonicsError.notInDictionary(word: word)
            }
            
            // each mnemonic word represents 11 bits
            // a unit member of the data represents 8 bits
            // iterate each word, decode as 11 bits and fill the data which is 8bit-based array
            var decodedBits = index
            for _ in 0..<11 {
                unitByteIdx += 1
                
                // streaming direction: higher bit first
                let unitBits = decodedBits & 0b1_00000_00000
                if (unitBits == 0b1_00000_00000) {
                    unitByte += 1
                }
                
                if (bitIdx < entropyBitLength && unitByteIdx == 8 || bitIdx == entropyBitLength - 1) {
                    entropyBits.append(unitByte)
                    unitByteIdx = 0
                    unitByte = 0
                } else if (bitIdx >= entropyBitLength && unitByteIdx == 8 || bitIdx == fullBitLength - 1) {
                    expectedChecksumBits.append(unitByte)
                    unitByteIdx = 0
                    unitByte = 0
                } else {
                    unitByte <<= 1
                }
                
                decodedBits <<= 1
                bitIdx += 1
            }
        }

        // derive checksum, and pick the first checksumBitLength bits
        let checksum = entropyBits.sha256()
        var checksumBits = Data()
        var checksumBitIdx = 0
        var isFinished = false
        
        for data in checksum {
            var currData = data
            var unitByte: UInt8 = 0
            for _ in 0..<8 {
                let currBit = currData & 0b10000000
                if (currBit == 0b10000000) {
                    unitByte += 1
                }
                
                if (checksumBitIdx == checksumBitLength - 1) {
                    checksumBits.append(unitByte)
                    isFinished = true
                    break
                }
                
                checksumBitIdx += 1
                unitByte <<= 1
                currData <<= 1
            }
            
            if (isFinished) {
                break
            } else {
                checksumBits.append(unitByte)
            }
        }
        
        guard expectedChecksumBits == checksumBits else {
            throw MnemonicsError.checksumMismatch
        }
    }
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
