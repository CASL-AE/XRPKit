//
//  SafeDict.swift
//
//
//  Created by Bryan on 9/6/24.
//

import Foundation
import Swift

class SafeDict<Key: Hashable, Value> {
    private var threadUnsafeDict: [Key: Value]
    private let dispatchQueue = DispatchQueue(label: "org.xrpl", attributes: .concurrent)
    
    public init(_ dict: [Key : Value]? = nil) {
        if dict != nil {
            self.threadUnsafeDict = dict!
        } else {
            self.threadUnsafeDict = [Key: Value]()
        }
    }

    func get(key: Key) -> Value? {
        var result: Value?
        dispatchQueue.sync {
            result = self.threadUnsafeDict[key]
        }
        return result
    }
    
    func contains(key: Key) -> Bool {
        var result: Bool?
        dispatchQueue.sync {
            result = self.threadUnsafeDict.contains(where: { $0.key == key })
        }
        
        return result!
    }
    
    func getByIndex(_ key: Dictionary<Key, Value>.Index) -> Value? {
        var result: Value?
        dispatchQueue.sync {
            result = self.threadUnsafeDict[key].value
        }
        
        return result
    }
    
    func firstIndex(_ searchKey: Key) -> Dictionary<Key, Value>.Index? {
        var idx: Dictionary<Key, Value>.Index?
        dispatchQueue.sync {
            idx = self.threadUnsafeDict.firstIndex(where: {$0.key == searchKey})
        }
        
        return idx
    }
    
    func keys() -> Dictionary<Key, Value>.Keys {
        var keys: Dictionary<Key, Value>.Keys!
        dispatchQueue.sync {
            keys = self.threadUnsafeDict.keys
        }
        
        return keys
    }

    func set(key: Key, value: Value?) {
        dispatchQueue.sync {
            self.threadUnsafeDict.removeValue(forKey: key) // added for preventing crash against below
            self.threadUnsafeDict[key] = value
        }
    }
    
    func remove(key: Key) {
        dispatchQueue.sync {
            guard let index = self.firstIndex(key) else { return }
            self.threadUnsafeDict.remove(at: index)
        }
    }
}
