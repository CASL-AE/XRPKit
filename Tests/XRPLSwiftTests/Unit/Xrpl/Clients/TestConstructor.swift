//
//  File.swift
//  
//
//  Created by Denis Angell on 7/28/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/test/client/constructor.ts

import Foundation

import XCTest
@testable import XRPLSwift

final class TestConstructor: XCTestCase {
    
    func testClientConstructor() {
        _ = try! XrplClient(server: "wss://s1.ripple.com")
    }
    
    // TODO: SHOULD PASS
    func _testClientInvalidOptions() {
        let options: ClientOptions = ClientOptions(
            feeCushion: nil,
            maxFeeXRP: nil,
            proxy: nil,
            timeout: nil
        )
        XCTAssertThrowsError(try XrplClient(server: "wss://s1.ripple.com", options: options))
    }
    
    func testClientValidOptions() {
        let client = try! XrplClient(server: "wss://s:1")
        XCTAssertEqual(client.url(), "wss://s:1")
    }
    
    // TODO: SHOULD FAIL
    func testClientInvalidConstructor() {
        XCTAssertThrowsError(try XrplClient(server: "wss://s:1"))
    }
}
