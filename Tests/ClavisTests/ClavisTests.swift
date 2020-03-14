//
//  ClavisTests.swift
//  clavis
//
//  Created by Pascal Braband on 14.03.20.
//  Copyright © 2019 Pascal Braband. All rights reserved.
//

import XCTest
@testable import Clavis

class ClavisTests: XCTestCase {
    
    let privateKey = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA8yNjQgx0wBm7jMZGiMf2cCKlq/qd3EQen9zzsJip7mFXFuU1
    do1FvPvk5Eqywe2ekAcbj6MhX0LsJiyaVevpQW4X1NcvKiQh2D5vs41Slf57MauB
    DDkSuXATX9hlf08DBxQISJBRs1BSuv+QpWIl+mf6g2Ql6V/eglqr/secAqm/HIyD
    bQhQbWKmGnaqygaLu81a1LSPKhbERiW76mxa68rhMts+WvfA5fpW4m5gCE3J9Leg
    JDdrQ/D4ni4DRU1TumlaqTTQZPxRnHkyJKe+H+Ko0HxF4RSUXYDf6iYoHGw2h+ZQ
    DdeV/QyQnsf5b26xItetqCqRkGLRXWGJT/Rt5QIDAQABAoIBADyVUsRAak77mnoH
    ZcfrW4Kxf2qM9gzOhHr9CVO1lpIpexPfZST3KqtecLhZzJT56oqk2r89vLEJ8eHJ
    N2O1dtew4QtN2xi7DBvf4uFwk2WAlZ3YyD0Nc5b1UD6PoyrHu09mNHIwU8tEdnjV
    +WrcO+5bPlbC+5ddJgqBIV5Iypz2xqxyz2hrkwY20kSShJSZ0T7ULdvcnjsUKIrY
    aDghvLB3Ba/1zAMT6dZvRTYdCR26spjjbekibUqvbB7YBxWGzs9fGFuvVeaa/f6p
    +ddupsEHj/Qi8xmp3QHwT+thtof8EFfMs59Ksn3hQp9iVSgp9e6HY9mnTZ6JJCbo
    kwPZxLkCgYEA+wnoOjkRwQiMTPQuCud9IQrN1/gKuxGca5q5YptP8eiW2nqEtWF8
    J+vqe4Zx1wn/5MLchVvXRCI2PAfH0G+mpfyMyjE8RuT4kJmiIfG376HlLFfjAeEL
    0vZ9rDUNJ0SSZvmY4QRLU7HwgU4OsXRGT8Tn4V+ee8ef2TiURei2XEcCgYEA9/GC
    ZS6mJcSPu6PPZPxdnloAaN6RhzjUFecS4Y/rRENjVgdTPk78Ca/EvWUrS4diTRsv
    3xvFKqhBYvm5aVVq6ff19vtYnDgLdRwsjk+2HRGQvMgQs9PvsZJykj4WDrTB0gDp
    9Wr1K624QRgluVDMKy5CSF0QyKhUkDzut+/eNnMCgYAOc9KPz4tLHq/dGk2wSQV2
    KoYRQfF0NZ5Yv46es6xVk/tjVpxfSN55+eYE+IeDRssZo3JIpzHsdT/EEvqY8GSa
    t8BvP4hl2HbK9F1WMPFS9XIZLHIgQJGKsrAnguJf+V2oWgRIKBQiHGNpPlIwOy51
    FzP2UKfyHlsAiXZX0/7zrwKBgC6TYJJPRAi+Nt3htLjcq11uvLr2bFIBe92tbZ+P
    oHtPSV7Eu39t6OyM5yFI2uwyP2YKoGCB3/TWbIoCLTE7SX0wBjViG9AkuwpBw6Ds
    GmK1hQHhdznAqzspLnqITS5wCCTB5TEj6XBODtmzhoqcQe4un2bmjJuU+2Wo/JLy
    7UQ/AoGBAMGgR4R+2qKuYRDjjFfuocHWTftJFwYCtxXth21NbNSDdejtSmurY9Eg
    cQzCrkha7RrEjkh3OAkjZ2jaTVmOmo98RRvLAn2mFCdz/gcGQ6WmKT6hanMOxh/x
    0PcXMFvTKGJdnlRui1XZxoyy8VU0uruZ3sgnxChlMB0T0FX9xDvG
    -----END RSA PRIVATE KEY-----
    """
    
    let publicKey = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8yNjQgx0wBm7jMZGiMf2
    cCKlq/qd3EQen9zzsJip7mFXFuU1do1FvPvk5Eqywe2ekAcbj6MhX0LsJiyaVevp
    QW4X1NcvKiQh2D5vs41Slf57MauBDDkSuXATX9hlf08DBxQISJBRs1BSuv+QpWIl
    +mf6g2Ql6V/eglqr/secAqm/HIyDbQhQbWKmGnaqygaLu81a1LSPKhbERiW76mxa
    68rhMts+WvfA5fpW4m5gCE3J9LegJDdrQ/D4ni4DRU1TumlaqTTQZPxRnHkyJKe+
    H+Ko0HxF4RSUXYDf6iYoHGw2h+ZQDdeV/QyQnsf5b26xItetqCqRkGLRXWGJT/Rt
    5QIDAQAB
    -----END PUBLIC KEY-----
    """

    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        Clavis.Keychain.removeLicense()
    }
    
    
    func testAddAndGetKeychainLicense() {
        let license = Clavis.Keychain.License(license: "1234-5678-ABCD-EFGH", plaintext: "unused here")
        Clavis.Keychain.addLicense(license)
        let keychainLicense = Clavis.Keychain.getLicense()
        XCTAssertEqual(keychainLicense, license)
    }
    
    
    func testGenerateValidate() throws {
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, keyMessage: plaintext)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, true)
    }
    
    
    func testStoredLicense() throws {
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, keyMessage: plaintext)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, true)
        
        // Validate with stored license
        let validateAgain = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validationResult, true)
        
        // Validate with removed license
        Clavis.Keychain.removeLicense()
        let validateAgainRemoved = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgainRemoved, false)
    }
}
