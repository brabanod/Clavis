//
//  ClavisTests.swift
//  Clavis
//
//  Created by Pascal Braband on 14.03.20.
//  Copyright © 2019 Pascal Braband. All rights reserved.
//

import XCTest
@testable import Clavis
import CryptoKit

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
    
    
    func testGenerateValidateUnlimited() throws {
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: nil)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, true)
    }
    
    
    func testStoredLicenseUnlimited() throws {
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: nil)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, true)
        
        // Validate with stored license
        let validateAgain = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgain, true)
        
        // Validate with removed license
        Clavis.Keychain.removeLicense()
        let validateAgainRemoved = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgainRemoved, false)
    }
    
    
    func testGenerateValidateLimitedValid() throws {
        // Expiration Date in one minute (will expire in one minute, thus still valid)
        let expirationDate = Date() + 60.0
        
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: expirationDate)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, true)
    }
    
    
    func testStoredLicenseLimitedValid() throws {
        // Expiration Date in one minute (will expire in one minute, thus still valid)
        let expirationDate = Date() + 60.0
        
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: expirationDate)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, true)
        
        // Validate with stored license
        let validateAgain = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgain, true)
        
        // Validate with removed license
        Clavis.Keychain.removeLicense()
        let validateAgainRemoved = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgainRemoved, false)
    }
    
    
    func testGenerateValidateLimitedInvalid() throws {
        // Expiration Date before one minute (did expire one minute ago, thus invalid)
        let expirationDate = Date() - 60.0
        
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: expirationDate)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, false)
    }
    
    
    func testStoredLicenseLimitedInvalid() throws {
        // Expiration Date before one minute (did expire one minute ago, thus invalid)
        let expirationDate = Date() - 60.0
        
        let plaintext = "test message"
        let license = try Clavis.Generator.license(privateKey: privateKey, publicKey: publicKey, keyMessage: plaintext, expirationDate: expirationDate)
        let validationResult = try Clavis.Validator.isValid(license: license, plaintext: plaintext, publicKey: publicKey)
        
        XCTAssertEqual(validationResult, false)
        
        // Validate with stored license
        let validateAgain = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgain, false)
        
        // Validate with removed license
        Clavis.Keychain.removeLicense()
        let validateAgainRemoved = try Clavis.Validator.hasValidLicense(publicKey: publicKey)
        XCTAssertEqual(validateAgainRemoved, false)
    }
    
    
    func testEncryptDecryptDate() throws {
        let date = Date()
        guard let dateEncrypted = try? LicenseController.encrypt(date: Date(), with: publicKey.removeSecKeyComments()) else { XCTFail("Encrypt shouldn't return nil."); return }
        guard let dateDecrypted = try LicenseController.decrypt(date: dateEncrypted, with: publicKey.removeSecKeyComments()) else { XCTFail("Decrypt shouldn't return nil."); return }
        
        XCTAssertEqual(ISO8601DateFormatter().string(from: date), ISO8601DateFormatter().string(from: dateDecrypted))
    }
    
    
    func testEncryptDecryptDateUnlimited() throws {
        guard let dateEncrypted = try? LicenseController.encrypt(date: nil, with: publicKey.removeSecKeyComments()) else { XCTFail("Encrypt shouldn't return nil."); return}
        let dateDecrypted = try LicenseController.decrypt(date: dateEncrypted, with: publicKey.removeSecKeyComments())
        
        XCTAssertNil(dateDecrypted)
    }
    
    
    func testEncryptDecryptDateWrongInput() throws {
        do {
            let _ = try LicenseController.decrypt(date: "gibberish", with: publicKey.removeSecKeyComments())
            XCTFail("Should throw error")
        } catch let error {
            print(error)
        }
    }
    
    
    func testBase64EncodeDecode() {
        // Create Base64 encoded String from a cleartext String
        let cleartext = "this is a simple test"
        guard let cleartextDataUTF8 = cleartext.data(using: .utf8) else { XCTFail("Failed to create Base64 Data from String"); return }
        let cleartextDataBase64String = cleartextDataUTF8.base64EncodedString()
        
        print("\n\"\(cleartext)\" encoded in Base64 String:\n\(cleartextDataBase64String)\n")
        
        // Decode Base64 encoded String to a cleartext String
        guard let cleartextDecodedData = Data(base64Encoded: cleartextDataBase64String) else { return }
        guard let cleartextDecodedString = String(data: cleartextDecodedData, encoding: .utf8) else { return }
        
        print("\n\"\(cleartextDecodedString)\" decoded from Base64 String:\n\(cleartextDataBase64String)\n")
        
        XCTAssertEqual(cleartext, cleartextDecodedString)
    }
}
