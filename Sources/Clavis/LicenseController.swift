//
//  LicenseController.swift
//  
//
//  Created by Pascal Braband on 15.03.20.
//

import Foundation
import CryptoKit

public enum LicenseError: Error{
    case failedDecomposingLicense(String)
    case failedDateEncryption(String)
    case failedDateDecryption(String)
}


class LicenseController {
    
    /** A fixed `String`, indicating that a license doesn't have an expiration date. */
    private static let noExpirationDateString = "NoExpiration"
    
    
    /**
     Encrypts a given `Date` with a key to a base64 encoded `String`.
     
     - parameters:
        - date: Optional `Date` object to be encrypted. If is `nil`, then the `noExpirationDateString` will be encrypted.
        - keyString: The key to decrypt the date.
     
     - returns:
     The `date` or `noExpirationDateString` encrypted using the key as a base64 encoded `String`.
     
     - throws:
     Throws errors when failed to encrypt data.
     */
    static func encrypt(date: Date?, with keyString: String) throws -> String  {
        // Create key from keyString
        let key = try SymmetricKey(string: keyString)
                    
        // Format date to String, if date not given -> no expiration
        var dateString = noExpirationDateString
        if date != nil {
            dateString = ISO8601DateFormatter().string(from: date!)
        }
        
        // Create data from date
        guard let dateData = dateString.data(using: .utf8) else { throw LicenseError.failedDateEncryption("Failed to create Data from Date String.") }
        
        // Encrypt dateData using the key
        let encryptedData = try AES.GCM.seal(dateData, using: key)
        
        guard let encryptedDataString = encryptedData.combined?.base64EncodedString() else { throw LicenseError.failedDateEncryption("Failed to get base64 encoded String from encrypted Data.")}
        return encryptedDataString
    }
    
    
    /**
     Decrypts a given `String` with a key to `Date`.
     
     - parameters:
        - date: The possible `Date` as decrypted base64 `String`
        - keyString: The key to decrypt the date.
     
     - returns:
     The decrypted expiration date or `nil`, if the expiration Date is unlimited.
     
     - throws:
     Throws errors when decryption failed or when it's not a `Date` but also not the `noExpirationDateString`.
     */
    static func decrypt(date encryptedString: String, with keyString: String) throws -> Date? {
        // Create key from keyString
        let key = try SymmetricKey(string: keyString)
        
        // Convert encryptedString to a suitable format for decryption
        guard let encryptedData = Data(base64Encoded: encryptedString) else { throw LicenseError.failedDateDecryption("Could not create Data from given base64 encoded date String.") }
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        
        // Decrypt data
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else { throw LicenseError.failedDateDecryption("Failed to convert decrypted data to String.") }
        
        // Decrypt date
        if decryptedString == noExpirationDateString {
            // Return nil if expiration date is unlimited
            return nil
        } else {
            // Return date if it is decodable from the String. Throw error otherwise
            guard let date = ISO8601DateFormatter().date(from: decryptedString) else { throw LicenseError.failedDateDecryption("Failed to decode Date from decrypted String.") }
            return date
        }
    }
    
    
    static func composeLicense(publicKey publicKeyString: String, licenseString: String, expirationDate: Date?) throws -> String {
        let encryptedDate = try encrypt(date: expirationDate, with: publicKeyString.removeSecKeyComments())
        let composed = encryptedDate + "-" + licenseString
        return composed
    }
    
    
    static func decomposeLicense(publicKey publicKeyString: String, licenseString: String) throws -> (Date?, String) {
        let licenseParts = licenseString.split(separator: "-").map({ String($0) })
        guard licenseParts.count == 2 else { throw LicenseError.failedDecomposingLicense("License not separable into 2 parts.") }
        let expirationDate = try LicenseController.decrypt(date: licenseParts[0], with: publicKeyString.removeSecKeyComments())
        let license = licenseParts[1]
        
        return (expirationDate, license)
    }
    
}
