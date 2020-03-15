import Foundation
import CryptorRSA
import CryptoKit

public class Clavis {
    
    
    public class Generator {
        
        public enum CipherError: Error {
            case failedCreatingKey(String)
            case failedDateEncryption(String)
            case failedDateDecryption(String)
        }
        
        /**
         Generates a license.
         
         - parameters:
            - privateKey: The private RSA key as a `String` in PEM format, which is used to sign the `keyMessage`.
            - keyMessage: The plaintext, which will be signed by the `privateKey`. This can be the persons name, for whom the license should be issued.
         
         - returns:
         A the generated license as a `String`.
         */
        public static func license(privateKey privateKeyString: String, keyMessage: String) throws -> String {
            let privateKey = try CryptorRSA.createPrivateKey(withPEM: privateKeyString)
            
            let plainLicense = try CryptorRSA.createPlaintext(with: keyMessage, using: .utf8)
            let licenseSigned = try plainLicense.signed(with: privateKey, algorithm: .sha256)!
            return licenseSigned.data.base64EncodedString()
        }
    }
    
    
    
    
    public class Validator {
        
        /**
         Checks if the given license is valid and if so stores the valid license in the keychain.
         
         - parameters:
            - license: The license to be validated in `String` format.
            - plaintext: The plaintext, against which the license should be verified.
            - publicKey: The public RSA key as a `String` in PEM format, which is used to verify the license.
         
         - returns:
         A `Bool` value, indicating whether the given license is valid.
         */
        public static func isValid(license licenseString: String, plaintext plaintextString: String, publicKey publicKeyString: String) throws -> Bool {
            // Create key
            let publicKey = try CryptorRSA.createPublicKey(withPEM: publicKeyString)
            
            // Create Plaintext object
            let plaintext = try CryptorRSA.createPlaintext(with: plaintextString, using: .utf8)
            
            // Create License object
            guard let licenseData = Data(base64Encoded: licenseString) else { return false }
            let license = CryptorRSA.SignedData(with: licenseData)
            
            // Verify with public key, that license is equal to plaintext
            let isValidLicense = try plaintext.verify(with: publicKey, signature: license, algorithm: .sha256)
            
            // Save license in keychain
            Keychain.addLicense(Keychain.License(license: licenseString, plaintext: plaintextString))
            
            return isValidLicense
        }
        
        
        /**
         Checks, whether there is a valid license stored in the keychain.
         
         - parameters:
            - publicKey: The public RSA key as a `String` in PEM format, which is used to verify the license.
         
         - returns:
         Returns a `Bool` value, indicating whether there is a valid license stored in the keychain.
         */
        public static func hasValidLicense(publicKey publicKeyString: String) throws -> Bool {
            if let storedLicense = Keychain.getLicense() {
                return try isValid(license: storedLicense.license, plaintext: storedLicense.plaintext, publicKey: publicKeyString)
            }
            return false
        }
    }
    
    
    
    
    class Keychain {
        
        struct License: Codable, Equatable {
            var license: String
            var plaintext: String
        }
        
        
        /**
         Stores a `License` object in the keychain.
         
         - parameters:
            - license: The `License` object, which should be stored in the keychain
         */
        static func addLicense(_ license: License) {
            guard let licenseId = getLicenseId() else { return }
            guard let licenseData = try? PropertyListEncoder().encode(license) else { return }
            let addQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                           kSecAttrLabel as String: licenseId,
                                           kSecAttrDescription as String: "Software License",
                                           kSecValueData as String: licenseData]

            // Add license to keychain
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            
            print("Adding keychain item status: \(SecCopyErrorMessageString(status, nil) ?? "\(status)" as CFString)")
        }
        
        
        /**
         Gets the `License` stored in the keychain.
         
         - returns:
         The `License` object, if one was stored and found, otherwise `nil`.
         */
        static func getLicense() -> License? {
            guard let licenseId = getLicenseId()  else { return nil }
            let getQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                           kSecAttrLabel as String: licenseId,
                                           kSecReturnData as String: true]
            
            // Get license from keychain
            var item: CFTypeRef?
            let status = SecItemCopyMatching(getQuery as CFDictionary, &item)
            guard status == errSecSuccess else { print("Getting keychain item status: \(SecCopyErrorMessageString(status, nil))"); return nil }
            
            // Convert license to string
            //guard let license = String(data: item as! Data, encoding: .utf8) else { return nil }
            guard let licenseData = item as? Data,
                let license = try? PropertyListDecoder().decode(License.self, from: licenseData)
                else { return nil }
            return license
        }
        
        
        /**
         Removes the `License` stored in the keychain.
         */
        public static func removeLicense() {
            guard let licenseId = getLicenseId()  else { return }
            let searchQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                              kSecAttrLabel as String: licenseId]
            
            // Remove the item from the keychain
            let status = SecItemDelete(searchQuery as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { print("Getting keychain item status: \(SecCopyErrorMessageString(status, nil))"); return }
        }
        
        
        /**
         - returns:
         The identifier for the keychain item, which is used to store the license.
         */
        static func getLicenseId() -> String? {
            guard let bundleId = Bundle.main.bundleIdentifier else { return nil }
            let licenseId = bundleId + ".license"
            return licenseId
        }
    }
}
