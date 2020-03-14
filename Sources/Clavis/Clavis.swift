import Foundation
import CryptorRSA

public class Clavis {
    
    
    public class Generator {
        
        public static func license(privateKey privateKeyString: String, keyMessage: String) throws -> String {
            let privateKey = try CryptorRSA.createPrivateKey(withPEM: privateKeyString)
            
            let plainLicense = try CryptorRSA.createPlaintext(with: keyMessage, using: .utf8)
            let licenseSigned = try plainLicense.signed(with: privateKey, algorithm: .sha256)!
            return licenseSigned.data.base64EncodedString()
        }
    }
    
    
    
    
    public class Validator {
        
        public static func hasValidLicense(publicKey publicKeyString: String) throws -> Bool {
            if let storedLicense = Keychain.getLicense() {
                return try isValid(license: storedLicense.license, plaintext: storedLicense.plaintext, publicKey: publicKeyString)
            }
            return false
        }
        
        
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
    }
    
    
    
    
    class Keychain {
        
        struct License: Codable, Equatable {
            var license: String
            var plaintext: String
        }
        
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
        
        
        static func removeLicense() {
            guard let licenseId = getLicenseId()  else { return }
            let searchQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                              kSecAttrLabel as String: licenseId]
            
            // Remove the item from the keychain
            let status = SecItemDelete(searchQuery as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { print("Getting keychain item status: \(SecCopyErrorMessageString(status, nil))"); return }
        }
        
        
        static func getLicenseId() -> String? {
            guard let bundleId = Bundle.main.bundleIdentifier else { return nil }
            let licenseId = bundleId + ".license"
            return licenseId
        }
    }
}
