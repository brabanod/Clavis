//
//  SymmetricKey+Extension.swift
//  
//
//  Created by Pascal Braband on 15.03.20.
//

import Foundation
import CryptoKit

extension SymmetricKey {
    
    /**
     Create a `SymmetricKey` from a `String`.
     
     - parameters:
        - keyString: The base64 encoded `String`, which should be used to create the `SymmetricKey`.
        - size: The size as `SymmetricKeySize` used to truncate the possibly to long `keyString`.
     
     - returns:
     A `SymmetricKey`.
     
     - throws:
     Throws errors, when creating the key from the given `String` isn't successful.
     */
    init(string keyString: String, size: SymmetricKeySize = .bits128) throws {
        // Create base64 encoded Data from String
        guard var keyData = Data(base64Encoded: keyString, options: .ignoreUnknownCharacters) else { throw CryptoKitError.incorrectParameterSize }
        
        // Only take the first n bits of keyData, specified by the size
        let keySizeBytes = size.bitCount / 8
        keyData = keyData.subdata(in: 0..<keySizeBytes)
        
        // Check if key is big enough for given size
        guard keyData.count >= keySizeBytes else { throw CryptoKitError.incorrectKeySize }
        
        // Create key from Data
        self.init(data: keyData)
    }
}
