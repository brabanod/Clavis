//
//  String+Extension.swift
//  
//
//  Created by Pascal Braband on 15.03.20.
//

import Foundation

extension String {
    
    func removeSecKeyComments() -> String {
        let regex = "(?i)(\n)?-* ?(BEGIN|END) ((PRIVATE RSA|PUBLIC RSA)|(RSA PRIVATE|RSA PUBLIC)|(PRIVATE|PUBLIC)) KEY ?-*(\n)?"
        let cleanString = self.replacingOccurrences(of: regex, with: "", options: [.regularExpression])
        return cleanString
    }
}
