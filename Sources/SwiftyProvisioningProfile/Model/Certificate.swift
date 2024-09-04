//
//  Certificate.swift
//  SwiftyProvisioningProfile
//
//  Created by Sherlock, James on 20/11/2018.
//

import Foundation

public struct Certificate: Encodable, Equatable {

    public enum InitError: Error {
        case failedToFindValue(key: String)
        case failedToCastValue(expected: String, actual: String)
        case failedToFindLabel(label: String)
    }
    
    public let notValidBefore: Date
    public let notValidAfter: Date
    
    public let issuerCommonName: String
    public let issuerCountryName: String
    public let issuerOrgName: String
    public let issuerOrgUnit: String
    
    public let commonName: String?
    public let countryName: String
    public let orgName: String?
    public let orgUnit: String
    
    public let serialNumer: String
    public let sha1: String
    
    init(results: [CFString: Any], commonName: String?) throws {
        self.commonName = commonName
        
        notValidBefore = try Certificate.getValue(for: kSecOIDX509V1ValidityNotBefore, from: results)
        notValidAfter = try Certificate.getValue(for: kSecOIDX509V1ValidityNotAfter, from: results)
        
        let issuerName: [[CFString: Any]] = try Certificate.getValue(for: kSecOIDX509V1IssuerName, from: results)
        issuerCommonName = try Certificate.getValue(for: kSecOIDCommonName, fromDict: issuerName)
        issuerCountryName = try Certificate.getValue(for: kSecOIDCountryName, fromDict: issuerName)
        issuerOrgName = try Certificate.getValue(for: kSecOIDOrganizationName, fromDict: issuerName)
        issuerOrgUnit = try Certificate.getValue(for: kSecOIDOrganizationalUnitName, fromDict: issuerName)
        
        let subjectName: [[CFString: Any]] = try Certificate.getValue(for: kSecOIDX509V1SubjectName, from: results)
        countryName = try Certificate.getValue(for: kSecOIDCountryName, fromDict: subjectName)
        orgName = try? Certificate.getValue(for: kSecOIDOrganizationName, fromDict: subjectName)
        orgUnit = try Certificate.getValue(for: kSecOIDOrganizationalUnitName, fromDict: subjectName)
        serialNumer = try Certificate.getValue(for: kSecOIDX509V1SerialNumber, from: results)
        
        let fingerprints: [[CFString: Any]] = try Certificate.getValue(for: "Fingerprints" as CFString, from: results)
        let sha1Data: Data = try Certificate.getValue(for: "SHA-1" as CFString, fromDict: fingerprints)
        sha1 = sha1Data.hexString()
    }

    static func getValue<T>(for key: CFString, from values: [CFString: Any]) throws -> T {
        let node = values[key] as? [CFString: Any]
        
        guard let rawValue = node?[kSecPropertyKeyValue] else {
            throw InitError.failedToFindValue(key: key as String)
        }
        
        if T.self is Date.Type {
            if let value = rawValue as? TimeInterval {
                // Force unwrap here is fine as we've validated the type above
                return Date(timeIntervalSinceReferenceDate: value) as! T
            }
        }
        
        guard let value = rawValue as? T else {
            let type = (node?[kSecPropertyKeyType] as? String) ?? String(describing: rawValue)
            throw InitError.failedToCastValue(expected: String(describing: T.self), actual: type)
        }
        
        return value
    }
    
    static func getValue<T>(for key: CFString, fromDict values: [[CFString: Any]]) throws -> T {
        
        guard let results = values.first(where: { ($0[kSecPropertyKeyLabel] as? String) == (key as String) }) else {
            throw InitError.failedToFindLabel(label: key as String)
        }
        
        guard let rawValue = results[kSecPropertyKeyValue] else {
            throw InitError.failedToFindValue(key: key as String)
        }
        
        guard let value = rawValue as? T else {
            let type = (results[kSecPropertyKeyType] as? String) ?? String(describing: rawValue)
            throw InitError.failedToCastValue(expected: String(describing: T.self), actual: type)
        }
        
        return value
    }
    
}

extension Data {
    /// 将 Data 转换为十六进制字符串
    func hexString() -> String {
        return map { String(format: "%02hhx", $0) }.joined().uppercased()
    }
}
