//
//  SecureDataStore.swift
//  Split
//
//  Created by Natalia  Stele on 19/01/2018.
//

import Foundation



public class SecureDataStore {
    
    let tokenSemaphore = NSRecursiveLock()
    
    enum asset: String {
        case accessToken = "user_auth_token"
    }
    
    
    public static let shared: SecureDataStore = {
        let instance = SecureDataStore();
        
        return instance;
    }()
    
    
    // MARK: - save access token
    
    public func setToken(token: String){
        tokenSemaphore.lock()
      
        
        
        if let token = getToken() {
            Logger.d(token)
            removeToken()
        }
        
        guard let valueData = token.data(using: String.Encoding.utf8) else {
            Logger.e("Error saving text to Keychain")
            tokenSemaphore.unlock()
            return
        }
        
        let queryAdd: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: asset.accessToken.rawValue,
            kSecValueData as String: valueData,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        
        let resultCode = SecItemAdd(queryAdd as CFDictionary, nil)
        
        if resultCode != noErr {
            
            Logger.e("Error saving to Keychain: \(resultCode).")
            
        } else {
            
            Logger.d("Saved to keychain successfully.")
            
        }
        tokenSemaphore.unlock()
    }
    
    // MARK: - retrieve access token
    
    public func getToken() -> String? {
        tokenSemaphore.lock()
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: asset.accessToken.rawValue
        ]
        
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        
        // Search for the keychain items
        var result: AnyObject?
        var lastResultCode: OSStatus = noErr
        
        lastResultCode = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }
        
        if lastResultCode == noErr, let dic = result as? [String:Any],let data = dic[kSecValueData as String] as? Data {
            
            if let token = String(data: data, encoding: .utf8) {
                tokenSemaphore.unlock()
                return token
            }
        }
        tokenSemaphore.unlock()
        return nil
    }
    
    // MARK: - delete access token
    
    public func removeToken() {
        tokenSemaphore.lock()
        
        let queryDelete: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: asset.accessToken.rawValue
        ]
        
        let resultCodeDelete = SecItemDelete(queryDelete as CFDictionary)
        
        if resultCodeDelete != noErr {
            
            Logger.e("Error deleting from Keychain: \(resultCodeDelete)")
            
        } else {
            
            Logger.d("Removed successfully from the keychain")
            
        }
        
        tokenSemaphore.unlock()
        
    }
    
}
