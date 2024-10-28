//
//  XRayVPMManager.swift
//  XRayLib
//
//  Created by Bahdan Piatrouski on 22.10.24.
//

import Foundation
import NetworkExtension
import SystemConfiguration

public typealias XRayProviderManagerCompletion = (_ manager: NETunnelProviderManager?) -> Void

public class XRayVPMManager {
    public static let shared = XRayVPMManager()
    
    private var _isVPNActive = false
    
    public var isVPNActive: Bool {
        self._isVPNActive
    }
    
    public var vpn: String?
    
    public static var kApplicationVPNLocalizedDescription = "VPN Tunnel Package"
    public static var kApplicationVPNServerAddress = "com.yourcompany"
    
    public init() {
        if Self.kApplicationVPNServerAddress == "com.yourcompany" {
            fatalError("Enter your variables into kApplicationVPNLocalizedDescription and kApplicationVPNServerAddress")
        }
    }
    
    public func fetchVPMManager(_ completion: @escaping XRayProviderManagerCompletion) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if managers?.isEmpty ?? true {
                self.createVPNConfiguration(completion)
                if let error {
                    debugPrint("loadAllFromPreferencesWithCompletionHandler: \(error)")
                }
                
                return
            }
            
            self.handlePreferences(managers, completion: completion)
        }
    }
    
    public func applyConfiguration(_ mode: String?) {
        
    }
    
    public func ping(_ x: String?) -> [String: String] {
        let pings = XRayFutureManager.ping(x)
        return [
            "action": "response",
            "type": "ping",
            "pings": pings ?? ""
        ]
    }
    
    public func stopTunnelWithReason() {
        XRayFutureManager.shared.stopTunnelWithReason()
    }
    
    public static func setLogLevel(_ l: XLogLevel) {
        XRayFutureManager.setLogLevel(l)
    }
    
    public static func setGlobalProxyEnable(_ enable: Bool) {
        XRayFutureManager.setGlobalProxyEnable(enable)
    }
    
    public static func setSocks5Enable(_ enable: Bool) {
        XRayFutureManager.setSocks5Enable(enable)
    }
    
    public static func parseURI(_ uri: String?) -> [String: Any]? {
        XRayFutureManager.parseURI(uri)
    }
    
    public func startTunnelWithOptions(_ options: NSDictionary?, configuration: NSDictionary?) {
        XRayFutureManager.shared.startTunnelWithOptions(options, configuration: configuration)
    }
}

// MARK: - Private
private extension XRayVPMManager {
    func handlePreferences(_ managers: [NETunnelProviderManager]?, completion: @escaping XRayProviderManagerCompletion) {
        guard let managers else {
            completion(nil)
            return
        }
        
        var manager: NETunnelProviderManager?
        for item in managers {
            if item.localizedDescription == Self.kApplicationVPNLocalizedDescription {
                manager = item
                break
            }
        }
        
        guard let manager else {
            completion(nil)
            return
        }
        
        completion(manager)
        debugPrint("Found a VPN configuration")
    }
    
    func createVPNConfiguration(_ completion: @escaping XRayProviderManagerCompletion) {
        let manager = NETunnelProviderManager()
        let protocolConfiguration = NETunnelProviderProtocol()
        
        protocolConfiguration.serverAddress = Self.kApplicationVPNServerAddress
        
        // providerConfiguration can be customized for storage
        protocolConfiguration.providerConfiguration = [:]
        manager.protocolConfiguration = protocolConfiguration
        
        manager.localizedDescription = Self.kApplicationVPNLocalizedDescription
        manager.isEnabled = true
        manager.saveToPreferences { error in
            if let error {
                debugPrint("saveToPreferencesWithCompletionHandler:\(error)")
                completion(nil)
                return
            }
            
            manager.loadFromPreferences { error in
                if let error {
                    debugPrint("loadFromPreferencesWithCompletionHandler:\(error)")
                    completion(nil)
                    return
                }
                
                completion(manager)
            }
        }
    }
}
