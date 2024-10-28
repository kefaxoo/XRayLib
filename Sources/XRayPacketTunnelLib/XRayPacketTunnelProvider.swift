//
//  XRayPacketTunnelProvider.swift
//  XRayLib
//
//  Created by Bahdan Piatrouski on 23.10.24.
//

import NetworkExtension
import XRayLib

open class XRayPacketTunnelProvider: NEPacketTunnelProvider {
    private static func logRedirect() {
        let logFilePath = String(format: "%@/Documents/%@", NSHomeDirectory(), "xray.log")
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: logFilePath))
        FileManager.default.createFile(atPath: logFilePath, contents: nil)
        freopen(logFilePath.cString(using: .ascii), "w+", stdout)
        freopen(logFilePath.cString(using: .ascii), "w+", stderr)
    }
    
    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping ((any Error)?) -> Void) {
        Self.logRedirect()
        var options = options
        if options == nil {
            let protocolConfiguration = self.protocolConfiguration as? NETunnelProviderProtocol
            let dict = protocolConfiguration?.providerConfiguration
            options = dict?["configuration"] as? [String: NSObject]
        }
        
        XRayFutureManager.shared.setPacketTunnelProvider(self)
        XRayFutureManager.shared.startTunnelWithOptions(options, completionHandler: completionHandler)
    }
    
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }
    
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        XRayFutureManager.setLogLevel(.warning)
        XRayFutureManager.setGlobalProxyEnable(false)
        
        let app = (try? JSONSerialization.jsonObject(with: messageData, options: .mutableContainers)) as? [String: Any]
        let type = app?["type"] as? Int
        let version = XRayFutureManager.version
        
        // Set up the configuration file
        if type == 0 {
            let configuration = app?["configuration"] as? String
            XRayFutureManager.shared.setupURL(configuration)
        }
        
        let response = [
            "desc": 200,
            "version": version,
            "tunnel_version": "1.0.7"
        ] as [String: Any]
        
        let ack = try? JSONSerialization.data(withJSONObject: response, options: .prettyPrinted)
        completionHandler?(ack)
    }
    
    open override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}
