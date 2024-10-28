//
//  XRayFutureManager.swift
//  XRayLib
//
//  Created by Bahdan Piatrouski on 22.10.24.
//

import Foundation
import NetworkExtension
import Future

public typealias XRayVPNDelayResponse = (_ isSuccess: Bool, _ delay: Float) -> Void

public enum XLogLevel: Int {
    case verbose
    case info
    case warning
    case error
    
    var string: String {
        switch self {
        case .verbose:
            "verbose"
        case .info:
            "info"
        case .warning:
            "warning"
        case .error:
            "error"
        }
    }
}

public protocol XRayVPNManagerDelegate: NSObject {
    /// Internet speed callback, once a second
    /// - Parameter speed: Unit bps
    /// - Parameter upload: true means upload, false means download
    func onConnectionSpeedReport(_ speed: Int, uplink: Bool)
}

public class XRayFutureManager: NSObject {
    public static let shared = XRayFutureManager()
    
    private var _dns = [String]()
    private var xray: [String: Any]?
    
    private var mProvider: NEPacketTunnelProvider?
    private var _allDNSServers = [String]()
    private var mSession: URLSession?
    private var mTimerQueue = DispatchQueue(label: "com.XRayLib.queue", attributes: .initiallyInactive)
    private var mUDPTimeout: CLongLong?
    private var mTCPTimeout: CLongLong?
    private var mHTTPDownFlow: CLongLong?
    private var mHTTPUpFlow: CLongLong?
    private var mTCPDownFlow: CLongLong?
    private var mTCPUpFlow: CLongLong?
    private var mRunning: Bool?
    
    public weak var delegate: XRayVPNManagerDelegate?
    
    public static var version: String {
        "25-\(FutureCheckVersionX())"
    }
    
    public var allDNSServers: [String] { self._allDNSServers }
    
    public var dns: [String] {
        // Temporary date
        ["114.114.114.114", "8.8.8.8"]
        
        // TODO: find method to fetch all dns in swift
    }
    
    public override init() {
        super.init()
        
        self.mTimerQueue.async { [weak self] in
            while true {
                self?.getStats()
                var timeout = timespec()
                timeout.tv_sec = 1
                timeout.tv_nsec = 0
                nanosleep(&timeout, nil)
            }
        }
    }
    
    public static func setLogLevel(_ level: XLogLevel) {
        XRayProtocolParser.setLogLevel(level.string)
    }
    
    public static func setHTTPProxyPort(_ port: Int) {
        XRayProtocolParser.setHttpProxyPort(UInt16(port))
    }
    
    public static func setGlobalProxyEnable(_ enable: Bool) {
        XRayProtocolParser.setGlobalProxyEnable(enable)
        let file = Bundle.main.path(forResource: "geosite", ofType: "dat") // TODO: File
        if let file,
           FileManager.default.fileExists(atPath: file) {
            let path = Bundle.main.resourcePath?.appending("/")
            FutureInitV2Env(path)
        }
    }
    
    public static func setDirectDomainList(_ list: [Any]) {
        XRayProtocolParser.setDirectDomainList(list)
    }
    
    public static func setProxyDomainList(_ list: [Any]) {
        XRayProtocolParser.setProxyDomainList(list)
    }
    
    public static func setBlockDomainList(_ list: [Any]) {
        XRayProtocolParser.setBlockDomainList(list)
    }
    
    public static func setSocks5Enable(_ socks5Enable: Bool) {
        
    }
    
    public static func parseURI(_ uri: String?) -> [String: Any]? {
        let list = uri?.components(separatedBy: "//")
        guard list?.count == 2 else { return nil }
        
        let `protocol`: xVPNProtocol? = if list?[0].contains("vmess") ?? false {
            .vmess
        } else if list?[0].contains("vless") ?? false {
            .vless
        } else {
            nil
        }
        
        guard let `protocol` else { return nil }
        
        return XRayProtocolParser.parse(list?[1], protocol: `protocol`)
    }
    
    public static func ping(_ ips: String?) -> String? {
        // FuturePing(ips)
        ""
    }
    
    public func setPacketTunnelProvider(_ provider: NEPacketTunnelProvider?) {
        self.mProvider = provider
    }
    
    public func startTunnelWithOptions(_ options: [String: NSObject]?, completionHandler: @escaping((Error?) -> Void)) {
        if let url = options?["uri"] as? String {
            self.setupURL(url)
            if let global = options?["global"] as? Bool {
                Self.setGlobalProxyEnable(global)
            }
        }
        
        guard let xray else {
            let error = NSError(domain: "Invalid Configuration", code: -1)
            completionHandler(error)
            return
        }
        
        let c = try? JSONSerialization.data(withJSONObject: xray, options: .prettyPrinted)
        let r = FutureStartVPN(c, self)
        guard r.isEmpty else {
            let error = NSError(domain: "Invalid json", code: 204)
            completionHandler(error)
            return
        }
        
        debugPrint("vpn configuration: \(xray)")
        
        FutureRegisterAppleNetworkInterface(self)
        
        self.mRunning = true
        let networkSettings = self.createNetworkSettings()
        self.mProvider?.setTunnelNetworkSettings(networkSettings, completionHandler: { [weak self] error in
            if let error {
                debugPrint("xx-\(error)")
            }
            
            self?.readPackets()
            completionHandler(error)
        })
    }
    
    public func stopTunnelWithReason(_ reason: NEProviderStopReason, completionHandler: @escaping(() -> Void)) {
        DispatchQueue.global(qos: .default).async {
            FutureStopVPN()
            completionHandler()
        }
    }
    
    public func wake() {
        
    }
    
    public func google204Delay(_ response: XRayVPNDelayResponse? = nil) {
        DispatchQueue.global(qos: .default).async {
            let duration = FutureGoogle204Delay()
            response?(duration != -1, Float(duration))
        }
    }
    
    public func sleepWithCompletionHandler(_ completionHandler: @escaping(() -> Void)) {
        completionHandler()
    }
    
    @discardableResult public func setupURL(_ url: String?) -> Bool {
        let configuration = Self.parseURI(url)
        if configuration == nil {
            return false
        }
        
        self.xray = configuration
        return true
    }
    
    public func startTunnelWithOptions(_ options: NSDictionary? = nil, configuration: Any?) {
        let c = try? JSONSerialization.data(withJSONObject: configuration as Any, options: .prettyPrinted)
        FutureStartVPN(c, self)
    }
    
    public func stopTunnelWithReason() {
        FutureStopVPN()
    }
}

// MARK: - Private
private extension XRayFutureManager {
    func writeToPacketFlow(_ ipPacket: Data?, family: Int) {
        guard let ipPacket else { return }
        
        self.mProvider?.packetFlow.writePackets([ipPacket], withProtocols: [NSNumber(value: family)])
    }
    
    func xNSPrint(_ logStr: String) {
        debugPrint("lwip=> \(logStr)")
    }
    
    func createNetworkSettings() -> NEPacketTunnelNetworkSettings {
        self._allDNSServers.removeAll()
        
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        let dns = Set(self.dns)
        
        dns.forEach({ self._allDNSServers.append($0) })
        
        networkSettings.dnsSettings = NEDNSSettings(servers: self._allDNSServers)
        networkSettings.mtu = 4096
        
        // Here is actually to create a virtual IP address, you need to create your own route
        let ipv4Settings = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [.default()]
        ipv4Settings.excludedRoutes = []
        networkSettings.ipv4Settings = ipv4Settings
        
        let proxySettings = NEProxySettings()
        let http = NEProxyServer(address: "127.0.0.1", port: Int(XRayProtocolParser.httpProxyPort))
        proxySettings.httpEnabled = true
        proxySettings.httpsEnabled = true
        proxySettings.httpServer = http
        proxySettings.httpsServer = http
        proxySettings.excludeSimpleHostnames = true
        proxySettings.autoProxyConfigurationEnabled = false
        proxySettings.exceptionList = [
            "captive.apple.com",
            "10.0.0.0/8",
            "localhost",
            "*.local",
            "172.16.0.0/12",
            "198.18.0.0/15",
            "114.114.114.114.dns",
            "192.168.0.0/16"
        ]
        
        networkSettings.proxySettings = proxySettings
        return networkSettings
    }
    
    func readPackets() {
        self.mProvider?.packetFlow.readPackets(completionHandler: { [weak self] packets, protocols in
            for i in 0..<packets.count {
                FutureWriteAppleNetworkInterfacePacket(packets[i])
//                self?.sendPacket(packets[i], family: protocols[i].intValue)
            }
            
            self?.readPackets()
        })
    }
    
    func getStats() {
        // Objective-C Code
        //
        //    int64_t downlink = FutureQueryStats(@"proxy", @"downlink");
        //    int64_t uplink = FutureQueryStats(@"proxy", @"uplink");
        //    if ([self.delegate respondsToSelector:@selector(onConnectionSpeedReport:uplink:)]) {
        //        [self.delegate onConnectionSpeedReport:downlink uplink:NO];
        //        [self.delegate onConnectionSpeedReport:uplink uplink:YES];
        //    }
    }
}

// MARK: - FuturePlatformWriterProtocol
extension XRayFutureManager: FuturePlatformWriterProtocol {
    public func write(to payload: String?) {
        debugPrint(payload)
    }
}

// MARK: - FutureAppleNetworkinterfaceProtocol
extension XRayFutureManager: FutureAppleNetworkinterfaceProtocol {
    public func writePacket(_ payload: Data?) -> Int {
        guard let payload else { return 0 }
        
        self.mProvider?.packetFlow.writePackets([payload], withProtocols: [NSNumber(value: AF_INET)])
        return payload.count
    }
}
