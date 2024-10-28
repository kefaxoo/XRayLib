//
//  XRayProtocolParser.swift
//  XRayLib
//
//  Created by Bahdan Piatrouski on 22.10.24.
//

import Foundation

public enum xVPNProtocol: Int {
    case vmess
    case vless
}

public class XRayProtocolParser {
    public static var httpProxyPort: UInt16 { self._httpProxyPort }
    
    private static var _httpProxyPort: UInt16 = 1082
    private static var logLevel: String = "info"
    private static var globalGeositeEnable = false
    private static var globalGeoipEnable = false
    private static var directDomainList = [Any]()
    private static var proxyDomainList = [Any]()
    private static var blockDomainList = [Any]()
    
    public static func parse(_ uri: String?, protocol vpnProtocol: xVPNProtocol) -> [String: Any]? {
        switch vpnProtocol {
        case .vmess:
            self.parseVmess(uri)
        case .vless:
            self.parseVless(uri)
        }
    }
    
    public static func setHttpProxyPort(_ port: UInt16) {
        self._httpProxyPort = port
    }
    
    public static func setLogLevel(_ level: String) {
        self.logLevel = level
    }
    
    public static func setGlobalProxyEnable(_ enable: Bool) {
        self.globalGeositeEnable = !enable
        self.globalGeoipEnable = !enable
    }
    
    public static func setDirectDomainList(_ list: [Any]) {
        self.directDomainList = list
    }
    
    public static func setProxyDomainList(_ list: [Any]) {
        self.proxyDomainList = list
    }
    
    public static func setBlockDomainList(_ list: [Any]) {
        self.blockDomainList = list
    }
    
    public static func parseUri(_ uri: String?) -> [String: Any]? {
        let list = uri?.components(separatedBy: "//")
        guard list?.count == 2 else { return nil }
        
        let vpnProtocol: xVPNProtocol? = if list?[0].contains("vmess") ?? false {
            .vmess
        } else if list?[0].contains("vless") ?? false {
            .vless
        } else {
            nil
        }
        
        guard let vpnProtocol else { return nil }
        
        return Self.parse(list?[1], protocol: vpnProtocol)
    }
}

// MARK: - Private
private extension XRayProtocolParser {
    static func parseVless(_ uri: String?) -> [String: Any]? {
        let info = uri?.components(separatedBy: "@")
        guard let info,
              info.count >= 2
        else { return nil }
        
        let uuid = info[0]
        let config = info[1].components(separatedBy: "?")
        guard config.count >= 2 else { return nil }
        
        let ipAddress = config[0].components(separatedBy: ":")
        guard ipAddress.count >= 2 else { return nil }
        
        let address = ipAddress[0]
        let port = Int(ipAddress[1])
        
        let suffix = config[1].components(separatedBy: "#")
        guard suffix.count >= 2 else { return nil }
        
        var remark: String? = nil
        if suffix.indices.contains(2) {
            remark = suffix[2]
        }
        
        let tag = "proxy"
        
        let parameters = suffix[0].components(separatedBy: "&")
        
        var network: String?
        var security = "none"
        var flow = ""
        
        var kcpKey: String?
        
        var quicSecurity: String?
        var quicKey: String?
        var quicHeaderType: String?
        
        var wspath: String?
        var wshost: String?
        
        var fingerPrint: String?
        var publicKey: String?
        var serverName: String?
        var shortId: String?
        
        for parameter in parameters {
            let items = parameter.components(separatedBy: "=")
            guard items.count >= 2 else { continue }
            
            switch items[0] {
            case "type":
                network = items[1]
            case "security":
                security = items[1]
            case "flow":
                flow = items[1]
            case "key":
                quicKey = items[1]
            case "quicSecurity":
                quicSecurity = items[1]
            case "headerType":
                quicHeaderType = items[1]
            case "seed":
                kcpKey = items[1]
            case "fp":
                fingerPrint = items[1]
            case "pbk":
                publicKey = items[1]
            case "sni":
                serverName = items[1]
            case "sid":
                shortId = items[1]
            default:
                continue
            }
        }
        
        guard let port,
              let network
        else { return nil }
        
        var configuration = [String: Any]()
        if flow != "xtls-rprx-vision" {
            configuration["log"] = ["logLevel": logLevel]
        } else {
            configuration["log"] = ["logLevel": XLogLevel.warning.string]
        }
        
        var rules = [Any]()
        
        if !proxyDomainList.isEmpty {
            rules.append([
                "type": "field",
                "domain": proxyDomainList,
                "outboundTag": tag
            ])
        }
        
        if !blockDomainList.isEmpty {
            rules.append([
                "type": "field",
                "domain": blockDomainList,
                "outboundTag": "block"
            ])
        }
        
        if globalGeositeEnable {
            rules.append(contentsOf: [[
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            ], [
                "type": "field",
                "domain": ["geosite:cn"],
                "outboundTag": "direct"
            ]])
        }
        
        if globalGeoipEnable {
            rules.append([
                "type": "field",
                "ip": ["geoip:private", "geoip:cn"],
                "outboundTag": "direct"
            ])
        }
        
        if globalGeoipEnable || globalGeositeEnable {
            rules.append([
                "type": "field",
                "domain": ["geosite:geolocation-!cn"],
                "outboundTag": tag
            ])
        }
        
        if !globalGeoipEnable,
           !globalGeositeEnable {
            rules.append([
                "type": "field",
                "outboundTag": tag,
                "port": "0-65535"
            ])
        }
        
        if flow != "xtls-rprx-vision" {
            configuration["routing"] = [
                "domainStrategy": "AsIs",
                "rules": rules
            ]
            
            configuration["stats"] = [:]
            
            configuration["policy"] = [
                "levels": [
                    "0": [
                        "statsUserUplink": NSNumber(value: true),
                        "statsUserDownlink": NSNumber(value: true)
                    ]
                ],
                "system": [
                    "statsInboundUplink": NSNumber(value: true),
                    "statsInboundDownlink": NSNumber(value: true),
                    "statsOutboundUplink": NSNumber(value: true),
                    "statsOutboundDownlink": NSNumber(value: true)
                ]
            ]
        }
        
        var inbounds = [Any]()
        
        if flow != "xtls-rprx-vision" {
            inbounds.append([
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": ["timeout": 60],
                "tag": "httpinbound",
                "port": httpProxyPort
            ])
        } else {
            inbounds.append(contentsOf: [[
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks"
            ], [
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http"
            ]])
        }
        
        configuration["inbounds"] = inbounds
        
        var outbounds = [Any]()
        
        var user = [
            "encryption": "none",
            "id": uuid,
            "flow": flow
        ] as [String: Any]
        
        if flow != "xtls-rprx-vision" {
            user["level"] = 0
        }
        
        var outbound = [
            "protocol": "vless",
            "settings": [
                "vnext": [
                    [
                        "address": address,
                        "port": port,
                        "users": [user]
                    ]
                ]
            ],
            "streamSettings": [
                "security": security,
                "network": network
            ]
        ] as [String: Any]
        
        outbound["tag"] = tag
        
        switch network {
        case "ws":
            if let wspath,
               let wshost {
                outbound["streamSettings"] = [
                    "security": security,
                    "network": network,
                    "wsSettings": [
                        "headers": ["Host": wshost],
                        "path": wspath
                    ]
                ]
            }
        case "quic":
            if let quicKey,
               let quicSecurity,
               let quicHeaderType {
                outbound["streamSettings"] = [
                    "security": security,
                    "network": network,
                    "quicSettings": [
                        "header": ["type": quicHeaderType],
                        "key": quicKey,
                        "security": quicSecurity
                    ]
                ]
            }
        case "tcp":
            switch security {
            case "xlts":
                outbound["streamSetting"] = [
                    "security": security,
                    "network": network,
                    "xltsSettings": ["serverName": address]
                ]
            case "reality":
                outbound["streamSettings"] = [
                    "realitySettings": [
                        "fingerprint": fingerPrint,
                        "publicKey": publicKey,
                        "serverName": serverName,
                        "shortId": shortId,
                        "spiderX": ""
                    ],
                    "network": network,
                    "security": security
                ]
            default:
                break
            }
        case "kcp":
            if let kcpKey {
                outbound["streamSettings"] = [
                    "security": security,
                    "network": network,
                    "kcpSettings": [
                        "congestion": NSNumber(value: false),
                        "downlinkCapacity": 100,
                        "header": ["type": "none"],
                        "mtu": 1350,
                        "readBufferSize": 1,
                        "seed": kcpKey,
                        "tti": 50,
                        "uplinkCapacity": 12,
                        "writeBufferSize": 1
                    ]
                ]
            }
        default:
            break
        }
        
        outbounds.append(outbound)
        
        if flow != "xtls-rprx-vision" {
            outbounds.append(contentsOf: [[
                "tag": "direct",
                "protocol": "freedom",
                "settings": [:]
            ], [
                "tag": "block",
                "protocol": "blackhole",
                "settings": ["response": ["type": "http"]]
            ]])
        }
        
        configuration["outbounds"] = outbounds
        
        var dns = [:] as [String: Any]
        dns["servers"] = []
        if flow != "xtls-rprx-vision" {
            configuration["dns"] = dns
        }
        
        configuration["remark"] = remark
        
        return configuration
    }
    
    static func parseVmess(_ uri: String?) -> [String: Any]? {
        guard let uri,
              let payload = Data(base64Encoded: uri, options: .ignoreUnknownCharacters)
        else { return nil }
        
        var info: [String: Any]?
        do {
            info = (try JSONSerialization.jsonObject(with: payload, options: .mutableContainers)) as? [String: Any]
        } catch {
            debugPrint(error)
            return nil
        }
        
        guard let info else { return nil }
        
        let address = info["add"] as? String
        let port = Int((info["port"] as? String) ?? "")
        let aid = info["aid"] == nil ? 0 : Int(info["aid"] as? String ?? "")
        
        let uuid = info["id"] as? String
        var tag = info["ps"] as? String
        let tls = info["tls"] == nil ? "none" : info["tls"] as? String
        
        let wsPath = info["path"] as? String
        let wsHost = info["host"] as? String
        let remark = (info["remark"] == nil ? info["ps"] : info["remark"]) as? String
     
        tag = "proxy"
        let network = info["net"] as? String
        
        let kcpKey = info["path"] as? String
        
        let quicSecurity = info["host"] as? String
        let quicKey = info["path"] as? String
        let quicHeaderType = info["type"] as? String
        
        guard let address,
              let port,
              let uuid,
              let tag,
              let network
        else { return nil }
        
        var configuration = [String: Any]()
        configuration["log"] = ["loglevel": Self.logLevel]
        
        var rules = [Any]()
        if !Self.proxyDomainList.isEmpty {
            rules.append([
                "type": "field",
                "domain": Self.proxyDomainList,
                "outboundTag": tag
            ])
        }
        
        if !Self.blockDomainList.isEmpty {
            rules.append([
                "type": "field",
                "domain": Self.blockDomainList,
                "outboundTag": "block"
            ])
        }
        
        if Self.globalGeositeEnable {
            rules.append(contentsOf: [[
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            ], [
                "type": "field",
                "domain": ["geosite:cn"],
                "outboundTag": "direct"
            ]])
        }
        
        if Self.globalGeoipEnable {
            rules.append([
                "type": "field",
                "ip": ["geoip:private", "geoip:cn"],
                "outboundTag": "direct"
            ])
        }
        
        if Self.globalGeoipEnable || Self.globalGeositeEnable {
            rules.append([
                "type": "field",
                "domain": ["geosite:geolocation-!cn"],
                "outboundTag": tag
            ])
        }
        
        if !Self.globalGeoipEnable,
           !Self.globalGeositeEnable {
            rules.append([
                "type": "field",
                "outboundTag": tag,
                "port": "0-65535"
            ])
        }
        
        configuration["routing"] = [
            "domainStrategy": "AsIs",
            "rules": rules
        ]
        
        var inbounds = [Any]()
        
        inbounds.append([
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": ["timeout": 60],
            "tag": "httpinbound",
            "port": Self.httpProxyPort
        ])
        
        configuration["inbounds"] = inbounds
        
        var outbounds = [Any]()
        
        var outbound = [
            "mux": [
                "concurrency": 8,
                "enabled": NSNumber(value: false)
            ],
            "protocol": "vmess",
            "tag": tag,
            "settings": [
                "vnext": [[
                    "address": address,
                    "port": port,
                    "users": [[
                        "encryption": "",
                        "security": "auto",
                        "alterId": aid,
                        "id": uuid,
                        "flow": "",
                        "level": 8
                    ]]
                ]]
            ],
            "streamSettings": [
                "security": tls,
                "network": network,
                "tcpSettings": ["header": ["type": "none"]]
            ]
        ] as [String: Any]
        
        switch network {
        case "ws":
            if let wsPath,
               let wsHost {
                outbound["streamSettings"] = [
                    "security": tls,
                    "network": network,
                    "wsSettings": [
                        "headers": ["Host": wsHost],
                        "path": wsPath
                    ],
                    "tlsSettings": [
                        "allowInsecure": false,
                        "serverName": wsHost
                    ]
                ]
            }
        case "quic":
            if let quicKey,
               let quicSecurity,
               let quicHeaderType {
                outbound["streamSettings"] = [
                    "security": tls,
                    "network": network,
                    "quicSettings": [
                        "header": ["type": quicHeaderType],
                        "key": quicKey,
                        "security": quicSecurity
                    ]
                ]
            }
        case "kcp":
            if let kcpKey {
                outbound["streamSettings"] = [
                    "security": tls,
                    "network": network,
                    "kcpSettings": [
                        "congestion": NSNumber(value: false),
                        "downlinkCapacity": 100,
                        "header": ["type": "none"],
                        "mtu": 1350,
                        "readBufferSize": 1,
                        "seed": kcpKey,
                        "tti": 50,
                        "uplinkCapacity": 12,
                        "writeBufferSize": 1
                    ]
                ]
            }
        default:
            break
        }
        
        outbounds.append(outbound)
        outbounds.append(contentsOf: [[
            "tag": "direct",
            "protocol": "freedom",
            "settings": [:]
        ], [
            "tag": "block",
            "protocol": "blackhole",
            "settings": ["response": ["type": "http"]]
        ]])
        
        configuration["outbounds"] = outbounds
        
        if let remark {
            configuration["remark"] = remark
        }
        
        configuration["dns"] = [
            "hosts": ["domain:googleapis.cn": "googleapis.com"],
            "servers": ["1.1.1.1"]
        ]
        
        return configuration
    }
}
