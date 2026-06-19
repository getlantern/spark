import FlutterMacOS
import Foundation
import NetworkExtension
import SystemExtensions

/// Log to the unified log (Console.app). Plain `NSLog` so we don't need `os.Logger` (macOS 11+);
/// the Runner deploys to 10.15.
private func sparkLog(_ message: String) { NSLog("%@", "[spark] \(message)") }

/// macOS controlling-app backend (Model A, ADR 0005). Exposes the Network Extension control surface
/// to Dart over a `MethodChannel` ("spark/ne"): activate the system extension, manage the
/// `NETunnelProviderManager`, start/stop the tunnel, and report status. The Dart side (`NEBackend`)
/// implements the same `SparkBackend` interface as the desktop/mobile bindings, so the UI is
/// unchanged. The NE/sysext logic mirrors platforms/apple's SparkApp.swift (the proven, live-gated
/// flow); this file only adds the channel plumbing.
enum SparkNeChannel {
  static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "spark/ne", binaryMessenger: registrar.messenger)
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "connect":
        // "config" arg: a "host:port" IP literal (plain relay) or a full TOML config (AnyTLS +
        // handshake shaping + gambit); absent → forward directly. The Dart NEBackend supplies it (a
        // future profile UI sets it). Back-compat: a legacy "server" host:port key is accepted too.
        let args = call.arguments as? [String: Any]
        let config = (args?["config"] as? String) ?? (args?["server"] as? String)
        SparkVpn.shared.connect(config: config, result: result)
      case "disconnect": SparkVpn.shared.disconnect(result: result)
      case "status": SparkVpn.shared.status(result: result)
      case "openExtensionSettings": SparkSysExt.shared.openSettings(); result(nil)
      default: result(FlutterMethodNotImplemented)
      }
    }
  }
}

/// Drives system-extension activation (`OSSystemExtensionRequest`); `completion` fires once the
/// extension is active (or with an error). Mirrors platforms/apple SparkApp.swift `SysExt`.
final class SparkSysExt: NSObject, OSSystemExtensionRequestDelegate {
  static let shared = SparkSysExt()
  private let extBundleId = "org.getlantern.spark.tunnel"
  private var completion: ((Error?) -> Void)?

  /// Activate the extension, invoking `completion` when it's installed/approved (or failed).
  func activate(completion: @escaping (Error?) -> Void) {
    self.completion = completion
    sparkLog("submitting system extension activation for \(extBundleId)")
    let req = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: extBundleId, queue: .main)
    req.delegate = self
    OSSystemExtensionManager.shared.submitRequest(req)
  }

  func openSettings() {
    // macOS 15+ deep-links to the Network Extensions pane; older falls back to Privacy & Security.
    let urls = [
      "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point",
      "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
      "x-apple.systempreferences:com.apple.preference.security",
    ]
    for u in urls where NSWorkspace.shared.open(URL(string: u)!) { return }
  }

  // MARK: OSSystemExtensionRequestDelegate

  func request(
    _: OSSystemExtensionRequest, actionForReplacingExtension _: OSSystemExtensionProperties,
    withExtension _: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction { .replace }

  func requestNeedsUserApproval(_: OSSystemExtensionRequest) {
    sparkLog("system extension needs user approval (System Settings)")
    DispatchQueue.main.async { self.openSettings() }
  }

  func request(_: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
    sparkLog("system extension activation finished: \(result.rawValue)")
    completion?(nil)
    completion = nil
  }

  func request(_: OSSystemExtensionRequest, didFailWithError error: Error) {
    let ns = error as NSError
    sparkLog("system extension activation failed (\(ns.domain) code=\(ns.code)): \(error.localizedDescription)")
    completion?(error)
    completion = nil
  }
}

/// Loads/saves the tunnel config and drives start/stop via `NETunnelProviderManager`. Mirrors
/// platforms/apple SparkApp.swift `Vpn`, adapted to report results back over the method channel.
final class SparkVpn {
  static let shared = SparkVpn()
  private let providerBundleId = "org.getlantern.spark.tunnel"

  /// Activate the system extension (if needed), then configure + start the tunnel. `config` is a
  /// "host:port" plain relay or a full TOML config (AnyTLS + shaping + gambit); nil forwards directly.
  func connect(config: String?, result: @escaping FlutterResult) {
    SparkSysExt.shared.activate { [weak self] error in
      if let error {
        return Self.fail(result, "sysext activation failed", error)
      }
      self?.startTunnel(config: config, result: result)
    }
  }

  private func startTunnel(config: String?, result: @escaping FlutterResult) {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
      guard let self else { return }
      if let error { return Self.fail(result, "loadAll failed", error) }
      let manager = managers?.first ?? NETunnelProviderManager()
      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = self.providerBundleId
      proto.serverAddress = "spark"
      // Hand the data-path config to the system extension; it reads providerConfiguration["config"]
      // (a host:port plain relay, or a full TOML config — AnyTLS + shaping + gambit).
      if let config, !config.isEmpty { proto.providerConfiguration = ["config": config] }
      manager.protocolConfiguration = proto
      manager.localizedDescription = "Spark"
      manager.isEnabled = true
      manager.saveToPreferences { error in
        if let error { return Self.fail(result, "saveToPreferences failed", error) }
        manager.loadFromPreferences { error in
          if let error { return Self.fail(result, "reload failed", error) }
          do {
            try manager.connection.startVPNTunnel()
            sparkLog("startVPNTunnel requested")
            DispatchQueue.main.async { result(nil) }
          } catch {
            Self.fail(result, "startVPNTunnel failed", error)
          }
        }
      }
    }
  }

  func disconnect(result: @escaping FlutterResult) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error { return Self.fail(result, "loadAll failed", error) }
      managers?.first?.connection.stopVPNTunnel()
      DispatchQueue.main.async { result(nil) }
    }
  }

  /// Report the current tunnel state as the string the Dart side maps to a `TunnelState`.
  func status(result: @escaping FlutterResult) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error { return Self.fail(result, "loadAll failed", error) }
      let status = managers?.first?.connection.status ?? .invalid
      DispatchQueue.main.async { result(Self.stateName(status)) }
    }
  }

  private static func stateName(_ s: NEVPNStatus) -> String {
    switch s {
    case .connecting: return "connecting"
    case .connected: return "connected"
    case .reasserting: return "connecting"
    case .disconnecting: return "disconnecting"
    case .disconnected, .invalid: return "disconnected"
    @unknown default: return "unknown"
    }
  }

  private static func fail(_ result: @escaping FlutterResult, _ what: String, _ error: Error) {
    DispatchQueue.main.async {
      result(FlutterError(code: "ne_error", message: "\(what): \(error.localizedDescription)", details: nil))
    }
  }
}
