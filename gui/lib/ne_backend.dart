import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

import 'spark_backend.dart';

/// Filename of the runtime data-path config the app reads on connect (in the app-support dir).
const _configFileName = 'config.toml';

/// macOS backend (Model A, ADR 0005): drives the Network Extension system extension through the
/// native `spark/ne` `MethodChannel` (implemented in macos/Runner/SparkVPN.swift). Implements the
/// same [SparkBackend] surface as every other binding, so the UI is unchanged. `connect` activates
/// the system extension (first run prompts approval) and starts the tunnel; `status` reports the
/// `NEVPNStatus`. There is no daemon/socket on this path — the OS owns the privileged tunnel.
class NEBackend implements SparkBackend {
  static const _channel = MethodChannel('spark/ne');

  /// Relay address ("host:port" IP literal). When set (and [config] is not), `connect` tunnels every
  /// flow through that plain relay. Sourced from `--dart-define=SPARK_PROXY=host:port`.
  final String? proxyServer;

  /// Build-time *fallback* TOML config (AnyTLS + handshake shaping + gambit), from
  /// `--dart-define=SPARK_CONFIG=<base64 TOML>`. The runtime [configFile] takes precedence over this.
  final String? config;

  NEBackend({this.proxyServer, this.config});

  /// The runtime config file the app reads on connect: `<app-support>/config.toml` — on macOS
  /// `~/Library/Application Support/org.getlantern.spark/config.toml`. Drop a TOML config here (from
  /// a download, a fetch from a trusted location, a future in-app importer) to point the tunnel at a
  /// relay without rebuilding. Returns the resolved path (also useful for a settings UI).
  static Future<File> configFile() async {
    final dir = await getApplicationSupportDirectory();
    return File('${dir.path}/$_configFileName');
  }

  @override
  Future<void> connect() async {
    final cfg = await _resolveConfig();
    // The native side accepts a TOML config or a bare host:port under the same key.
    final args = (cfg != null && cfg.isNotEmpty) ? {'config': cfg} : null;
    await _guard(() => _channel.invokeMethod<void>('connect', args));
  }

  /// Resolve the data-path config, newest-wins: (1) the runtime [configFile] (user-downloaded /
  /// fetched), (2) the build-time-baked [config], (3) [proxyServer], (4) null = direct.
  Future<String?> _resolveConfig() async {
    try {
      final f = await configFile();
      if (await f.exists()) {
        final s = (await f.readAsString()).trim();
        if (s.isNotEmpty) {
          debugPrint('NEBackend: using runtime config ${f.path}');
          return s;
        }
      }
    } catch (e) {
      // Unreadable file → fall back to the baked config rather than failing the connect.
      debugPrint('NEBackend: could not read runtime config ($e); using baked fallback');
    }
    if (config != null && config!.isNotEmpty) return config;
    if (proxyServer != null && proxyServer!.isNotEmpty) return proxyServer;
    return null;
  }

  @override
  Future<void> disconnect() => _invoke('disconnect');

  @override
  Future<TunnelStatus> status() async {
    final state = await _guard(() => _channel.invokeMethod<String>('status'));
    // The NE manager doesn't surface a kill-switch fail-open signal; the data plane runs in the
    // sysext, so direct_fallback isn't applicable on this path.
    return TunnelStatus(_stateOf(state), false);
  }

  Future<void> _invoke(String method) async {
    await _guard(() => _channel.invokeMethod<void>(method));
  }

  /// Map a native `FlutterError`/`PlatformException` to the UI-facing [SparkException].
  Future<T> _guard<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on PlatformException catch (e) {
      throw SparkException(e.message ?? e.code);
    } on MissingPluginException {
      throw SparkException('the spark NE channel is unavailable (macOS only)');
    }
  }

  TunnelState _stateOf(String? s) {
    switch (s) {
      case 'connecting':
        return TunnelState.connecting;
      case 'connected':
        return TunnelState.connected;
      case 'disconnecting':
        return TunnelState.disconnecting;
      case 'disconnected':
        return TunnelState.disconnected;
      case 'failed':
        return TunnelState.failed;
      default:
        return TunnelState.unknown;
    }
  }
}
