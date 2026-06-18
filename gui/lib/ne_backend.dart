import 'package:flutter/services.dart';

import 'spark_backend.dart';

/// macOS backend (Model A, ADR 0005): drives the Network Extension system extension through the
/// native `spark/ne` `MethodChannel` (implemented in macos/Runner/SparkVPN.swift). Implements the
/// same [SparkBackend] surface as every other binding, so the UI is unchanged. `connect` activates
/// the system extension (first run prompts approval) and starts the tunnel; `status` reports the
/// `NEVPNStatus`. There is no daemon/socket on this path — the OS owns the privileged tunnel.
class NEBackend implements SparkBackend {
  static const _channel = MethodChannel('spark/ne');

  @override
  Future<void> connect() => _invoke('connect');

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
