import 'spark_backend.dart';
import 'src/rust/api/control.dart' as rust;
import 'src/rust/frb_generated.dart';

/// Desktop backend that drives `spark-service` through the Rust `spark-bridge`
/// (`flutter_rust_bridge` over `spark-backend` → `spark-ipc`) — **in-process, no subprocess**, so
/// unlike [CliBackend] it isn't blocked by the macOS App Sandbox's process-spawn restriction.
///
/// Construct with [FrbBackend.create] (it loads + initializes the Rust library once, then binds to
/// the service control endpoint). Implements the same [SparkBackend] surface as every other binding,
/// so the UI is unchanged.
class FrbBackend implements SparkBackend {
  final rust.SparkBridge _bridge;

  FrbBackend._(this._bridge);

  /// Whether [RustLib] has been initialized (its `init()` throws if called twice).
  static bool _initialized = false;

  /// Initialize the Rust library (idempotent across calls) and bind to the service at [socket].
  static Future<FrbBackend> create({String socket = '/var/run/spark.sock'}) async {
    if (!_initialized) {
      await RustLib.init();
      _initialized = true;
    }
    return FrbBackend._(rust.SparkBridge(socketPath: socket));
  }

  @override
  Future<void> connect() => _guard(() => _bridge.connect());

  @override
  Future<void> disconnect() => _guard(() => _bridge.disconnect());

  @override
  Future<TunnelStatus> status() => _guard(() async {
    final s = await _bridge.status();
    return TunnelStatus(_stateOf(s.state), s.directFallback);
  });

  /// Run a bridge call, remapping the generated `BridgeError` (and any other failure) to the
  /// UI-facing [SparkException], so callers handle one exception type regardless of binding.
  Future<T> _guard<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on rust.BridgeError catch (e) {
      throw SparkException(_messageOf(e));
    } catch (e) {
      throw SparkException(e.toString());
    }
  }

  /// Mirror the Rust `BridgeError` Display strings (which don't cross the FFI boundary). Exhaustive
  /// over the sealed class — a new Rust variant fails analysis here until it's handled.
  String _messageOf(rust.BridgeError e) => switch (e) {
    rust.BridgeError_Unauthorized() => 'not authorized to control the service',
    rust.BridgeError_UnsupportedVersion() => 'no common control-protocol version',
    rust.BridgeError_InvalidRequest() => 'invalid request for the current state',
    rust.BridgeError_NotConnected() => 'the operation requires an active tunnel',
    rust.BridgeError_Internal(:final message) => 'service error: $message',
    rust.BridgeError_Transport(:final message) => message,
  };

  TunnelState _stateOf(rust.BridgeState s) => switch (s) {
    rust.BridgeState.disconnected => TunnelState.disconnected,
    rust.BridgeState.connecting => TunnelState.connecting,
    rust.BridgeState.connected => TunnelState.connected,
    rust.BridgeState.disconnecting => TunnelState.disconnecting,
    rust.BridgeState.failed => TunnelState.failed,
  };
}
