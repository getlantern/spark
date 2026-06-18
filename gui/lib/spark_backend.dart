import 'dart:io';

/// Tunnel lifecycle state — mirrors `spark_ipc::TunnelState`.
enum TunnelState { disconnected, connecting, connected, disconnecting, failed, unknown }

/// A status snapshot from the service.
class TunnelStatus {
  final TunnelState state;

  /// The kill-switch failed open and traffic is routing directly — surface loudly.
  final bool directFallback;

  const TunnelStatus(this.state, this.directFallback);

  static const unknown = TunnelStatus(TunnelState.unknown, false);
}

/// Raised when the backend can't reach or drive the service.
class SparkException implements Exception {
  final String message;
  SparkException(this.message);
  @override
  String toString() => message;
}

/// The control-plane surface the UI drives — deliberately the same small shape as
/// `spark-ffi`'s `Backend`. Desktop v1 is [CliBackend] (shells out to the `spark` CLI, which
/// speaks `spark-ipc` to `spark-service`); the real desktop binding (`flutter_rust_bridge` over
/// `spark-ipc::Client`) and the mobile binding (a platform channel to the native VpnService/NE
/// shim) implement this same interface, so the UI never changes.
abstract class SparkBackend {
  Future<TunnelStatus> status();
  Future<void> connect();
  Future<void> disconnect();
}

/// Desktop placeholder backend: invokes the `spark` CLI control subcommands.
///
/// `binary` is the path to the `spark` executable (default: resolved on `PATH`; point it at
/// `target/debug/spark` in development). `socket` is the service's control endpoint.
class CliBackend implements SparkBackend {
  final String binary;
  final String socket;

  CliBackend({this.binary = 'spark', this.socket = '/var/run/spark.sock'});

  Future<ProcessResult> _run(String command) {
    return Process.run(binary, [command, '--socket', socket]).catchError(
      // The binary wasn't found / couldn't launch — surface it as a transport error.
      (e) => throw SparkException('could not run "$binary": $e'),
    );
  }

  String _error(ProcessResult r) {
    final out = r.stderr.toString().trim();
    final msg = out.isNotEmpty ? out : r.stdout.toString().trim();
    return msg.isEmpty ? 'spark exited with code ${r.exitCode}' : msg;
  }

  @override
  Future<void> connect() async {
    final r = await _run('connect');
    if (r.exitCode != 0) throw SparkException(_error(r));
  }

  @override
  Future<void> disconnect() async {
    final r = await _run('disconnect');
    if (r.exitCode != 0) throw SparkException(_error(r));
  }

  @override
  Future<TunnelStatus> status() async {
    final r = await _run('status');
    if (r.exitCode != 0) throw SparkException(_error(r));
    return _parseStatus(r.stdout.toString());
  }

  /// Parse the CLI's human-readable `status` output (`state: Connected`, plus an optional
  /// fail-open warning line).
  TunnelStatus _parseStatus(String out) {
    var state = TunnelState.unknown;
    var directFallback = false;
    for (final raw in out.split('\n')) {
      final line = raw.trim();
      if (line.startsWith('state:')) {
        state = _stateOf(line.substring('state:'.length).trim());
      } else if (line.contains('failed open')) {
        directFallback = true;
      }
    }
    return TunnelStatus(state, directFallback);
  }

  TunnelState _stateOf(String s) {
    switch (s) {
      case 'Disconnected':
        return TunnelState.disconnected;
      case 'Connecting':
        return TunnelState.connecting;
      case 'Connected':
        return TunnelState.connected;
      case 'Disconnecting':
        return TunnelState.disconnecting;
      case 'Failed':
        return TunnelState.failed;
      default:
        return TunnelState.unknown;
    }
  }
}
