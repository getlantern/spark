import 'dart:async';

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import 'frb_backend.dart';
import 'spark_backend.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(SparkApp(backend: await _desktopBackend()));
}

/// The desktop backend: the in-process Rust bridge ([FrbBackend], no subprocess → works under the
/// macOS App Sandbox). Falls back to [CliBackend] if the Rust library can't be loaded/initialized,
/// so the app always launches (degraded to driving the `spark` CLI).
Future<SparkBackend> _desktopBackend() async {
  try {
    return await FrbBackend.create();
  } catch (e) {
    debugPrint('FrbBackend unavailable ($e); falling back to CliBackend');
    return CliBackend();
  }
}

/// Palette — a dark "signal" aesthetic: near-black field, electric-teal connected accent.
class _Palette {
  static const bg = Color(0xFF0B0F14);
  static const bgVignette = Color(0xFF111826);
  static const text = Color(0xFFE6EDF3);
  static const dim = Color(0xFF7D8896);
  static const slate = Color(0xFF64748B); // disconnected
  static const teal = Color(0xFF2DD4BF); // connected
  static const amber = Color(0xFFF59E0B); // transitional
  static const rose = Color(0xFFFB7185); // failed / fail-open
}

class SparkApp extends StatelessWidget {
  /// The backend to drive. `main` passes the desktop backend ([FrbBackend], or a [CliBackend]
  /// fallback); tests inject a fake. If null (e.g. `const SparkApp()`), [HomePage] uses [CliBackend].
  final SparkBackend? backend;

  const SparkApp({super.key, this.backend});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'spark',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: _Palette.bg,
        colorScheme: const ColorScheme.dark(
          primary: _Palette.teal,
          surface: _Palette.bg,
        ),
      ),
      home: HomePage(backend: backend),
    );
  }
}

class HomePage extends StatefulWidget {
  final SparkBackend? backend;
  const HomePage({super.key, this.backend});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with SingleTickerProviderStateMixin {
  // `main` injects the desktop backend (the in-process flutter_rust_bridge `FrbBackend`, or a
  // `CliBackend` fallback); a null override (e.g. a bare `const SparkApp()`) defaults to `CliBackend`.
  late final SparkBackend _backend = widget.backend ?? CliBackend();

  TunnelStatus _status = TunnelStatus.unknown;
  String? _error; // set when the service is unreachable
  bool _busy = false; // a connect/disconnect is in flight

  Timer? _poll;
  late final AnimationController _pulse;

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(vsync: this, duration: const Duration(milliseconds: 1300))
      ..repeat(reverse: true);
    _refresh();
    _poll = Timer.periodic(const Duration(seconds: 2), (_) => _refresh());
  }

  @override
  void dispose() {
    _poll?.cancel();
    _pulse.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final s = await _backend.status();
      if (mounted) {
        setState(() {
          _status = s;
          _error = null;
        });
      }
    } on SparkException catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  Future<void> _toggle() async {
    final connected = _status.state == TunnelState.connected ||
        _status.state == TunnelState.connecting;
    setState(() => _busy = true);
    try {
      if (connected) {
        await _backend.disconnect();
      } else {
        await _backend.connect();
      }
      await _refresh();
    } on SparkException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  bool get _transitional =>
      _status.state == TunnelState.connecting || _status.state == TunnelState.disconnecting;

  Color get _accent {
    if (_error != null) return _Palette.dim;
    switch (_status.state) {
      case TunnelState.connected:
        return _Palette.teal;
      case TunnelState.connecting:
      case TunnelState.disconnecting:
        return _Palette.amber;
      case TunnelState.failed:
        return _Palette.rose;
      case TunnelState.disconnected:
        return _Palette.slate;
      case TunnelState.unknown:
        return _Palette.dim;
    }
  }

  String get _stateLabel {
    if (_error != null) return 'UNREACHABLE';
    switch (_status.state) {
      case TunnelState.connected:
        return 'CONNECTED';
      case TunnelState.connecting:
        return 'CONNECTING';
      case TunnelState.disconnecting:
        return 'DISCONNECTING';
      case TunnelState.disconnected:
        return 'DISCONNECTED';
      case TunnelState.failed:
        return 'FAILED';
      case TunnelState.unknown:
        return '—';
    }
  }

  @override
  Widget build(BuildContext context) {
    final accent = _accent;
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: RadialGradient(
            center: Alignment(0, -0.35),
            radius: 1.1,
            colors: [_Palette.bgVignette, _Palette.bg],
          ),
        ),
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Column(
              children: [
                const SizedBox(height: 28),
                _header(),
                const Spacer(),
                _orb(accent),
                const SizedBox(height: 36),
                Text(
                  _stateLabel,
                  style: GoogleFonts.jetBrainsMono(
                    color: accent,
                    fontSize: 22,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 4,
                  ),
                ),
                const SizedBox(height: 10),
                Text(
                  _error ?? _subLabel(),
                  textAlign: TextAlign.center,
                  style: GoogleFonts.sora(color: _Palette.dim, fontSize: 13, height: 1.4),
                ),
                if (_status.directFallback) ...[
                  const SizedBox(height: 16),
                  _failOpenBanner(),
                ],
                const Spacer(),
                _actionButton(accent),
                const SizedBox(height: 40),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _header() {
    return Row(
      children: [
        Container(
          width: 9,
          height: 9,
          decoration: BoxDecoration(color: _accent, shape: BoxShape.circle),
        ),
        const SizedBox(width: 10),
        Text(
          'spark',
          style: GoogleFonts.sora(
            color: _Palette.text,
            fontSize: 22,
            fontWeight: FontWeight.w700,
            letterSpacing: 1,
          ),
        ),
        const Spacer(),
        Text(
          'control',
          style: GoogleFonts.jetBrainsMono(color: _Palette.dim, fontSize: 12, letterSpacing: 2),
        ),
      ],
    );
  }

  /// The signal orb: a ring that glows with the state colour and pulses while transitioning.
  Widget _orb(Color accent) {
    return AnimatedBuilder(
      animation: _pulse,
      builder: (context, _) {
        final t = _transitional ? _pulse.value : 0.0;
        final glow = 24.0 + 26.0 * t;
        return AnimatedContainer(
          duration: const Duration(milliseconds: 400),
          width: 188,
          height: 188,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: accent.withValues(alpha: 0.06),
            border: Border.all(color: accent.withValues(alpha: 0.85), width: 2.5),
            boxShadow: [
              BoxShadow(
                color: accent.withValues(alpha: 0.35 + 0.25 * t),
                blurRadius: glow,
                spreadRadius: 2,
              ),
            ],
          ),
          child: Center(
            child: Icon(
              _status.state == TunnelState.connected ? Icons.shield : Icons.shield_outlined,
              color: accent,
              size: 64,
            ),
          ),
        );
      },
    );
  }

  String _subLabel() {
    switch (_status.state) {
      case TunnelState.connected:
        return 'Traffic is tunneled through spark.';
      case TunnelState.disconnected:
        return 'Your traffic is not tunneled.';
      case TunnelState.failed:
        return 'The tunnel failed — see the service logs.';
      default:
        return 'Talking to spark-service…';
    }
  }

  Widget _failOpenBanner() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: _Palette.rose.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: _Palette.rose.withValues(alpha: 0.5)),
      ),
      child: Text(
        'Failed open — traffic is routing directly, not tunneled.',
        textAlign: TextAlign.center,
        style: GoogleFonts.sora(color: _Palette.rose, fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }

  Widget _actionButton(Color accent) {
    final connected = _status.state == TunnelState.connected ||
        _status.state == TunnelState.connecting;
    final label = connected ? 'Disconnect' : 'Connect';
    final enabled = !_busy && _error == null && !_transitional;
    return SizedBox(
      width: double.infinity,
      child: FilledButton(
        onPressed: enabled ? _toggle : null,
        style: FilledButton.styleFrom(
          backgroundColor: connected ? Colors.transparent : accent,
          foregroundColor: connected ? accent : _Palette.bg,
          side: connected ? BorderSide(color: accent, width: 1.5) : BorderSide.none,
          padding: const EdgeInsets.symmetric(vertical: 18),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          textStyle: GoogleFonts.sora(fontSize: 16, fontWeight: FontWeight.w600, letterSpacing: 0.5),
        ),
        child: _busy
            ? SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2.5, color: accent),
              )
            : Text(label),
      ),
    );
  }
}
