import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import 'frb_backend.dart';
import 'ne_backend.dart';
import 'spark_backend.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(SparkApp(backend: await _desktopBackend()));
}

/// Pick the platform's backend (Model A/B per ADR 0005):
/// - **macOS** → [NEBackend]: drives the Network Extension system extension (the OS owns the
///   privileged tunnel; no daemon). This is the macOS *product* path.
/// - **Linux/Windows** → the in-process Rust bridge [FrbBackend] over `spark-service`, falling back
///   to [CliBackend] if the Rust library can't initialize, so the app always launches.
///
/// Overridable for dev/testing via `--dart-define=SPARK_BACKEND=frb|ne|cli`. `frb` drives a
/// (root-run) `spark-service` from the macOS app — how we exercise the AnyTLS data path through the
/// GUI before the NE provider learns the AnyTLS config.
Future<SparkBackend> _desktopBackend() async {
  const choice = String.fromEnvironment('SPARK_BACKEND');
  if (choice == 'ne' || (choice.isEmpty && Platform.isMacOS)) {
    // A plain relay via --dart-define=SPARK_PROXY=host:port, or a full TOML config (AnyTLS +
    // shaping + gambit) via --dart-define=SPARK_CONFIG=<base64 TOML>; else direct.
    const proxy = String.fromEnvironment('SPARK_PROXY');
    const configB64 = String.fromEnvironment('SPARK_CONFIG');
    final config = configB64.isEmpty ? null : utf8.decode(base64.decode(configB64));
    return NEBackend(
      proxyServer: proxy.isEmpty ? null : proxy,
      config: config,
    );
  }
  if (choice == 'cli') {
    return CliBackend();
  }
  // `frb` (explicit) or the Linux/Windows default: the in-process bridge over spark-service.
  try {
    return await FrbBackend.create();
  } catch (e) {
    debugPrint('FrbBackend unavailable ($e); falling back to CliBackend');
    return CliBackend();
  }
}

/// Palette — Lantern's light look (getlantern/lantern): near-white field, white cards, the cyan
/// brand (Blue.400) for connected, grey for off, a white knob. Mirrors `app_colors.dart` +
/// `app_semantic_colors.dart`'s `actionToggle*`.
class _Palette {
  static const bg = Color(0xFFF8FAFB); // gray1 — near-white scaffold
  static const surface = Color(0xFFFFFFFF); // white cards
  static const brand = Color(0xFF00BDD6); // blue4 — connected (Lantern cyan)
  static const off = Color(0xFF616569); // gray7 — toggle off / connecting
  static const offLight = Color(0xFFA2A2A2); // gray5 — transitional / unknown track
  static const knob = Color(0xFFFFFFFF); // gray0 — white toggle knob
  static const textPrimary = Color(0xFF1B1C1D); // gray9
  static const textSecondary = Color(0xFF616569); // gray7
  static const border = Color(0xFFEDEFEF); // gray2
  static const danger = Color(0xFFD92D20); // fail-open / failed
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
        brightness: Brightness.light,
        scaffoldBackgroundColor: _Palette.bg,
        colorScheme: const ColorScheme.light(
          primary: _Palette.brand,
          surface: _Palette.surface,
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

class _HomePageState extends State<HomePage> {
  // `main` injects the desktop backend (the in-process flutter_rust_bridge `FrbBackend`, or a
  // `CliBackend` fallback); a null override (e.g. a bare `const SparkApp()`) defaults to `CliBackend`.
  late final SparkBackend _backend = widget.backend ?? CliBackend();

  TunnelStatus _status = TunnelStatus.unknown;
  String? _error; // set when the service is unreachable
  bool _busy = false; // a connect/disconnect is in flight

  Timer? _poll;

  @override
  void initState() {
    super.initState();
    _refresh();
    _poll = Timer.periodic(const Duration(seconds: 2), (_) => _refresh());
  }

  @override
  void dispose() {
    _poll?.cancel();
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

  bool get _connected => _status.state == TunnelState.connected;

  bool get _transitional =>
      _status.state == TunnelState.connecting || _status.state == TunnelState.disconnecting;

  /// The toggle track colour, mirroring Lantern's `VPNSwitch._wrapperColor`.
  Color get _trackColor {
    if (_error != null) return _Palette.offLight;
    switch (_status.state) {
      case TunnelState.connected:
        return _Palette.brand;
      case TunnelState.connecting:
      case TunnelState.disconnected:
        return _Palette.off;
      case TunnelState.disconnecting:
      case TunnelState.failed:
      case TunnelState.unknown:
        return _Palette.offLight;
    }
  }

  String get _stateLabel {
    if (_error != null) return 'Service unreachable';
    switch (_status.state) {
      case TunnelState.connected:
        return 'Connected';
      case TunnelState.connecting:
        return 'Connecting…';
      case TunnelState.disconnecting:
        return 'Disconnecting…';
      case TunnelState.disconnected:
        return 'Not connected';
      case TunnelState.failed:
        return 'Failed';
      case TunnelState.unknown:
        return '—';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _appBar(),
      body: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Column(
            children: [
              const SizedBox(height: 44),
              _pillToggle(),
              const SizedBox(height: 18),
              Text(
                _error ?? _subLabel(),
                textAlign: TextAlign.center,
                style: GoogleFonts.sora(color: _Palette.textSecondary, fontSize: 14, height: 1.4),
              ),
              if (_status.directFallback) ...[
                const SizedBox(height: 16),
                _failOpenBanner(),
              ],
              const Spacer(),
              _settingsCard(),
              const SizedBox(height: 18),
            ],
          ),
        ),
      ),
    );
  }

  /// The top bar — a centered `spark` wordmark with a state dot + a (placeholder) menu, over a
  /// hairline divider. Mirrors Lantern's `Home` AppBar (logo title, leading menu, bottom divider).
  PreferredSizeWidget _appBar() {
    return AppBar(
      backgroundColor: _Palette.bg,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      centerTitle: true,
      leading: IconButton(
        icon: const Icon(Icons.menu, color: _Palette.textSecondary, size: 22),
        onPressed: () {}, // settings screen TBD
      ),
      title: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 9,
            height: 9,
            decoration: BoxDecoration(
              color: _connected ? _Palette.brand : _Palette.off,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 8),
          Text(
            'spark',
            style: GoogleFonts.sora(
              color: _Palette.textPrimary,
              fontSize: 20,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(height: 1, color: _Palette.border),
      ),
    );
  }

  /// The Lantern-style pill toggle: a rounded track (cyan when connected, grey when off) with a
  /// white circular knob that slides right on connect; a spinner fills the knob while transitioning.
  /// Tapping it connects/disconnects (mirrors `VPNSwitch`).
  Widget _pillToggle() {
    final enabled = !_busy && _error == null && !_transitional;
    final on = _connected;
    const trackW = 176.0, trackH = 76.0, knobD = 60.0;
    return GestureDetector(
      key: const Key('vpn.toggle'),
      onTap: enabled ? _toggle : null,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 320),
        curve: Curves.easeOut,
        width: trackW,
        height: trackH,
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: _trackColor,
          borderRadius: BorderRadius.circular(trackH / 2),
          boxShadow: on
              ? [
                  BoxShadow(
                    color: _Palette.brand.withValues(alpha: 0.35),
                    blurRadius: 28,
                    spreadRadius: 1,
                    offset: const Offset(0, 6),
                  ),
                ]
              : const [],
        ),
        child: AnimatedAlign(
          duration: const Duration(milliseconds: 320),
          curve: Curves.easeOut,
          alignment: on ? Alignment.centerRight : Alignment.centerLeft,
          child: Container(
            width: knobD,
            height: knobD,
            decoration: const BoxDecoration(
              color: _Palette.knob,
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(color: Color(0x33000000), blurRadius: 8, offset: Offset(0, 2)),
              ],
            ),
            child: _transitional
                ? const Padding(
                    padding: EdgeInsets.all(18),
                    child: CircularProgressIndicator(strokeWidth: 3.5, color: _Palette.brand),
                  )
                : null,
          ),
        ),
      ),
    );
  }

  String _subLabel() {
    switch (_status.state) {
      case TunnelState.connected:
        return 'Your traffic is protected through spark.';
      case TunnelState.disconnected:
        return 'Tap to connect.';
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
        color: _Palette.danger.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: _Palette.danger.withValues(alpha: 0.4)),
      ),
      child: Text(
        'Failed open — traffic is routing directly, not tunneled.',
        textAlign: TextAlign.center,
        style: GoogleFonts.sora(color: _Palette.danger, fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }

  /// The bottom settings card — Lantern's elevated white card of `SettingTile` rows (icon + label
  /// on top, value indented below, a trailing indicator/chevron), separated by hairline dividers.
  Widget _settingsCard() {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: _Palette.surface,
        borderRadius: BorderRadius.circular(16),
        boxShadow: const [
          BoxShadow(color: Color(0x14000000), blurRadius: 24, offset: Offset(0, 4)),
        ],
      ),
      child: Column(
        children: [
          _settingRow(
            icon: Icons.public,
            label: 'VPN status',
            value: _stateLabel,
            trailing: Container(
              width: 10,
              height: 10,
              decoration: BoxDecoration(
                color: _connected ? _Palette.brand : _Palette.off,
                shape: BoxShape.circle,
              ),
            ),
          ),
          _divider(),
          _settingRow(
            icon: Icons.lock_outline,
            label: 'Protocol',
            value: 'AnyTLS',
            trailing: const Icon(Icons.chevron_right, color: _Palette.textSecondary, size: 20),
          ),
          _divider(),
          _settingRow(
            icon: Icons.alt_route,
            label: 'Routing',
            value: 'Full tunnel',
            trailing: const Icon(Icons.chevron_right, color: _Palette.textSecondary, size: 20),
          ),
        ],
      ),
    );
  }

  Widget _divider() => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16),
        child: Divider(height: 1, thickness: 1, color: _Palette.border),
      );

  /// One Lantern `SettingTile`-style row: a small icon + secondary-color label, the value below it
  /// (indented to align under the label), and an optional trailing indicator.
  Widget _settingRow({
    required IconData icon,
    required String label,
    required String value,
    Widget? trailing,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 18, color: _Palette.textSecondary),
              const SizedBox(width: 8),
              Text(
                label,
                style: GoogleFonts.sora(
                  color: _Palette.textSecondary,
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              const SizedBox(width: 26),
              Expanded(
                child: Text(
                  value,
                  style: GoogleFonts.sora(
                    color: _Palette.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              ?trailing,
            ],
          ),
        ],
      ),
    );
  }
}
