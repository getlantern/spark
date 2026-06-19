// Smoke test: the app builds and shows its header against a fake backend.

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:spark_gui/main.dart';
import 'package:spark_gui/spark_backend.dart';

/// A backend that answers without touching the network / spawning the CLI.
class _FakeBackend implements SparkBackend {
  @override
  Future<TunnelStatus> status() async => const TunnelStatus(TunnelState.disconnected, false);
  @override
  Future<void> connect() async {}
  @override
  Future<void> disconnect() async {}
}

void main() {
  testWidgets('renders the spark home screen with the toggle', (tester) async {
    await tester.pumpWidget(SparkApp(backend: _FakeBackend()));
    expect(find.text('spark'), findsOneWidget);
    // The Lantern-style connect toggle (rendered regardless of status).
    expect(find.byKey(const Key('vpn.toggle')), findsOneWidget);
    // Unmount so the poll timer is cancelled (no pending timers at test end).
    await tester.pumpWidget(const SizedBox());
  });
}
