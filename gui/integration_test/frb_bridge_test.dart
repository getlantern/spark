// Runtime end-to-end test for the flutter_rust_bridge desktop backend. Unlike `flutter test`
// (which runs on the Dart VM with no native library), this runs on a real macOS app instance, so
// the cargokit-linked `spark_bridge` framework is actually loaded — exercising the full stack:
// RustLib.init() → SparkBridge (opaque Rust object) → spark-backend → spark-ipc, and the typed
// error back across the FFI boundary.
//
// Run: flutter test integration_test/frb_bridge_test.dart -d macos
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:spark_gui/frb_backend.dart';
import 'package:spark_gui/spark_backend.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('the Rust bridge loads and round-trips a typed error', (tester) async {
    // Bind to a socket with no service behind it. A successful round-trip would need a running
    // spark-service; here the point is to prove the bridge is wired, not to connect.
    final backend = await FrbBackend.create(socket: '/tmp/spark-frb-itest-nonexistent.sock');

    // status() must surface a typed SparkException (mapped from spark-backend's transport error):
    // reaching it proves RustLib.init() loaded the framework, the FFI call dispatched into Rust,
    // spark-backend attempted the connection, and the error propagated back through the bridge.
    await expectLater(backend.status(), throwsA(isA<SparkException>()));
  });
}
