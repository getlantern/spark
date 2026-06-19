import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()

    // A fixed phone-portrait window with a transparent title bar — matches the Lantern app
    // (getlantern/lantern MainFlutterWindow): not a resizable desktop window.
    let size = NSSize(width: 390, height: 760)
    self.setContentSize(size)
    self.minSize = size
    self.maxSize = size
    self.styleMask.remove(.resizable)
    self.titleVisibility = .hidden
    self.titlebarAppearsTransparent = true
    self.isMovableByWindowBackground = true
    self.center()

    self.contentViewController = flutterViewController
    RegisterGeneratedPlugins(registry: flutterViewController)

    // macOS controlling-app backend (Model A): the "spark/ne" channel driving the NE system extension.
    SparkNeChannel.register(with: flutterViewController.registrar(forPlugin: "SparkNeChannel"))

    super.awakeFromNib()
  }
}
