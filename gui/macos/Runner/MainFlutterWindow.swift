import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    // Set the content view *before* sizing/centering so the window has its Flutter backing.
    self.contentViewController = flutterViewController

    // A fixed phone-portrait window with a transparent title bar — matches the Lantern app
    // (getlantern/lantern MainFlutterWindow): not a resizable desktop window.
    let size = NSSize(width: 390, height: 760)
    self.styleMask.remove(.resizable)
    self.titleVisibility = .hidden
    self.titlebarAppearsTransparent = true
    self.isMovableByWindowBackground = true
    self.minSize = size
    self.maxSize = size
    self.setContentSize(size)
    self.center()

    RegisterGeneratedPlugins(registry: flutterViewController)

    // macOS controlling-app backend (Model A): the "spark/ne" channel driving the NE system extension.
    SparkNeChannel.register(with: flutterViewController.registrar(forPlugin: "SparkNeChannel"))

    super.awakeFromNib()
    // Force the window visible + frontmost (the storyboard's visible-at-launch alone left it hidden
    // after the style changes above).
    self.makeKeyAndOrderFront(nil)
  }
}
