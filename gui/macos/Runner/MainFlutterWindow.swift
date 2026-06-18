import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    // macOS controlling-app backend (Model A): the "spark/ne" channel driving the NE system extension.
    SparkNeChannel.register(with: flutterViewController.registrar(forPlugin: "SparkNeChannel"))

    super.awakeFromNib()
  }
}
