import NetworkExtension

// A NetworkExtension *system extension* is a standalone executable (unlike an app-extension,
// which the system hosts). Its entry point hands control to the NE runtime, which instantiates
// the NEProviderClasses from Info.plist (PacketTunnelProvider) on demand.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
