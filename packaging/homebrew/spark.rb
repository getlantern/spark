# Homebrew formula for spark (binary install). The release process fills in the per-arch
# `url` + `sha256` from the published release tarballs and pushes this to the tap — see
# packaging/README.md. The sha256 values below are placeholders until then.
class Spark < Formula
  desc "From-scratch multi-protocol VPN/proxy tunnel"
  homepage "https://github.com/getlantern/spark"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/getlantern/spark/releases/download/v0.1.0/spark-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/getlantern/spark/releases/download/v0.1.0/spark-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "spark"
    sbin.install "spark-service"
    # Ship the example as the live config on first install; never clobber an edited one.
    (etc/"spark").mkpath
    cp "config.example.toml", etc/"spark/config.toml" unless (etc/"spark/config.toml").exist?
    pkgshare.install "config.example.toml"
  end

  # The daemon needs root to open the TUN + manage routes, so the service runs as root.
  service do
    run [opt_sbin/"spark-service", "--config", etc/"spark/config.toml"]
    require_root true
    keep_alive true
    log_path var/"log/spark.log"
    error_log_path var/"log/spark.log"
  end

  test do
    assert_match "spark", shell_output("#{bin}/spark --help")
  end
end
