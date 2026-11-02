class Velcrux < Formula
  desc "High-throughput, resumable, verifiable bulk data transfer over QUIC"
  homepage "https://github.com/Velcrux/velcrux"
  version "0.1.0"
  license "Apache-2.0 OR MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Velcrux/velcrux/releases/download/v#{version}/velcrux-v#{version}-darwin-arm64.tar.gz"
      # sha256 placeholder updated dynamically upon release publish
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/Velcrux/velcrux/releases/download/v#{version}/velcrux-v#{version}-darwin-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Velcrux/velcrux/releases/download/v#{version}/velcrux-v#{version}-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/Velcrux/velcrux/releases/download/v#{version}/velcrux-v#{version}-linux-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "velcrux"
    bin.install "velcruxd"

    # Install shell completions if present
    if File.directory?("completions")
      bash_completion.install "completions/velcrux.bash" => "velcrux" if File.exist?("completions/velcrux.bash")
      zsh_completion.install "completions/_velcrux" => "_velcrux" if File.exist?("completions/_velcrux")
      fish_completion.install "completions/velcrux.fish" => "velcrux.fish" if File.exist?("completions/velcrux.fish")
    end

    (etc/"velcrux").mkpath
    (var/"lib/velcrux").mkpath
    (var/"log/velcrux").mkpath
  end

  def post_install
    (var/"lib/velcrux").mkpath
    (var/"log/velcrux").mkpath
  end

  service do
    run [opt_bin/"velcruxd", "run", "--config", etc/"velcrux/server.toml"]
    keep_alive true
    working_dir var/"lib/velcrux"
    log_path var/"log/velcrux/velcruxd.log"
    error_log_path var/"log/velcrux/velcruxd.err"
  end

  test do
    assert_match "velcrux client CLI", shell_output("#{bin}/velcrux --help")
    assert_match "velcruxd server daemon", shell_output("#{bin}/velcruxd --help")
  end
end

