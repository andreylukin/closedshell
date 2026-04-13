class Closedshell < Formula
  desc "macOS sandbox for AI coding agents — network-level permission enforcement"
  homepage "https://github.com/andreylukin/closedshell"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-aarch64-apple-darwin.tar.gz"
      # sha256 will be filled after first release
    else
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-x86_64-apple-darwin.tar.gz"
      # sha256 will be filled after first release
    end
  end

  def install
    bin.install "closedshell"
    bin.install_symlink "closedshell" => "cs"

    # Install bundled templates
    (share/"closedshell/templates").install Dir["templates/*"] if Dir.exist?("templates")
  end

  def caveats
    <<~EOS
      Bundled templates installed to:
        #{share}/closedshell/templates

      Copy them to your config directory:
        cp -r #{share}/closedshell/templates ~/.closedshell/templates
    EOS
  end

  test do
    assert_match "closedshell", shell_output("#{bin}/closedshell --help")
  end
end
