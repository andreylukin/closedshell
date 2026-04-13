class Closedshell < Formula
  desc "macOS sandbox for AI coding agents — network-level permission enforcement"
  homepage "https://github.com/andreylukin/closedshell"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "42f473cd8cf6dc0e40bf148ed2d8b216b183286f102bb9c61cbca14961cab3c4"
    else
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "eb2438e21af4a8bb82466c1623fbc667d9202dad6303a0ab3d1c5a42753e5712"
    end
  end

  def install
    bin.install "cs"
    bin.install_symlink "cs" => "closedshell"
  end

  test do
    assert_match "cs", shell_output("#{bin}/cs --help")
  end
end
