class Closedshell < Formula
  desc "macOS sandbox for AI coding agents — network-level permission enforcement"
  homepage "https://github.com/andreylukin/closedshell"
  license "MIT"
  version "0.1.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "3920847c5b779c5697a1a306d58b1430bd97d0676e1b787d3de95c53849ff95c"
    else
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "4507caa14583ab0348d68a4d1bcdaa634fb7f347d9dde16e0df551679d60a7bd"
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
