class Closedshell < Formula
  desc "macOS sandbox for AI coding agents — network-level permission enforcement"
  homepage "https://github.com/andreylukin/closedshell"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "87e016b6cb2e3e298a9a159c72b1ca6dc7af8e92a0aec1379ff3d9349e1bee60"
    else
      url "https://github.com/andreylukin/closedshell/releases/download/v#{version}/closedshell-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0eafa2472bb67bb32e2cbc6625e128af0a1a2112e55e8c1147fa942b64886ae9"
    end
  end

  def install
    bin.install "closedshell"
    bin.install_symlink "closedshell" => "cs"

    # Stage templates to share for post_install to copy to ~/.closedshell/templates
    (share/"closedshell/templates").install Dir["templates/*"] if Dir.exist?("templates")
  end

  def post_install
    templates_src = share/"closedshell/templates"
    return unless templates_src.exist?

    templates_dst = Pathname.new(Dir.home)/".closedshell"/"templates"
    templates_dst.mkpath
    FileUtils.cp_r(Dir["#{templates_src}/*"], templates_dst)
  end

  def caveats
    <<~EOS
      Bundled templates installed to:
        ~/.closedshell/templates
    EOS
  end

  test do
    assert_match "closedshell", shell_output("#{bin}/closedshell --help")
  end
end
