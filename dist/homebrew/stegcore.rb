# Author:  Daniel Iwugo
# Comment: Christ is King
# Homebrew formula for Stegcore
# To install: brew install elementmerc/tap/stegcore
# Or: brew tap elementmerc/tap && brew install stegcore

class Stegcore < Formula
  desc "Crypto-steganography toolkit — hide encrypted messages inside ordinary files"
  homepage "https://github.com/elementmerc/Stegcore"
  license "AGPL-3.0-only"
  version "3.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/elementmerc/Stegcore/releases/download/v#{version}/stegcore-v#{version}-darwin-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_ARM64"
    else
      url "https://github.com/elementmerc/Stegcore/releases/download/v#{version}/stegcore-v#{version}-darwin-x86_64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_X64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/elementmerc/Stegcore/releases/download/v#{version}/stegcore-v#{version}-linux-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/elementmerc/Stegcore/releases/download/v#{version}/stegcore-v#{version}-linux-x86_64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X64"
    end
  end

  def install
    bin.install "stegcore"
    bin.install "stegcore-gui" if File.exist?("stegcore-gui")

    # Shell completions
    generate_completions_from_executable(bin/"stegcore", "completions")
  end

  test do
    assert_match "stegcore", shell_output("#{bin}/stegcore --version")
    assert_match "Ascon-128", shell_output("#{bin}/stegcore ciphers")
  end
end
