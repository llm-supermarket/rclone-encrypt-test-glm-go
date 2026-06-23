class RcloneEncryptTestGlm < Formula
  desc "CLI tool that encrypts and decrypts files using rclone's crypt defaults"
  homepage "https://github.com/yetanotherchris/rclone-encrypt-test-glm"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-darwin-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-darwin-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-linux-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "rclone-encrypt-test-glm-darwin-arm64" => "rclone-encrypt-test-glm" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-glm-darwin-amd64" => "rclone-encrypt-test-glm" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-glm-linux-arm64" => "rclone-encrypt-test-glm" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-glm-linux-amd64" => "rclone-encrypt-test-glm" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt-test-glm #{version}", shell_output("#{bin}/rclone-encrypt-test-glm --version")
  end
end
