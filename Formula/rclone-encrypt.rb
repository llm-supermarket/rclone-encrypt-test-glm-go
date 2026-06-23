class RcloneEncrypt < Formula
  desc "CLI tool that encrypts and decrypts files using rclone's crypt defaults"
  homepage "https://github.com/yetanotherchris/rclone-encrypt-test-glm"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "f9cb8264829ffa1d38d4db11f48df1416ed82ed9cda84f8a3aedf578641918f6"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "abc3d2fc73b352a3c10f6d6a521acd08a53f09ce95c6b5270dd1019d30115a24"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "5aa4a65e39340a1eb83df341faca78f00dad36e8da906b61a7db814094597315"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "db0da8ab60f36918799bf115d5fd446eb80416df658087b15ad02cb07e110be2"
    end
  end

  def install
    bin.install "rclone-encrypt-darwin-arm64" => "rclone-encrypt" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-darwin-amd64" => "rclone-encrypt" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-linux-arm64" => "rclone-encrypt" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-linux-amd64" => "rclone-encrypt" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt #{version}", shell_output("#{bin}/rclone-encrypt --version")
  end
end