class RcloneEncryptTestGlm < Formula
  desc "CLI tool that encrypts and decrypts files using rclone's crypt defaults"
  homepage "https://github.com/yetanotherchris/rclone-encrypt-test-glm"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-darwin-arm64.tar.gz"
      sha256 "dfe556f70d0102a5e6b34fc8529fba3ab184c963e8f4bf05d15c917d511ee4e2"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-darwin-amd64.tar.gz"
      sha256 "956edb1af2c2685147ae8f61efff64d0c71fa3b55e45e96e6c26b554d8fd7697"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-linux-arm64.tar.gz"
      sha256 "79090d8eca8acde74d8461ad4d3f9c7a3ce74af398c91d760f2cc5ae09a18390"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-glm/releases/download/v0.1.0/rclone-encrypt-test-glm-linux-amd64.tar.gz"
      sha256 "0adb25ca40d778fcabff975b05c975247971e1585cbc07821ceb3beb6cb5705e"
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