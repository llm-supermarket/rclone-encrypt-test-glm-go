param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "yetanotherchris/rclone-encrypt-test-glm"
$platforms = @("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64")
$formulaPath = "$PSScriptRoot/Formula/rclone-encrypt.rb"
$base = "https://github.com/$repo/releases/download/v$Version"
$artifactsDir = Join-Path $PSScriptRoot "artifacts"

# Hash the tarballs that were built and downloaded into artifacts/ by the
# release job. This avoids a race against the GitHub Release upload (which can
# briefly 404 a follow-up download) and matches how updatescoop.ps1 works.
$hash = @{}
foreach ($platform in $platforms) {
    $file = Join-Path $artifactsDir "rclone-encrypt-$platform.tar.gz"
    if (-not (Test-Path $file)) {
        throw "Unable to locate rclone-encrypt-$platform.tar.gz at $file"
    }
    $hash[$platform] = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLower()
    Write-Host "SHA256 for ${platform}: $($hash[$platform])"
}

# Regenerate the formula wholesale so it stays correct across releases.
$formula = @"
class RcloneEncrypt < Formula
  desc "CLI tool that encrypts and decrypts files using rclone's crypt defaults"
  homepage "https://github.com/$repo"
  version "$Version"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "$($hash['darwin-arm64'])"
    else
      url "$base/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "$($hash['darwin-amd64'])"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "$($hash['linux-arm64'])"
    else
      url "$base/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "$($hash['linux-amd64'])"
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
"@

Set-Content -Path $formulaPath -Value $formula -NoNewline
Write-Host "Wrote $formulaPath for version $Version"
