# rclone-encrypt-test-glm

A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:

- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 for the filenames.
- scrypt for key material.

The CLI is a single, statically-linked binary with no runtime dependencies, so it works cross-platform without a Go toolchain installed.

## Installation

**Homebrew (macOS/Linux)**

```bash
brew tap yetanotherchris/rclone-encrypt-test-glm https://github.com/yetanotherchris/rclone-encrypt-test-glm
brew install rclone-encrypt-test-glm
```

**Scoop (Windows)**

```bash
scoop bucket add rclone-encrypt-test-glm https://github.com/yetanotherchris/rclone-encrypt-test-glm
scoop install rclone-encrypt-test-glm
```

## Example usage

### Basic example

```bash
# Encrypt a file (prompts for a password and an optional salt)
rclone-encrypt-test-glm encrypt -i photo.jpg -o photo.jpg.bin

# Decrypt it back (prints the recovered file name to stderr)
rclone-encrypt-test-glm decrypt -i photo.jpg.bin -o photo.jpg
```

### Non-interactive with an env var (recommended)

```bash
export RCLONE_ENCRYPT_PASSWORD='correct horse battery staple'
rclone-encrypt-test-glm encrypt -i notes.txt -o notes.bin
rclone-encrypt-test-glm decrypt -i notes.bin -o notes.txt
```

### With a salt

```bash
rclone-encrypt-test-glm encrypt -i notes.txt -o notes.bin --salt 'my-salt'
rclone-encrypt-test-glm decrypt -i notes.bin -o notes.txt --salt 'my-salt'
```

### Custom filename encoding (base64)

```bash
rclone-encrypt-test-glm encrypt -i report.txt -o report.bin --filename-encoding base64
rclone-encrypt-test-glm decrypt -i report.bin -o report.txt --filename-encoding base64
```

### Using --password (insecure)

```bash
# This is visible in your shell history and the process list - prefer the env var above.
rclone-encrypt-test-glm encrypt -i data.bin -o data.enc --password 'pw'

# Wipe the entry from your history afterwards, e.g. in bash:
history -d $(history 1)
```

## Details

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-i`, `--input-file` | *(required)* | Input file path |
| `-o`, `--output-file` | *(stdout)* | Output file path |
| `--password` | *(none)* | Password (insecure on the command line; prefer `RCLONE_ENCRYPT_PASSWORD`) |
| `--salt` | *(none)* | Optional salt (prefer `RCLONE_ENCRYPT_SALT`) |
| `--filename-encoding` | `base32` | `base32`, `base64`, or `base32768` |
| `--filename-encryption` | `standard` | `off`, `standard`, or `obfuscate` |
| `--directory-name-encryption` | `true` | Encrypt directory names in paths |

### Environment variables

| Variable | Description |
| --- | --- |
| `RCLONE_ENCRYPT_PASSWORD` | Password (preferred over `--password`) |
| `RCLONE_ENCRYPT_SALT` | Optional salt |

When no password is supplied via a flag or env var, the CLI prompts for one (without echo) plus an optional salt. rclone's built-in default salt is used when no salt is provided. The (de)crypted file name is always printed to stderr so you can script around it.

## Building from Source

Requires Go 1.25+.

```bash
git clone https://github.com/yetanotherchris/rclone-encrypt-test-glm
cd rclone-encrypt-test-glm
go build -o rclone-encrypt-test-glm .
```

Run the tests:

```bash
go test ./...
```

## Releases

Pushing a `vX.Y.Z` tag triggers the [Build and Release workflow](.github/workflows/build-release.yml), which cross-compiles binaries for Linux and macOS (amd64/arm64) and Windows (amd64), publishes a GitHub Release, and updates the Scoop manifest (`rclone-encrypt-test-glm.json`) and Homebrew formula (`Formula/rclone-encrypt-test-glm.rb`) in this repo.
