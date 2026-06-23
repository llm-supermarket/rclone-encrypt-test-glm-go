// Package crypt implements rclone-compatible file and filename encryption.
//
// It mirrors the defaults of rclone's crypt backend:
//   - File contents: NaCl SecretBox (XSalsa20 + Poly1305) with a 24-byte
//     nonce, streamed in 64 KiB blocks.
//   - File names: AES-EME (deterministic, wide-block) with PKCS#7 padding.
//   - Key material: scrypt with N=16384, r=8, p=1.
//
// When no salt is supplied rclone's built-in default salt is used.
package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	fileMagic       = "RCLONE\x00\x00"
	fileMagicSize   = len(fileMagic)
	fileNonceSize   = 24
	fileHeaderSize  = fileMagicSize + fileNonceSize
	blockHeaderSize = secretbox.Overhead
	blockDataSize   = 64 * 1024
	blockSize       = blockHeaderSize + blockDataSize
	keySize         = 32 + 32 + 16
)

// defaultSalt is rclone's built-in salt, used when the caller does not
// provide one. It makes attackers' lives slightly harder than no salt.
var defaultSalt = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}

// Errors returned by the cipher.
var (
	ErrEncryptedFileTooShort = errors.New("file is too short to be encrypted")
	ErrEncryptedFileBadHeader = errors.New("file has truncated block header")
	ErrEncryptedBadMagic     = errors.New("not an encrypted file - bad magic string")
	ErrEncryptedBadBlock     = errors.New("failed to authenticate decrypted block - bad password?")
)

// Config holds the parameters for constructing a Cipher.
type Config struct {
	Password       string
	Salt           string
	Mode           NameEncryptionMode
	DirNameEncrypt bool
	Encoding       NameEncoding
	Suffix         string
	Rand           io.Reader
}

// Cipher is an rclone-compatible encryptor/decryptor.
type Cipher struct {
	dataKey        [32]byte
	nameKey        [32]byte
	nameTweak      [nameCipherBlockSize]byte
	block          cipher.Block
	mode           NameEncryptionMode
	enc            NameEncoding
	dirNameEncrypt bool
	suffix         string
	rand           io.Reader
}

// New constructs a Cipher from the given config.
func New(cfg Config) (*Cipher, error) {
	if cfg.Encoding == nil {
		return nil, errors.New("crypt: encoding is required")
	}
	suffix := cfg.Suffix
	if suffix == "" {
		suffix = ".bin"
	}
	if strings.EqualFold(suffix, "none") {
		suffix = ""
	} else if !hasSuffixDot(suffix) {
		suffix = "." + suffix
	}
	r := cfg.Rand
	if r == nil {
		r = rand.Reader
	}
	c := &Cipher{
		mode:           cfg.Mode,
		enc:            cfg.Encoding,
		dirNameEncrypt: cfg.DirNameEncrypt,
		suffix:         suffix,
		rand:           r,
	}
	if err := c.deriveKeys(cfg.Password, cfg.Salt); err != nil {
		return nil, err
	}
	return c, nil
}

func hasSuffixDot(suffix string) bool {
	return len(suffix) > 0 && suffix[0] == '.'
}

// NameEncoding returns the configured name encoding.
func (c *Cipher) NameEncoding() NameEncoding { return c.enc }

// NameEncryptionMode returns the configured name encryption mode.
func (c *Cipher) NameEncryptionMode() NameEncryptionMode { return c.mode }

// Suffix returns the suffix appended to file names when name encryption is off.
func (c *Cipher) Suffix() string { return c.suffix }

// deriveKeys generates the data, name and tweak keys from the password using
// scrypt. An empty password produces all-zero keys (matching rclone's tests).
func (c *Cipher) deriveKeys(password, salt string) error {
	saltBytes := defaultSalt
	if salt != "" {
		saltBytes = []byte(salt)
	}
	var key []byte
	if password == "" {
		key = make([]byte, keySize)
	} else {
		var err error
		key, err = scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, keySize)
		if err != nil {
			return fmt.Errorf("crypt: scrypt key derivation failed: %w", err)
		}
	}
	copy(c.dataKey[:], key[0:32])
	copy(c.nameKey[:], key[32:64])
	copy(c.nameTweak[:], key[64:80])
	block, err := aes.NewCipher(c.nameKey[:])
	if err != nil {
		return fmt.Errorf("crypt: aes cipher init failed: %w", err)
	}
	c.block = block
	return nil
}

// incrementNonce adds 1 to the 24-byte nonce, treated as a little-endian
// counter, matching rclone's carry behaviour.
func incrementNonce(n *[fileNonceSize]byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// EncryptStream reads plaintext from src and writes the encrypted file to dst.
func (c *Cipher) EncryptStream(dst io.Writer, src io.Reader) error {
	var nonce [fileNonceSize]byte
	if _, err := io.ReadFull(c.rand, nonce[:]); err != nil {
		return fmt.Errorf("crypt: failed to read nonce: %w", err)
	}
	if _, err := dst.Write([]byte(fileMagic)); err != nil {
		return err
	}
	if _, err := dst.Write(nonce[:]); err != nil {
		return err
	}
	buf := make([]byte, blockDataSize)
	out := make([]byte, blockSize)
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			secretbox.Seal(out[:0], buf[:n], &nonce, &c.dataKey)
			if _, werr := dst.Write(out[:blockHeaderSize+n]); werr != nil {
				return werr
			}
			incrementNonce(&nonce)
		}
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
	}
}

// DecryptStream reads an encrypted file from src and writes plaintext to dst.
func (c *Cipher) DecryptStream(dst io.Writer, src io.Reader) error {
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return ErrEncryptedFileTooShort
	}
	if !bytes.Equal(header[:fileMagicSize], []byte(fileMagic)) {
		return ErrEncryptedBadMagic
	}
	var nonce [fileNonceSize]byte
	copy(nonce[:], header[fileMagicSize:])
	buf := make([]byte, blockSize)
	for {
		n, err := io.ReadFull(src, buf)
		if n == 0 {
			if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		if n <= blockHeaderSize {
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return err
			}
			return ErrEncryptedFileBadHeader
		}
		out, ok := secretbox.Open(nil, buf[:n], &nonce, &c.dataKey)
		if !ok {
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return err
			}
			return ErrEncryptedBadBlock
		}
		if _, werr := dst.Write(out); werr != nil {
			return werr
		}
		incrementNonce(&nonce)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
	}
}

// EncryptedSize returns the encrypted length of size plaintext bytes.
func (c *Cipher) EncryptedSize(size int64) int64 {
	blocks, residue := size/blockDataSize, size%blockDataSize
	total := int64(fileHeaderSize) + blocks*(blockHeaderSize+blockDataSize)
	if residue != 0 {
		total += blockHeaderSize + residue
	}
	return total
}

// DecryptedSize returns the decrypted length of size encrypted bytes.
func (c *Cipher) DecryptedSize(size int64) (int64, error) {
	size -= int64(fileHeaderSize)
	if size < 0 {
		return 0, ErrEncryptedFileTooShort
	}
	blocks, residue := size/blockSize, size%blockSize
	decrypted := blocks * blockDataSize
	if residue != 0 {
		residue -= blockHeaderSize
		if residue <= 0 {
			return 0, ErrEncryptedFileBadHeader
		}
	}
	decrypted += residue
	return decrypted, nil
}
