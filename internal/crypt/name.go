package crypt

import (
	"crypto/aes"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Max-Sum/base32768"
	"github.com/rfjakob/eme"
)

// NameEncryptionMode controls how file names are encrypted.
type NameEncryptionMode int

const (
	NameOff NameEncryptionMode = iota
	NameStandard
	NameObfuscated
)

// ParseNameMode turns a string into a NameEncryptionMode.
func ParseNameMode(s string) (NameEncryptionMode, error) {
	switch strings.ToLower(s) {
	case "off":
		return NameOff, nil
	case "standard":
		return NameStandard, nil
	case "obfuscate":
		return NameObfuscated, nil
	default:
		return 0, fmt.Errorf("unknown filename encryption mode %q", s)
	}
}

func (m NameEncryptionMode) String() string {
	switch m {
	case NameOff:
		return "off"
	case NameStandard:
		return "standard"
	case NameObfuscated:
		return "obfuscate"
	default:
		return fmt.Sprintf("unknown mode #%d", int(m))
	}
}

// NameEncoding converts between raw encrypted bytes and the textual
// representation used for file names.
type NameEncoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

// caseInsensitiveBase32Encoding is rclone's default name encoding: RFC 4648
// base32 with the extended-hex alphabet, lowercased and with padding stripped.
type caseInsensitiveBase32Encoding struct{}

func (caseInsensitiveBase32Encoding) EncodeToString(src []byte) string {
	encoded := base32.HexEncoding.EncodeToString(src)
	encoded = strings.TrimRight(encoded, "=")
	return strings.ToLower(encoded)
}

func (caseInsensitiveBase32Encoding) DecodeString(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, errBadBase32Encoding
	}
	roundUp := (len(s) + 7) &^ 7
	equals := roundUp - len(s)
	s = strings.ToUpper(s) + "========"[:equals]
	return base32.HexEncoding.DecodeString(s)
}

// NewNameEncoding creates a NameEncoding from a string.
func NewNameEncoding(s string) (NameEncoding, error) {
	switch strings.ToLower(s) {
	case "base32":
		return caseInsensitiveBase32Encoding{}, nil
	case "base64":
		return base64.RawURLEncoding, nil
	case "base32768":
		return base32768.SafeEncoding, nil
	default:
		return nil, fmt.Errorf("unknown filename encoding %q", s)
	}
}

var (
	errBadBase32Encoding       = errors.New("bad base32 filename encoding")
	errNotAMultipleOfBlocksize = errors.New("not a multiple of blocksize")
	errTooShortAfterDecode     = errors.New("too short after decode")
	errTooLongAfterDecode      = errors.New("too long after decode")
	errNotAnEncryptedName      = errors.New("not an encrypted file name")
)

const (
	nameCipherBlockSize = aes.BlockSize
	nameMaxDecodeLen    = 2048
	obfuscQuoteRune     = '!'
)

// encryptSegment encrypts a single path segment using EME-AES, producing
// deterministic ciphertext that is then text-encoded.
func (c *Cipher) encryptSegment(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	padded := pkcs7Pad(nameCipherBlockSize, []byte(plaintext))
	ciphertext := eme.Transform(c.block, c.nameTweak[:], padded, eme.DirectionEncrypt)
	return c.enc.EncodeToString(ciphertext)
}

// decryptSegment reverses encryptSegment.
func (c *Cipher) decryptSegment(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := c.enc.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", errTooShortAfterDecode
	}
	if len(raw)%nameCipherBlockSize != 0 {
		return "", errNotAMultipleOfBlocksize
	}
	if len(raw) > nameMaxDecodeLen {
		return "", errTooLongAfterDecode
	}
	padded := eme.Transform(c.block, c.nameTweak[:], raw, eme.DirectionDecrypt)
	plaintext, err := pkcs7Unpad(nameCipherBlockSize, padded)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// obfuscateSegment applies rclone's reversible obfuscation rotation.
func (c *Cipher) obfuscateSegment(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	if !utf8.ValidString(plaintext) {
		return "!." + plaintext
	}
	var dir int
	for _, r := range plaintext {
		dir += int(r)
	}
	dir %= 256
	var result strings.Builder
	result.WriteString(strconv.Itoa(dir) + ".")
	for i := range len(c.nameKey) {
		dir += int(c.nameKey[i])
	}
	for _, r := range plaintext {
		switch {
		case r == obfuscQuoteRune:
			result.WriteRune(obfuscQuoteRune)
			result.WriteRune(obfuscQuoteRune)
		case r >= '0' && r <= '9':
			thisDir := dir%9 + 1
			result.WriteRune(rune('0' + (int(r)-'0'+thisDir)%10))
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
			thisDir := dir%25 + 1
			pos := int(r - 'A')
			if pos >= 26 {
				pos -= 6
			}
			pos = (pos + thisDir) % 52
			if pos >= 26 {
				pos += 6
			}
			result.WriteRune(rune('A' + pos))
		case r >= 0xA0 && r <= 0xFF:
			thisDir := dir%95 + 1
			result.WriteRune(rune(0xA0 + (int(r)-0xA0+thisDir)%96))
		case r >= 0x100:
			thisDir := dir%127 + 1
			base := int(r) - int(r)%256
			newRune := rune(base + (int(r)-base+thisDir)%256)
			if !utf8.ValidRune(newRune) {
				result.WriteRune(obfuscQuoteRune)
				result.WriteRune(r)
			} else {
				result.WriteRune(newRune)
			}
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// deobfuscateSegment reverses obfuscateSegment.
func (c *Cipher) deobfuscateSegment(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	before, after, ok := strings.Cut(ciphertext, ".")
	if !ok {
		return "", errNotAnEncryptedName
	}
	if before == "!" {
		return after, nil
	}
	dir, err := strconv.Atoi(before)
	if err != nil {
		return "", errNotAnEncryptedName
	}
	for i := range len(c.nameKey) {
		dir += int(c.nameKey[i])
	}
	var result strings.Builder
	inQuote := false
	for _, r := range after {
		switch {
		case inQuote:
			result.WriteRune(r)
			inQuote = false
		case r == obfuscQuoteRune:
			inQuote = true
		case r >= '0' && r <= '9':
			thisDir := dir%9 + 1
			newRune := '0' + int(r) - '0' - thisDir
			if newRune < '0' {
				newRune += 10
			}
			result.WriteRune(rune(newRune))
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
			thisDir := dir%25 + 1
			pos := int(r - 'A')
			if pos >= 26 {
				pos -= 6
			}
			pos -= thisDir
			if pos < 0 {
				pos += 52
			}
			if pos >= 26 {
				pos += 6
			}
			result.WriteRune(rune('A' + pos))
		case r >= 0xA0 && r <= 0xFF:
			thisDir := dir%95 + 1
			newRune := 0xA0 + int(r) - 0xA0 - thisDir
			if newRune < 0xA0 {
				newRune += 96
			}
			result.WriteRune(rune(newRune))
		case r >= 0x100:
			thisDir := dir%127 + 1
			base := int(r) - int(r)%256
			newRune := rune(base + (int(r) - base - thisDir))
			if int(newRune) < base {
				newRune += 256
			}
			result.WriteRune(newRune)
		default:
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}

// EncryptFileName encrypts a file path.
func (c *Cipher) EncryptFileName(in string) string {
	if c.mode == NameOff {
		return in + c.suffix
	}
	return c.encryptPath(in)
}

// EncryptDirName encrypts a directory path.
func (c *Cipher) EncryptDirName(in string) string {
	if c.mode == NameOff || !c.dirNameEncrypt {
		return in
	}
	return c.encryptPath(in)
}

func (c *Cipher) encryptPath(in string) string {
	segments := strings.Split(in, "/")
	for i := range segments {
		if !c.dirNameEncrypt && i != len(segments)-1 {
			continue
		}
		if c.mode == NameStandard {
			segments[i] = c.encryptSegment(segments[i])
		} else {
			segments[i] = c.obfuscateSegment(segments[i])
		}
	}
	return strings.Join(segments, "/")
}

// DecryptFileName decrypts a file path.
func (c *Cipher) DecryptFileName(in string) (string, error) {
	if c.mode == NameOff {
		remaining := len(in) - len(c.suffix)
		if remaining == 0 || !strings.HasSuffix(in, c.suffix) {
			return "", errNotAnEncryptedName
		}
		return in[:remaining], nil
	}
	return c.decryptPath(in)
}

// DecryptDirName decrypts a directory path.
func (c *Cipher) DecryptDirName(in string) (string, error) {
	if c.mode == NameOff || !c.dirNameEncrypt {
		return in, nil
	}
	return c.decryptPath(in)
}

func (c *Cipher) decryptPath(in string) (string, error) {
	segments := strings.Split(in, "/")
	for i := range segments {
		if !c.dirNameEncrypt && i != len(segments)-1 {
			continue
		}
		var err error
		if c.mode == NameStandard {
			segments[i], err = c.decryptSegment(segments[i])
		} else {
			segments[i], err = c.deobfuscateSegment(segments[i])
		}
		if err != nil {
			return "", err
		}
	}
	return strings.Join(segments, "/"), nil
}
