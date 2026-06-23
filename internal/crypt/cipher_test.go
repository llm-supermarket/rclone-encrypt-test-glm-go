package crypt

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// fixedReader returns a fixed byte sequence, used to make the random nonce
// deterministic in tests.
type fixedReader struct {
	b []byte
	i int
}

func (r *fixedReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func mustEnc(t *testing.T, name string) NameEncoding {
	t.Helper()
	enc, err := NewNameEncoding(name)
	if err != nil {
		t.Fatalf("NewNameEncoding(%q): %v", name, err)
	}
	return enc
}

func newCipher(t *testing.T, password, salt string, mode NameEncryptionMode, enc NameEncoding) *Cipher {
	t.Helper()
	c, err := New(Config{
		Password:       password,
		Salt:           salt,
		Mode:           mode,
		DirNameEncrypt: true,
		Encoding:       enc,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func encryptBytes(t *testing.T, c *Cipher, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := c.EncryptStream(&out, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	return out.Bytes()
}

func decryptBytes(t *testing.T, c *Cipher, ciphertext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := c.DecryptStream(&out, bytes.NewReader(ciphertext)); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	return out.Bytes()
}

func TestRoundTripFileContents(t *testing.T) {
	sizes := []int{0, 1, 7, 100, 64 * 1024, 64*1024 + 1, 130 * 1024}
	salts := []string{"", "mysalt"}
	for _, enc := range []NameEncoding{mustEnc(t, "base32"), mustEnc(t, "base64"), mustEnc(t, "base32768")} {
		for _, salt := range salts {
			for _, size := range sizes {
				plaintext := make([]byte, size)
				rnd := rand.New(rand.NewSource(int64(size) + 42))
				rnd.Read(plaintext)

				c := newCipher(t, "p@ssw0rd", salt, NameStandard, enc)
				ciphertext := encryptBytes(t, c, plaintext)
				got := decryptBytes(t, c, ciphertext)

				if !bytes.Equal(got, plaintext) {
					t.Errorf("roundtrip mismatch: enc=%T salt=%q size=%d", enc, salt, size)
				}
				if want := c.EncryptedSize(int64(size)); int64(len(ciphertext)) != want {
					t.Errorf("EncryptedSize: got %d want %d (size=%d)", len(ciphertext), want, size)
				}
				if gotSize, err := c.DecryptedSize(int64(len(ciphertext))); err != nil || gotSize != int64(size) {
					t.Errorf("DecryptedSize: got %d want %d (size=%d) err=%v", gotSize, size, size, err)
				}
			}
		}
	}
}

func TestDecryptFailsWithWrongPassword(t *testing.T) {
	c1 := newCipher(t, "correct", "", NameStandard, mustEnc(t, "base32"))
	c2 := newCipher(t, "wrong", "", NameStandard, mustEnc(t, "base32"))
	ciphertext := encryptBytes(t, c1, []byte("secret data"))
	if err := c2.DecryptStream(io.Discard, bytes.NewReader(ciphertext)); err == nil {
		t.Fatal("expected decryption to fail with wrong password")
	}
}

func TestSaltChangesCiphertext(t *testing.T) {
	cNoSalt := newCipher(t, "pw", "", NameStandard, mustEnc(t, "base32"))
	cSalt := newCipher(t, "pw", "salt", NameStandard, mustEnc(t, "base32"))
	a := encryptBytes(t, cNoSalt, []byte("hello"))
	b := encryptBytes(t, cSalt, []byte("hello"))
	if bytes.Equal(a, b) {
		t.Fatal("ciphertext should differ when a salt is used")
	}
	if !bytes.Equal(decryptBytes(t, cSalt, b), []byte("hello")) {
		t.Fatal("decrypt with salt failed")
	}
	// Decrypting the salted file with the no-salt cipher must fail.
	if err := cNoSalt.DecryptStream(io.Discard, bytes.NewReader(b)); err == nil {
		t.Fatal("expected decryption to fail without the salt")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"../../..", "../.."} {
		if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	t.Skip("could not locate repo root")
	return ""
}

// knownFile holds the details of the two rclone-generated fixture files
// committed at the repo root.
type knownFile struct {
	path        string
	encoding    string
	plainName   string
	plainText   string
}

var knownFiles = []knownFile{
	{
		path:      "kr9tu4e1da4u3nifdd99g9tf5o",
		encoding:  "base32",
		plainName: "TEST_FILE.txt",
		plainText: "## This is a test file\r\n\r\numbrella top kit charge tobacco know distance clinic detail prosper then gain museum ozone absurd neither rate correct certain scrub increase",
	},
	{
		path:      "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY",
		encoding:  "base64",
		plainName: "TEST_FILE BASE64.txt",
		plainText: "## This is a test file\r\n\r\numbrella top kit charge tobacco know distance clinic detail prosper then gain museum ozone absurd neither rate correct certain scrub increase",
	},
}

func TestKnownFilesDecryptAndRoundTripByteForByte(t *testing.T) {
	root := repoRoot(t)
	for _, kf := range knownFiles {
		t.Run(kf.encoding, func(t *testing.T) {
			enc := mustEnc(t, kf.encoding)
			c := newCipher(t, "Testpassword1", "", NameStandard, enc)

			fileBytes, err := os.ReadFile(filepath.Join(root, kf.path))
			if err != nil {
				t.Skipf("fixture missing: %v", err)
			}

			// Decrypting the file name must recover the original name.
			gotName, err := c.DecryptFileName(kf.path)
			if err != nil {
				t.Fatalf("DecryptFileName: %v", err)
			}
			if gotName != kf.plainName {
				t.Errorf("file name: got %q want %q", gotName, kf.plainName)
			}

			// Encrypting the original name must reproduce the fixture name.
			if got := c.EncryptFileName(kf.plainName); got != kf.path {
				t.Errorf("EncryptFileName: got %q want %q", got, kf.path)
			}

			// Decrypting the contents must recover the original plaintext.
			got := decryptBytes(t, c, fileBytes)
			if string(got) != kf.plainText {
				t.Errorf("content mismatch:\ngot  %q\nwant %q", string(got), kf.plainText)
			}

			// Re-encrypting with the same nonce must reproduce the file byte-for-byte.
			nonce := append([]byte{}, fileBytes[fileMagicSize:fileHeaderSize]...)
			reCipher, err := New(Config{
				Password:       "Testpassword1",
				Salt:           "",
				Mode:           NameStandard,
				DirNameEncrypt: true,
				Encoding:       enc,
				Rand:           &fixedReader{b: nonce},
			})
			if err != nil {
				t.Fatalf("New with fixed nonce: %v", err)
			}
			reEncrypted := encryptBytes(t, reCipher, got)
			if !bytes.Equal(reEncrypted, fileBytes) {
				t.Errorf("re-encrypted bytes do not match the rclone fixture (len %d vs %d)", len(reEncrypted), len(fileBytes))
			}
		})
	}
}

func TestFileNameRoundTripAllEncodingsAndModes(t *testing.T) {
	names := []string{"a", "hello.txt", "sub/dir/file.tar.gz", "UPPER.CASE", "ünïcödé.txt", ""}
	for _, encName := range []string{"base32", "base64", "base32768"} {
		enc := mustEnc(t, encName)
		for _, mode := range []NameEncryptionMode{NameStandard, NameObfuscated} {
			c := newCipher(t, "pw", "s", mode, enc)
			for _, name := range names {
				got, err := c.DecryptFileName(c.EncryptFileName(name))
				if err != nil {
					t.Errorf("DecryptFileName(enc(%q)) [%s/%s]: %v", name, mode, encName, err)
					continue
				}
				if got != name {
					t.Errorf("roundtrip [%s/%s]: got %q want %q", mode, encName, got, name)
				}
			}
		}
	}
}

func TestNameEncodingRoundTrip(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for _, encName := range []string{"base32", "base64", "base32768"} {
		enc := mustEnc(t, encName)
		for _, n := range []int{1, 7, 16, 31, 32, 100} {
			data := make([]byte, n)
			rnd.Read(data)
			s := enc.EncodeToString(data)
			got, err := enc.DecodeString(s)
			if err != nil {
				t.Errorf("decode %s: %v", encName, err)
				continue
			}
			if !bytes.Equal(got, data) {
				t.Errorf("encoding roundtrip %s len=%d mismatch", encName, n)
			}
		}
	}
}

func TestNameOffModeUsesSuffix(t *testing.T) {
	enc := mustEnc(t, "base32")
	c := newCipher(t, "pw", "", NameOff, enc)
	if got := c.EncryptFileName("photo.jpg"); got != "photo.jpg.bin" {
		t.Errorf("off encrypt: got %q want photo.jpg.bin", got)
	}
	got, err := c.DecryptFileName("photo.jpg.bin")
	if err != nil {
		t.Fatalf("off decrypt: %v", err)
	}
	if got != "photo.jpg" {
		t.Errorf("off decrypt: got %q want photo.jpg", got)
	}
}
