package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	bin := filepath.Join(os.TempDir(), "rclone-encrypt-test-bin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Always rebuild so a stale binary from a previous run is never used.
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
	binPath = bin
	os.Exit(m.Run())
}

// baseEnv returns the current environment with the password/salt env vars
// removed, so interactive tests are not affected by a developer shell that
// happens to have them set. On Windows the first occurrence of a duplicated
// env key wins, so simply appending an empty value is not enough.
func baseEnv() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); k == envPassword || k == envSalt {
			continue
		}
		env = append(env, kv)
	}
	return env
}

type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func runCLI(t *testing.T, stdin string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Env = baseEnv()
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run CLI: %v", err)
		}
	}
	return runResult{stdout: out.String(), stderr: errOut.String(), exitCode: code}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// lastLine returns the last non-empty line of s, used to read the encrypted or
// decrypted file name that the CLI prints to stderr.
func lastLine(s string) string {
	parts := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(parts[len(parts)-1])
}

// renameToEncryptedName moves the encrypted output produced with -o onto a path
// whose base is the encrypted file name (as rclone would store it), so a later
// decrypt can recover the original name.
func renameToEncryptedName(t *testing.T, stderr, outPath, dir string) string {
	t.Helper()
	encName := lastLine(stderr)
	if encName == "" {
		t.Fatalf("no encrypted name in stderr: %q", stderr)
	}
	named := filepath.Join(dir, encName)
	if err := os.Rename(outPath, named); err != nil {
		t.Fatal(err)
	}
	return named
}

func TestVersion(t *testing.T) {
	r := runCLI(t, "", "--version")
	if r.exitCode != 0 {
		t.Fatalf("exit %d: %s", r.exitCode, r.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(r.stdout), "rclone-encrypt-test-glm ") {
		t.Errorf("version output: %q", r.stdout)
	}
}

func TestMissingInputFile(t *testing.T) {
	r := runCLI(t, "", "encrypt", "--password", "pw")
	if r.exitCode != 2 {
		t.Fatalf("expected exit 2, got %d: %s", r.exitCode, r.stderr)
	}
	if !strings.Contains(r.stderr, "input-file is required") {
		t.Errorf("stderr: %q", r.stderr)
	}
}

func TestPasswordFlagWarns(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "plain.txt", "hello world")
	r := runCLI(t, "", "encrypt", "-i", in, "-o", filepath.Join(dir, "out.bin"), "--password", "pw")
	if r.exitCode != 0 {
		t.Fatalf("exit %d: %s", r.exitCode, r.stderr)
	}
	if !strings.Contains(r.stderr, "warning") || !strings.Contains(r.stderr, "insecure") {
		t.Errorf("expected security warning on stderr, got: %q", r.stderr)
	}
}

func TestEncryptDecryptWithPasswordFlag(t *testing.T) {
	dir := t.TempDir()
	plain := "the quick brown fox jumps over the lazy dog"
	in := writeFile(t, dir, "input.txt", plain)
	encOut := filepath.Join(dir, "encrypted")
	r := runCLI(t, "", "encrypt", "-i", in, "-o", encOut, "--password", "pw")
	if r.exitCode != 0 {
		t.Fatalf("encrypt exit %d: %s", r.exitCode, r.stderr)
	}
	if !strings.Contains(r.stderr, "warning") || !strings.Contains(r.stderr, "insecure") {
		t.Errorf("expected security warning on stderr, got: %q", r.stderr)
	}
	if _, err := os.Stat(encOut); err != nil {
		t.Fatalf("encrypted file not created: %v", err)
	}
	// Store the encrypted file under its encrypted name, as rclone would.
	named := renameToEncryptedName(t, r.stderr, encOut, dir)

	decOut := filepath.Join(dir, "decrypted.txt")
	r2 := runCLI(t, "", "decrypt", "-i", named, "-o", decOut, "--password", "pw")
	if r2.exitCode != 0 {
		t.Fatalf("decrypt exit %d: %s", r2.exitCode, r2.stderr)
	}
	got, err := os.ReadFile(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Errorf("decrypted content mismatch: got %q want %q", string(got), plain)
	}
	if !strings.Contains(r2.stderr, "input.txt") {
		t.Errorf("expected decrypted file name on stderr, got: %q", r2.stderr)
	}
}

func TestEncryptDecryptWithEnvVar(t *testing.T) {
	dir := t.TempDir()
	plain := "secret via env var"
	in := writeFile(t, dir, "data.bin", plain)
	encOut := filepath.Join(dir, "enc")

	cmd := exec.Command(binPath, "encrypt", "-i", in, "-o", encOut)
	cmd.Env = append(baseEnv(), "RCLONE_ENCRYPT_PASSWORD=envpw")
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("encrypt: %v %s", err, errOut.String())
	}
	if strings.Contains(errOut.String(), "warning") {
		t.Errorf("env var path should not emit the --password warning, got: %q", errOut.String())
	}

	decOut := filepath.Join(dir, "dec")
	cmd2 := exec.Command(binPath, "decrypt", "-i", encOut, "-o", decOut)
	cmd2.Env = append(baseEnv(), "RCLONE_ENCRYPT_PASSWORD=envpw")
	var decErr bytes.Buffer
	cmd2.Stderr = &decErr
	if err := cmd2.Run(); err != nil {
		t.Fatalf("decrypt: %v %s", err, decErr.String())
	}
	got, err := os.ReadFile(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Errorf("mismatch: got %q want %q", string(got), plain)
	}
}

func TestWrongPasswordFails(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "p.txt", "content")
	encOut := filepath.Join(dir, "e")
	if r := runCLI(t, "", "encrypt", "-i", in, "-o", encOut, "--password", "right"); r.exitCode != 0 {
		t.Fatalf("encrypt: %s", r.stderr)
	}
	r := runCLI(t, "", "decrypt", "-i", encOut, "-o", filepath.Join(dir, "d"), "--password", "wrong")
	if r.exitCode == 0 {
		t.Fatalf("expected decrypt to fail with wrong password, got stdout=%q stderr=%q", r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "authenticate") && !strings.Contains(r.stderr, "bad password") {
		t.Errorf("expected auth error, got: %q", r.stderr)
	}
}

func TestSaltRoundTripViaFlag(t *testing.T) {
	dir := t.TempDir()
	plain := "salted round trip"
	in := writeFile(t, dir, "in.txt", plain)
	encOut := filepath.Join(dir, "enc")
	r := runCLI(t, "", "encrypt", "-i", in, "-o", encOut, "--password", "pw", "--salt", "salty")
	if r.exitCode != 0 {
		t.Fatalf("encrypt: %s", r.stderr)
	}
	decOut := filepath.Join(dir, "dec")
	r2 := runCLI(t, "", "decrypt", "-i", encOut, "-o", decOut, "--password", "pw", "--salt", "salty")
	if r2.exitCode != 0 {
		t.Fatalf("decrypt: %s", r2.stderr)
	}
	got, err := os.ReadFile(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Errorf("mismatch: got %q want %q", string(got), plain)
	}
	// Without the salt, decryption must fail.
	r3 := runCLI(t, "", "decrypt", "-i", encOut, "-o", filepath.Join(dir, "dec2"), "--password", "pw")
	if r3.exitCode == 0 {
		t.Fatal("expected decrypt without salt to fail")
	}
}

func TestCustomEncodingBase64(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "report.txt", "base64 encoded name")
	encOut := filepath.Join(dir, "enc")
	r := runCLI(t, "", "encrypt", "-i", in, "-o", encOut, "--password", "pw", "--filename-encoding", "base64")
	if r.exitCode != 0 {
		t.Fatalf("encrypt: %s", r.stderr)
	}
	encryptedName := lastLine(r.stderr)
	if encryptedName == "" {
		t.Fatal("expected encrypted file name on stderr")
	}
	// base64 raw URL encoding uses - and _ which base32 hex never does.
	if !strings.ContainsAny(encryptedName, "-_") && !strings.ContainsAny(encryptedName, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("does not look base64: %q", encryptedName)
	}
	// Store under the encrypted name so decrypt can recover "report.txt".
	named := renameToEncryptedName(t, r.stderr, encOut, dir)

	decOut := filepath.Join(dir, "dec")
	r2 := runCLI(t, "", "decrypt", "-i", named, "-o", decOut, "--password", "pw", "--filename-encoding", "base64")
	if r2.exitCode != 0 {
		t.Fatalf("decrypt: %s", r2.stderr)
	}
	if !strings.Contains(r2.stderr, "report.txt") {
		t.Errorf("expected original name on stderr, got: %q", r2.stderr)
	}
	got, err := os.ReadFile(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "base64 encoded name" {
		t.Errorf("content mismatch: got %q", string(got))
	}
}

func TestInteractivePromptForPasswordAndSalt(t *testing.T) {
	dir := t.TempDir()
	plain := "interactive round trip"
	in := writeFile(t, dir, "in.txt", plain)
	encOut := filepath.Join(dir, "enc")
	// No --password and no env var: pipe "password\nmysalt\n" to stdin.
	r := runCLI(t, "password\nmysalt\n", "encrypt", "-i", in, "-o", encOut)
	if r.exitCode != 0 {
		t.Fatalf("encrypt exit %d: %s", r.exitCode, r.stderr)
	}

	decOut := filepath.Join(dir, "dec")
	r2 := runCLI(t, "password\nmysalt\n", "decrypt", "-i", encOut, "-o", decOut)
	if r2.exitCode != 0 {
		t.Fatalf("decrypt exit %d: %s", r2.exitCode, r2.stderr)
	}
	got, err := os.ReadFile(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Errorf("mismatch: got %q want %q", string(got), plain)
	}

	// Interactive prompt with the wrong salt must fail to decrypt.
	r3 := runCLI(t, "password\nwrongsalt\n", "decrypt", "-i", encOut, "-o", filepath.Join(dir, "dec2"))
	if r3.exitCode == 0 {
		t.Fatal("expected decrypt with wrong salt to fail")
	}
}

func TestInteractivePromptPasswordOnlyNoSalt(t *testing.T) {
	dir := t.TempDir()
	plain := "no salt interactive"
	in := writeFile(t, dir, "in.txt", plain)
	encOut := filepath.Join(dir, "enc")
	// Pipe password then an empty line (no salt).
	r := runCLI(t, "mypw\n\n", "encrypt", "-i", in, "-o", encOut)
	if r.exitCode != 0 {
		t.Fatalf("encrypt exit %d: %s", r.exitCode, r.stderr)
	}
	decOut := filepath.Join(dir, "dec")
	r2 := runCLI(t, "mypw\n\n", "decrypt", "-i", encOut, "-o", decOut)
	if r2.exitCode != 0 {
		t.Fatalf("decrypt exit %d: %s", r2.exitCode, r2.stderr)
	}
	got, err := os.ReadFile(decOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plain {
		t.Errorf("mismatch: got %q want %q", string(got), plain)
	}
}
