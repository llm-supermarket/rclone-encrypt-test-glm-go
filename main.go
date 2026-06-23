// Command rclone-encrypt-test-glm encrypts and decrypts files using rclone's
// crypt backend defaults (NaCl SecretBox for contents, AES-EME for names,
// scrypt for key derivation). It is a standalone, cross-platform binary with
// no runtime dependencies.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yetanotherchris/rclone-encrypt-test-glm/internal/crypt"
	"golang.org/x/term"
)

var version = "dev"

const (
	envPassword = "RCLONE_ENCRYPT_PASSWORD"
	envSalt     = "RCLONE_ENCRYPT_SALT"
	appName     = "rclone-encrypt-test-glm"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "-v", "--version", "version":
		fmt.Printf("%s %s\n", appName, version)
		return 0
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	case "encrypt":
		return doCommand(args[1:], true)
	case "decrypt":
		return doCommand(args[1:], false)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func doCommand(args []string, encrypt bool) int {
	cmd := "encrypt"
	if !encrypt {
		cmd = "decrypt"
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	input := fs.String("input-file", "", "input file path (required)")
	output := fs.String("output-file", "", "output file path (defaults to stdout)")
	password := fs.String("password", "", "password (INSECURE on the command line - prefer "+envPassword+")")
	salt := fs.String("salt", "", "optional salt (prefer "+envSalt+")")
	nameMode := fs.String("filename-encryption", "standard", "filename encryption mode: off|standard|obfuscate")
	nameEnc := fs.String("filename-encoding", "base32", "filename text encoding: base32|base64|base32768")
	dirNameEnc := fs.Bool("directory-name-encryption", true, "encrypt directory names in paths")

	fs.StringVar(input, "i", "", "shorthand for -input-file")
	fs.StringVar(output, "o", "", "shorthand for -output-file")

	fs.Usage = func() { cmdUsage(fs, os.Stderr, cmd) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: -i/--input-file is required")
		return 2
	}

	mode, err := crypt.ParseNameMode(*nameMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	enc, err := crypt.NewNameEncoding(*nameEnc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	pw, src, err := resolvePassword(*password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if src == credFlag {
		fmt.Fprintln(os.Stderr, "warning: supplying --password on the command line is insecure - it is visible in your shell history and the process list. Prefer the "+envPassword+" environment variable, and clear the history entry afterwards.")
	}
	saltVal, err := resolveSalt(*salt, src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	cipher, err := crypt.New(crypt.Config{
		Password:       pw,
		Salt:           saltVal,
		Mode:           mode,
		DirNameEncrypt: *dirNameEnc,
		Encoding:       enc,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	in, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer in.Close()

	var out io.Writer
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	if encrypt {
		if err := cipher.EncryptStream(out, in); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, cipher.EncryptFileName(filepath.Base(*input)))
	} else {
		if err := cipher.DecryptStream(out, in); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		name, err := cipher.DecryptFileName(filepath.Base(*input))
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not decode file name:", err)
		} else {
			fmt.Fprintln(os.Stderr, name)
		}
	}
	return 0
}

type credSource int

const (
	credFlag credSource = iota
	credEnv
	credPrompt
)

// stdinBuf is shared across prompts so that buffered (but unconsumed) input from
// the first prompt is still available to the next one.
var stdinBuf = bufio.NewReader(os.Stdin)

func resolvePassword(flagPw string) (string, credSource, error) {
	if flagPw != "" {
		return flagPw, credFlag, nil
	}
	if env := os.Getenv(envPassword); env != "" {
		return env, credEnv, nil
	}
	pw, err := readSecretLine("Password: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return "", credPrompt, err
	}
	if pw == "" {
		return "", credPrompt, errors.New("password is required")
	}
	return pw, credPrompt, nil
}

// resolveSalt returns the salt. When the password came from a flag or env var
// (non-interactive) and no salt source is set, it defaults to no salt without
// prompting. It only prompts when the user is already being prompted for the
// password.
func resolveSalt(flagSalt string, pwSrc credSource) (string, error) {
	if flagSalt != "" {
		return flagSalt, nil
	}
	if env := os.Getenv(envSalt); env != "" {
		return env, nil
	}
	if pwSrc != credPrompt {
		return "", nil
	}
	s, err := readSecretLine("Salt (optional - press Enter to skip): ")
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return s, nil
}

func readSecretLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdinBuf.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "%s %s - rclone-compatible file encryption\n\n", appName, version)
	fmt.Fprintf(w, "Usage:\n  %s <command> [flags]\n\n", appName)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  encrypt   encrypt an input file")
	fmt.Fprintln(w, "  decrypt   decrypt an input file")
	fmt.Fprintln(w, "  version   print the version")
	fmt.Fprintln(w, "  help      print this help")
	fmt.Fprintln(w, "\nFlags:")
	fmt.Fprintln(w, "  -i, --input-file PATH        input file (required)")
	fmt.Fprintln(w, "  -o, --output-file PATH       output file (defaults to stdout)")
	fmt.Fprintln(w, "      --password PW            password (insecure; prefer "+envPassword+")")
	fmt.Fprintln(w, "      --salt S                 optional salt (prefer "+envSalt+")")
	fmt.Fprintln(w, "      --filename-encoding ENC  base32|base64|base32768 (default base32)")
	fmt.Fprintln(w, "      --filename-encryption M  off|standard|obfuscate (default standard)")
	fmt.Fprintln(w, "      --directory-name-encryption   encrypt directory names (default true)")
	fmt.Fprintf(w, "\nEnvironment:\n  %s  password\n  %s  salt\n", envPassword, envSalt)
}

func cmdUsage(fs *flag.FlagSet, w io.Writer, cmd string) {
	fmt.Fprintf(w, "Usage: %s %s -i <input> [-o <output>] [flags]\n\n", appName, cmd)
	fs.PrintDefaults()
}
