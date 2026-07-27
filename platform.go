package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/term"
)

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, cliThemeFor(os.Stderr).accent.Render(prompt))
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read password: %w", err)
	}
	return password, nil
}

func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func clipboardHash(text []byte) string {
	sum := sha256.Sum256(text)
	return hex.EncodeToString(sum[:])
}

func colorOutputEnabled(file *os.File) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled ||
		os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func setClipboard(text []byte) error {
	if err := clipboard.WriteAll(string(text)); err != nil {
		return fmt.Errorf("could not write to clipboard: %w", err)
	}
	return nil
}

func getClipboard() ([]byte, error) {
	text, err := clipboard.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("could not read clipboard: %w", err)
	}
	return []byte(text), nil
}

func copyToClipboard(text []byte, clearAfter time.Duration) error {
	if err := setClipboard(text); err != nil {
		return err
	}
	executable, err := executablePath()
	if err != nil {
		return nil
	}
	return startClipboardClearer(
		executable, clearAfter.String(), clipboardHash(text))
}

func clearClipboardAfter(delay time.Duration, expectedHash string) error {
	time.Sleep(delay)
	current, err := getClipboard()
	if err != nil {
		return err
	}
	defer wipe(current)
	if clipboardHash(current) == expectedHash {
		return setClipboard(nil)
	}
	return nil
}
