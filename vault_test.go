package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultLifecycle(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := []byte("correct horse battery staple")
	if err := initVault(root, password); err != nil {
		t.Fatal(err)
	}
	vault, err := openVault(root, password)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	entry := newEntry()
	entry.Secret = "secret"
	entry.Identity = "alice"
	if err := vault.Add("github/work", entry); err != nil {
		t.Fatal(err)
	}
	got, err := vault.Get("github/work")
	if err != nil || got.Secret != entry.Secret {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	got.Notes = "updated"
	if err := vault.Update("github/work", got); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	if err := vault.Move("github/work", "github/personal"); err != nil {
		t.Fatal(err)
	}
	names, err := vault.List()
	if err != nil || strings.Join(names, ",") != "github/personal" {
		t.Fatalf("List() = %v, %v", names, err)
	}
	if failures := vault.Check(); len(failures) != 0 {
		t.Fatal(failures)
	}
	if err := vault.ChangePassword([]byte("new password")); err != nil {
		t.Fatal(err)
	}
	if _, err := openVault(root, password); err == nil {
		t.Fatal("old password unexpectedly opened vault")
	}
	reopened, err := openVault(root, []byte("new password"))
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestVaultDefaultsToLocalAppData(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	path, err := defaultVaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(localAppData, "pm", "vault")
	if path != want {
		t.Fatalf("defaultVaultPath() = %q, want %q", path, want)
	}
}

func TestExpiredEntryIsPreservedForMetadataAndEditing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	password := []byte("correct horse battery staple")
	if err := initVault(root, password); err != nil {
		t.Fatal(err)
	}
	vault, err := openVault(root, password)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	expiration := "2000-01-01"
	entry := newEntry()
	entry.Secret = "preserve me"
	entry.Identity = "alice"
	entry.ExpiresAt = &expiration
	if err := vault.Add("expired/account", entry); err != nil {
		t.Fatal(err)
	}
	got, err := vault.Get("expired/account")
	if err != nil {
		t.Fatal(err)
	}
	if !isExpired(got) || got.Secret != entry.Secret {
		t.Fatalf("expired entry was changed: %#v", got)
	}
	got.ExpiresAt = nil
	if err := vault.Update("expired/account", got); err != nil {
		t.Fatalf("expired entry could not be edited: %v", err)
	}
}

func TestExpiredMetadataStatus(t *testing.T) {
	entry := newEntry()
	expiration := "2000-01-01"
	entry.ExpiresAt = &expiration
	plain := formatMetadata("expired/account", entry, expiredStatus(false))
	if !strings.Contains(plain, "status:      EXPIRED\n") ||
		strings.Contains(plain, "\x1b[") {
		t.Fatalf("unexpected plain metadata: %q", plain)
	}
	colored := formatMetadata("expired/account", entry, expiredStatus(true))
	if !strings.Contains(colored, "\x1b[1;31mEXPIRED\x1b[0m") {
		t.Fatalf("colored metadata lacks highlighted status: %q", colored)
	}
}

func TestInteractiveInputRejectsTerminalControls(t *testing.T) {
	if err := validateIdentity("safe identity"); err != nil {
		t.Fatal(err)
	}
	if err := validateIdentity("unsafe\x1b[2J"); err == nil {
		t.Fatal("identity containing an ANSI escape was accepted")
	}
	if err := validateNotes("line one\nline two\tvalue"); err != nil {
		t.Fatal(err)
	}
	if err := validateNotes("unsafe\x00note"); err == nil {
		t.Fatal("notes containing a NUL were accepted")
	}
	if err := validateOptionalDate("2026-07-27"); err != nil {
		t.Fatal(err)
	}
	if err := validateOptionalDate("27/07/2026"); err == nil {
		t.Fatal("invalid date was accepted")
	}
}

func TestVaultRejectsSymlinkEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	outside := t.TempDir()
	password := []byte("correct horse battery staple")
	if err := initVault(root, password); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	vault, err := openVault(root, password)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	entry := newEntry()
	entry.Secret = "must-not-escape"
	if err := vault.Add("escape/secret", entry); err == nil {
		t.Fatal("entry write through an escaping symlink unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "secret.pm")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("entry escaped the vault: %v", err)
	}
}

func TestEntryValidation(t *testing.T) {
	entry := newEntry()
	entry.Secret = "x"
	text, err := serializeEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseEntry(text); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), text[:len(text)-2]...)
	bad = append(bad, ',', '"', 'x', '"', ':', '1', '}', '\n')
	if _, err := parseEntry(bad); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestTree(t *testing.T) {
	got := formatTree([]string{"gitlab/team", "github/zeta", "github/alpha"})
	want := "├── github\n│   ├── alpha\n│   └── zeta\n└── gitlab\n    └── team\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
