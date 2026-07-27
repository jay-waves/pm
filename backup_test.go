package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedBackupRoundTrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	sourceRoot := filepath.Join(t.TempDir(), "source")
	if err := initVault(sourceRoot, password); err != nil {
		t.Fatal(err)
	}
	source, err := openVault(sourceRoot, password)
	if err != nil {
		t.Fatal(err)
	}
	entry := newEntry()
	entry.Secret = "very secret"
	entry.Identity = "alice@example.test"
	entry.Notes = "private notes"
	if err := source.Add("example/work", entry); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "vault.pmb")
	count, err := exportEncryptedBackup(source, backupPath)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("export count = %d, want 1", count)
	}
	backupText, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if containsBytes(backupText, []byte("example/work")) ||
		containsBytes(backupText, []byte("very secret")) ||
		containsBytes(backupText, []byte("alice@example.test")) {
		t.Fatal("encrypted backup exposes entry plaintext")
	}

	targetRoot := filepath.Join(t.TempDir(), "imported")
	count, err = importEncryptedBackup(targetRoot, backupPath, password)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("import count = %d, want 1", count)
	}
	imported, err := openVault(targetRoot, password)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	got, err := imported.Get("example/work")
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != entry.Secret || got.Identity != entry.Identity || got.Notes != entry.Notes {
		t.Fatalf("imported entry = %#v", got)
	}
}

func TestEncryptedBackupRejectsTamperingAndExistingVault(t *testing.T) {
	password := []byte("backup password")
	sourceRoot := filepath.Join(t.TempDir(), "source")
	if err := initVault(sourceRoot, password); err != nil {
		t.Fatal(err)
	}
	source, err := openVault(sourceRoot, password)
	if err != nil {
		t.Fatal(err)
	}
	entry := newEntry()
	entry.Secret = "secret"
	if err := source.Add("service/account", entry); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "vault.pmb")
	if _, err := exportEncryptedBackup(source, backupPath); err != nil {
		t.Fatal(err)
	}
	source.Close()

	text, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(text, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 1
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered.pmb")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	targetRoot := filepath.Join(t.TempDir(), "target")
	if _, err := importEncryptedBackup(targetRoot, tamperedPath, password); err == nil {
		t.Fatal("tampered backup unexpectedly imported")
	}
	if _, err := os.Stat(targetRoot); !os.IsNotExist(err) {
		t.Fatalf("failed import left a target vault behind: %v", err)
	}

	existingRoot := filepath.Join(t.TempDir(), "existing")
	if err := initVault(existingRoot, []byte("different password")); err != nil {
		t.Fatal(err)
	}
	if _, err := importEncryptedBackup(existingRoot, backupPath, password); err == nil {
		t.Fatal("import unexpectedly replaced an existing vault")
	}
}

func containsBytes(text, fragment []byte) bool {
	for index := 0; index+len(fragment) <= len(text); index++ {
		if string(text[index:index+len(fragment)]) == string(fragment) {
			return true
		}
	}
	return false
}
