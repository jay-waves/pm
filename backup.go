package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	backupVersion       = 1
	backupContext       = "pm-go-encrypted-backup-v1"
	maxBackupSize       = 256 << 20
	maxBackupEntrySize  = 16 << 20
	maxBackupEntryCount = 100000
)

type backupEnvelope struct {
	Version    int         `json:"version"`
	Vault      vaultConfig `json:"vault"`
	Ciphertext []byte      `json:"ciphertext"`
}

type backupPayload struct {
	Entries []backupEntry `json:"entries"`
}

type backupEntry struct {
	Name       string `json:"name"`
	Ciphertext []byte `json:"ciphertext"`
}

func exportEncryptedBackup(vault *Vault, destination string) (int, error) {
	if failures := vault.Check(); len(failures) != 0 {
		return 0, fmt.Errorf("refusing to export a damaged vault: %w", failures[0])
	}
	config := vault.config
	if err := validateVaultConfig(config); err != nil {
		return 0, err
	}

	names, err := vault.List()
	if err != nil {
		return 0, err
	}
	if len(names) > maxBackupEntryCount {
		return 0, errors.New("vault contains too many entries to export")
	}
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	payload := backupPayload{Entries: make([]backupEntry, 0, len(names))}
	for _, name := range names {
		relative, err := entryRelativePath(name)
		if err != nil {
			return 0, err
		}
		ciphertext, err := root.ReadFile(relative)
		if err != nil {
			return 0, err
		}
		if len(ciphertext) > maxBackupEntrySize {
			return 0, fmt.Errorf("entry %q is too large to export", name)
		}
		payload.Entries = append(payload.Entries, backupEntry{Name: name, Ciphertext: ciphertext})
	}
	payloadText, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	defer wipe(payloadText)
	backupKey := deriveEntryKey(vault.dataKey, backupContext)
	defer wipe(backupKey)
	ciphertext, err := encrypt(payloadText, backupKey, backupContext)
	if err != nil {
		return 0, err
	}
	envelope := backupEnvelope{
		Version: backupVersion, Vault: config, Ciphertext: ciphertext,
	}
	text, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return 0, err
	}
	if len(text) > maxBackupSize {
		return 0, errors.New("encrypted backup exceeds the size limit")
	}
	if err := writeNewFile(destination, append(text, '\n')); err != nil {
		return 0, err
	}
	return len(names), nil
}

func importEncryptedBackup(target, source string, password []byte) (int, error) {
	if len(password) == 0 {
		return 0, errors.New("backup master password cannot be empty")
	}
	if _, err := os.Lstat(target); err == nil {
		return 0, fmt.Errorf("refusing to replace existing vault at %q", target)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	text, err := readLimitedFile(source, maxBackupSize)
	if err != nil {
		return 0, err
	}
	var envelope backupEnvelope
	if err := decodeStrictJSON(text, &envelope); err != nil {
		return 0, fmt.Errorf("encrypted backup is invalid: %w", err)
	}
	if envelope.Version != backupVersion {
		return 0, fmt.Errorf("unsupported encrypted backup version %d", envelope.Version)
	}
	if envelope.Vault.Time > 5 || envelope.Vault.MemoryKiB > 256*1024 ||
		envelope.Vault.Threads > 8 {
		return 0, errors.New("encrypted backup requests excessive password-derivation resources")
	}
	dataKey, err := unlockVaultConfig(envelope.Vault, password)
	if err != nil {
		return 0, fmt.Errorf("could not unlock encrypted backup: %w", err)
	}
	defer wipe(dataKey)
	backupKey := deriveEntryKey(dataKey, backupContext)
	defer wipe(backupKey)
	payloadText, err := decrypt(envelope.Ciphertext, backupKey, backupContext)
	if err != nil {
		return 0, errors.New("encrypted backup authentication failed; it was modified or damaged")
	}
	defer wipe(payloadText)
	var payload backupPayload
	if err := decodeStrictJSON(payloadText, &payload); err != nil {
		return 0, fmt.Errorf("encrypted backup payload is invalid: %w", err)
	}
	if err := validateBackupEntries(payload.Entries); err != nil {
		return 0, err
	}

	target, err = filepath.Abs(target)
	if err != nil {
		return 0, err
	}
	parent, base := filepath.Dir(target), filepath.Base(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return 0, err
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return 0, err
	}
	defer parentRoot.Close()
	if _, err := parentRoot.Lstat(base); err == nil {
		return 0, fmt.Errorf("refusing to replace existing vault at %q", target)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	random, err := randomBytes(12)
	if err != nil {
		return 0, err
	}
	temporary := ".pm-import-" + hexBytes(random)
	wipe(random)
	if err := parentRoot.Mkdir(temporary, 0o700); err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = parentRoot.RemoveAll(temporary)
		}
	}()
	tempRoot, err := parentRoot.OpenRoot(temporary)
	if err != nil {
		return 0, err
	}
	configText, err := json.MarshalIndent(envelope.Vault, "", "  ")
	if err == nil {
		err = atomicWriteRoot(tempRoot, vaultConfigName, append(configText, '\n'))
	}
	for _, entry := range payload.Entries {
		if err != nil {
			break
		}
		relative, pathErr := entryRelativePath(entry.Name)
		if pathErr != nil {
			err = pathErr
			break
		}
		err = atomicWriteRoot(tempRoot, relative, entry.Ciphertext)
	}
	closeErr := tempRoot.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, closeErr
	}

	imported, err := openVault(filepath.Join(parent, temporary), password)
	if err != nil {
		return 0, fmt.Errorf("import validation failed: %w", err)
	}
	failures := imported.Check()
	imported.Close()
	if len(failures) != 0 {
		return 0, fmt.Errorf("import validation failed: %w", failures[0])
	}
	if _, err := parentRoot.Lstat(base); err == nil {
		return 0, fmt.Errorf("refusing to replace existing vault at %q", target)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if err := parentRoot.Rename(temporary, base); err != nil {
		return 0, err
	}
	committed = true
	return len(payload.Entries), nil
}

func validateBackupEntries(entries []backupEntry) error {
	if len(entries) > maxBackupEntryCount {
		return errors.New("encrypted backup contains too many entries")
	}
	previous := ""
	for index, entry := range entries {
		if _, err := entryRelativePath(entry.Name); err != nil {
			return fmt.Errorf("encrypted backup contains an invalid entry: %w", err)
		}
		if index > 0 && entry.Name <= previous {
			return errors.New("encrypted backup entry names are duplicated or not sorted")
		}
		if len(entry.Ciphertext) < len(entryMagic) ||
			!bytes.Equal(entry.Ciphertext[:len(entryMagic)], entryMagic) {
			return fmt.Errorf("encrypted backup entry %q has an unsupported format", entry.Name)
		}
		if len(entry.Ciphertext) > maxBackupEntrySize {
			return fmt.Errorf("encrypted backup entry %q exceeds the size limit", entry.Name)
		}
		previous = entry.Name
	}
	return nil
}

func decodeStrictJSON(text []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	text, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(text)) > limit {
		return nil, errors.New("encrypted backup exceeds the size limit")
	}
	return text, nil
}

func writeNewFile(path string, data []byte) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing backup %q", path)
		}
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}
