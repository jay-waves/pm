package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	vaultConfigName = "vault.json"
	entryExtension  = ".pm"
	keyContext      = "pm-go-vault-key-v1"
)

var entryMagic = []byte{'P', 'M', 'G', '1'}

type vaultConfig struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Salt       string `json:"salt"`
	WrappedKey string `json:"wrapped_key"`
}

type Vault struct {
	root    string
	dataKey []byte
	config  vaultConfig
}

func initVault(root string, password []byte) error {
	if len(password) == 0 {
		return errors.New("master password cannot be empty")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, vaultConfigName)); err == nil {
		return fmt.Errorf("a vault already exists at %q", root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	dataKey, err := randomBytes(keySize)
	if err != nil {
		return err
	}
	defer wipe(dataKey)
	if err := writeVaultConfig(root, password, dataKey); err != nil {
		return err
	}
	return nil
}

func writeVaultConfig(root string, password, dataKey []byte) error {
	salt, err := randomBytes(saltSize)
	if err != nil {
		return err
	}
	defer wipe(salt)
	wrappingKey := derivePasswordKey(password, salt, defaultTime, defaultMemory, defaultThreads)
	defer wipe(wrappingKey)
	wrappedKey, err := encrypt(dataKey, wrappingKey, keyContext)
	if err != nil {
		return err
	}
	config := vaultConfig{
		Version: 1, KDF: "argon2id", Time: defaultTime,
		MemoryKiB: defaultMemory, Threads: defaultThreads,
		Salt: hexBytes(salt), WrappedKey: hexBytes(wrappedKey),
	}
	text, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(root, vaultConfigName), append(text, '\n'))
}

func openVault(path string, password []byte) (*Vault, error) {
	root, err := validateVaultRoot(path)
	if err != nil {
		return nil, err
	}
	text, err := os.ReadFile(filepath.Join(root, vaultConfigName))
	if err != nil {
		return nil, err
	}
	var config vaultConfig
	if err := json.Unmarshal(text, &config); err != nil {
		return nil, errors.New("vault configuration is invalid or damaged")
	}
	dataKey, err := unlockVaultConfig(config, password)
	if err != nil {
		return nil, err
	}
	return &Vault{root: root, dataKey: dataKey, config: config}, nil
}

func unlockVaultConfig(config vaultConfig, password []byte) ([]byte, error) {
	if err := validateVaultConfig(config); err != nil {
		return nil, err
	}
	salt, err := parseHex(config.Salt, saltSize)
	if err != nil {
		return nil, err
	}
	wrappedKey, err := parseHex(config.WrappedKey, chachaEncryptedSize(keySize))
	if err != nil {
		return nil, err
	}
	wrappingKey := derivePasswordKey(password, salt, config.Time, config.MemoryKiB, config.Threads)
	defer wipe(wrappingKey)
	dataKey, err := decrypt(wrappedKey, wrappingKey, keyContext)
	if err != nil || len(dataKey) != keySize {
		wipe(dataKey)
		return nil, errors.New("authentication failed; the password is wrong or the vault is damaged")
	}
	return dataKey, nil
}

func validateVaultConfig(config vaultConfig) error {
	if config.Version != 1 || config.KDF != "argon2id" ||
		config.Time < 1 || config.Time > 10 ||
		config.MemoryKiB < 8*1024 || config.MemoryKiB > 1024*1024 ||
		config.Threads < 1 || config.Threads > 16 {
		return errors.New("unsupported vault configuration")
	}
	if _, err := parseHex(config.Salt, saltSize); err != nil {
		return err
	}
	if _, err := parseHex(config.WrappedKey, chachaEncryptedSize(keySize)); err != nil {
		return err
	}
	return nil
}

func chachaEncryptedSize(plaintextSize int) int {
	return 24 + plaintextSize + 16
}

func (vault *Vault) Close() {
	wipe(vault.dataKey)
}

func entryRelativePath(name string) (string, error) {
	if err := validateNoUnsafeControls(name, false); err != nil {
		return "", fmt.Errorf("invalid entry name %q: %w", name, err)
	}
	if name == "" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") ||
		strings.Contains(name, "\\") || strings.Contains(name, "//") {
		return "", fmt.Errorf("invalid entry name %q; expected organization/project", name)
	}
	parts := strings.Split(name, "/")
	if len(parts) != 2 || parts[0] == "." || parts[0] == ".." ||
		parts[1] == "." || parts[1] == ".." || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid entry name %q; expected exactly organization/project", name)
	}
	relative := filepath.Join(parts[0], parts[1]+entryExtension)
	if !filepath.IsLocal(relative) {
		return "", fmt.Errorf("entry name %q escapes the vault", name)
	}
	return relative, nil
}

func (vault *Vault) writeEntry(name string, entry Entry, overwrite bool) error {
	relative, err := entryRelativePath(name)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if !overwrite {
		if _, err := root.Stat(relative); err == nil {
			return fmt.Errorf("entry %q already exists; use 'pm edit %s'", name, name)
		}
	}
	text, err := serializeEntry(entry)
	if err != nil {
		return err
	}
	defer wipe(text)
	key := deriveEntryKey(vault.dataKey, name)
	defer wipe(key)
	ciphertext, err := encrypt(text, key, name)
	if err != nil {
		return err
	}
	return atomicWriteRoot(
		root, relative, append(append([]byte(nil), entryMagic...), ciphertext...))
}

func (vault *Vault) Add(name string, entry Entry) error {
	if entry.Secret == "" {
		return fmt.Errorf("entry %q must contain a non-empty secret", name)
	}
	return vault.writeEntry(name, entry, false)
}

func (vault *Vault) readEntry(name string) (Entry, error) {
	relative, err := entryRelativePath(name)
	if err != nil {
		return Entry{}, err
	}
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return Entry{}, err
	}
	defer root.Close()
	encrypted, err := root.ReadFile(relative)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Entry{}, fmt.Errorf("entry %q was not found", name)
		}
		return Entry{}, err
	}
	if len(encrypted) < len(entryMagic) || string(encrypted[:len(entryMagic)]) != string(entryMagic) {
		return Entry{}, fmt.Errorf("entry %q uses an unsupported format", name)
	}
	key := deriveEntryKey(vault.dataKey, name)
	defer wipe(key)
	text, err := decrypt(encrypted[len(entryMagic):], key, name)
	if err != nil {
		return Entry{}, err
	}
	defer wipe(text)
	entry, err := parseEntry(text)
	if err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func (vault *Vault) Get(name string) (Entry, error) {
	return vault.readEntry(name)
}

func (vault *Vault) Update(name string, entry Entry) error {
	if entry.Secret == "" {
		return fmt.Errorf("entry %q must contain a non-empty secret", name)
	}
	relative, err := entryRelativePath(name)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat(relative); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("entry %q was not found", name)
	}
	return vault.writeEntry(name, entry, true)
}

func (vault *Vault) Remove(name string) error {
	relative, err := entryRelativePath(name)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(relative); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("entry %q was not found", name)
		}
		return err
	}
	parent := filepath.Dir(relative)
	for parent != "." {
		if err := root.Remove(parent); err != nil {
			break
		}
		parent = filepath.Dir(parent)
	}
	return nil
}

func (vault *Vault) Move(source, destination string) error {
	destinationRelative, err := entryRelativePath(destination)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return err
	}
	if _, err := root.Stat(destinationRelative); err == nil {
		root.Close()
		return fmt.Errorf("entry %q already exists", destination)
	}
	root.Close()
	entry, err := vault.readEntry(source)
	if err != nil {
		return err
	}
	if err := vault.writeEntry(destination, entry, false); err != nil {
		return err
	}
	return vault.Remove(source)
}

func (vault *Vault) ChangePassword(password []byte) error {
	if len(password) == 0 {
		return errors.New("master password cannot be empty")
	}
	if err := writeVaultConfig(vault.root, password, vault.dataKey); err != nil {
		return err
	}
	text, err := os.ReadFile(filepath.Join(vault.root, vaultConfigName))
	if err != nil {
		return err
	}
	var config vaultConfig
	if err := json.Unmarshal(text, &config); err != nil {
		return err
	}
	vault.config = config
	return nil
}

func (vault *Vault) List() ([]string, error) {
	var entries []string
	root, err := os.OpenRoot(vault.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	err = fs.WalkDir(root.FS(), ".", func(path string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !item.IsDir() && filepath.Ext(path) == entryExtension {
			relative := strings.TrimSuffix(path, entryExtension)
			name := filepath.ToSlash(relative)
			expected, validationErr := entryRelativePath(name)
			if validationErr != nil ||
				filepath.Clean(filepath.FromSlash(path)) != filepath.Clean(expected) {
				return fmt.Errorf("vault contains unsafe entry path %q", path)
			}
			entries = append(entries, name)
		}
		return nil
	})
	sort.Strings(entries)
	return entries, err
}

func (vault *Vault) Check() []error {
	names, err := vault.List()
	if err != nil {
		return []error{err}
	}
	var failures []error
	for _, name := range names {
		if _, err := vault.readEntry(name); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
	}
	return failures
}

func (vault *Vault) Find(query string) ([]string, error) {
	names, err := vault.List()
	if err != nil {
		return nil, err
	}
	type match struct {
		score int
		name  string
	}
	var matches []match
	for _, name := range names {
		if score := fuzzyScore(name, query); score >= 0 {
			matches = append(matches, match{score, name})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].name < matches[j].name
	})
	out := make([]string, len(matches))
	for i := range matches {
		out[i] = matches[i].name
	}
	return out, nil
}

func fuzzyScore(name, query string) int {
	if query == "" {
		return 0
	}
	name, query = strings.ToLower(name), strings.ToLower(query)
	if index := strings.Index(name, query); index >= 0 {
		return 1000 - index
	}
	queryIndex, score, streak := 0, 0, 0
	for _, character := range name {
		if queryIndex < len(query) && byte(character) == query[queryIndex] {
			queryIndex++
			score += 10 + streak*5
			streak++
		} else {
			streak = 0
		}
	}
	if queryIndex == len(query) {
		return score
	}
	return -1
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporary, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func atomicWriteRoot(root *os.Root, path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := root.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	random, err := randomBytes(8)
	if err != nil {
		return err
	}
	temporary := filepath.Join(parent, "."+filepath.Base(path)+".tmp-"+hexBytes(random))
	wipe(random)
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = root.Remove(temporary)
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
	if err := root.Rename(temporary, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateVaultRoot(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(filepath.Join(root, vaultConfigName))
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("%q is not a valid Go vault", root)
	}
	return filepath.EvalSymlinks(root)
}

func defaultVaultPath() (string, error) {
	root := os.Getenv("LOCALAPPDATA")
	if root == "" {
		var err error
		root, err = os.UserConfigDir()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(root, "pm", "vault"), nil
}
