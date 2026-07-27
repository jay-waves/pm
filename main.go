package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

const version = "0.2.0"
const clipboardClearDelay = time.Minute

func usage() string {
	return `pm ` + version + ` - lightweight offline password manager

Usage:
  pm init
  pm add <organization/project>
  pm get [-c] <organization/project>
  pm edit <organization/project>
  pm rm <organization/project>
  pm mv <source> <destination>
  pm ls
  pm find <query>
  pm passwd
  pm generate [--length <number>]
  pm export <backup-file>
  pm import <backup-file>
  pm check
`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pm:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 || arguments[0] == "-h" || arguments[0] == "--help" {
		fmt.Print(usage())
		return nil
	}
	if arguments[0] == "--version" {
		fmt.Println(version)
		return nil
	}
	if arguments[0] == "--internal-clear-clipboard" {
		if len(arguments) != 3 {
			return errors.New("invalid internal clipboard command")
		}
		delay, err := time.ParseDuration(arguments[1])
		if err != nil {
			return err
		}
		return clearClipboardAfter(delay, arguments[2])
	}

	command := arguments[0]
	args := arguments[1:]
	if command == "init" {
		if len(args) != 0 {
			return errors.New("usage: pm init")
		}
		password, err := confirmedPassword("Master password: ", "Confirm password: ")
		if err != nil {
			return err
		}
		defer wipe(password)
		root, err := defaultVaultPath()
		if err != nil {
			return err
		}
		if err := initVault(root, password); err != nil {
			return err
		}
		fmt.Printf("Initialized vault at %s\n", root)
		return nil
	}
	if command == "generate" {
		length, err := parseGenerateArgs(args)
		if err != nil {
			return err
		}
		secret, err := generateSecret(length)
		if err != nil {
			return err
		}
		defer wipe(secret)
		if err := copyToClipboard(secret, clipboardClearDelay); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Generated secret copied; clipboard will be cleared in 1 minute.")
		return nil
	}
	if command == "import" {
		if len(args) != 1 {
			return errors.New("usage: pm import <backup-file>")
		}
		password, err := readPassword("Backup master password: ")
		if err != nil {
			return err
		}
		defer wipe(password)
		root, err := defaultVaultPath()
		if err != nil {
			return err
		}
		count, err := importEncryptedBackup(root, args[0], password)
		if err != nil {
			return err
		}
		fmt.Printf("Imported %d encrypted entries into %s\n", count, root)
		return nil
	}
	if command == "ls" || command == "find" {
		expected := 0
		if command == "find" {
			expected = 1
		}
		if len(args) != expected {
			return fmt.Errorf("usage: pm %s%s", command, map[bool]string{true: " <query>"}[command == "find"])
		}
		root, err := defaultVaultPath()
		if err != nil {
			return err
		}
		root, err = validateVaultRoot(root)
		if err != nil {
			return err
		}
		vault := &Vault{root: root}
		if command == "ls" {
			entries, err := vault.List()
			if err != nil {
				return err
			}
			fmt.Print(formatTree(entries))
		} else {
			entries, err := vault.Find(args[0])
			if err != nil {
				return err
			}
			for _, entry := range entries {
				fmt.Println(entry)
			}
		}
		return nil
	}

	password, err := readPassword("Master password: ")
	if err != nil {
		return err
	}
	root, err := defaultVaultPath()
	if err != nil {
		wipe(password)
		return err
	}
	vault, err := openVault(root, password)
	wipe(password)
	if err != nil {
		return err
	}
	defer vault.Close()

	switch command {
	case "add":
		if len(args) != 1 {
			return errors.New("usage: pm add <organization/project>")
		}
		entry, err := runAddForm()
		if err != nil {
			if errors.Is(err, errCancelled) {
				return nil
			}
			return err
		}
		return vault.Add(args[0], entry)
	case "get":
		copyOnly, name, err := parseGetArgs(args)
		if err != nil {
			return err
		}
		entry, err := vault.Get(name)
		if err != nil {
			return err
		}
		if isExpired(entry) {
			entry.Secret = ""
			fmt.Print(formatMetadata(
				name, entry, expiredStatus(colorOutputEnabled(os.Stdout))))
			return fmt.Errorf("entry %q is expired; secret was not copied", name)
		}
		secret := []byte(entry.Secret)
		entry.Secret = ""
		defer wipe(secret)
		if err := copyToClipboard(secret, clipboardClearDelay); err != nil {
			return err
		}
		if !copyOnly {
			fmt.Print(formatMetadata(name, entry, ""))
		}
		fmt.Fprintln(os.Stderr, "Secret copied; clipboard will be cleared in 1 minute.")
		return nil
	case "edit":
		if len(args) != 1 {
			return errors.New("usage: pm edit <organization/project>")
		}
		entry, err := vault.Get(args[0])
		if err != nil {
			return err
		}
		entry, err = runEditForm(args[0], entry)
		if err != nil {
			if errors.Is(err, errCancelled) {
				return nil
			}
			return err
		}
		return vault.Update(args[0], entry)
	case "export":
		if len(args) != 1 {
			return errors.New("usage: pm export <backup-file>")
		}
		count, err := exportEncryptedBackup(vault, args[0])
		if err != nil {
			return err
		}
		fmt.Printf("Exported %d encrypted entries to %s\n", count, args[0])
		return nil
	case "rm":
		if len(args) != 1 {
			return errors.New("usage: pm rm <organization/project>")
		}
		return vault.Remove(args[0])
	case "mv":
		if len(args) != 2 {
			return errors.New("usage: pm mv <source> <destination>")
		}
		return vault.Move(args[0], args[1])
	case "passwd":
		if len(args) != 0 {
			return errors.New("usage: pm passwd")
		}
		newPassword, err := confirmedPassword("New master password: ", "Confirm new master password: ")
		if err != nil {
			return err
		}
		defer wipe(newPassword)
		if err := vault.ChangePassword(newPassword); err != nil {
			return err
		}
		fmt.Println("Master password changed.")
		return nil
	case "check":
		if len(args) != 0 {
			return errors.New("usage: pm check")
		}
		failures := vault.Check()
		if len(failures) != 0 {
			for _, failure := range failures {
				fmt.Fprintln(os.Stderr, failure)
			}
			return fmt.Errorf("vault check failed for %d entries", len(failures))
		}
		entries, _ := vault.List()
		fmt.Printf("Vault check passed: %d entries.\n", len(entries))
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%s", command, usage())
	}
}

func confirmedPassword(prompt, confirmationPrompt string) ([]byte, error) {
	password, err := readPassword(prompt)
	if err != nil {
		return nil, err
	}
	repeated, err := readPassword(confirmationPrompt)
	if err != nil {
		wipe(password)
		return nil, err
	}
	matches := len(password) == len(repeated) &&
		subtle.ConstantTimeCompare(password, repeated) == 1
	wipe(repeated)
	if !matches {
		wipe(password)
		return nil, errors.New("master passwords do not match")
	}
	return password, nil
}

func parseGenerateArgs(args []string) (int, error) {
	if len(args) == 0 {
		return 24, nil
	}
	if len(args) != 2 || args[0] != "--length" {
		return 0, errors.New("usage: pm generate [--length <number>]")
	}
	return strconv.Atoi(args[1])
}

func parseGetArgs(args []string) (bool, string, error) {
	if len(args) == 1 {
		return false, args[0], nil
	}
	if len(args) == 2 && (args[0] == "-c" || args[0] == "--copy-only") {
		return true, args[1], nil
	}
	return false, "", errors.New("usage: pm get [-c] <organization/project>")
}
