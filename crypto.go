package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keySize        = 32
	saltSize       = 16
	defaultTime    = 3
	defaultMemory  = 64 * 1024
	defaultThreads = 1
)

func randomBytes(size int) ([]byte, error) {
	out := make([]byte, size)
	_, err := rand.Read(out)
	return out, err
}

func derivePasswordKey(password, salt []byte, timeCost, memory uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, timeCost, memory, threads, keySize)
}

func deriveEntryKey(dataKey []byte, name string) []byte {
	mac := hmac.New(sha256.New, dataKey)
	_, _ = mac.Write([]byte(name))
	return mac.Sum(nil)
}

func encrypt(plaintext, key []byte, associatedData string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(associatedData)), nil
}

func decrypt(ciphertext, key []byte, associatedData string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("encrypted data is truncated")
	}
	plaintext, err := aead.Open(
		nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():],
		[]byte(associatedData))
	if err != nil {
		return nil, errors.New("authentication failed; the password is wrong or data is damaged")
	}
	return plaintext, nil
}

func wipe(value []byte) {
	clear(value)
}

func hexBytes(value []byte) string {
	return hex.EncodeToString(value)
}

func parseHex(value string, size int) ([]byte, error) {
	out, err := hex.DecodeString(value)
	if err != nil || len(out) != size {
		return nil, errors.New("vault contains invalid hexadecimal data")
	}
	return out, nil
}

func generateSecret(length int) ([]byte, error) {
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const lower = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	const all = upper + lower + digits
	if length < 12 || length > 1024 {
		return nil, errors.New("secret length must be between 12 and 1024")
	}
	out := make([]byte, length)
	groups := []string{upper, lower, digits}
	for i, group := range groups {
		index, err := randomIndex(len(group))
		if err != nil {
			return nil, err
		}
		out[i] = group[index]
	}
	for i := len(groups); i < length; i++ {
		index, err := randomIndex(len(all))
		if err != nil {
			return nil, err
		}
		out[i] = all[index]
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := randomIndex(i + 1)
		if err != nil {
			return nil, err
		}
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func randomIndex(limit int) (int, error) {
	if limit <= 0 || limit > 256 {
		return 0, errors.New("invalid random range")
	}
	var sample [1]byte
	cutoff := 256 - 256%limit
	for {
		if _, err := rand.Read(sample[:]); err != nil {
			return 0, err
		}
		if int(sample[0]) < cutoff {
			return int(sample[0]) % limit, nil
		}
	}
}
