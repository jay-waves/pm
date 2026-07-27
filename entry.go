package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Entry struct {
	Secret     string  `json:"secret"`
	Identity   string  `json:"identity"`
	CreatedAt  string  `json:"created_at"`
	ModifiedAt string  `json:"modified_at"`
	ExpiresAt  *string `json:"expires_at"`
	Notes      string  `json:"notes"`
}

var entryFields = map[string]bool{
	"secret": true, "identity": true, "created_at": true,
	"modified_at": true, "expires_at": true, "notes": true,
}

func today() string {
	return time.Now().Format("2006-01-02")
}

func newEntry() Entry {
	date := today()
	return Entry{CreatedAt: date, ModifiedAt: date}
}

func parseEntry(text []byte) (Entry, error) {
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(text))
	if err := decoder.Decode(&raw); err != nil {
		return Entry{}, errors.New("entry is not valid JSON")
	}
	if len(raw) != len(entryFields) {
		return Entry{}, errors.New("entry JSON must contain exactly: secret, identity, created_at, modified_at, expires_at, notes")
	}
	for field := range raw {
		if !entryFields[field] {
			return Entry{}, fmt.Errorf("entry JSON contains unknown field %q", field)
		}
	}
	var entry Entry
	if err := json.Unmarshal(text, &entry); err != nil {
		return Entry{}, errors.New("entry JSON has a missing field or incorrect field type")
	}
	for _, date := range []string{entry.CreatedAt, entry.ModifiedAt} {
		if !validDate(date) {
			return Entry{}, errors.New("entry JSON contains an invalid date; expected YYYY-MM-DD")
		}
	}
	if entry.ExpiresAt != nil && !validDate(*entry.ExpiresAt) {
		return Entry{}, errors.New("entry JSON contains an invalid date; expected YYYY-MM-DD")
	}
	return entry, nil
}

func validDate(value string) bool {
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}

func serializeEntry(entry Entry) ([]byte, error) {
	text, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(text, '\n'), nil
}

func isExpired(entry Entry) bool {
	return entry.ExpiresAt != nil && *entry.ExpiresAt <= today()
}

func formatMetadata(name string, entry Entry, status string) string {
	identity, expires, notes := entry.Identity, "-", entry.Notes
	if identity == "" {
		identity = "-"
	}
	if entry.ExpiresAt != nil {
		expires = *entry.ExpiresAt
	}
	if notes == "" {
		notes = "-"
	}
	metadata := fmt.Sprintf(
		"entry:       %s\nidentity:    %s\ncreated:     %s\nmodified:    %s\nexpires:     %s\nnotes:       %s\n",
		name, identity, entry.CreatedAt, entry.ModifiedAt, expires, notes)
	if status != "" {
		return fmt.Sprintf("status:      %s\n%s", status, metadata)
	}
	return metadata
}

func expiredStatus(color bool) string {
	if color {
		return "\x1b[1;31mEXPIRED\x1b[0m"
	}
	return "EXPIRED"
}
