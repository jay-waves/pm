package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeEntryReader map[string]Entry

func (reader fakeEntryReader) Get(name string) (Entry, error) {
	entry, exists := reader[name]
	if !exists {
		return Entry{}, os.ErrNotExist
	}
	return entry, nil
}

func TestParseRunArgs(t *testing.T) {
	options, err := parseRunArgs([]string{"--env-file=.env", "--", "program.exe", "--no-color"})
	if err != nil {
		t.Fatal(err)
	}
	if options.envFile != ".env" || strings.Join(options.command, ",") != "program.exe,--no-color" {
		t.Fatalf("parseRunArgs() = %#v", options)
	}
	options, err = parseRunArgs([]string{"--env-file", "local.env", "--", "program.exe"})
	if err != nil || options.envFile != "local.env" {
		t.Fatalf("parseRunArgs() = %#v, %v", options, err)
	}
	for _, args := range [][]string{{"program.exe"}, {"--"}, {"--", ""}, {"--bad", "--", "program.exe"}} {
		if _, err := parseRunArgs(args); err == nil {
			t.Fatalf("parseRunArgs(%q) unexpectedly succeeded", args)
		}
	}
}

func TestEnvironmentAssignmentsPreservesWindowsDriveEntry(t *testing.T) {
	assignments, err := environmentAssignments([]string{"=C:=C:\\work", "NAME=value"})
	if err != nil {
		t.Fatal(err)
	}
	if assignments[0].name != "=C:" || assignments[0].value != "C:\\work" {
		t.Fatalf("environmentAssignments() = %#v", assignments)
	}
}

func TestReadDotEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	text := "\ufeff# comment\nPLAIN=value\nQUOTED=\"value with spaces\"\n" +
		"LITERAL='a # b'\nexport EMPTY=\nTOKEN=pm://acme/token # reference\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	assignments, err := readDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []envAssignment{
		{name: "PLAIN", value: "value"},
		{name: "QUOTED", value: "value with spaces"},
		{name: "LITERAL", value: "a # b"},
		{name: "EMPTY", value: ""},
		{name: "TOKEN", value: "pm://acme/token"},
	}
	if len(assignments) != len(want) {
		t.Fatalf("readDotEnv() = %#v", assignments)
	}
	for index := range want {
		if assignments[index] != want[index] {
			t.Fatalf("assignment %d = %#v, want %#v", index, assignments[index], want[index])
		}
	}
}

func TestResolveSecretReferences(t *testing.T) {
	entry := newEntry()
	entry.Secret = "resolved-secret"
	assignments := []envAssignment{
		{name: "TOKEN", value: "pm://acme/token"},
		{name: "PLAIN", value: "prefix-pm://acme/token"},
	}
	resolved, err := resolveSecretReferences(fakeEntryReader{"acme/token": entry}, assignments)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].value != "resolved-secret" || resolved[1].value != assignments[1].value {
		t.Fatalf("resolveSecretReferences() = %#v", resolved)
	}
}

func TestResolveSecretReferencesRejectsExpiredAndMalformed(t *testing.T) {
	expiration := "2000-01-01"
	entry := newEntry()
	entry.Secret = "secret"
	entry.ExpiresAt = &expiration
	reader := fakeEntryReader{"acme/token": entry}
	for _, value := range []string{"pm://acme/token", "pm://bad/path/extra", "pm://"} {
		_, err := resolveSecretReferences(reader, []envAssignment{{name: "TOKEN", value: value}})
		if err == nil {
			t.Fatalf("reference %q unexpectedly resolved", value)
		}
	}
}

func TestEnvironmentFileOverridesInheritedValue(t *testing.T) {
	merged := mergeAssignments(
		[]envAssignment{{name: "TOKEN", value: "parent"}, {name: "KEEP", value: "yes"}},
		[]envAssignment{{name: "TOKEN", value: "file"}},
	)
	if len(merged) != 2 || merged[0].value != "file" || merged[1].value != "yes" {
		t.Fatalf("mergeAssignments() = %#v", merged)
	}
}

func TestNoColorDoesNotConsumeChildArgument(t *testing.T) {
	args, disabled, err := parseNoColor([]string{"run", "--no-color", "--", "program.exe", "--no-color"})
	if err != nil || !disabled || strings.Join(args, ",") != "run,--,program.exe,--no-color" {
		t.Fatalf("parseNoColor() = %v, %v, %v", args, disabled, err)
	}
}
