package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const secretReferencePrefix = "pm://"

type runOptions struct {
	envFile string
	command []string
}

type envAssignment struct {
	name  string
	value string
}

type secretEntryReader interface {
	Get(string) (Entry, error)
}

type commandExitError struct {
	code int
}

func (err *commandExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", err.code)
}

func parseRunArgs(args []string) (runOptions, error) {
	var options runOptions
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator == len(args)-1 || args[separator+1] == "" {
		return options, errors.New("usage: pm run [--env-file <file>] -- <command> [arguments...]")
	}
	for index := 0; index < separator; index++ {
		arg := args[index]
		switch {
		case arg == "--env-file":
			index++
			if index >= separator || args[index] == "" || options.envFile != "" {
				return options, errors.New("usage: pm run [--env-file <file>] -- <command> [arguments...]")
			}
			options.envFile = args[index]
		case strings.HasPrefix(arg, "--env-file="):
			if options.envFile != "" || strings.TrimPrefix(arg, "--env-file=") == "" {
				return options, errors.New("usage: pm run [--env-file <file>] -- <command> [arguments...]")
			}
			options.envFile = strings.TrimPrefix(arg, "--env-file=")
		default:
			return options, fmt.Errorf("unknown run option %q", arg)
		}
	}
	options.command = append([]string(nil), args[separator+1:]...)
	return options, nil
}

func runWithSecrets(vault *Vault, options runOptions) error {
	assignments, err := environmentAssignments(os.Environ())
	if err != nil {
		return err
	}
	if options.envFile != "" {
		fileAssignments, err := readDotEnv(options.envFile)
		if err != nil {
			return err
		}
		assignments = mergeAssignments(assignments, fileAssignments)
	}
	environment, err := resolveSecretReferences(vault, assignments)
	if err != nil {
		return err
	}
	command := exec.Command(options.command[0], options.command[1:]...)
	command.Env = assignmentsToEnvironment(environment)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			code := exitError.ExitCode()
			if code < 0 {
				code = 1
			}
			return &commandExitError{code: code}
		}
		return fmt.Errorf("could not start %q: %w", options.command[0], err)
	}
	return nil
}

func environmentAssignments(environment []string) ([]envAssignment, error) {
	assignments := make([]envAssignment, 0, len(environment))
	for _, item := range environment {
		index := strings.IndexByte(item, '=')
		if index == 0 {
			// Windows may expose hidden drive-current-directory variables such as
			// "=C:=C:\\work". Preserve them when constructing the child block.
			next := strings.IndexByte(item[1:], '=')
			if next >= 0 {
				index = next + 1
			}
		}
		if index <= 0 {
			return nil, fmt.Errorf("invalid inherited environment entry %q", item)
		}
		assignments = append(assignments, envAssignment{name: item[:index], value: item[index+1:]})
	}
	return assignments, nil
}

func readDotEnv(path string) ([]envAssignment, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open environment file %q: %w", path, err)
	}
	defer file.Close()

	var assignments []envAssignment
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		assignment, present, err := parseDotEnvLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if present {
			assignments = append(assignments, assignment)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read environment file %q: %w", path, err)
	}
	return assignments, nil
}

func parseDotEnvLine(line string) (envAssignment, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return envAssignment{}, false, nil
	}
	if strings.HasPrefix(line, "export ") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	}
	index := strings.IndexByte(line, '=')
	if index < 1 {
		return envAssignment{}, false, errors.New("expected NAME=value")
	}
	name := strings.TrimSpace(line[:index])
	if !validEnvironmentName(name) {
		return envAssignment{}, false, fmt.Errorf("invalid environment variable name %q", name)
	}
	value, err := parseDotEnvValue(strings.TrimSpace(line[index+1:]))
	if err != nil {
		return envAssignment{}, false, err
	}
	return envAssignment{name: name, value: value}, true, nil
}

func validEnvironmentName(name string) bool {
	for index, character := range name {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') || character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return name != ""
}

func parseDotEnvValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] == '\'' {
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", errors.New("unterminated single-quoted value")
		}
		return value[1 : len(value)-1], nil
	}
	if value[0] == '"' {
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return "", errors.New("invalid double-quoted value")
		}
		return decoded, nil
	}
	for index, character := range value {
		if character == '#' && index > 0 && (value[index-1] == ' ' || value[index-1] == '\t') {
			return strings.TrimSpace(value[:index]), nil
		}
	}
	return value, nil
}

func mergeAssignments(base, overrides []envAssignment) []envAssignment {
	result := append([]envAssignment(nil), base...)
	positions := make(map[string]int, len(result))
	for index, assignment := range result {
		positions[environmentNameKey(assignment.name)] = index
	}
	for _, assignment := range overrides {
		key := environmentNameKey(assignment.name)
		if index, exists := positions[key]; exists {
			result[index] = assignment
			continue
		}
		positions[key] = len(result)
		result = append(result, assignment)
	}
	return result
}

func environmentNameKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

func resolveSecretReferences(vault secretEntryReader, assignments []envAssignment) ([]envAssignment, error) {
	resolved := append([]envAssignment(nil), assignments...)
	cache := make(map[string]string)
	for index := range resolved {
		value := resolved[index].value
		if !strings.HasPrefix(value, secretReferencePrefix) {
			continue
		}
		name := strings.TrimPrefix(value, secretReferencePrefix)
		if _, err := entryRelativePath(name); err != nil {
			return nil, fmt.Errorf("environment variable %s has invalid secret reference %q: %w", resolved[index].name, value, err)
		}
		secret, exists := cache[name]
		if !exists {
			entry, err := vault.Get(name)
			if err != nil {
				return nil, fmt.Errorf("could not resolve %s from %q: %w", resolved[index].name, value, err)
			}
			if isExpired(entry) {
				return nil, fmt.Errorf("could not resolve %s: entry %q is expired", resolved[index].name, name)
			}
			secret = entry.Secret
			cache[name] = secret
		}
		resolved[index].value = secret
	}
	return resolved, nil
}

func assignmentsToEnvironment(assignments []envAssignment) []string {
	environment := make([]string, len(assignments))
	for index, assignment := range assignments {
		environment[index] = assignment.name + "=" + assignment.value
	}
	return environment
}
