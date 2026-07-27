package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const govulncheckVersion = "v1.6.0"

func main() {
	root, err := repositoryRoot()
	if err != nil {
		fatal(err)
	}
	steps := []struct {
		name string
		args []string
	}{
		{"unit tests", []string{"test", "-buildvcs=false", "-count=1", "./..."}},
		{"vulnerability scan", []string{
			"run", "golang.org/x/vuln/cmd/govulncheck@" + govulncheckVersion, "./...",
		}},
		{"build", buildArguments(root)},
	}
	for _, step := range steps {
		if err := runGo(root, step.name, nil, step.args...); err != nil {
			fatal(fmt.Errorf("%s failed: %w", step.name, err))
		}
	}
	if err := checkCrossPlatformBuilds(root); err != nil {
		fatal(err)
	}
	fmt.Println("Tests, vulnerability scan, and build passed.")
}

func checkCrossPlatformBuilds(root string) error {
	temporary, err := os.MkdirTemp("", "pm-cross-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	for _, target := range []string{"windows", "linux", "darwin"} {
		name := "pm-" + target
		if target == "windows" {
			name += ".exe"
		}
		environment := []string{
			"GOOS=" + target,
			"GOARCH=" + runtime.GOARCH,
			"CGO_ENABLED=0",
		}
		args := []string{
			"build", "-buildvcs=false", "-trimpath",
			"-o", filepath.Join(temporary, name), ".",
		}
		if err := runGo(root, target+" build check", environment, args...); err != nil {
			return fmt.Errorf("%s build check failed: %w", target, err)
		}
	}
	return nil
}

func runGo(root, name string, environment []string, arguments ...string) error {
	fmt.Printf("==> %s\n", name)
	command := exec.Command("go", arguments...)
	command.Dir = root
	command.Env = append(os.Environ(), environment...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func buildArguments(root string) []string {
	name := "pm"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return []string{
		"build", "-buildvcs=false", "-trimpath",
		"-o", filepath.Join(root, "build", name), ".",
	}
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil && !info.IsDir() {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("could not find go.mod from %q", directory)
		}
		directory = parent
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "test:", err)
	os.Exit(1)
}
