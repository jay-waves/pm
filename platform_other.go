//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func startClipboardClearer(executable, delay, expectedHash string) error {
	command := exec.Command(executable, "--internal-clear-clipboard",
		delay, expectedHash)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Start(); err != nil {
		return err
	}
	_ = command.Process.Release()
	return nil
}

func replaceFile(temporary, destination string) error {
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return nil
}
