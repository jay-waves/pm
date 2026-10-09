//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func openUserTerminal() (*os.File, *os.File, error) {
	input, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	output, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		input.Close()
		return nil, nil, err
	}
	return input, output, nil
}

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
