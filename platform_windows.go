//go:build windows

package main

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func startClipboardClearer(executable, delay, expectedHash string) error {
	command := exec.Command(executable, "--internal-clear-clipboard",
		delay, expectedHash)
	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
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
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
