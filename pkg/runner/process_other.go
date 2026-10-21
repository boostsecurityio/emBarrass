// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !darwin && !linux && !windows

package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func configureCommand(_ *exec.Cmd) {}

func stopCommand(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	err := command.Process.Kill()
	if err == nil || errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return fmt.Errorf("kill process %d: %w", command.Process.Pid, err)
}
