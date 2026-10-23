// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later
//go:build !darwin && !linux

package repair

import (
	"errors"
	"os"
)

func ownedBy(_ os.FileInfo, _ int) bool             { return false }
func preserveOwner(_ *os.File, _ os.FileInfo) error { return errors.New("unsupported platform") }
func readSecure(_ string, _ bool) ([]byte, os.FileInfo, error) {
	return nil, nil, errors.New("system bundle repair is unsupported on this platform")
}
func lockStore(_ string) (func(), error) {
	return nil, errors.New("system bundle repair is unsupported on this platform")
}
