// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package repair

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Store owns the fixed bundle and its adjacent, protected recovery records.
type Store struct {
	path  string
	owner int
}

// Receipt records a completed or recoverable transaction. Backup is retained.
type Receipt struct {
	Version      int    `json:"version"`
	Created      string `json:"created"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	Backup       string `json:"backup"`
	Mode         uint32 `json:"mode"`
	Removed      []Root `json:"removed"`
}

// Backend owns platform discovery, planning, mutation, and recovery. The CLI
// never selects arbitrary privileged paths or supplies replacement contents.
type Backend interface {
	Inspect() (Plan, error)
	UndoPlan() (Plan, error)
	Apply(expected string, undo bool) (Receipt, error)
}

// System opens the supported platform store, never a caller-selected path.
func System() (Backend, error) {
	if runtime.GOOS == "linux" {
		return linuxSystem()
	}
	if runtime.GOOS != "darwin" {
		return nil, errors.New("fix supports macOS and selected Linux CA stores; use batch to test this platform")
	}
	for _, dir := range []string{"/private", "/private/etc", "/private/etc/ssl"} {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("inspect bundle directory: %w", err)
		}
		if !info.IsDir() || info.Mode().Perm()&0022 != 0 || !ownedBy(info, 0) {
			return nil, fmt.Errorf("unsafe system bundle directory %s", dir)
		}
	}
	return &Store{path: BundlePath}, nil
}

func (s *Store) stateDir() string { return s.path + ".embarass" }

// Inspect reads and validates the bundle without acquiring privilege or writing.
func (s *Store) Inspect() (Plan, error) {
	data, info, err := readSecure(s.path, false)
	if err != nil {
		return Plan{}, err
	}
	if !ownedBy(info, s.owner) {
		return Plan{}, errors.New("unexpected bundle owner or hard links")
	}
	plan, err := inspect(data)
	plan.Path = s.path
	plan.BundlePath, plan.Platform = s.path, "macOS system PEM bundle"
	return plan, err
}

// UndoPlan validates both the recovery data and the current bundle before asking
// for confirmation. It never restores across an intervening system/admin update.
func (s *Store) UndoPlan() (Plan, error) {
	receipt, original, err := s.recovery()
	if err != nil {
		return Plan{}, err
	}
	current, _, err := readSecure(s.path, false)
	if err != nil {
		return Plan{}, err
	}
	if digest(current) != receipt.AfterSHA256 && digest(current) != receipt.BeforeSHA256 {
		return Plan{}, errors.New("bundle changed since repair; refusing to overwrite an OS update or administrator edit")
	}
	plan, err := inspect(original)
	if err != nil {
		return Plan{}, err
	}
	plan.Path = s.path
	plan.BundlePath, plan.Platform = s.path, "macOS system PEM bundle"
	plan.BeforeSHA256, plan.AfterSHA256 = digest(current), receipt.BeforeSHA256
	plan.original, plan.replacement = current, original
	return plan, nil
}

func (s *Store) recovery() (Receipt, []byte, error) {
	var receipt Receipt
	info, err := os.Lstat(s.stateDir())
	if err != nil {
		return receipt, nil, fmt.Errorf("read repair record: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0755 || !ownedBy(info, s.owner) {
		return receipt, nil, errors.New("unsafe repair record directory")
	}
	encoded, receiptInfo, err := readSecure(filepath.Join(s.stateDir(), "receipt.json"), false)
	if err != nil {
		return receipt, nil, err
	}
	if !ownedBy(receiptInfo, s.owner) {
		return receipt, nil, errors.New("unexpected receipt owner")
	}
	if err = json.Unmarshal(encoded, &receipt); err != nil {
		return receipt, nil, fmt.Errorf("decode repair receipt: %w", err)
	}
	backup := filepath.Join(s.stateDir(), "original.pem")
	if receipt.Version != 1 || receipt.Backup != backup || receipt.Mode & ^uint32(0777) != 0 || receipt.Mode&0022 != 0 {
		return receipt, nil, errors.New("invalid repair receipt")
	}
	original, backupInfo, err := readSecure(backup, false)
	if err != nil {
		return receipt, nil, err
	}
	if !ownedBy(backupInfo, s.owner) {
		return receipt, nil, errors.New("unexpected backup owner")
	}
	plan, err := inspect(original)
	if err != nil {
		return receipt, nil, err
	}
	if plan.BeforeSHA256 != receipt.BeforeSHA256 || plan.AfterSHA256 != receipt.AfterSHA256 || len(plan.Removed) == 0 {
		return receipt, nil, errors.New("repair backup does not match the recorded certificate transformation")
	}
	return receipt, original, nil
}

// Apply locks, re-reads, backs up, and atomically replaces the bundle. A journal
// written before replacement supports recovery if the process is interrupted.
func (s *Store) Apply(expected string, undo bool) (Receipt, error) {
	unlock, err := lockStore(s.path + ".embarass.lock")
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	if undo {
		return s.undo(expected)
	}
	plan, err := s.Inspect()
	if err != nil {
		return Receipt{}, err
	}
	if plan.BeforeSHA256 != expected {
		return Receipt{}, errors.New("bundle changed after preview; inspect it again")
	}
	if len(plan.Removed) == 0 {
		return Receipt{}, errors.New("target roots are already absent; nothing to apply")
	}
	_, info, err := readSecure(s.path, true)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{Version: 1, Created: time.Now().UTC().Format(time.RFC3339Nano),
		BeforeSHA256: plan.BeforeSHA256, AfterSHA256: plan.AfterSHA256,
		Backup: filepath.Join(s.stateDir(), "original.pem"), Mode: uint32(info.Mode().Perm()), Removed: plan.Removed}
	if err = os.Mkdir(s.stateDir(), 0755); err != nil {
		return Receipt{}, fmt.Errorf("create exclusive repair record; existing records must be recovered or archived first: %w", err)
	}
	// Once replacement begins, keep the recovery record even if an operation fails.
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(filepath.Join(s.stateDir(), "receipt.json"))
			_ = os.Remove(receipt.Backup)
			_ = os.Remove(s.stateDir())
		}
	}()
	if err = os.Chmod(s.stateDir(), 0755); err != nil {
		return Receipt{}, fmt.Errorf("set repair directory permissions: %w", err)
	}
	if err = writeExclusive(receipt.Backup, plan.original, info.Mode().Perm()); err != nil {
		return Receipt{}, err
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return Receipt{}, fmt.Errorf("encode receipt: %w", err)
	}
	if err = writeExclusive(filepath.Join(s.stateDir(), "receipt.json"), encoded, 0644); err != nil {
		return Receipt{}, err
	}
	if err = syncDirectory(s.stateDir()); err != nil {
		return Receipt{}, err
	}
	if err = syncDirectory(filepath.Dir(s.path)); err != nil {
		return Receipt{}, err
	}
	keep = true
	if err = replace(s.path, expected, plan.replacement, info.Mode().Perm()); err != nil {
		return receipt, fmt.Errorf("repair did not complete; recovery record retained at %s: %w", s.stateDir(), err)
	}
	verified, verifyErr := s.Inspect()
	if verifyErr == nil && verified.BeforeSHA256 == plan.AfterSHA256 && len(verified.Removed) == 0 {
		return receipt, nil
	}
	// Roll back only our exact replacement, never an unrelated concurrent edit.
	rollbackErr := replace(s.path, plan.AfterSHA256, plan.original, info.Mode().Perm())
	return receipt, errors.Join(errors.New("post-write integrity check failed; attempted to restore original bundle"), verifyErr, rollbackErr)
}

func (s *Store) undo(expected string) (Receipt, error) {
	receipt, original, err := s.recovery()
	if err != nil {
		return receipt, err
	}
	current, _, err := readSecure(s.path, true)
	if err != nil {
		return receipt, err
	}
	if digest(current) != expected {
		return receipt, errors.New("bundle changed after undo preview")
	}
	if expected != receipt.AfterSHA256 && expected != receipt.BeforeSHA256 {
		return receipt, errors.New("bundle changed since repair; refusing to overwrite it")
	}
	// The original hash also permits recovery after a crash before installation,
	// or after restoration but before the record directory could be archived.
	if expected == receipt.AfterSHA256 {
		if err = replace(s.path, expected, original, os.FileMode(receipt.Mode)); err != nil {
			return receipt, err
		}
	}
	archive := s.stateDir() + ".restored-" + time.Now().UTC().Format("20060102T150405.000000000")
	if err = os.Rename(s.stateDir(), archive); err != nil {
		return receipt, fmt.Errorf("bundle restored but record could not be archived: %w", err)
	}
	receipt.Backup = filepath.Join(archive, "original.pem")
	return receipt, syncDirectory(filepath.Dir(s.path))
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	_, writeErr := file.Write(data)
	modeErr := file.Chmod(mode)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, modeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("persist %s: %w", path, err)
	}
	return nil
}

func replace(path, expected string, data []byte, mode os.FileMode) error {
	_, originalInfo, err := readSecure(path, true)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".embarass-stage-*")
	if err != nil {
		return fmt.Errorf("stage bundle: %w", err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, writeErr := file.Write(data)
	ownerErr := preserveOwner(file, originalInfo)
	modeErr := file.Chmod(mode)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, ownerErr, modeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("persist staged bundle: %w", err)
	}
	current, _, err := readSecure(path, true)
	if err != nil {
		return err
	}
	if digest(current) != expected {
		return errors.New("bundle changed during repair; refusing replacement")
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("install staged bundle: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	err = errors.Join(file.Sync(), file.Close())
	if err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
