// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin || linux

package repair

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func ownedBy(info os.FileInfo, uid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(uid) && (!info.Mode().IsRegular() || stat.Nlink == 1)
}

func preserveOwner(file *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read original bundle ownership")
	}
	if err := file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("preserve bundle ownership: %w", err)
	}
	return nil
}

func readSecure(path string, requireOwner bool) ([]byte, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || (requireOwner && !ownedBy(info, os.Geteuid())) {
		return nil, nil, fmt.Errorf("unsafe ownership, permissions, or file type: %s", path)
	}
	const maximum = 10 << 20
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maximum {
		return nil, nil, errors.New("bundle or receipt exceeds 10 MiB")
	}
	return data, info, nil
}

func lockStore(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open repair lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedBy(info, os.Geteuid()) || info.Mode().Perm() != 0600 {
		_ = file.Close()
		return nil, errors.New("unsafe repair lock")
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another repair is running: %w", err)
	}
	return func() { _ = file.Close() }, nil
}
