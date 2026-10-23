// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin || linux

package repair

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type nativeFixture struct {
	store        *linuxStore
	ordinary     []byte
	extra        []byte
	vendorDenied bool
	failRefresh  bool
	refreshes    int
}

func TestNativeSourceRejectsSkippedMalformedPEM(t *testing.T) {
	t.Parallel()
	fixture := newNativeFixture(t, "debian")
	path := filepath.Join(fixture.store.spec.sources, "mozilla/aaa.crt")
	malformed := append([]byte("-----BEGIN CERTIFICATE-----\nbroken\n"), affectedRoot(t, "aaa")...)
	require.NoError(t, os.WriteFile(path, malformed, 0644))
	_, err := fixture.store.Inspect()
	require.ErrorContains(t, err, "malformed native certificate PEM")
	require.Zero(t, fixture.refreshes)
}

func newNativeFixture(t *testing.T, family string) *nativeFixture {
	t.Helper()
	base := t.TempDir()
	spec := linuxSpec{root: base, family: family, label: family + " fixture", state: filepath.Join(base, "etc/embarass-fix"),
		bundle: filepath.Join(base, "etc/ssl/certs/ca-certificates.crt"), updater: filepath.Join(base, "usr/bin/update-ca"),
		config: filepath.Join(base, "etc/ca-certificates.conf"), sources: filepath.Join(base, "usr/share/ca-certificates"),
		local: filepath.Join(base, "usr/local/share/ca-certificates"), blocklist: filepath.Join(base, "etc/pki/ca-trust/source/blocklist")}
	for _, dir := range []string{filepath.Dir(spec.bundle), filepath.Dir(spec.updater), spec.local, spec.blocklist, filepath.Join(spec.sources, "mozilla")} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}
	require.NoError(t, os.WriteFile(spec.updater, []byte("#!/bin/sh\n"), 0755))
	fixture := &nativeFixture{ordinary: ordinaryRoot(t, "corporate root")}
	fixture.store = &linuxStore{spec: spec, owner: os.Geteuid()}
	for _, name := range []string{"aaa", "emsign"} {
		require.NoError(t, os.WriteFile(filepath.Join(spec.sources, "mozilla", name+".crt"), affectedRoot(t, name), 0644))
	}
	require.NoError(t, os.WriteFile(spec.config, []byte("# administrator comment\nmozilla/aaa.crt\nmozilla/emsign.crt\n"), 0644))
	fixture.store.rebuild = func() error {
		fixture.refreshes++
		if fixture.failRefresh {
			return errors.New("test native updater failed")
		}
		bundle := append(append([]byte{}, fixture.ordinary...), fixture.extra...)
		config, err := os.ReadFile(spec.config)
		if err != nil {
			return fmt.Errorf("read fixture configuration: %w", err)
		}
		for _, name := range []string{"aaa", "emsign"} {
			cert := affectedRoot(t, name)
			roots, err := matchingRoots(cert)
			if err != nil {
				return err
			}
			allowed := !fixture.vendorDenied
			if family == "debian" {
				allowed = allowed && strings.Contains(string(config), "\nmozilla/"+name+".crt\n")
			} else {
				_, err := os.Stat(filepath.Join(spec.blocklist, "embarass-"+roots[0].SHA256+".pem"))
				allowed = allowed && errors.Is(err, os.ErrNotExist)
			}
			if allowed {
				bundle = append(bundle, cert...)
			}
		}
		return os.WriteFile(spec.bundle, bundle, 0644)
	}
	require.NoError(t, fixture.store.rebuild())
	fixture.refreshes = 0
	return fixture
}

func TestNativeRepairAndUndo(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"debian", "p11-kit"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			fixture := newNativeFixture(t, family)
			store := fixture.store
			plan, err := store.Inspect()
			require.NoError(t, err)
			require.Len(t, plan.Removed, 2)
			require.NotEmpty(t, plan.Refresh)
			receipt, err := store.Apply(plan.BeforeSHA256, false)
			require.NoError(t, err)
			require.FileExists(t, receipt.Backup)
			fixed, err := store.Inspect()
			require.NoError(t, err)
			require.Empty(t, fixed.Removed)
			bundle, err := os.ReadFile(store.spec.bundle)
			require.NoError(t, err)
			require.Equal(t, fixture.ordinary, bundle)
			undo, err := store.UndoPlan()
			require.NoError(t, err)
			restored, err := store.Apply(undo.BeforeSHA256, true)
			require.NoError(t, err)
			require.FileExists(t, restored.Backup)
			again, err := store.Inspect()
			require.NoError(t, err)
			require.Len(t, again.Removed, 2)
			require.Equal(t, 2, fixture.refreshes)
		})
	}
}

func TestNativeUndoKeepsCurrentVendorStore(t *testing.T) {
	t.Parallel()
	fixture := newNativeFixture(t, "p11-kit")
	store := fixture.store
	plan, err := store.Inspect()
	require.NoError(t, err)
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	fixture.vendorDenied = true
	fixture.extra = ordinaryRoot(t, "new vendor root after repair")
	require.NoError(t, store.rebuild())
	undo, err := store.UndoPlan()
	require.NoError(t, err)
	_, err = store.Apply(undo.BeforeSHA256, true)
	require.NoError(t, err)
	current, err := os.ReadFile(store.spec.bundle)
	require.NoError(t, err)
	require.Equal(t, append(append([]byte{}, fixture.ordinary...), fixture.extra...), current)
	check, err := store.Inspect()
	require.NoError(t, err)
	require.Empty(t, check.Removed, "vendor distrust must survive removal of our override")
}

func TestNativeUndoRefusesChangedSourcePolicy(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"config", "vendor source"} {
		t.Run(change, func(t *testing.T) {
			fixture := newNativeFixture(t, "debian")
			store := fixture.store
			plan, err := store.Inspect()
			require.NoError(t, err)
			_, err = store.Apply(plan.BeforeSHA256, false)
			require.NoError(t, err)
			if change == "config" {
				data, err := os.ReadFile(store.spec.config)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(store.spec.config, append(data, []byte("# new policy\n")...), 0644))
			} else {
				require.NoError(t, os.WriteFile(filepath.Join(store.spec.sources, "mozilla/aaa.crt"), ordinaryRoot(t, "replacement vendor root"), 0644))
			}
			_, err = store.UndoPlan()
			require.ErrorContains(t, err, "changed since repair")
		})
	}
}

func TestNativeFailureLeavesRecoverablePolicy(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"debian", "p11-kit"} {
		t.Run(family, func(t *testing.T) {
			fixture := newNativeFixture(t, family)
			store := fixture.store
			plan, err := store.Inspect()
			require.NoError(t, err)
			fixture.failRefresh = true
			receipt, err := store.Apply(plan.BeforeSHA256, false)
			require.ErrorContains(t, err, "regeneration incomplete")
			require.FileExists(t, receipt.Backup)
			fixture.failRefresh = false
			undo, err := store.UndoPlan()
			require.NoError(t, err)
			_, err = store.Apply(undo.BeforeSHA256, true)
			require.NoError(t, err)
			current, err := store.Inspect()
			require.NoError(t, err)
			require.Len(t, current.Removed, 2)
		})
	}
}

func TestDebianRefusesLocalDuplicatesAndMixedSources(t *testing.T) {
	t.Parallel()
	for _, location := range []string{"local", "mixed vendor"} {
		t.Run(location, func(t *testing.T) {
			fixture := newNativeFixture(t, "debian")
			path := filepath.Join(fixture.store.spec.local, "duplicate.crt")
			data := affectedRoot(t, "aaa")
			if location == "mixed vendor" {
				path = filepath.Join(fixture.store.spec.sources, "mozilla/aaa.crt")
				data = append(data, fixture.ordinary...)
			}
			require.NoError(t, os.WriteFile(path, data, 0644))
			_, err := fixture.store.Inspect()
			require.Error(t, err)
			require.NoDirExists(t, fixture.store.spec.state)
		})
	}
}

func TestNativeMissingUpdaterAndStalePreview(t *testing.T) {
	t.Parallel()
	fixture := newNativeFixture(t, "debian")
	plan, err := fixture.store.Inspect()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture.store.spec.config, []byte("# changed\nmozilla/aaa.crt\n"), 0644))
	_, err = fixture.store.Apply(plan.BeforeSHA256, false)
	require.ErrorContains(t, err, "changed after preview")
	require.NoError(t, os.Remove(fixture.store.spec.updater))
	_, err = fixture.store.Inspect()
	require.ErrorContains(t, err, "full ca-certificates package")
}

func TestExistingP11DistrustIsNotOwnedByUndo(t *testing.T) {
	t.Parallel()
	fixture := newNativeFixture(t, "p11-kit")
	store := fixture.store
	root := affectedRoot(t, "aaa")
	roots, err := matchingRoots(root)
	require.NoError(t, err)
	path := filepath.Join(store.spec.blocklist, "embarass-"+roots[0].SHA256+".pem")
	require.NoError(t, os.WriteFile(path, root, 0644))
	plan, err := store.Inspect()
	require.NoError(t, err)
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	undo, err := store.UndoPlan()
	require.NoError(t, err)
	_, err = store.Apply(undo.BeforeSHA256, true)
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, bytes.Equal(root, data))
}
