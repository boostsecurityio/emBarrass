// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin || linux

package repair

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/stretchr/testify/require"
)

func TestSystemCurlRejectsBothPathsAfterFixtureRepair(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("exercises Apple's curl")
	}
	t.Parallel()
	for _, chain := range []certforge.Chain{certforge.ChainEMSign, certforge.ChainSectigo} {
		t.Run(string(chain), func(t *testing.T) {
			t.Parallel()
			store, _ := testStore(t)
			forge, err := certforge.New(certforge.Options{Chain: chain})
			require.NoError(t, err)
			certificate, err := forge.Certificate("127.0.0.1")
			require.NoError(t, err)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "local test") }))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			empty := t.TempDir()
			check := func() error {
				cmd := exec.Command("/usr/bin/curl", "-q", "--silent", "--output", "/dev/null", "--cacert", store.path,
					"--capath", empty, "--noproxy", "*", "--max-time", "5", server.URL)
				cmd.Env = []string{"PATH=/usr/bin:/bin"}
				return cmd.Run()
			}
			// A positive control proves this client can exercise this exact chain.
			require.NoError(t, check(), "unmodified fixture must accept the compromised chain")
			plan, err := store.Inspect()
			require.NoError(t, err)
			_, err = store.Apply(plan.BeforeSHA256, false)
			require.NoError(t, err)
			err = check()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, 60, exit.ExitCode(), "repair must cause certificate rejection")
		})
	}
}

func testStore(t *testing.T) (*Store, []byte) {
	t.Helper()
	store := &Store{path: filepath.Join(t.TempDir(), "cert.pem"), owner: os.Geteuid()}
	original := fixtureBundle(t)
	require.NoError(t, os.WriteFile(store.path, original, 0644))
	return store, original
}

func TestApplyAndUndoRoundTrip(t *testing.T) {
	t.Parallel()
	store, original := testStore(t)
	plan, err := store.Inspect()
	require.NoError(t, err)
	receipt, err := store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	backup, err := os.ReadFile(receipt.Backup)
	require.NoError(t, err)
	require.Equal(t, original, backup)
	fixed, err := store.Inspect()
	require.NoError(t, err)
	require.Empty(t, fixed.Removed)
	require.Equal(t, plan.AfterSHA256, fixed.BeforeSHA256)
	info, err := os.Stat(store.path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0644), info.Mode().Perm())
	_, err = store.Apply(fixed.BeforeSHA256, false)
	require.ErrorContains(t, err, "already absent")
	undo, err := store.UndoPlan()
	require.NoError(t, err)
	restored, err := store.Apply(undo.BeforeSHA256, true)
	require.NoError(t, err)
	data, err := os.ReadFile(store.path)
	require.NoError(t, err)
	require.Equal(t, original, data)
	require.FileExists(t, restored.Backup)
	_, err = os.Stat(store.stateDir())
	require.True(t, os.IsNotExist(err))
}

func TestApplyRefusesStalePreviewAndUndoRefusesLaterChanges(t *testing.T) {
	t.Parallel()
	store, original := testStore(t)
	plan, err := store.Inspect()
	require.NoError(t, err)
	changed := append(append([]byte{}, original...), []byte("\n# administrator change\n")...)
	require.NoError(t, os.WriteFile(store.path, changed, 0644))
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.ErrorContains(t, err, "changed after preview")
	plan, err = store.Inspect()
	require.NoError(t, err)
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	newer := append(append([]byte{}, plan.replacement...), []byte("\n# vendor update\n")...)
	require.NoError(t, os.WriteFile(store.path, newer, 0644))
	_, err = store.UndoPlan()
	require.ErrorContains(t, err, "changed since repair")
	_, err = store.Apply(digest(newer), true)
	require.ErrorContains(t, err, "changed since repair")
	data, err := os.ReadFile(store.path)
	require.NoError(t, err)
	require.Equal(t, newer, data)
}

func TestUndoRejectsTamperedBackup(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	plan, err := store.Inspect()
	require.NoError(t, err)
	receipt, err := store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(receipt.Backup, fixtureBundle(t), 0644))
	_, err = store.UndoPlan()
	require.ErrorContains(t, err, "does not match")
}

func TestRepairRefusesSymlinksAndConcurrentWriters(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	plan, err := store.Inspect()
	require.NoError(t, err)
	unlock, err := lockStore(store.path + ".embarass.lock")
	require.NoError(t, err)
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.ErrorContains(t, err, "another repair")
	unlock()
	require.NoError(t, os.Rename(store.path, store.path+".real"))
	require.NoError(t, os.Symlink(store.path+".real", store.path))
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.Error(t, err)
}

func TestUndoCanRecoverAlreadyRestoredOriginal(t *testing.T) {
	t.Parallel()
	store, original := testStore(t)
	plan, err := store.Inspect()
	require.NoError(t, err)
	_, err = store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	// Simulate interruption between restoring the file and archiving the record.
	require.NoError(t, os.WriteFile(store.path, original, 0644))
	undo, err := store.UndoPlan()
	require.NoError(t, err)
	_, err = store.Apply(undo.BeforeSHA256, true)
	require.NoError(t, err)
}

func TestRepairPreservesPermissionsAndDoesNotWidenBackupAccess(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	require.NoError(t, os.Chmod(store.path, 0440))
	plan, err := store.Inspect()
	require.NoError(t, err)
	receipt, err := store.Apply(plan.BeforeSHA256, false)
	require.NoError(t, err)
	for _, path := range []string{store.path, receipt.Backup} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0440), info.Mode().Perm())
	}
	undo, err := store.UndoPlan()
	require.NoError(t, err)
	_, err = store.Apply(undo.BeforeSHA256, true)
	require.NoError(t, err)
	info, err := os.Stat(store.path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0440), info.Mode().Perm())
}
