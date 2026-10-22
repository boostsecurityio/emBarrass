// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/batchtest"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestBatchModelPreviewsThenRunsConfirmedProbe(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plan := batchtest.Plan{
		Probes: []batchtest.Probe{
			{
				Name:       "curl",
				Executable: "/usr/bin/curl",
				Arguments:  []string{"https://example.com/"},
				Preview:    "curl https://example.com/",
			},
		},
		Unavailable: []string{"docker"},
	}
	var received runner.Options
	run := func(_ context.Context, options runner.Options) (runner.Result, error) {
		received = options
		return runner.Result{
			Outcome:  runner.OutcomeVulnerable,
			Host:     "example.com",
			Duration: time.Millisecond,
		}, nil
	}
	ui := newTerminalUI(testWriter{t})
	model := newBatchModel(
		ctx,
		cancel,
		ui.styles,
		plan,
		run,
		30*time.Second,
		false,
	)

	require.Contains(t, model.View(), "BATCH TRUST PREFLIGHT")
	require.Contains(t, model.View(), "curl https://example.com/")
	require.Contains(t, model.View(), "docker")
	require.Contains(t, model.View(), "[y/N]")

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	running := updated.(batchModel)
	require.True(t, running.confirmed)
	require.Equal(t, batchRunning, running.items[0].state)

	message := running.runCurrent()().(batchResultMsg)
	updated, command := running.Update(message)
	finished := updated.(batchModel)
	require.NotNil(t, command)
	require.True(t, finished.done)
	require.Equal(t, batchVulnerable, finished.items[0].state)
	require.Equal(t, exitVulnerable, finished.summary().exitCode())
	require.Contains(t, finished.View(), "COMPLETELY EMBARRASSED")
	require.Equal(t, []string{"/usr/bin/curl", "https://example.com/"}, received.Command)
}

func TestBatchModelDefaultsToCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	plan := batchtest.Plan{Probes: []batchtest.Probe{{Name: "curl"}}}
	ui := newTerminalUI(testWriter{t})
	model := newBatchModel(
		ctx,
		cancel,
		ui.styles,
		plan,
		func(context.Context, runner.Options) (runner.Result, error) {
			t.Fatal("probe must not run before confirmation")
			return runner.Result{}, errors.New("unreachable")
		},
		30*time.Second,
		false,
	)

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	canceled := updated.(batchModel)
	require.NotNil(t, command)
	require.True(t, canceled.canceled)
	require.True(t, canceled.done)
	require.Equal(t, exitProtected, canceled.summary().exitCode())
	require.Contains(t, canceled.View(), "No probes were run")
}

func TestBatchRunnerOptionsIsolateWritesAndDiscardOutput(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	plan, err := batchtest.Discover()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, plan.Cleanup()) })
	probe := batchtest.Probe{
		Name:          "docker/git",
		Executable:    "/usr/bin/docker",
		Arguments:     []string{"run", "example.invalid/image@sha256:deadbeef"},
		Containerized: true,
		EnvironmentOverrides: map[string]string{
			"GOCACHE": filepath.Join(workspace, "go-build"),
		},
	}
	options := batchRunnerOptions(plan, probe, 5*time.Second)

	require.Equal(t, probe.Command(), options.Command)
	require.Equal(t, probe.EnvironmentOverrides, options.EnvironmentOverrides)
	require.Equal(t, plan.WorkingDirectory(), options.WorkingDirectory)
	require.Equal(t, 5*time.Second, options.Timeout)
	require.Equal(t, runner.ProxyTargetDockerContainer, options.ProxyTarget)
}

func TestBatchRunnerOptionsDefaultToHostProxy(t *testing.T) {
	t.Parallel()

	options := batchRunnerOptions(
		batchtest.Plan{},
		batchtest.Probe{Name: "curl", Executable: "/usr/bin/curl"},
		time.Second,
	)

	require.Equal(t, runner.ProxyTargetHost, options.ProxyTarget)
}

func TestBatchModelDisclosesDigestPinnedImagePull(t *testing.T) {
	t.Parallel()

	ui := newTerminalUI(testWriter{t})
	model := batchModel{
		styles: ui.styles,
		width:  100,
		items: []batchItem{{probe: batchtest.Probe{
			Name:         "docker/git",
			MayPullImage: true,
		}}},
	}

	require.Contains(t, model.View(), "may pull and retain one digest-pinned image")
}

func TestBatchSummaryExitCode(t *testing.T) {
	t.Parallel()

	require.Equal(t, exitProtected, (batchSummary{rejected: 3}).exitCode())
	require.Equal(t, exitVulnerable, (batchSummary{vulnerable: 1, failed: 1}).exitCode())
	require.Equal(t, exitInconclusive, (batchSummary{inconclusive: 1}).exitCode())
	require.Equal(t, exitInconclusive, (batchSummary{failed: 1}).exitCode())
	require.Equal(t, exitProtected, (batchSummary{canceled: true}).exitCode())
	require.Equal(t, exitInconclusive, (batchSummary{canceled: true, rejected: 1}).exitCode())
}

func TestBatchVerdictReflectsMixedResults(t *testing.T) {
	t.Parallel()

	ui := newTerminalUI(testWriter{t})
	model := batchModel{styles: ui.styles}
	testCases := []struct {
		name    string
		summary batchSummary
		want    string
	}{
		{
			name:    "every executed probe vulnerable",
			summary: batchSummary{vulnerable: 3, skipped: 2},
			want:    "COMPLETELY EMBARRASSED",
		},
		{
			name:    "vulnerable and held",
			summary: batchSummary{vulnerable: 2, rejected: 1},
			want:    "PARTIALLY EMBARRASSED",
		},
		{
			name:    "vulnerable and inconclusive",
			summary: batchSummary{vulnerable: 1, inconclusive: 1},
			want:    "PARTIALLY EMBARRASSED",
		},
		{
			name:    "vulnerable and harness error",
			summary: batchSummary{vulnerable: 1, failed: 1},
			want:    "PARTIALLY EMBARRASSED",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			rendered := model.batchVerdict(testCase.summary)
			require.Contains(t, rendered, testCase.want)
		})
	}
}

func TestWrapCommandPreservesArguments(t *testing.T) {
	t.Parallel()

	command := "npm view is-number version --registry=https://registry.npmjs.org/"
	wrapped := wrapCommand(command, 35)

	require.Contains(t, wrapped, "--registry=https://registry.npmjs.org/")
	require.NotContains(t, wrapped, "--\nregistry")
	require.Equal(t, command, strings.ReplaceAll(wrapped, "\n", " "))
}

// testWriter keeps Lip Gloss in its deterministic, no-color output path while
// making accidental writes visible in the failing test log.
type testWriter struct {
	t *testing.T
}

func (writer testWriter) Write(data []byte) (int, error) {
	writer.t.Helper()
	return len(data), nil
}
