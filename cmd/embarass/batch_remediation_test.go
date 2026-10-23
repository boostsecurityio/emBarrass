// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/batchtest"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestBatchReviewDoesNotRunCommandsOrChangeVerdict(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	model := newBatchModel(ctx, cancel, newTerminalUI(testWriter{t}).styles,
		batchtest.Plan{Probes: []batchtest.Probe{{Name: "curl"}, {Name: "gcloud"}, {Name: "dotnet"}}},
		func(context.Context, runner.Options) (runner.Result, error) {
			t.Fatal("review must not execute probes or repairs")
			return runner.Result{}, nil
		}, time.Second, false)
	model.reviewResults, model.confirmed = true, true
	model.platform, model.invocation = "darwin", "./embarass"
	model.items[0].state, model.items[0].result.Outcome = batchRejected, runner.OutcomeRejected
	model.items[1].state, model.items[1].result.Outcome = batchVulnerable, runner.OutcomeVulnerable
	updated, cmd := model.Update(batchResultMsg{index: 2, result: runner.Result{Outcome: runner.OutcomeVulnerable}})
	model = updated.(batchModel)
	require.Nil(t, cmd, "exposed interactive results stay open for review")
	require.True(t, model.done)
	require.Contains(t, model.View(), "PARTIALLY EMBARRASSED")
	require.Contains(t, model.View(), "[d] WHY STILL EXPOSED?")
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	model = updated.(batchModel)
	require.Nil(t, cmd)
	require.Contains(t, model.View(), "gcloud · 1/2")
	require.NotContains(t, model.View(), "curl ·")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRight})
	model = updated.(batchModel)
	require.Contains(t, model.View(), "dotnet · 2/2")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnd})
	model = updated.(batchModel)
	require.Positive(t, model.detailScroll)
	require.Contains(t, model.View(), "DETAILS")
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 50, Height: 20})
	model = updated.(batchModel)
	require.Zero(t, model.detailScroll)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(batchModel)
	require.False(t, model.detailsExpanded)
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = updated.(batchModel)
	require.NotNil(t, cmd)
	require.False(t, model.canceled)
	require.NoError(t, ctx.Err())
	require.Equal(t, exitVulnerable, model.summary().exitCode())
}

func TestRemediationCoverageDependsOnPlatformAndContainer(t *testing.T) {
	t.Parallel()
	mac := remediationFor(batchtest.Probe{Name: "dotnet"}, "darwin", "./embarass")
	require.Contains(t, mac.coverage, "does not change Keychain")
	require.NotContains(t, strings.Join(mac.commands, "\n"), " fix")
	linux := remediationFor(batchtest.Probe{Name: "dotnet"}, "linux", "./embarass")
	require.Contains(t, linux.coverage, "supported distribution")
	windows := remediationFor(batchtest.Probe{Name: "curl"}, "windows", "embarass.exe")
	require.Contains(t, windows.coverage, "does not support")
	require.NotContains(t, strings.Join(windows.commands, "\n"), " fix")
	container := remediationFor(batchtest.Probe{Name: "docker/git", Containerized: true}, "darwin", "./embarass")
	require.Contains(t, container.details, "not evidence that the host repair failed")
	require.Empty(t, container.commands)
	gcloud := remediationFor(batchtest.Probe{Name: "gcloud"}, "darwin", "./embarass")
	require.Contains(t, gcloud.details, "saved gcloud config properties are not loaded")
	require.Contains(t, gcloud.commands, "export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=/etc/ssl/cert.pem")
	for tool, formula := range map[string]string{"aws": "awscli", "python": "python", "node": "node", "uv": "uv"} {
		guide := remediationFor(batchtest.Probe{Name: tool}, "darwin", "./embarass")
		require.Contains(t, guide.commands, "brew upgrade "+formula)
		require.Contains(t, guide.remediation, "If installed with Homebrew")
	}
}

func TestHeldBatchStillExitsWithoutReview(t *testing.T) {
	t.Parallel()
	model := batchModel{reviewResults: true, confirmed: true, items: []batchItem{{probe: batchtest.Probe{Name: "curl"}}}}
	updated, cmd := model.Update(batchResultMsg{index: 0, result: runner.Result{Outcome: runner.OutcomeRejected}})
	require.NotNil(t, cmd)
	require.True(t, updated.(batchModel).done)
}

func TestHeadlessDetailsDescribeExposureWithoutExtraProbes(t *testing.T) {
	t.Parallel()
	for _, details := range []bool{false, true} {
		var output bytes.Buffer
		log := zerolog.New(&output)
		calls := 0
		app := application{batchDetails: details, invocation: "./embarass", run: func(context.Context, runner.Options) (runner.Result, error) {
			calls++
			return runner.Result{Outcome: runner.OutcomeVulnerable}, nil
		}}
		plan := batchtest.Plan{Probes: []batchtest.Probe{{Name: "gcloud", Executable: "gcloud"}}}
		summary := app.runBatchHeadless(log.WithContext(context.Background()), plan, allChains)
		require.Equal(t, 1, calls)
		require.Equal(t, exitVulnerable, summary.exitCode())
		if details {
			require.Contains(t, output.String(), "SDK normally supplies its own CA bundle")
			require.Contains(t, output.String(), "saved gcloud config properties are not loaded")
		} else {
			require.NotContains(t, output.String(), "SDK normally supplies its own CA bundle")
			require.Contains(t, output.String(), "batch --yes --headless --details")
		}
	}
}
