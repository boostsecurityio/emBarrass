// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/boostsecurityio/emBarrass/pkg/repair"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func testFixModel() fixModel {
	return newFixModel(newTerminalUI(&bytes.Buffer{}).styles, repair.Plan{
		Certificates: 128,
		Removed: []repair.Root{{Name: "AAA Certificate Services", SHA256: "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"},
			{Name: "emSign ECC Root CA - G3", SHA256: "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"}},
	}, false, "embarass")
}

func TestFixPreviewRequiresExplicitConsent(t *testing.T) {
	t.Parallel()
	for _, key := range []tea.KeyMsg{{Type: tea.KeyEnter}, {Type: tea.KeyEsc}, {Type: tea.KeyCtrlC}, {Type: tea.KeyRunes, Runes: []rune("n")}} {
		model := testFixModel()
		updated, _ := model.Update(key)
		require.False(t, updated.(fixModel).confirmed)
		require.True(t, updated.(fixModel).canceled)
	}
	model := testFixModel()
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	require.True(t, updated.(fixModel).confirmed)
	require.Contains(t, model.View(), "Legitimate chains")
	require.Contains(t, model.View(), "126 other certificates preserved")
}

func TestFixCancellationWaitsForTransactionReceipt(t *testing.T) {
	t.Parallel()
	model := testFixModel()
	model.running = true
	model.steps = []fixStep{{transaction: true, label: "commit"}, {after: true, label: "verify"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	model.cancel = cancel
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	model = updated.(fixModel)
	require.Nil(t, cmd, "must not quit while the transaction is running")
	require.False(t, model.done)
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	updated, cmd = model.Update(fixResultMsg{index: 0, result: fixStepResult{receipt: repair.Receipt{Backup: "/protected/backup.pem"}}})
	model = updated.(fixModel)
	require.NotNil(t, cmd)
	require.True(t, model.done)
	require.True(t, model.canceled)
	require.Equal(t, "/protected/backup.pem", model.receipt.Backup)
	require.Equal(t, exitInconclusive, model.exitCode())
}

func TestFixVerdictRequiresBothAfterChecks(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		results []runner.Outcome
		want    int
	}{
		{"both reject", []runner.Outcome{runner.OutcomeRejected, runner.OutcomeRejected}, exitProtected},
		{"one inconclusive", []runner.Outcome{runner.OutcomeRejected, runner.OutcomeInconclusive}, exitInconclusive},
		{"still exposed", []runner.Outcome{runner.OutcomeVulnerable, runner.OutcomeInconclusive}, exitVulnerable},
		{"one missing", []runner.Outcome{runner.OutcomeRejected}, exitInconclusive},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := testFixModel()
			model.running, model.done = true, true
			for _, outcome := range test.results {
				model.steps = append(model.steps, fixStep{after: true, finished: true, result: fixStepResult{outcome: outcome}})
			}
			require.Equal(t, test.want, model.exitCode())
			if test.want != exitProtected {
				require.NotContains(t, model.View(), "BOTH FORGERIES REJECTED")
			}
		})
	}
}

func TestFixFailureNeverReportsPatched(t *testing.T) {
	t.Parallel()
	model := testFixModel()
	model.running, model.done = true, true
	model.steps = []fixStep{{transaction: true}}
	model.record(0, fixStepResult{err: errors.New("disk full"), detail: "disk full"})
	require.Equal(t, exitInconclusive, model.exitCode())
	require.Contains(t, model.View(), "REPAIR INCOMPLETE")
	require.NotContains(t, model.View(), "BUNDLE PATCHED")
}

func TestFixHelpAndCompletionDoNotProbe(t *testing.T) {
	t.Parallel()
	app := &application{run: func(context.Context, runner.Options) (runner.Result, error) {
		t.Fatal("unexpected probe")
		return runner.Result{}, nil
	}}
	command := newRootCommand(app)
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"fix", "--help"})
	require.NoError(t, command.Execute())
	require.Contains(t, output.String(), "--dry-run")
	require.Contains(t, output.String(), "--undo")
	require.Contains(t, executeCompletion(t, "embarass", []string{"__completeNoDesc", "fi"}), "fix")
	require.NotContains(t, executeCompletion(t, "embarass", []string{"__completeNoDesc", "_"}), "_fix-commit")
}

func TestFixVerificationDoesNotConfuseTLSFailureWithCertificateRejection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root deliberately skips behavioral probes")
	}
	t.Parallel()
	for _, test := range []struct {
		name   string
		result runner.Result
		err    error
		want   runner.Outcome
	}{
		{"certificate rejected", runner.Result{Outcome: runner.OutcomeRejected, ChildExitCode: 60}, nil, runner.OutcomeRejected},
		{"post-handshake certificate rejection", runner.Result{Outcome: runner.OutcomeInconclusive, Reason: runner.ReasonNoTLSDecision, ChildExitCode: 60}, nil, runner.OutcomeRejected},
		{"unobserved exit 60", runner.Result{Outcome: runner.OutcomeInconclusive, Reason: runner.ReasonNoTraffic, ChildExitCode: 60}, nil, runner.OutcomeInconclusive},
		{"other TLS failure", runner.Result{Outcome: runner.OutcomeRejected, ChildExitCode: 35}, nil, runner.OutcomeInconclusive},
		{"timeout", runner.Result{Outcome: runner.OutcomeInconclusive}, nil, runner.OutcomeInconclusive},
		{"harness failure", runner.Result{}, errors.New("listener failed"), runner.OutcomeInconclusive},
		{"accepted", runner.Result{Outcome: runner.OutcomeVulnerable}, nil, runner.OutcomeVulnerable},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := &application{run: func(_ context.Context, options runner.Options) (runner.Result, error) {
				require.Equal(t, "/usr/bin/curl", options.Command[0])
				require.Equal(t, "-q", options.Command[1])
				return test.result, test.err
			}}
			steps := app.fixSteps(context.Background(), repair.Plan{}, "/tmp/empty", nil, false)
			require.Len(t, steps, 2)
			for _, step := range steps {
				require.Equal(t, test.want, step.run().outcome)
			}
		})
	}
}
