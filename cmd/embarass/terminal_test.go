// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestTerminalUIResultStates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		result   runner.Result
		exitCode int
		want     string
	}{
		{
			name:     "vulnerable",
			result:   runner.Result{Outcome: runner.OutcomeVulnerable, Host: "example.com"},
			exitCode: exitVulnerable,
			want:     "COMPLETELY EMBARRASSED",
		},
		{
			name:     "rejected",
			result:   runner.Result{Outcome: runner.OutcomeRejected, Host: "example.com"},
			exitCode: exitProtected,
			want:     "TRUST HELD. CHAIN DENIED.",
		},
		{
			name: "inconclusive",
			result: runner.Result{
				Outcome: runner.OutcomeInconclusive,
				Reason:  runner.ReasonNoTraffic,
			},
			exitCode: exitInconclusive,
			want:     "NO SIGNAL",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			output := &bytes.Buffer{}
			ui := newTerminalUI(output)
			require.NoError(t, ui.result(testCase.result, certforge.ChainSectigo, testCase.exitCode))
			require.Contains(t, output.String(), testCase.want)
			require.Contains(t, output.String(), "EXIT")
			require.NotContains(t, output.String(), "\x1b[")
		})
	}
}

func TestTerminalUIStartRendersCeremonyWithoutArguments(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	ui := newTerminalUI(output)
	require.NoError(t, ui.start(
		[]string{"curl", "https://user:do-not-print@example.com/"},
		certforge.ChainSectigo,
		30*time.Second,
		nil,
	))

	rendered := output.String()
	require.Contains(t, rendered, "KEY CEREMONY REPLAY · GRADE-SCHOOL MATH")
	require.Contains(t, rendered, `begin "advanced cryptanalysis"`)
	require.Contains(t, rendered, "do grade-school math: 1×G, 2×G, …")
	require.Contains(t, rendered, "156×G = Q")
	require.Contains(t, rendered, `admire all ≈8 bits of "entropy"`)
	require.Contains(t, rendered, "P-384: STILL SECURE")
	require.Contains(t, rendered, "KEYGEN: GOLD STAR FOR TRYING")
	require.Contains(t, rendered, "COMMAND  curl · arguments hidden")
	require.Contains(t, rendered, "CHILD OUTPUT")
	require.NotContains(t, rendered, "do-not-print")
}

func TestTerminalUIStartDisclosesGHCredentialIsolation(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	ui := newTerminalUI(output)
	require.NoError(t, ui.start(
		[]string{"gh", "api", "meta", "--silent"},
		certforge.ChainSectigo,
		30*time.Second,
		[]runner.CommandAdjustment{runner.AdjustmentGHCredentialsIsolated},
	))

	require.Contains(t, output.String(), "GitHub CLI public probe · user credentials bypassed")
}

func TestCeremonyModelUsesCompactBrandOnNarrowTerminals(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	ui := newTerminalUI(output)
	model := newCeremonyModel(
		ui.styles,
		[]string{"curl"},
		certforge.ChainSectigo,
		30*time.Second,
		nil,
	)
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 50})
	compact := updated.(ceremonyModel)
	compact.stage = len(ceremonySteps)

	require.Contains(t, compact.View(), "emBarrass // TLS TRUST BREAKER")
	require.NotContains(t, compact.View(), terminalLogo)
}

func TestTerminalUIFailure(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	ui := newTerminalUI(output)
	require.NoError(t, ui.failure(errors.New("listener unavailable")))
	require.Contains(t, output.String(), "HARNESS FAULT")
	require.Contains(t, output.String(), "listener unavailable")
	require.Contains(t, output.String(), "EXIT    2")
}

func TestTerminalUIFailureAfterStartDoesNotRepeatBrand(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	ui := newTerminalUI(output)
	require.NoError(t, ui.failureAfterStart(errors.New("listener unavailable")))
	require.Contains(t, output.String(), "HARNESS FAULT")
	require.NotContains(t, output.String(), terminalTagline)
	require.NotContains(t, output.String(), terminalLogo)
}

func TestTerminalUIMissingCommandOffersActionableExamples(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	ui := newTerminalUI(output)
	require.NoError(t, ui.missingCommand("./embarass"))
	require.Contains(t, output.String(), "PICK A TARGET")
	require.Contains(t, output.String(), "./embarass curl --silent https://example.com/")
	require.Contains(t, output.String(), "./embarass git ls-remote")
	require.Contains(t, output.String(), "./embarass gh api meta --silent")
	require.Contains(t, output.String(), "./embarass batch")
	require.Contains(t, output.String(), "More examples: ./embarass --help")
	require.NotContains(t, output.String(), "HARNESS FAULT")
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()

	require.Equal(t, 33*time.Millisecond, humanDuration(32_673_292*time.Nanosecond))
	require.Equal(t, 333*time.Microsecond, humanDuration(333_333*time.Nanosecond))
}
