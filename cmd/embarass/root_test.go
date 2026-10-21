// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	"github.com/stretchr/testify/require"
)

func TestRootCommandPassesChildFlagsUnchanged(t *testing.T) {
	t.Parallel()

	var received runner.Options
	app := &application{
		exitCode: exitInconclusive,
		run: func(_ context.Context, options runner.Options) (runner.Result, error) {
			received = options
			return runner.Result{Outcome: runner.OutcomeRejected}, nil
		},
	}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--timeout", "5s", "--chain", "emsign", "curl", "-I", "https://example.com/"})

	require.NoError(t, command.Execute())
	require.Equal(t, []string{"curl", "-I", "https://example.com/"}, received.Command)
	require.Equal(t, 5*time.Second, received.Timeout)
	require.Equal(t, certforge.ChainEMSign, received.Chain)
	require.Equal(t, exitProtected, app.exitCode)
}

func TestRootCommandMapsVulnerableToExitOne(t *testing.T) {
	t.Parallel()

	app := &application{
		exitCode: exitInconclusive,
		run: func(_ context.Context, _ runner.Options) (runner.Result, error) {
			return runner.Result{
				Outcome:  runner.OutcomeVulnerable,
				Host:     "example.com",
				Duration: time.Millisecond,
			}, nil
		},
	}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"curl", "https://example.com/"})

	require.NoError(t, command.Execute())
	require.Equal(t, exitVulnerable, app.exitCode)
	require.Contains(t, output.String(), "putting the “em” in MITM")
	require.Contains(t, output.String(), "COMPLETELY EMBARRASSED")
	require.Contains(t, output.String(), "EXIT    1 · 1ms")
}

func TestRootCommandHeadlessPreservesCompactLogs(t *testing.T) {
	t.Parallel()

	app := &application{
		exitCode: exitInconclusive,
		run: func(_ context.Context, _ runner.Options) (runner.Result, error) {
			return runner.Result{
				Outcome:  runner.OutcomeVulnerable,
				Host:     "example.com",
				Duration: time.Millisecond,
			}, nil
		},
	}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--headless", "curl", "https://example.com/"})

	require.NoError(t, command.Execute())
	require.Equal(t, exitVulnerable, app.exitCode)
	require.Contains(t, output.String(), "ERR VULNERABLE:")
	require.NotContains(t, output.String(), "Find out whether you’ve been emBarrassed.")
}

func TestRootCommandHeadlessDisclosesGHCredentialIsolation(t *testing.T) {
	t.Parallel()

	app := &application{
		run: func(_ context.Context, _ runner.Options) (runner.Result, error) {
			return runner.Result{Outcome: runner.OutcomeRejected}, nil
		},
	}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--headless", "gh", "api", "meta", "--silent"})

	require.NoError(t, command.Execute())
	require.Contains(t, output.String(), "GitHub CLI public probe isolated")
	require.Contains(t, output.String(), "adjustment=gh_credentials_isolated")
}

func TestRootCommandHumanModeDoesNotEchoArguments(t *testing.T) {
	t.Parallel()

	app := &application{
		exitCode: exitInconclusive,
		run: func(_ context.Context, _ runner.Options) (runner.Result, error) {
			return runner.Result{Outcome: runner.OutcomeRejected}, nil
		},
	}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"curl", "https://user:do-not-print@example.com/"})

	require.NoError(t, command.Execute())
	require.Contains(t, output.String(), "COMMAND  curl · arguments hidden")
	require.NotContains(t, output.String(), "do-not-print")
}

func TestRootCommandPinsGitHTTPSAgainstTransportRewrites(t *testing.T) {
	t.Parallel()

	var received runner.Options
	app := &application{
		exitCode: exitInconclusive,
		run: func(_ context.Context, options runner.Options) (runner.Result, error) {
			received = options
			return runner.Result{
				Outcome: runner.OutcomeInconclusive,
				Reason:  runner.ReasonNoTraffic,
			}, nil
		},
	}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{
		"git",
		"clone",
		"https://github.com/actions/checkout",
	})

	require.NoError(t, command.Execute())
	require.Equal(t, []string{
		"git",
		"-c",
		"url.https://github.com:443/actions/checkout.insteadOf=https://github.com:443/actions/checkout",
		"clone",
		"https://github.com:443/actions/checkout",
	}, received.Command)
	require.Contains(t, output.String(), "Git HTTPS pinned")
}

func TestRootCommandRejectsInvalidChain(t *testing.T) {
	t.Parallel()

	app := &application{run: runner.Run}
	command := newRootCommand(app)
	command.SetArgs([]string{"--chain", "unknown", "curl", "https://example.com/"})

	err := command.Execute()
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported chain")
}

func TestRootCommandHelpIncludesSupportedToolExamples(t *testing.T) {
	t.Parallel()

	app := &application{run: runner.Run}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--help"})

	require.NoError(t, command.Execute())
	for _, expected := range []string{
		"embarass curl",
		"embarass git",
		"embarass gh",
		"embarass wget",
		"embarass npm",
		"embarass go",
		"embarass pip",
		"embarass docker",
		"embarass crane",
		"embarass batch",
	} {
		require.Contains(t, output.String(), expected)
	}
}

func TestRootCommandHelpUsesLocalInvocation(t *testing.T) {
	t.Parallel()

	app := &application{run: runner.Run, invocation: "./embarass"}
	command := newRootCommand(app)
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{"--help"})

	require.NoError(t, command.Execute())
	require.Contains(t, output.String(), "Usage:\n  ./embarass [flags]")
	require.Contains(t, output.String(), "./embarass curl")
	require.Contains(t, output.String(), "./embarass batch")
}

func TestDisplayedInvocationPreservesLaunchForm(t *testing.T) {
	t.Parallel()

	require.Equal(t, "./embarass", displayedInvocation("./embarass"))
	require.Equal(t, "embarass", displayedInvocation("embarass"))
	require.Equal(t, "../bin/embarass", displayedInvocation("../bin/embarass"))
	require.Equal(t, `.\embarass.exe`, displayedInvocation(`.\embarass.exe`))
	require.Equal(t, `..\bin\embarass.exe`, displayedInvocation(`..\bin\embarass.exe`))
	require.Equal(t, "embarass", displayedInvocation(""))
	require.Equal(t, "embarass", displayedInvocation("bad\nname"))
}

func TestInformationalCommandsKeepSuccessfulExitCode(t *testing.T) {
	t.Parallel()

	for _, arguments := range [][]string{{"--help"}, {"version"}} {
		app := &application{run: runner.Run, exitCode: exitProtected}
		command := newRootCommand(app)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		command.SetArgs(arguments)

		require.NoError(t, command.Execute())
		require.Equal(t, exitProtected, app.exitCode)
	}
}

func TestRootCommandRequiresTarget(t *testing.T) {
	t.Parallel()

	app := &application{run: runner.Run}
	command := newRootCommand(app)
	command.SetArgs(nil)

	err := command.Execute()
	require.ErrorIs(t, err, errCommandRequired)
}
