// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/boostsecurityio/emBarrass/pkg/runner"
	"github.com/stretchr/testify/require"
)

func TestShellCompletion(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{"batch command", []string{"ba"}, []string{"batch", ":4"}},
		{"version command", []string{"ver"}, []string{"version", ":4"}},
		{"completion command", []string{"comp"}, []string{"completion", ":4"}},
		{"root flag", []string{"--he"}, []string{"--headless", "--help", ":4"}},
		{"batch flag", []string{"batch", "--y"}, []string{"--yes", ":4"}},
		{"root chains", []string{"--chain", ""}, []string{"all", "emsign", "sectigo", ":4"}},
		{"batch chains", []string{"batch", "--chain", ""}, []string{"all", "emsign", "sectigo", ":4"}},
		{"chain prefix", []string{"--chain", "em"}, []string{"emsign", ":4"}},
		{"chain equals", []string{"batch", "--chain=se"}, []string{"sectigo", ":4"}},
		{"unknown chain", []string{"--chain", "unknown"}, []string{":4"}},
		{"after flag", []string{"--headless", "--ch"}, []string{"--chain", ":4"}},
		{"child flags", []string{"curl", "--he"}, []string{":0"}},
		{"child chain flag", []string{"curl", "--chain", ""}, []string{":0"}},
		{"separator", []string{"--", "curl", "--he"}, []string{":0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := executeCompletion(t, "embarass", append([]string{"__completeNoDesc"}, test.args...))
			require.ElementsMatch(t, test.want, strings.Split(strings.TrimSpace(output), "\n"))
		})
	}
}

func TestCompletionScriptsUseStableCommandName(t *testing.T) {
	t.Parallel()

	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		for _, invocation := range []string{"embarass", "./embarass", "/tmp/local build/embarass", `.\embarass.exe`} {
			t.Run(shell+"/"+invocation, func(t *testing.T) {
				t.Parallel()
				output := executeCompletion(t, invocation, []string{"completion", shell})
				require.Contains(t, output, "embarass")
				require.Contains(t, output, "__complete")
				if invocation != "embarass" {
					require.NotContains(t, output, invocation)
				}
			})
		}
	}
}

func executeCompletion(t *testing.T, invocation string, args []string) string {
	t.Helper()
	app := &application{
		invocation: invocation,
		run: func(context.Context, runner.Options) (runner.Result, error) {
			t.Fatal("completion must not run a TLS probe")
			return runner.Result{}, nil
		},
	}
	command := newRootCommand(app)
	var output, stderr bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&stderr)
	command.SetArgs(args)
	require.NoError(t, command.Execute(), stderr.String())
	require.Equal(t, exitProtected, app.exitCode)
	return output.String()
}
