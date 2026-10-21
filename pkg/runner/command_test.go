// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrepareCommandPinsGitHTTPS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		command    []string
		want       []string
		adjustment bool
	}{
		{
			name:    "Git clone",
			command: []string{"git", "clone", "https://github.com/actions/checkout", "checkout"},
			want: []string{
				"git",
				"-c",
				"url.https://github.com:443/actions/checkout.insteadOf=https://github.com:443/actions/checkout",
				"clone",
				"https://github.com:443/actions/checkout",
				"checkout",
			},
			adjustment: true,
		},
		{
			name:       "curl remains unchanged",
			command:    []string{"curl", "https://github.com/actions/checkout"},
			want:       []string{"curl", "https://github.com/actions/checkout"},
			adjustment: false,
		},
		{
			name:       "GitHub CLI public metadata probe is isolated",
			command:    []string{"gh", "api", "meta", "--silent"},
			want:       []string{"gh", "api", "meta", "--silent"},
			adjustment: true,
		},
		{
			name:       "Git SSH remains unchanged",
			command:    []string{"git", "clone", "git@github.com:actions/checkout.git"},
			want:       []string{"git", "clone", "git@github.com:actions/checkout.git"},
			adjustment: false,
		},
		{
			name: "already pinned Git command is unchanged",
			command: []string{
				"git",
				"-c",
				"url.https://github.com:443/actions/checkout.insteadOf=https://github.com:443/actions/checkout",
				"ls-remote",
				"https://github.com:443/actions/checkout",
			},
			want: []string{
				"git",
				"-c",
				"url.https://github.com:443/actions/checkout.insteadOf=https://github.com:443/actions/checkout",
				"ls-remote",
				"https://github.com:443/actions/checkout",
			},
			adjustment: false,
		},
		{
			name:    "query is excluded from identity prefix",
			command: []string{"git", "ls-remote", "https://example.com/repo?version=1"},
			want: []string{
				"git",
				"-c",
				"url.https://example.com:443/repo.insteadOf=https://example.com:443/repo",
				"ls-remote",
				"https://example.com:443/repo?version=1",
			},
			adjustment: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			prepared, adjustments := PrepareCommand(testCase.command)
			require.Equal(t, testCase.want, prepared)
			if testCase.adjustment {
				if isGHMetaProbe(testCase.command) {
					require.Equal(t, []CommandAdjustment{AdjustmentGHCredentialsIsolated}, adjustments)
				} else {
					require.Equal(t, []CommandAdjustment{AdjustmentGitHTTPSPinned}, adjustments)
				}
			} else {
				require.Empty(t, adjustments)
			}
		})
	}
}

func TestCompatibilityEnvironmentIsolatesOnlyPublicGHProbe(t *testing.T) {
	t.Parallel()

	overrides := compatibilityEnvironment([]string{"gh", "api", "/meta", "--silent"})
	require.Equal(t, "embarass-intentionally-invalid-token", overrides["GH_TOKEN"])
	require.Equal(t, "embarass-intentionally-invalid-token", overrides["GITHUB_TOKEN"])
	require.Equal(t, "1", overrides["GH_PROMPT_DISABLED"])

	require.Nil(t, compatibilityEnvironment([]string{"gh", "api", "user", "--silent"}))
	require.Nil(t, compatibilityEnvironment([]string{"gh", "repo", "view"}))
}

func TestPreparedGitCommandPreservesHTTPSAgainstInsteadOf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("trace assertion uses Unix command formatting")
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}

	globalConfig := filepath.Join(t.TempDir(), "gitconfig")
	require.NoError(t, os.WriteFile(
		globalConfig,
		[]byte("[url \"git@github.com:\"]\n\tinsteadOf = https://github.com/actions/checkout\n"),
		0o600,
	))

	prepared, adjustments := PrepareCommand([]string{
		gitPath,
		"ls-remote",
		"https://github.com/actions/checkout",
	})
	require.Equal(t, []CommandAdjustment{AdjustmentGitHTTPSPinned}, adjustments)

	command := exec.Command(prepared[0], prepared[1:]...)
	command.Env = append(os.Environ(),
		"GIT_TRACE=1",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+globalConfig,
		"HTTP_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9",
		"HTTPS_PROXY=http://127.0.0.1:9",
		"https_proxy=http://127.0.0.1:9",
		"ALL_PROXY=http://127.0.0.1:9",
		"all_proxy=http://127.0.0.1:9",
		"NO_PROXY=",
		"no_proxy=",
	)
	output, err := command.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), "remote-https")
	require.NotContains(t, string(output), " ssh ")
}
