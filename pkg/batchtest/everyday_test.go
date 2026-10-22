// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package batchtest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var everydayProbeHosts = map[string]string{
	"python":   "example.com",
	"node":     "example.com",
	"gem":      "rubygems.org",
	"dotnet":   "api.nuget.org",
	"pnpm":     "registry.npmjs.org",
	"httpie":   "example.com",
	"helm":     "helm.github.io",
	"composer": "repo.packagist.org",
}

func TestEverydayProbeDiscoverySupportsExecutableAliases(t *testing.T) {
	t.Parallel()
	for _, aliases := range [][]string{
		{"python3", "node", "http"},
		{"python", "nodejs", "https"},
	} {
		workspace := t.TempDir()
		installed := map[string]bool{"gem": true, "dotnet": true, "pnpm": true, "helm": true, "composer": true}
		for _, alias := range aliases {
			installed[alias] = true
		}
		plan := discover(workspace, func(name string) (string, error) {
			if installed[name] {
				return filepath.Join(workspace, "bin", name), nil
			}
			return "", errors.New("not found")
		})
		require.Equal(t, []string{"python", "node", "gem", "dotnet", "pnpm", "httpie", "helm", "composer"}, probeNames(plan.Probes))
		require.Equal(t, filepath.Join(workspace, "bin", aliases[0]), plan.Probes[0].Executable)
		require.Equal(t, filepath.Join(workspace, "bin", aliases[1]), plan.Probes[1].Executable)
		require.Equal(t, filepath.Join(workspace, "bin", aliases[2]), plan.Probes[5].Executable)
	}
}

func TestEverydayProbesAvoidInstallationAndIsolateState(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	testCases := []struct {
		name      string
		arguments []string
		paths     []string
		settings  map[string]string
	}{
		{name: "python", arguments: []string{"-I", "-c", "https://example.com/"}},
		{name: "node", arguments: []string{filepath.Join(workspace, "node-probe.cjs"), "https://example.com/"}},
		{name: "gem", arguments: []string{"search", "--remote", "--norc", "--clear-sources", "https://rubygems.org/"}, paths: []string{"GEM_HOME", "GEM_PATH", "GEM_SPEC_CACHE"}},
		{
			name: "dotnet", arguments: []string{"package", "search", "--configfile", filepath.Join(workspace, "NuGet.Config"), "https://api.nuget.org/v3/index.json"},
			paths:    []string{"DOTNET_CLI_HOME", "NUGET_PACKAGES", "NUGET_HTTP_CACHE_PATH", "NUGET_PLUGINS_CACHE_PATH"},
			settings: map[string]string{"DOTNET_GENERATE_ASPNET_CERTIFICATE": "false", "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "false", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"},
		},
		{
			name: "pnpm", arguments: []string{"view", "--registry=https://registry.npmjs.org/"},
			paths:    []string{"NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_CACHE", "PNPM_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"},
			settings: map[string]string{"COREPACK_ENABLE_NETWORK": "0", "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0"},
		},
		{name: "httpie", arguments: []string{"--ignore-stdin", "--ignore-netrc", "HEAD", "https://example.com/"}, paths: []string{"HTTPIE_CONFIG_DIR"}},
		{
			name: "helm", arguments: []string{"show", "chart", "--repo", "https://helm.github.io/examples"},
			paths:    []string{"HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME", "HELM_REPOSITORY_CONFIG", "HELM_REPOSITORY_CACHE", "HELM_REGISTRY_CONFIG", "HELM_PLUGINS"},
			settings: map[string]string{"KUBECONFIG": os.DevNull},
		},
		{
			name: "composer", arguments: []string{"show", "--all", "--no-plugins", "--no-scripts", "--no-interaction", "--no-cache"},
			paths: []string{"COMPOSER", "COMPOSER_HOME", "COMPOSER_CACHE_DIR"}, settings: map[string]string{"COMPOSER_AUTH": "{}"},
		},
	}
	definitions := everydayTools()
	for i, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			probe := definitions[i].build("/tools/"+testCase.name, workspace)
			require.Equal(t, testCase.name, probe.Name)
			for _, argument := range testCase.arguments {
				require.Contains(t, probe.Arguments, argument)
			}
			for _, key := range testCase.paths {
				require.Contains(t, probe.EnvironmentOverrides, key)
				require.True(t, filepath.IsLocal(mustRelativePath(t, workspace, probe.EnvironmentOverrides[key])), key)
			}
			for key, value := range testCase.settings {
				require.Equal(t, value, probe.EnvironmentOverrides[key], key)
			}
			require.False(t, probe.Containerized)
			require.False(t, probe.MayPullImage)
		})
	}
}

func mustRelativePath(t *testing.T, root, path string) string {
	t.Helper()
	relative, err := filepath.Rel(root, path)
	require.NoError(t, err)
	return relative
}

func TestEverydayProbeFilesArePreparedAndCleanedUp(t *testing.T) {
	t.Parallel()
	plan, err := Discover()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, plan.Cleanup()) })
	for _, name := range []string{"node-probe.cjs", "NuGet.Config", "composer.json", "npm-user-config", "npm-global-config"} {
		require.FileExists(t, filepath.Join(plan.WorkingDirectory(), name))
	}
	script, err := os.ReadFile(filepath.Join(plan.WorkingDirectory(), "node-probe.cjs"))
	require.NoError(t, err)
	require.Equal(t, nodeProbeScript, script)
	require.NoError(t, plan.Cleanup())
	require.NoDirExists(t, plan.WorkingDirectory())
}
