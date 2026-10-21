// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package batchtest

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoverBuildsSafeProbesForInstalledTools(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	installed := map[string]string{
		"curl":   "/tools/curl",
		"gh":     "/tools/gh",
		"go":     "/tools/go",
		"pip":    "/tools/pip",
		"docker": "/tools/docker",
		"crane":  "/tools/crane",
	}
	lookup := func(name string) (string, error) {
		if path, ok := installed[name]; ok {
			return path, nil
		}
		return "", errors.New("not found")
	}

	plan := discover(workspace, lookup)
	require.Equal(
		t,
		[]string{"curl", "gh", "go", "pip", "docker", "docker/git", "crane"},
		probeNames(plan.Probes),
	)
	require.Equal(t, []string{"git", "wget", "npm"}, plan.Unavailable)
	require.Equal(t, workspace, plan.WorkingDirectory())

	ghProbe := plan.Probes[1]
	require.Equal(t, []string{"/tools/gh", "api", "meta", "--silent"}, ghProbe.Command())
	require.Equal(t, filepath.Join(workspace, "gh-config"), ghProbe.EnvironmentOverrides["GH_CONFIG_DIR"])
	require.Equal(t, "embarass-intentionally-invalid-token", ghProbe.EnvironmentOverrides["GH_TOKEN"])
	require.Equal(t, "embarass-intentionally-invalid-token", ghProbe.EnvironmentOverrides["GITHUB_TOKEN"])
	require.Equal(t, "1", ghProbe.EnvironmentOverrides["GH_PROMPT_DISABLED"])

	goProbe := plan.Probes[2]
	require.Equal(t, "https://proxy.golang.org", goProbe.EnvironmentOverrides["GOPROXY"])
	require.Equal(t, filepath.Join(workspace, "go-mod"), goProbe.EnvironmentOverrides["GOMODCACHE"])
	require.Equal(t, []string{
		"/tools/go", "list", "-m", "-versions", "golang.org/x/text@latest",
	}, goProbe.Command())

	pipProbe := plan.Probes[3]
	require.Contains(t, pipProbe.Arguments, "--no-cache-dir")
	require.Contains(t, pipProbe.Preview, "https://pypi.org/simple")

	dockerGitProbe := plan.Probes[5]
	require.True(t, dockerGitProbe.Containerized)
	require.True(t, dockerGitProbe.MayPullImage)
	require.Equal(t, "/tools/docker", dockerGitProbe.Executable)
	require.Contains(t, dockerGitProbe.Arguments, "--pull=missing")
	require.Contains(t, dockerGitProbe.Arguments, "--read-only")
	require.Contains(t, dockerGitProbe.Arguments, "--cap-drop=ALL")
	require.Contains(t, dockerGitProbe.Arguments, "--security-opt=no-new-privileges")
	require.Contains(t, dockerGitProbe.Arguments, "GIT_TERMINAL_PROMPT")
	require.Contains(
		t,
		dockerGitProbe.Arguments,
		"cgr.dev/chainguard/git@sha256:06119871a608d163eac2daddd0745582e457a29ee8402bd351c13f294ede30e1",
	)
	require.NotContains(t, dockerGitProbe.Preview, "62087eb4f17f6d09e27f4eace690f264e091bbbf0f99c8882dc5b8eae4013bab")
	require.NotContains(t, dockerGitProbe.Preview, ":latest")
	require.Equal(t, "0", dockerGitProbe.EnvironmentOverrides["GIT_TERMINAL_PROMPT"])

	craneProbe := plan.Probes[6]
	require.Equal(t, []string{
		"/tools/crane", "manifest", "registry.k8s.io/pause:3.10",
	}, craneProbe.Command())
	require.Equal(
		t,
		filepath.Join(workspace, "crane-docker-config"),
		craneProbe.EnvironmentOverrides["DOCKER_CONFIG"],
	)
}

func TestDockerGitArgumentsUsePortableHostBridge(t *testing.T) {
	t.Parallel()

	linuxArguments := dockerGitArguments("linux")
	require.Contains(t, linuxArguments, "--add-host=host.docker.internal:host-gateway")

	darwinArguments := dockerGitArguments("darwin")
	require.NotContains(t, darwinArguments, "--add-host=host.docker.internal:host-gateway")

	currentArguments := dockerGitArguments(runtime.GOOS)
	joined := strings.Join(currentArguments, " ")
	require.Contains(
		t,
		joined,
		"cgr.dev/chainguard/git@sha256:06119871a608d163eac2daddd0745582e457a29ee8402bd351c13f294ede30e1",
	)
	require.NotContains(t, joined, "62087eb4f17f6d09e27f4eace690f264e091bbbf0f99c8882dc5b8eae4013bab")
	require.NotContains(t, joined, "cgr.dev/chainguard/git:latest")
	require.Contains(t, joined, "ls-remote https://github.com/actions/checkout.git HEAD")
}

func TestPlanCleanupRemovesOnlyItsWorkspace(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	workspace := filepath.Join(parent, "embarass-batch-test")
	require.NoError(t, os.Mkdir(workspace, 0o700))

	plan := Plan{workspace: workspace}
	require.NoError(t, plan.Cleanup())
	require.NoDirExists(t, workspace)
	require.DirExists(t, parent)
}

func TestZeroPlanCleanupIsSafe(t *testing.T) {
	t.Parallel()

	require.NoError(t, (Plan{}).Cleanup())
}

func probeNames(probes []Probe) []string {
	names := make([]string, 0, len(probes))
	for _, probe := range probes {
		names = append(names, probe.Name)
	}
	return names
}
