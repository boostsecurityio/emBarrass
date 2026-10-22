// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package batchtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
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
	require.Equal(t, []string{
		"git", "wget", "npm", "aws", "gcloud", "cargo", "uv", "kubectl",
		"python", "node", "gem", "dotnet", "pnpm", "httpie", "helm", "composer",
	}, plan.Unavailable)
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

func TestAdditionalProbesIsolateCredentialsAndWrites(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	installed := []string{"aws", "gcloud", "cargo", "uv", "kubectl"}
	plan := discover(workspace, func(name string) (string, error) {
		for _, tool := range installed {
			if name == tool {
				return filepath.Join(workspace, "bin", name), nil
			}
		}
		return "", errors.New("not found")
	})
	require.Equal(t, installed, probeNames(plan.Probes))
	for _, probe := range plan.Probes {
		require.Equal(t, filepath.Join(workspace, "bin", probe.Name), probe.Command()[0])
		require.Equal(t, probe.Name+" "+strings.Join(probe.Arguments, " "), probe.Preview)
		require.False(t, probe.Containerized)
		require.False(t, probe.MayPullImage)
	}

	aws := plan.Probes[0]
	require.Contains(t, aws.Arguments, "--no-sign-request")
	require.Contains(t, aws.Arguments, "head-bucket")
	require.Contains(t, aws.Arguments, "https://s3.us-east-1.amazonaws.com")
	require.Equal(t, filepath.Join(workspace, "aws-config"), aws.EnvironmentOverrides["AWS_CONFIG_FILE"])
	require.Equal(t, os.DevNull, aws.EnvironmentOverrides["AWS_SHARED_CREDENTIALS_FILE"])
	require.Equal(t, "default", aws.EnvironmentOverrides["AWS_PROFILE"])
	require.Equal(t, "default", aws.EnvironmentOverrides["AWS_DEFAULT_PROFILE"])
	require.Equal(t, "true", aws.EnvironmentOverrides["AWS_EC2_METADATA_DISABLED"])

	gcloud := plan.Probes[1]
	require.Equal(t, "true", gcloud.EnvironmentOverrides["CLOUDSDK_AUTH_DISABLE_CREDENTIALS"])
	require.Equal(t, filepath.Join(workspace, "gcloud-config"), gcloud.EnvironmentOverrides["CLOUDSDK_CONFIG"])
	require.Equal(t, "true", gcloud.EnvironmentOverrides["CLOUDSDK_CORE_DISABLE_USAGE_REPORTING"])
	require.Equal(t, "false", gcloud.EnvironmentOverrides["CLOUDSDK_CORE_CHECK_GCE_METADATA"])
	require.Equal(t, []string{"components", "list", "--quiet"}, gcloud.Arguments)
	require.Equal(t, "https://dl.google.com/dl/cloudsdk/channels/rapid/components-2.json", gcloud.EnvironmentOverrides["CLOUDSDK_COMPONENT_MANAGER_SNAPSHOT_URL"])

	cargo := plan.Probes[2]
	require.Equal(t, filepath.Join(workspace, "cargo"), cargo.EnvironmentOverrides["CARGO_HOME"])
	require.Equal(t, "sparse", cargo.EnvironmentOverrides["CARGO_REGISTRIES_CRATES_IO_PROTOCOL"])
	require.Equal(t, "0", cargo.EnvironmentOverrides["RUSTUP_AUTO_INSTALL"])
	require.Equal(t, []string{"search", "serde", "--limit", "1", "--registry", "crates-io"}, cargo.Arguments)

	uv := plan.Probes[3]
	for _, flag := range []string{"--no-config", "--no-python-downloads", "--no-build", "--no-deps"} {
		require.Contains(t, uv.Arguments, flag)
	}
	require.Equal(t, filepath.Join(workspace, "uv-cache"), uv.EnvironmentOverrides["UV_CACHE_DIR"])
	require.Equal(t, os.DevNull, uv.EnvironmentOverrides["NETRC"])

	kubectl := plan.Probes[4]
	require.Equal(t, []string{
		"--kubeconfig", os.DevNull, "--server", "https://example.com",
		"--cache-dir", filepath.Join(workspace, "kubectl-cache"), "get", "--raw=/version",
	}, kubectl.Arguments)
}

func TestDiscoverPreparesCloudConfiguration(t *testing.T) {
	t.Parallel()

	plan, err := Discover()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, plan.Cleanup()) })
	config, err := os.ReadFile(filepath.Join(plan.WorkingDirectory(), "aws-config"))
	require.NoError(t, err)
	require.Equal(t, "[default]\n", string(config))
	require.DirExists(t, filepath.Join(plan.WorkingDirectory(), "gcloud-config"))
}

// Opt in to exercise real installed clients through the non-forwarding proxy.
// Ordinary unit tests do not depend on external CLI installations.
func TestInstalledAdditionalProbesReachTLS(t *testing.T) {
	if os.Getenv("EMBARASS_TEST_INSTALLED_TOOLS") != "1" {
		t.Skip("set EMBARASS_TEST_INSTALLED_TOOLS=1 to test installed clients")
	}
	// A configured shell must not require these profiles or credential files.
	t.Setenv("AWS_PROFILE", "embarass-nonexistent-profile")
	t.Setenv("AWS_DEFAULT_PROFILE", "embarass-nonexistent-profile")
	t.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-token"))
	t.Setenv("CARGO_REGISTRY_DEFAULT", "embarass-nonexistent-registry")
	plan, err := Discover()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, plan.Cleanup()) })
	for _, name := range []string{
		"aws", "gcloud", "cargo", "uv", "kubectl",
		"python", "node", "gem", "dotnet", "pnpm", "httpie", "helm", "composer",
	} {
		t.Run(name, func(t *testing.T) {
			for _, probe := range plan.Probes {
				if probe.Name != name {
					continue
				}
				for _, chain := range []certforge.Chain{certforge.ChainEMSign, certforge.ChainSectigo} {
					t.Run(string(chain), func(t *testing.T) {
						var stderr bytes.Buffer
						result, err := runner.Run(context.Background(), runner.Options{
							Command: probe.Command(), Timeout: 20 * time.Second,
							Chain:                chain,
							WorkingDirectory:     plan.WorkingDirectory(),
							EnvironmentOverrides: probe.EnvironmentOverrides,
							Stdout:               io.Discard, Stderr: &stderr,
						})
						require.NoError(t, err)
						require.Contains(t, []runner.Outcome{runner.OutcomeRejected, runner.OutcomeVulnerable}, result.Outcome, "%+v\n%s", result, stderr.String())
						if host, ok := everydayProbeHosts[name]; ok {
							require.Equal(t, host, result.Host)
						}
						t.Logf("%s/%s: %s (%s)", name, chain, result.Outcome, result.Host)
					})
				}
				return
			}
			t.Skip("executable not installed")
		})
	}
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
