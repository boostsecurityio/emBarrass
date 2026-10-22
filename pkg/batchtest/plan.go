// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package batchtest discovers installed TLS-capable CLI tools and constructs
// read-only, credential-conscious probes for them.
package batchtest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	workspacePattern         = "embarass-batch-*"
	dockerGitVulnerableImage = "cgr.dev/chainguard/git@sha256:06119871a608d163eac2daddd0745582e457a29ee8402bd351c13f294ede30e1"
)

// Probe is one installed CLI and the safe command used to exercise its TLS
// trust. Arguments may contain paths inside Plan's temporary workspace.
type Probe struct {
	Name                 string
	Executable           string
	Arguments            []string
	Preview              string
	EnvironmentOverrides map[string]string
	Containerized        bool
	MayPullImage         bool
}

// Command returns the executable and arguments accepted by runner.Options.
func (probe Probe) Command() []string {
	command := make([]string, 0, len(probe.Arguments)+1)
	command = append(command, probe.Executable)
	return append(command, probe.Arguments...)
}

// Plan is a PATH preflight plus an isolated workspace for tools that need a
// cache. Call Cleanup after the probes finish.
type Plan struct {
	Probes      []Probe
	Unavailable []string
	workspace   string
}

// Discover inventories supported tools in PATH and prepares their probes.
func Discover() (Plan, error) {
	workspace, err := os.MkdirTemp("", workspacePattern)
	if err != nil {
		return Plan{}, fmt.Errorf("create batch workspace: %w", err)
	}
	// An explicit profile must exist even for unsigned AWS requests. Keep it
	// separate from the user's configuration and credential-process settings.
	if err := os.WriteFile(filepath.Join(workspace, "aws-config"), []byte("[default]\n"), 0o600); err != nil {
		return Plan{}, errors.Join(fmt.Errorf("prepare AWS batch configuration: %w", err), (Plan{workspace: workspace}).Cleanup())
	}
	// With file logging disabled, gcloud may open its database before creating
	// the configuration directory itself.
	if err := os.Mkdir(filepath.Join(workspace, "gcloud-config"), 0o700); err != nil {
		return Plan{}, errors.Join(fmt.Errorf("prepare gcloud batch configuration: %w", err), (Plan{workspace: workspace}).Cleanup())
	}
	if err := prepareEverydayProbes(workspace); err != nil {
		return Plan{}, errors.Join(err, (Plan{workspace: workspace}).Cleanup())
	}
	return discover(workspace, exec.LookPath), nil
}

// WorkingDirectory returns the isolated directory used for child processes.
func (plan Plan) WorkingDirectory() string {
	return plan.workspace
}

// Cleanup removes only the workspace created by Discover.
func (plan Plan) Cleanup() error {
	if plan.workspace == "" || filepath.Base(plan.workspace) == "." {
		return nil
	}
	if err := os.RemoveAll(plan.workspace); err != nil {
		return fmt.Errorf("remove batch workspace: %w", err)
	}
	return nil
}

type toolDefinition struct {
	name        string
	executables []string
	build       func(executable, workspace string) Probe
}

type pathLookup func(string) (string, error)

func discover(workspace string, lookup pathLookup) Plan {
	plan := Plan{workspace: workspace}
	for _, definition := range supportedTools() {
		executable := firstExecutable(definition.executables, lookup)
		if executable == "" {
			plan.Unavailable = append(plan.Unavailable, definition.name)
			continue
		}
		plan.Probes = append(plan.Probes, definition.build(executable, workspace))
	}
	return plan
}

func firstExecutable(candidates []string, lookup pathLookup) string {
	for _, candidate := range candidates {
		path, err := lookup(candidate)
		if err == nil {
			return path
		}
	}
	return ""
}

func supportedTools() []toolDefinition {
	return append([]toolDefinition{
		{
			name:        "curl",
			executables: []string{"curl"},
			build: func(executable, _ string) Probe {
				return Probe{
					Name:       "curl",
					Executable: executable,
					Arguments:  []string{"--silent", "--show-error", "https://example.com/"},
					Preview:    "curl --silent --show-error https://example.com/",
				}
			},
		},
		{
			name:        "git",
			executables: []string{"git"},
			build: func(executable, _ string) Probe {
				return Probe{
					Name:       "git",
					Executable: executable,
					Arguments: []string{
						"ls-remote",
						"https://github.com/actions/checkout.git",
						"HEAD",
					},
					Preview: "git ls-remote https://github.com/actions/checkout.git HEAD",
				}
			},
		},
		{
			name:        "gh",
			executables: []string{"gh"},
			build: func(executable, workspace string) Probe {
				return Probe{
					Name:       "gh",
					Executable: executable,
					Arguments:  []string{"api", "meta", "--silent"},
					Preview:    "gh api meta --silent",
					EnvironmentOverrides: map[string]string{
						// Force a public, non-interactive request without reading or
						// transmitting credentials from the user's gh configuration.
						"GH_CONFIG_DIR":                   filepath.Join(workspace, "gh-config"),
						"GH_HOST":                         "github.com",
						"GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
						"GH_NO_UPDATE_NOTIFIER":           "1",
						"GH_PROMPT_DISABLED":              "1",
						"GH_TELEMETRY":                    "0",
						"GH_TOKEN":                        "embarass-intentionally-invalid-token",
						"GITHUB_TOKEN":                    "embarass-intentionally-invalid-token",
					},
				}
			},
		},
		{
			name:        "wget",
			executables: []string{"wget"},
			build: func(executable, _ string) Probe {
				return Probe{
					Name:       "wget",
					Executable: executable,
					Arguments:  []string{"--spider", "--quiet", "https://example.com/"},
					Preview:    "wget --spider --quiet https://example.com/",
				}
			},
		},
		{
			name:        "npm",
			executables: []string{"npm"},
			build: func(executable, workspace string) Probe {
				cache := filepath.Join(workspace, "npm-cache")
				return Probe{
					Name:       "npm",
					Executable: executable,
					Arguments: []string{
						"--cache", cache,
						"--registry", "https://registry.npmjs.org/",
						"--ignore-scripts",
						"view", "is-number", "version",
					},
					Preview: "npm view is-number version --registry=https://registry.npmjs.org/",
				}
			},
		},
		{
			name:        "go",
			executables: []string{"go"},
			build: func(executable, workspace string) Probe {
				return Probe{
					Name:       "go",
					Executable: executable,
					Arguments:  []string{"list", "-m", "-versions", "golang.org/x/text@latest"},
					Preview:    "go list -m -versions golang.org/x/text@latest",
					EnvironmentOverrides: map[string]string{
						"GOCACHE":     filepath.Join(workspace, "go-build"),
						"GOMODCACHE":  filepath.Join(workspace, "go-mod"),
						"GOPROXY":     "https://proxy.golang.org",
						"GOTOOLCHAIN": "local",
					},
				}
			},
		},
		{
			name:        "pip",
			executables: []string{"pip3", "pip"},
			build: func(executable, _ string) Probe {
				return Probe{
					Name:       "pip",
					Executable: executable,
					Arguments: []string{
						"index", "versions", "pip",
						"--index-url", "https://pypi.org/simple",
						"--no-cache-dir",
						"--disable-pip-version-check",
					},
					Preview: "pip index versions pip --index-url=https://pypi.org/simple --no-cache-dir",
				}
			},
		},
		{
			name:        "docker",
			executables: []string{"docker"},
			build: func(executable, _ string) Probe {
				return Probe{
					Name:       "docker",
					Executable: executable,
					Arguments:  []string{"manifest", "inspect", "docker.io/library/alpine:latest"},
					Preview:    "docker manifest inspect docker.io/library/alpine:latest",
				}
			},
		},
		{
			name:        "docker/git",
			executables: []string{"docker"},
			build: func(executable, _ string) Probe {
				arguments := dockerGitArguments(runtime.GOOS)
				return Probe{
					Name:          "docker/git",
					Executable:    executable,
					Arguments:     arguments,
					Preview:       "docker " + strings.Join(arguments, " "),
					Containerized: true,
					MayPullImage:  true,
					EnvironmentOverrides: map[string]string{
						"GIT_TERMINAL_PROMPT": "0",
					},
				}
			},
		},
		{
			name:        "aws",
			executables: []string{"aws"},
			build: func(executable, workspace string) Probe {
				arguments := []string{
					"s3api", "head-bucket", "--bucket", "noaa-goes16",
					"--region", "us-east-1", "--endpoint-url", "https://s3.us-east-1.amazonaws.com",
					"--no-sign-request",
				}
				return Probe{
					Name:       "aws",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "aws " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"AWS_CONFIG_FILE":             filepath.Join(workspace, "aws-config"),
						"AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
						"AWS_PROFILE":                 "default",
						"AWS_DEFAULT_PROFILE":         "default",
						"AWS_EC2_METADATA_DISABLED":   "true",
						"AWS_CLI_AUTO_PROMPT":         "off",
						"AWS_PAGER":                   "",
						"AWS_MAX_ATTEMPTS":            "1",
					},
				}
			},
		},
		{
			name:        "gcloud",
			executables: []string{"gcloud"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"components", "list", "--quiet"}
				return Probe{
					Name:       "gcloud",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "gcloud " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"CLOUDSDK_CONFIG":                                 filepath.Join(workspace, "gcloud-config"),
						"CLOUDSDK_ACTIVE_CONFIG_NAME":                     "default",
						"CLOUDSDK_AUTH_DISABLE_CREDENTIALS":               "true",
						"CLOUDSDK_CORE_DISABLE_PROMPTS":                   "true",
						"CLOUDSDK_CORE_DISABLE_USAGE_REPORTING":           "true",
						"CLOUDSDK_CORE_DISABLE_FILE_LOGGING":              "true",
						"CLOUDSDK_CORE_CHECK_GCE_METADATA":                "false",
						"CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK": "true",
						"CLOUDSDK_COMPONENT_MANAGER_SNAPSHOT_URL":         "https://dl.google.com/dl/cloudsdk/channels/rapid/components-2.json",
					},
				}
			},
		},
		{
			name:        "cargo",
			executables: []string{"cargo"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"search", "serde", "--limit", "1", "--registry", "crates-io"}
				return Probe{
					Name:       "cargo",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "cargo " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"CARGO_HOME":                          filepath.Join(workspace, "cargo"),
						"CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
						"CARGO_NET_RETRY":                     "0",
					},
				}
			},
		},
		{
			name:        "uv",
			executables: []string{"uv"},
			build: func(executable, workspace string) Probe {
				arguments := []string{
					"--no-config", "--no-python-downloads", "pip", "compile",
					"https://raw.githubusercontent.com/psf/requests/main/requirements-dev.txt",
					"--no-build", "--no-deps", "--python-version", "3.12",
					"--keyring-provider", "disabled",
				}
				return Probe{
					Name:       "uv",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "uv " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"UV_CACHE_DIR":    filepath.Join(workspace, "uv-cache"),
						"UV_WORKING_DIR":  workspace,
						"UV_HTTP_RETRIES": "0",
						"NETRC":           os.DevNull,
					},
				}
			},
		},
		{
			name:        "kubectl",
			executables: []string{"kubectl"},
			build: func(executable, workspace string) Probe {
				arguments := []string{
					"--kubeconfig", os.DevNull, "--server", "https://example.com",
					"--cache-dir", filepath.Join(workspace, "kubectl-cache"),
					"get", "--raw=/version",
				}
				return Probe{
					Name:       "kubectl",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "kubectl " + strings.Join(arguments, " "),
				}
			},
		},
		{
			name:        "crane",
			executables: []string{"crane"},
			build: func(executable, workspace string) Probe {
				return Probe{
					Name:       "crane",
					Executable: executable,
					Arguments:  []string{"manifest", "registry.k8s.io/pause:3.10"},
					Preview:    "crane manifest registry.k8s.io/pause:3.10",
					EnvironmentOverrides: map[string]string{
						"DOCKER_CONFIG": filepath.Join(workspace, "crane-docker-config"),
					},
				}
			},
		},
	}, everydayTools()...)
}

func dockerGitArguments(goos string) []string {
	arguments := []string{
		"run",
		"--rm",
		"--pull=missing",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
	}
	if goos == "linux" {
		arguments = append(arguments, "--add-host=host.docker.internal:host-gateway")
	}
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy",
		"GIT_TERMINAL_PROMPT",
	} {
		arguments = append(arguments, "--env", key)
	}
	return append(
		arguments,
		dockerGitVulnerableImage,
		"ls-remote",
		"https://github.com/actions/checkout.git",
		"HEAD",
	)
}
