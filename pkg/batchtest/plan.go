// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package batchtest discovers installed TLS-capable CLI tools and constructs
// read-only, credential-conscious probes for them.
package batchtest

import (
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
	return []toolDefinition{
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
	}
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
