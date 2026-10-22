// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package batchtest

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed probes/node.cjs
var nodeProbeScript []byte

func prepareEverydayProbes(workspace string) error {
	files := map[string][]byte{
		"node-probe.cjs":    nodeProbeScript,
		"NuGet.Config":      []byte(`<configuration><packageSources><clear /></packageSources></configuration>`),
		"composer.json":     []byte(`{"repositories":[{"type":"composer","url":"https://repo.packagist.org"},{"packagist.org":false}]}`),
		"npm-user-config":   {},
		"npm-global-config": {},
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(workspace, name), contents, 0o600); err != nil {
			return fmt.Errorf("prepare batch probe file %s: %w", name, err)
		}
	}
	return nil
}

func everydayTools() []toolDefinition {
	return []toolDefinition{
		{
			name:        "python",
			executables: []string{"python3", "python"},
			build: func(executable, _ string) Probe {
				const script = "import sys, urllib.request; urllib.request.urlopen(sys.argv[1]).close()"
				return Probe{
					Name:       "python",
					Executable: executable,
					Arguments:  []string{"-I", "-c", script, "https://example.com/"},
					Preview:    "python3 -I -c '" + script + "' https://example.com/",
				}
			},
		},
		{
			name:        "node",
			executables: []string{"node", "nodejs"},
			build: func(executable, workspace string) Probe {
				arguments := []string{filepath.Join(workspace, "node-probe.cjs"), "https://example.com/"}
				return Probe{
					Name:       "node",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "node " + strings.Join(arguments, " "),
				}
			},
		},
		{
			name:        "gem",
			executables: []string{"gem"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"search", "rake", "--exact", "--remote", "--norc", "--clear-sources", "--source", "https://rubygems.org/"}
				return Probe{
					Name:       "gem",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "gem " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"GEM_HOME":       filepath.Join(workspace, "gem-home"),
						"GEM_PATH":       filepath.Join(workspace, "gem-home"),
						"GEM_SPEC_CACHE": filepath.Join(workspace, "gem-cache"),
					},
				}
			},
		},
		{
			name:        "dotnet",
			executables: []string{"dotnet"},
			build: func(executable, workspace string) Probe {
				arguments := []string{
					"package", "search", "Newtonsoft.Json", "--exact-match",
					"--source", "https://api.nuget.org/v3/index.json",
					"--configfile", filepath.Join(workspace, "NuGet.Config"),
				}
				return Probe{
					Name:       "dotnet",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "dotnet " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"DOTNET_CLI_HOME":                           filepath.Join(workspace, "dotnet-home"),
						"DOTNET_CLI_TELEMETRY_OPTOUT":               "1",
						"DOTNET_SKIP_FIRST_TIME_EXPERIENCE":         "1",
						"DOTNET_GENERATE_ASPNET_CERTIFICATE":        "false",
						"DOTNET_ADD_GLOBAL_TOOLS_TO_PATH":           "false",
						"DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
						"NUGET_PACKAGES":                            filepath.Join(workspace, "nuget-packages"),
						"NUGET_HTTP_CACHE_PATH":                     filepath.Join(workspace, "nuget-cache"),
						"NUGET_PLUGINS_CACHE_PATH":                  filepath.Join(workspace, "nuget-plugins"),
					},
				}
			},
		},
		{
			name:        "pnpm",
			executables: []string{"pnpm"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"view", "is-number", "version", "--registry=https://registry.npmjs.org/"}
				return Probe{
					Name:       "pnpm",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "pnpm " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"NPM_CONFIG_USERCONFIG":           filepath.Join(workspace, "npm-user-config"),
						"NPM_CONFIG_GLOBALCONFIG":         filepath.Join(workspace, "npm-global-config"),
						"NPM_CONFIG_CACHE":                filepath.Join(workspace, "pnpm-cache"),
						"NPM_CONFIG_FETCH_RETRIES":        "0",
						"NPM_CONFIG_UPDATE_NOTIFIER":      "false",
						"PNPM_HOME":                       filepath.Join(workspace, "pnpm-home"),
						"XDG_CACHE_HOME":                  filepath.Join(workspace, "pnpm-xdg-cache"),
						"XDG_CONFIG_HOME":                 filepath.Join(workspace, "pnpm-xdg-config"),
						"XDG_DATA_HOME":                   filepath.Join(workspace, "pnpm-xdg-data"),
						"XDG_STATE_HOME":                  filepath.Join(workspace, "pnpm-xdg-state"),
						"COREPACK_HOME":                   corepackHome(workspace),
						"COREPACK_ENABLE_NETWORK":         "0",
						"COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
					},
				}
			},
		},
		{
			name:        "httpie",
			executables: []string{"http", "https"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"--ignore-stdin", "--ignore-netrc", "--headers", "HEAD", "https://example.com/"}
				return Probe{
					Name:       "httpie",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "http " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"HTTPIE_CONFIG_DIR": filepath.Join(workspace, "httpie-config"),
					},
				}
			},
		},
		{
			name:        "helm",
			executables: []string{"helm"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"show", "chart", "hello-world", "--repo", "https://helm.github.io/examples"}
				return Probe{
					Name:       "helm",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "helm " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"HELM_CACHE_HOME":        filepath.Join(workspace, "helm-cache"),
						"HELM_CONFIG_HOME":       filepath.Join(workspace, "helm-config"),
						"HELM_DATA_HOME":         filepath.Join(workspace, "helm-data"),
						"HELM_REPOSITORY_CONFIG": filepath.Join(workspace, "helm-config", "repositories.yaml"),
						"HELM_REPOSITORY_CACHE":  filepath.Join(workspace, "helm-cache", "repository"),
						"HELM_REGISTRY_CONFIG":   filepath.Join(workspace, "helm-config", "registry.json"),
						"HELM_PLUGINS":           filepath.Join(workspace, "helm-plugins"),
						"KUBECONFIG":             os.DevNull,
					},
				}
			},
		},
		{
			name:        "composer",
			executables: []string{"composer"},
			build: func(executable, workspace string) Probe {
				arguments := []string{"--no-plugins", "--no-scripts", "--no-interaction", "--no-cache", "show", "--all", "symfony/console"}
				return Probe{
					Name:       "composer",
					Executable: executable,
					Arguments:  arguments,
					Preview:    "composer " + strings.Join(arguments, " "),
					EnvironmentOverrides: map[string]string{
						"COMPOSER":           filepath.Join(workspace, "composer.json"),
						"COMPOSER_HOME":      filepath.Join(workspace, "composer-home"),
						"COMPOSER_CACHE_DIR": filepath.Join(workspace, "composer-cache"),
						"COMPOSER_AUTH":      "{}",
					},
				}
			},
		},
	}
}

// Resolve Corepack's executable cache before XDG_CACHE_HOME is isolated. This
// follows nodejs/corepack's sources/folderUtils.ts, including its Windows
// fallback. Package-manager downloads remain disabled for the probe.
func corepackHome(workspace string) string {
	if home, ok := os.LookupEnv("COREPACK_HOME"); ok {
		return home
	}
	for _, key := range []string{"XDG_CACHE_HOME", "LOCALAPPDATA"} {
		if cache, ok := os.LookupEnv(key); ok {
			return filepath.Join(cache, "node", "corepack")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Without a home, leave Corepack an empty isolated cache. It will
		// fail without bootstrapping instead of guessing a user's cache.
		return filepath.Join(workspace, "corepack")
	}
	cache := ".cache"
	if runtime.GOOS == "windows" {
		cache = filepath.Join("AppData", "Local")
	}
	return filepath.Join(home, cache, "node", "corepack")
}
