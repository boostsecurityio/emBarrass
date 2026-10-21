// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package runner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyEnvironment(t *testing.T) {
	t.Parallel()

	environment := proxyEnvironment([]string{
		"PATH=/usr/bin",
		"HTTPS_PROXY=http://old.example:8080",
		"no_proxy=github.com",
		"TOKEN=preserved",
	}, "http://127.0.0.1:43210")

	require.Contains(t, environment, "PATH=/usr/bin")
	require.Contains(t, environment, "TOKEN=preserved")
	require.NotContains(t, environment, "HTTPS_PROXY=http://old.example:8080")
	require.NotContains(t, environment, "no_proxy=github.com")

	for _, key := range controlledProxyVariables {
		expectedValue := "http://127.0.0.1:43210"
		if strings.EqualFold(key, "NO_PROXY") {
			expectedValue = ""
		}
		require.Contains(t, environment, key+"="+expectedValue)
	}
}

func TestChildEnvironmentAppliesSafeOverridesBeforeProxyControls(t *testing.T) {
	t.Parallel()

	environment, err := childEnvironment(
		[]string{
			"PATH=/usr/bin",
			"GOCACHE=/old-cache",
			"HTTPS_PROXY=http://old.example:8080",
		},
		map[string]string{
			"GOCACHE":    "/tmp/new-cache",
			"GOMODCACHE": "/tmp/new-mod-cache",
		},
		"http://127.0.0.1:43210",
	)

	require.NoError(t, err)
	require.Contains(t, environment, "PATH=/usr/bin")
	require.Contains(t, environment, "GOCACHE=/tmp/new-cache")
	require.Contains(t, environment, "GOMODCACHE=/tmp/new-mod-cache")
	require.NotContains(t, environment, "GOCACHE=/old-cache")
	require.NotContains(t, environment, "HTTPS_PROXY=http://old.example:8080")
	require.Contains(t, environment, "HTTPS_PROXY=http://127.0.0.1:43210")
}

func TestChildEnvironmentRejectsTrustAndProxyOverrides(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"SSL_CERT_FILE", "curl_ca_bundle", "HTTPS_PROXY"} {
		_, err := childEnvironment(
			[]string{"PATH=/usr/bin"},
			map[string]string{key: "/tmp/rigged"},
			"http://127.0.0.1:43210",
		)
		require.ErrorContains(t, err, "would alter proxy or TLS trust")
	}
}

func TestMergeEnvironmentOverridesLetsCallerReplaceDefaults(t *testing.T) {
	t.Parallel()

	merged := mergeEnvironmentOverrides(
		map[string]string{"GH_TOKEN": "throwaway", "GH_HOST": "github.com"},
		map[string]string{"GH_TOKEN": "batch-throwaway", "GH_CONFIG_DIR": "/tmp/gh"},
	)

	require.Equal(t, map[string]string{
		"GH_TOKEN":      "batch-throwaway",
		"GH_HOST":       "github.com",
		"GH_CONFIG_DIR": "/tmp/gh",
	}, merged)
}

func TestGHCompatibilityEnvironmentReplacesInheritedCredentials(t *testing.T) {
	t.Parallel()

	environment, err := childEnvironment(
		[]string{"GH_TOKEN=user-secret", "GITHUB_TOKEN=another-secret"},
		compatibilityEnvironment([]string{"gh", "api", "meta", "--silent"}),
		"http://127.0.0.1:1234",
	)
	require.NoError(t, err)
	require.Contains(t, environment, "GH_TOKEN=embarass-intentionally-invalid-token")
	require.Contains(t, environment, "GITHUB_TOKEN=embarass-intentionally-invalid-token")
	require.NotContains(t, environment, "GH_TOKEN=user-secret")
	require.NotContains(t, environment, "GITHUB_TOKEN=another-secret")
}

func TestChildEnvironmentRejectsMalformedOverrides(t *testing.T) {
	t.Parallel()

	_, err := childEnvironment(
		[]string{"PATH=/usr/bin"},
		map[string]string{"BAD=KEY": "value"},
		"http://127.0.0.1:43210",
	)
	require.ErrorContains(t, err, "invalid child environment override")

	_, err = childEnvironment(
		[]string{"PATH=/usr/bin"},
		map[string]string{"VALID_KEY": "bad\x00value"},
		"http://127.0.0.1:43210",
	)
	require.ErrorContains(t, err, "contains a NUL byte")
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	require.Equal(t, 0, exitCode(nil))
	require.Equal(t, -1, exitCode(assertionError{}))
}

type assertionError struct{}

func (assertionError) Error() string { return "test error" }
