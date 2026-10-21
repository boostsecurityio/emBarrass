// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package runner

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// CommandAdjustment identifies a transparent compatibility adjustment made to
// keep a wrapped command on the transport the user requested.
type CommandAdjustment string

const (
	// AdjustmentGitHTTPSPinned prevents Git url.*.insteadOf rules from changing
	// an explicit HTTPS URL into SSH before the interceptor can observe it.
	AdjustmentGitHTTPSPinned CommandAdjustment = "git_https_transport_pinned"
	// AdjustmentGHCredentialsIsolated prevents the documented public GitHub CLI
	// probe from reading or transmitting the user's stored credentials.
	AdjustmentGHCredentialsIsolated CommandAdjustment = "gh_credentials_isolated"
)

// PrepareCommand applies narrow, disclosed compatibility behavior for known
// probes. It preserves explicit Git HTTPS URLs and identifies the public gh
// metadata probe whose credentials Run isolates before launch.
func PrepareCommand(command []string) ([]string, []CommandAdjustment) {
	prepared := append([]string(nil), command...)
	adjustments := make([]CommandAdjustment, 0, 1)
	if isGHMetaProbe(command) {
		adjustments = append(adjustments, AdjustmentGHCredentialsIsolated)
	}
	if len(command) == 0 || !isGitExecutable(command[0]) {
		return prepared, adjustments
	}

	pinnedURLs := make([]string, 0, 1)
	seen := make(map[string]struct{})
	for index, argument := range command[1:] {
		value, identity, ok := pinHTTPSURL(argument)
		if !ok {
			continue
		}
		prepared[index+1] = value
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		pinnedURLs = append(pinnedURLs, identity)
	}
	if len(pinnedURLs) == 0 {
		return prepared, adjustments
	}

	gitOptions := make([]string, 0, len(pinnedURLs)*2)
	adjusted := false
	for _, identity := range pinnedURLs {
		rule := "url." + identity + ".insteadOf=" + identity
		if hasGitConfigOverride(command, rule) {
			continue
		}
		gitOptions = append(gitOptions, "-c", rule)
		adjusted = true
	}
	if !adjusted {
		return prepared, adjustments
	}

	arguments := prepared[1:]
	result := make([]string, 0, len(command)+len(gitOptions))
	result = append(result, command[0])
	result = append(result, gitOptions...)
	result = append(result, arguments...)
	return result, append(adjustments, AdjustmentGitHTTPSPinned)
}

func compatibilityEnvironment(command []string) map[string]string {
	if !isGHMetaProbe(command) {
		return nil
	}
	return map[string]string{
		"GH_HOST":                         "github.com",
		"GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
		"GH_NO_UPDATE_NOTIFIER":           "1",
		"GH_PROMPT_DISABLED":              "1",
		"GH_TELEMETRY":                    "0",
		"GH_TOKEN":                        "embarass-intentionally-invalid-token",
		"GITHUB_TOKEN":                    "embarass-intentionally-invalid-token",
	}
}

func isGHMetaProbe(command []string) bool {
	if len(command) < 3 || len(command) > 4 || !isGHExecutable(command[0]) {
		return false
	}
	if command[1] != "api" || strings.TrimPrefix(command[2], "/") != "meta" {
		return false
	}
	return len(command) == 3 || command[3] == "--silent"
}

func isGitExecutable(executable string) bool {
	name := strings.ToLower(filepath.Base(executable))
	return name == "git" || name == "git.exe"
}

func isGHExecutable(executable string) bool {
	name := strings.ToLower(filepath.Base(executable))
	return name == "gh" || name == "gh.exe"
}

func pinHTTPSURL(argument string) (string, string, bool) {
	parsed, err := url.Parse(argument)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return "", "", false
	}
	if parsed.Port() == "" {
		parsed.Host = net.JoinHostPort(parsed.Hostname(), "443")
	}
	pinned := parsed.String()
	identity := *parsed
	identity.RawQuery = ""
	identity.ForceQuery = false
	identity.Fragment = ""
	identity.RawFragment = ""
	return pinned, identity.String(), true
}

func hasGitConfigOverride(command []string, rule string) bool {
	for index := 1; index+1 < len(command); index++ {
		if command[index] == "-c" && command[index+1] == rule {
			return true
		}
	}
	return false
}
