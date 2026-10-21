// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package runner

import (
	"fmt"
	"strings"
)

var controlledProxyVariables = []string{
	"HTTP_PROXY",
	"http_proxy",
	"HTTPS_PROXY",
	"https_proxy",
	"ALL_PROXY",
	"all_proxy",
	"NO_PROXY",
	"no_proxy",
}

// These variables can bypass or replace the native trust decision that
// emBarrass exists to measure. EnvironmentOverrides rejects them so callers
// can isolate caches and working files without accidentally rigging the test.
var controlledTrustVariables = []string{
	"CURL_CA_BUNDLE",
	"GIT_SSL_NO_VERIFY",
	"GIT_SSL_CAINFO",
	"GOINSECURE",
	"NODE_EXTRA_CA_CERTS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
	"NPM_CONFIG_CAFILE",
	"NPM_CONFIG_STRICT_SSL",
	"PIP_CERT",
	"PYTHONHTTPSVERIFY",
	"REQUESTS_CA_BUNDLE",
	"SSL_CERT_DIR",
	"SSL_CERT_FILE",
}

func childEnvironment(
	environ []string,
	overrides map[string]string,
	proxyURL string,
) ([]string, error) {
	blocked := make(map[string]struct{}, len(controlledProxyVariables)+len(controlledTrustVariables))
	for _, key := range append(controlledProxyVariables, controlledTrustVariables...) {
		blocked[strings.ToUpper(key)] = struct{}{}
	}

	keys := make(map[string]struct{}, len(overrides))
	for key, value := range overrides {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return nil, fmt.Errorf("invalid child environment override %q", key)
		}
		if strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("child environment override %q contains a NUL byte", key)
		}
		normalized := strings.ToUpper(key)
		if _, reserved := blocked[normalized]; reserved {
			return nil, fmt.Errorf("child environment override %q would alter proxy or TLS trust", key)
		}
		keys[normalized] = struct{}{}
	}

	merged := make([]string, 0, len(environ)+len(overrides))
	for _, entry := range environ {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, replace := keys[strings.ToUpper(key)]; replace {
			continue
		}
		merged = append(merged, entry)
	}
	for key, value := range overrides {
		merged = append(merged, key+"="+value)
	}
	return proxyEnvironment(merged, proxyURL), nil
}

func proxyEnvironment(environ []string, proxyURL string) []string {
	controlled := make(map[string]struct{}, len(controlledProxyVariables))
	for _, key := range controlledProxyVariables {
		controlled[strings.ToUpper(key)] = struct{}{}
	}

	result := make([]string, 0, len(environ)+len(controlledProxyVariables))
	for _, entry := range environ {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, replace := controlled[strings.ToUpper(key)]; replace {
			continue
		}
		result = append(result, entry)
	}

	for _, key := range controlledProxyVariables {
		value := proxyURL
		if strings.EqualFold(key, "NO_PROXY") {
			value = ""
		}
		result = append(result, key+"="+value)
	}
	return result
}
