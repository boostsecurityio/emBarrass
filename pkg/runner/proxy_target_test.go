// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyTargetAddresses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		target         ProxyTarget
		listener       string
		wantListenHost string
		wantAdvertised string
	}{
		{
			name:           "host command",
			target:         ProxyTargetHost,
			listener:       "127.0.0.1:43210",
			wantListenHost: "127.0.0.1",
			wantAdvertised: "127.0.0.1:43210",
		},
		{
			name:           "docker container",
			target:         ProxyTargetDockerContainer,
			listener:       "[::]:43210",
			wantListenHost: "0.0.0.0",
			wantAdvertised: "host.docker.internal:43210",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			listenHost, err := proxyListenHost(testCase.target)
			require.NoError(t, err)
			require.Equal(t, testCase.wantListenHost, listenHost)

			advertised, err := advertisedProxyAddress(testCase.listener, testCase.target)
			require.NoError(t, err)
			require.Equal(t, testCase.wantAdvertised, advertised)
		})
	}
}

func TestProxyTargetRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, err := proxyListenHost(ProxyTarget(99))
	require.ErrorContains(t, err, "unsupported proxy target")

	_, err = advertisedProxyAddress("not-an-address", ProxyTargetHost)
	require.ErrorContains(t, err, "parse interceptor address")

	_, err = advertisedProxyAddress("127.0.0.1:1234", ProxyTarget(99))
	require.ErrorContains(t, err, "unsupported proxy target")
}
