// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package certforge

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	testCases := []struct {
		name        string
		host        string
		chain       Chain
		chainLength int
	}{
		{name: "Sectigo DNS name", host: "github.com", chain: ChainSectigo, chainLength: 2},
		{name: "eMudhra DNS name", host: "github.com", chain: ChainEMSign, chainLength: 3},
		{name: "IP address", host: "127.0.0.1", chain: ChainSectigo, chainLength: 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			forge, newErr := New(Options{
				Now:   func() time.Time { return fixedNow },
				Chain: testCase.chain,
			})
			require.NoError(t, newErr)
			certificate, certErr := forge.Certificate(testCase.host)
			require.NoError(t, certErr)
			require.Len(t, certificate.Certificate, testCase.chainLength)

			leaf, parseErr := x509.ParseCertificate(certificate.Certificate[0])
			require.NoError(t, parseErr)
			require.NoError(t, leaf.VerifyHostname(testCase.host))
			require.NoError(t, leaf.CheckSignatureFrom(forge.intermediate))
			require.Equal(t, fixedNow.Add(-5*time.Minute), leaf.NotBefore)
		})
	}
}

func TestCertificateRejectedByPatchedGoVerifier(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	forge, err := New(Options{Now: func() time.Time { return fixedNow }})
	require.NoError(t, err)
	certificate, err := forge.Certificate("github.com")
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	compromisedIssuer, err := x509.ParseCertificate(certificate.Certificate[1])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(compromisedIssuer)

	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:     "github.com",
		Roots:       roots,
		CurrentTime: fixedNow,
	})
	require.Error(t, err, "Go 1.27.3 and later must reject the compromised eMudhra SPKI")
}

func TestNewRejectsUnsupportedChain(t *testing.T) {
	t.Parallel()

	_, err := New(Options{Chain: Chain("unknown")})
	require.Error(t, err)
}

func TestCertificateRejectsInvalidHost(t *testing.T) {
	t.Parallel()

	forge, err := New(Options{
		Now: func() time.Time {
			return time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
		},
	})
	require.NoError(t, err)

	_, err = forge.Certificate("bad.example\r\nInjected: yes")
	require.Error(t, err)
}
