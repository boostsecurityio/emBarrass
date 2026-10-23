// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package repair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ordinaryRoot(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func affectedRoot(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".pem")
	require.NoError(t, err)
	return data
}

func fixtureBundle(t *testing.T) []byte {
	t.Helper()
	data := []byte("# enterprise roots must survive byte-for-byte\n")
	data = append(data, ordinaryRoot(t, "Enterprise test root")...)
	data = append(data, affectedRoot(t, "aaa")...)
	return append(data, affectedRoot(t, "emsign")...)
}

func TestInspectRemovesExactCertificatesPreservingOtherBytes(t *testing.T) {
	t.Parallel()
	trusted := ordinaryRoot(t, "Enterprise test root")
	before := "### metadata\r\n"
	between := "\r\n# not a trust anchor\n"
	after := "\n# end of bundle\n"
	data := append([]byte(before), trusted...)
	data = append(data, []byte(between)...)
	data = append(data, affectedRoot(t, "aaa")...)
	data = append(data, affectedRoot(t, "emsign")...)
	data = append(data, []byte(after)...)
	plan, err := inspect(data)
	require.NoError(t, err)
	require.Len(t, plan.Removed, 2)
	require.Equal(t, 3, plan.Certificates)
	require.Equal(t, before+string(trusted)+between+"\n\n"+after, string(plan.replacement))
	again, err := inspect(plan.replacement)
	require.NoError(t, err)
	require.Empty(t, again.Removed)
	require.Equal(t, again.original, again.replacement)
}

func TestInspectRejectsMalformedAndAmbiguousBundles(t *testing.T) {
	t.Parallel()
	valid := ordinaryRoot(t, "unrelated")
	for name, data := range map[string][]byte{
		"empty":                      {},
		"no survivors":               affectedRoot(t, "aaa"),
		"truncated":                  append(append([]byte{}, valid...), []byte("-----BEGIN CERTIFICATE-----\nbroken")...),
		"stray end":                  append(append([]byte{}, valid...), []byte("-----END CERTIFICATE-----")...),
		"malformed before valid":     append([]byte("-----BEGIN CERTIFICATE-----\nbroken\n"), valid...),
		"wrong certificate type":     append(append([]byte{}, valid...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})...),
		"same subject different key": append(append([]byte{}, valid...), ordinaryRoot(t, "AAA Certificate Services")...),
	} {
		t.Run(name, func(t *testing.T) { _, err := inspect(data); require.Error(t, err) })
	}
}

func TestInspectRemovesDuplicateAffectedCertificates(t *testing.T) {
	t.Parallel()
	data := append(fixtureBundle(t), affectedRoot(t, "aaa")...)
	plan, err := inspect(data)
	require.NoError(t, err)
	require.Len(t, plan.Removed, 3)
	require.Equal(t, 4, plan.Certificates)
}

func TestLegacyNegativeSerialRootIsPreservedExactly(t *testing.T) {
	t.Parallel()
	legacy := affectedRoot(t, "legacy-negative-serial")
	data := append(append([]byte{}, legacy...), affectedRoot(t, "aaa")...)
	plan, err := inspect(data)
	require.NoError(t, err)
	require.Len(t, plan.Removed, 1)
	require.Equal(t, string(legacy)+"\n", string(plan.replacement))
	block, _ := pem.Decode(legacy)
	before := append([]byte{}, block.Bytes...)
	_, err = parseBundleCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, before, block.Bytes, "compatibility validation must never mutate input DER")
}
