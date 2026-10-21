// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package intercept

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/stretchr/testify/require"
)

func TestServerObservesAcceptedForgedTLS(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	forge, err := certforge.New(certforge.Options{Now: func() time.Time { return fixedNow }})
	require.NoError(t, err)
	server := newPipeServer(forge)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverConnection, connection := net.Pipe()
	t.Cleanup(func() { _ = connection.Close() })
	go server.handleConnection(ctx, serverConnection)
	_, err = fmt.Fprintf(connection, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nProxy-Authorization: %s\r\n\r\n", basicAuthorization("test-token"))
	require.NoError(t, err)

	reader := bufio.NewReader(connection)
	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1 200 Connection Established\r\n", response)
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	connectObservation := awaitObservation(t, server.Observations())
	require.Equal(t, ObservationConnect, connectObservation.Kind)

	tlsConnection := tls.Client(connection, &tls.Config{
		// This client intentionally models a vulnerable verifier. Go 1.27.3's
		// normal verifier rejects the compromised eMudhra SPKI even when it is
		// explicitly trusted, so it cannot exercise the server's accepted path.
		InsecureSkipVerify: true, //nolint:gosec -- deliberately simulate a vulnerable client in this test
		ServerName:         "github.com",
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) < 2 {
				return fmt.Errorf("expected forged leaf and issuer, got %d certificates", len(state.PeerCertificates))
			}
			leaf, issuer := state.PeerCertificates[0], state.PeerCertificates[1]
			if err := leaf.VerifyHostname("github.com"); err != nil {
				return fmt.Errorf("verify forged leaf hostname: %w", err)
			}
			if err := leaf.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf("verify forged leaf signature: %w", err)
			}
			return nil
		},
	})
	require.NoError(t, tlsConnection.Handshake())

	handshakeObservation := awaitObservation(t, server.Observations())
	require.Equal(t, ObservationHandshake, handshakeObservation.Kind)
	_, err = tlsConnection.Write([]byte{'G'})
	require.NoError(t, err)

	acceptedObservation := awaitObservation(t, server.Observations())
	require.Equal(t, ObservationAccepted, acceptedObservation.Kind)
	require.Equal(t, "github.com", acceptedObservation.Host)
}

func TestServerObservesRejectedForgedTLS(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	forge, err := certforge.New(certforge.Options{Now: func() time.Time { return fixedNow }})
	require.NoError(t, err)
	server := newPipeServer(forge)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverConnection, connection := net.Pipe()
	t.Cleanup(func() { _ = connection.Close() })
	go server.handleConnection(ctx, serverConnection)
	_, err = fmt.Fprintf(connection, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nProxy-Authorization: %s\r\n\r\n", basicAuthorization("test-token"))
	require.NoError(t, err)
	reader := bufio.NewReader(connection)
	_, err = reader.ReadString('\n')
	require.NoError(t, err)
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	connectObservation := awaitObservation(t, server.Observations())
	require.Equal(t, ObservationConnect, connectObservation.Kind)

	tlsConnection := tls.Client(connection, &tls.Config{
		RootCAs:    x509.NewCertPool(),
		ServerName: "github.com",
		MinVersion: tls.VersionTLS12,
	})
	require.Error(t, tlsConnection.Handshake())

	rejectedObservation := awaitObservation(t, server.Observations())
	require.Equal(t, ObservationRejected, rejectedObservation.Kind)
}

func TestConnectHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		target  string
		host    string
		wantErr bool
	}{
		{name: "DNS", target: "example.com:443", host: "example.com"},
		{name: "IPv6", target: "[::1]:443", host: "::1"},
		{name: "missing port", target: "example.com", wantErr: true},
		{name: "empty host", target: ":443", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			host, err := connectHost(testCase.target)
			if testCase.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.host, host)
		})
	}
}

func TestProxyAuthorization(t *testing.T) {
	t.Parallel()

	require.Equal(t, "Basic ZW1iYXJhc3M6dGVzdC10b2tlbg==", basicAuthorization("test-token"))
}

func TestServerRequiresProxyAuthorization(t *testing.T) {
	t.Parallel()

	server := newPipeServer(nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverConnection, connection := net.Pipe()
	t.Cleanup(func() { _ = connection.Close() })
	go server.handleConnection(ctx, serverConnection)

	_, err := fmt.Fprint(connection, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
	require.NoError(t, err)
	status, err := bufio.NewReader(connection).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1 407 Proxy Authentication Required\r\n", status)

	select {
	case observation := <-server.Observations():
		t.Fatalf("unauthorized request produced an observation: %#v", observation)
	default:
	}
}

func TestListenAddressUsesRequestedHost(t *testing.T) {
	t.Parallel()

	require.Equal(t, "0.0.0.0:0", listenAddress("0.0.0.0"))
}

func TestListenAddressDefaultsToLoopback(t *testing.T) {
	t.Parallel()

	require.Equal(t, "127.0.0.1:0", listenAddress(""))
}

func awaitObservation(t *testing.T, observations <-chan Observation) Observation {
	t.Helper()
	select {
	case observation := <-observations:
		return observation
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for proxy observation")
		return Observation{}
	}
}

func newPipeServer(source CertificateSource) *Server {
	return &Server{
		source:            source,
		connectionTimeout: time.Second,
		authorization:     basicAuthorization("test-token"),
		observations:      make(chan Observation, observationBuffer),
	}
}
