// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package intercept implements an authenticated HTTPS CONNECT interceptor.
// It listens on loopback by default and can opt into a caller-supplied host
// address for isolated network namespaces such as containers.
package intercept

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultConnectionTimeout = 10 * time.Second
	maxProxyRequestBytes     = 64 << 10
	observationBuffer        = 32
)

// ObservationKind identifies how far a wrapped connection progressed.
type ObservationKind string

const (
	// ObservationConnect means the child asked the proxy for an HTTPS tunnel.
	ObservationConnect ObservationKind = "connect"
	// ObservationRejected means the forged TLS handshake did not complete.
	ObservationRejected ObservationKind = "rejected"
	// ObservationHandshake means the child completed TLS with the forged chain.
	ObservationHandshake ObservationKind = "handshake"
	// ObservationAccepted means the child sent application data over forged TLS.
	ObservationAccepted ObservationKind = "accepted"
	// ObservationUnsupported means the child sent traffic other than CONNECT.
	ObservationUnsupported ObservationKind = "unsupported"
)

// Observation reports a privacy-preserving connection milestone. It never
// contains request paths, headers, bodies, or credentials.
type Observation struct {
	Kind ObservationKind
	Host string
}

// CertificateSource creates a forged certificate for a requested hostname.
type CertificateSource interface {
	Certificate(host string) (tls.Certificate, error)
}

// Options configures a Server.
type Options struct {
	Source             CertificateSource
	ConnectionTimeout  time.Duration
	AuthorizationToken string
	ListenHost         string
}

// Server is an authenticated HTTPS CONNECT interceptor.
type Server struct {
	listener          net.Listener
	source            CertificateSource
	connectionTimeout time.Duration
	authorization     string
	observations      chan Observation
	closeOnce         sync.Once
}

// New binds a listener and returns a ready interceptor. The listener defaults
// to loopback unless ListenHost explicitly selects another local interface.
func New(options Options) (*Server, error) {
	if options.Source == nil {
		return nil, errors.New("certificate source is required")
	}
	if options.AuthorizationToken == "" {
		return nil, errors.New("proxy authorization token is required")
	}
	connectionTimeout := options.ConnectionTimeout
	if connectionTimeout <= 0 {
		connectionTimeout = defaultConnectionTimeout
	}

	address := listenAddress(options.ListenHost)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}

	return &Server{
		listener:          listener,
		source:            options.Source,
		connectionTimeout: connectionTimeout,
		authorization:     basicAuthorization(options.AuthorizationToken),
		observations:      make(chan Observation, observationBuffer),
	}, nil
}

func listenAddress(host string) string {
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, "0")
}

// Address returns the bound host and port to use as an HTTP proxy.
func (s *Server) Address() string {
	return s.listener.Addr().String()
}

// Observations returns connection milestones emitted by the interceptor.
func (s *Server) Observations() <-chan Observation {
	return s.observations
}

// Serve accepts connections until the context is canceled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer handlers.Wait()

	for {
		connection, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept proxy connection: %w", err)
		}

		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.handleConnection(ctx, connection)
		}()
	}
}

// Close stops the listener. It is safe to call more than once.
func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = fmt.Errorf("close proxy listener: %w", err)
		}
	})
	return closeErr
}

func (s *Server) handleConnection(ctx context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(s.connectionTimeout)); err != nil {
		return
	}

	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(connection, maxProxyRequestBytes)))
	if err != nil {
		return
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	if !s.authorized(request) {
		_, _ = connection.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"emBarrass\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if request.Method != http.MethodConnect {
		s.observe(ctx, Observation{Kind: ObservationUnsupported})
		_, _ = connection.Write([]byte("HTTP/1.1 400 HTTPS CONNECT required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	host, err := connectHost(request.Host)
	if err != nil {
		_, _ = connection.Write([]byte("HTTP/1.1 400 Invalid CONNECT target\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	s.observe(ctx, Observation{Kind: ObservationConnect, Host: host})

	certificate, err := s.source.Certificate(host)
	if err != nil {
		s.observe(ctx, Observation{Kind: ObservationRejected, Host: host})
		return
	}
	if _, err = connection.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConnection := tls.Server(connection, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		s.observe(ctx, Observation{Kind: ObservationRejected, Host: host})
		return
	}

	s.observe(ctx, Observation{Kind: ObservationHandshake, Host: host})

	// Read only the first application byte. This proves that application-level
	// policy accepted the TLS session without retaining headers, bodies, paths,
	// or credentials.
	var firstByte [1]byte
	bytesRead, _ := tlsConnection.Read(firstByte[:])
	if bytesRead == 0 {
		return
	}
	s.observe(ctx, Observation{Kind: ObservationAccepted, Host: host})
}

func (s *Server) authorized(request *http.Request) bool {
	provided := request.Header.Get("Proxy-Authorization")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.authorization)) == 1
}

func basicAuthorization(token string) string {
	credentials := "embarass:" + token
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

func (s *Server) observe(ctx context.Context, observation Observation) {
	select {
	case s.observations <- observation:
	case <-ctx.Done():
	}
}

func connectHost(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("parse CONNECT target %q: %w", target, err)
	}
	if host == "" || port == "" || strings.ContainsAny(host, "\x00\r\n") {
		return "", fmt.Errorf("invalid CONNECT target %q", target)
	}
	return host, nil
}
