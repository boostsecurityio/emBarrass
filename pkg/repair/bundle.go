// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package repair implements narrowly scoped, reversible system CA repairs.
package repair

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// BundlePath is the sole production repair target. /etc is a macOS symlink.
const BundlePath = "/private/etc/ssl/cert.pem"

// Root identifies an exact certificate, rather than a comment or subject name.
type Root struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

var affectedRoots = []Root{
	{"AAA Certificate Services", "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"},
	{"emSign ECC Root CA - G3", "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"},
}

// Plan is an immutable snapshot. Apply checks its input hash again under a lock.
type Plan struct {
	Path         string
	BundlePath   string
	Platform     string
	Refresh      string
	BeforeSHA256 string
	AfterSHA256  string
	Certificates int
	Removed      []Root
	original     []byte
	replacement  []byte
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// inspect parses every PEM block and preserves all bytes outside removed blocks.
// Apple includes descriptive text between certificates; it is not trust data.
func inspect(data []byte) (Plan, error) {
	plan := Plan{BeforeSHA256: digest(data), original: bytes.Clone(data)}
	rest := data
	for len(rest) > 0 {
		start := bytes.Index(rest, []byte("-----BEGIN "))
		if start < 0 {
			if bytes.Contains(rest, []byte("-----END ")) {
				return Plan{}, errors.New("unmatched PEM end marker")
			}
			plan.replacement = append(plan.replacement, rest...)
			break
		}
		prefix := rest[:start]
		if bytes.Contains(prefix, []byte("-----END ")) {
			return Plan{}, errors.New("unmatched PEM end marker")
		}
		end := bytes.Index(rest[start:], []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return Plan{}, errors.New("unterminated or unsupported PEM block")
		}
		end += start + len("-----END CERTIFICATE-----")
		encoded := rest[start:end]
		if bytes.Count(encoded, []byte("-----BEGIN ")) != 1 {
			return Plan{}, errors.New("nested or malformed PEM block")
		}
		block, trailing := pem.Decode(encoded)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(trailing) != 0 {
			return Plan{}, errors.New("malformed or unsupported certificate PEM")
		}
		cert, err := parseBundleCertificate(block.Bytes)
		if err != nil {
			return Plan{}, fmt.Errorf("parse bundle certificate: %w", err)
		}
		plan.Certificates++
		fingerprint := digest(block.Bytes)
		remove := false
		for _, root := range affectedRoots {
			if fingerprint == root.SHA256 {
				plan.Removed = append(plan.Removed, root)
				remove = true
				break
			}
			if cert.Subject.CommonName == root.Name {
				return Plan{}, fmt.Errorf("unexpected fingerprint for %s; refusing an ambiguous repair", root.Name)
			}
		}
		plan.replacement = append(plan.replacement, prefix...)
		if !remove {
			plan.replacement = append(plan.replacement, encoded...)
		}
		rest = rest[end:]
	}
	if plan.Certificates == 0 || plan.Certificates == len(plan.Removed) {
		return Plan{}, errors.New("repair would leave no trusted certificates")
	}
	plan.AfterSHA256 = digest(plan.replacement)
	return plan, nil
}

// Apple still ships a legacy root with a negative ASN.1 serial. Modern Go
// rejects it by default. Validate a positive-serial COPY in that one case;
// never change the bundle's DER, fingerprint the copy, or use it for trust
// verification. This avoids changing process-wide GODEBUG parser policy.
func parseBundleCertificate(der []byte) (*x509.Certificate, error) {
	cert, originalErr := x509.ParseCertificate(der)
	if originalErr == nil {
		return cert, nil
	}
	originalErr = fmt.Errorf("parse X.509 certificate: %w", originalErr)
	var outer, tbs, first, serial asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || outer.Tag != asn1.TagSequence || outer.Class != asn1.ClassUniversal {
		return nil, originalErr
	}
	tail, err := asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil || tbs.Tag != asn1.TagSequence || tbs.Class != asn1.ClassUniversal {
		return nil, originalErr
	}
	afterFirst, err := asn1.Unmarshal(tbs.Bytes, &first)
	if err != nil {
		return nil, originalErr
	}
	prefix := []byte(nil)
	serial, rest = first, afterFirst
	if first.Class == asn1.ClassContextSpecific && first.Tag == 0 {
		prefix = first.FullBytes
		rest, err = asn1.Unmarshal(afterFirst, &serial)
		if err != nil {
			return nil, originalErr
		}
	}
	if serial.Class != asn1.ClassUniversal || serial.Tag != asn1.TagInteger || serial.IsCompound || len(serial.Bytes) == 0 || serial.Bytes[0]&0x80 == 0 {
		return nil, originalErr
	}
	serial.FullBytes = nil
	serial.Bytes = append([]byte{0}, serial.Bytes...)
	encoded, err := asn1.Marshal(serial)
	if err != nil {
		return nil, originalErr
	}
	tbs.FullBytes = nil
	tbs.Bytes = append(append(bytes.Clone(prefix), encoded...), rest...)
	encoded, err = asn1.Marshal(tbs)
	if err != nil {
		return nil, originalErr
	}
	outer.FullBytes = nil
	outer.Bytes = append(encoded, tail...)
	encoded, err = asn1.Marshal(outer)
	if err != nil {
		return nil, originalErr
	}
	cert, err = x509.ParseCertificate(encoded)
	if err != nil {
		return nil, originalErr
	}
	return cert, nil
}
