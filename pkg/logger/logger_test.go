// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package logger

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupDisablesColorForNonTerminalOutput(t *testing.T) {
	t.Parallel()

	output := &bytes.Buffer{}
	log := Setup(false, output)
	log.Error().Msg("VULNERABLE: test message")

	require.Contains(t, output.String(), "ERR VULNERABLE: test message")
	require.NotContains(t, output.String(), "\x1b[")
}
