// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package logger configures the command's structured console logger.
package logger

import (
	"io"
	"os"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
)

// Setup returns a human-readable zerolog logger writing to output.
func Setup(verbose bool, output io.Writer) zerolog.Logger {
	level := zerolog.InfoLevel
	if verbose {
		level = zerolog.DebugLevel
	}
	console := zerolog.ConsoleWriter{
		Out:        output,
		TimeFormat: time.RFC3339,
		NoColor:    !supportsColor(output),
	}
	return zerolog.New(console).Level(level).With().Timestamp().Logger()
}

func supportsColor(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	return isatty.IsTerminal(file.Fd()) || isatty.IsCygwinTerminal(file.Fd())
}
