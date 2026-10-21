// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"Version: %s\nCommit: %s\nBuilt At: %s\n",
				Version,
				Commit,
				Date,
			); err != nil {
				return fmt.Errorf("write version: %w", err)
			}
			return nil
		},
	}
}
