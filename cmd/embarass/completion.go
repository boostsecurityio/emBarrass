// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"strings"

	"github.com/spf13/cobra"
)

func registerChainCompletion(command *cobra.Command) {
	err := command.RegisterFlagCompletionFunc("chain", func(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		choices := make([]string, 0, 1+len(allChains))
		choices = append(choices, chainAll)
		for _, chain := range allChains {
			choices = append(choices, string(chain))
		}
		var matches []string
		for _, choice := range choices {
			if strings.HasPrefix(choice, prefix) {
				matches = append(matches, choice)
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	})
	if err != nil {
		// A missing or duplicate registration is a command construction bug.
		panic(err)
	}
}
