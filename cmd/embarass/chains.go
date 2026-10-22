// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	"github.com/rs/zerolog"
)

// Testing one path can miss clients that trust the compromised key through another.
const chainAll = "all"

// emSign runs first because current Mozilla-derived stores trust it for TLS,
// allowing vulnerable clients to stop after one run.
var allChains = []certforge.Chain{certforge.ChainEMSign, certforge.ChainSectigo}

const chainFlagUsage = "trust path to test: all, sectigo, or emsign"

func parseChains(value string) ([]certforge.Chain, error) {
	switch chain := certforge.Chain(strings.ToLower(value)); chain {
	case chainAll:
		return allChains, nil
	case certforge.ChainSectigo, certforge.ChainEMSign:
		return []certforge.Chain{chain}, nil
	default:
		return nil, fmt.Errorf("unsupported chain %q: use all, sectigo, or emsign", value)
	}
}

// runChains stops at the first accepted path. It reports rejection only if all
// paths reject, and inconclusive otherwise. The returned paths identify the
// result; an inconclusive result names only the path its reason and child exit
// came from. beforePath, if set, runs before each path so callers can separate
// the child output of consecutive runs.
func runChains(
	ctx context.Context,
	run runFunc,
	options runner.Options,
	chains []certforge.Chain,
	beforePath func(certforge.Chain),
) (runner.Result, []certforge.Chain, error) {
	var (
		reported      runner.Result
		reportedChain certforge.Chain
		elapsed       time.Duration
	)
	for _, chain := range chains {
		// Do not start another child, and repeat its side effects, after cancellation.
		if ctx.Err() != nil {
			return runner.Result{}, nil, fmt.Errorf("test %s trust path: %w", chain, context.Cause(ctx))
		}
		zerolog.Ctx(ctx).Debug().Str("chain", string(chain)).Msg("Testing trust path")
		if beforePath != nil {
			beforePath(chain)
		}
		options.Chain = chain
		result, err := run(ctx, options)
		if err != nil {
			return runner.Result{}, nil, fmt.Errorf("test %s trust path: %w", chain, err)
		}
		elapsed += result.Duration
		switch result.Outcome {
		case runner.OutcomeVulnerable:
			result.Duration = elapsed
			return result, []certforge.Chain{chain}, nil
		case runner.OutcomeRejected, runner.OutcomeInconclusive:
			if reported.Outcome != runner.OutcomeInconclusive {
				reported, reportedChain = result, chain
			}
		default:
			return result, []certforge.Chain{chain}, nil
		}
	}
	reported.Duration = elapsed
	if reported.Outcome == runner.OutcomeInconclusive {
		return reported, []certforge.Chain{reportedChain}, nil
	}
	return reported, chains, nil
}

// acrossChains overrides Options.Chain to give batch probes the same path coverage.
func acrossChains(run runFunc, chains []certforge.Chain) runFunc {
	return func(ctx context.Context, options runner.Options) (runner.Result, error) {
		result, _, err := runChains(ctx, run, options, chains, nil)
		return result, err
	}
}

func chainNames(chains []certforge.Chain, separator string) string {
	names := make([]string, 0, len(chains))
	for _, chain := range chains {
		names = append(names, string(chain))
	}
	return strings.Join(names, separator)
}
