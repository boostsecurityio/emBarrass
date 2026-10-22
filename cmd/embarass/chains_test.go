// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	"github.com/stretchr/testify/require"
)

func TestRunChainsCombinesTrustPaths(t *testing.T) {
	t.Parallel()

	rejected := runner.Result{Outcome: runner.OutcomeRejected, Duration: time.Second}
	vulnerable := runner.Result{Outcome: runner.OutcomeVulnerable, Duration: time.Second}
	noTraffic := runner.Result{
		Outcome:       runner.OutcomeInconclusive,
		Reason:        runner.ReasonNoTraffic,
		ChildExitCode: 7,
		Duration:      time.Second,
	}
	timedOut := runner.Result{
		Outcome:       runner.OutcomeInconclusive,
		Reason:        runner.ReasonTimeout,
		ChildExitCode: 9,
		Duration:      time.Second,
	}

	testCases := []struct {
		name          string
		outcomes      map[certforge.Chain]runner.Result
		wantOutcome   runner.Outcome
		wantReason    runner.Reason
		wantChildExit int
		wantChains    []certforge.Chain
		wantRan       []certforge.Chain
		wantDuration  time.Duration
	}{
		{
			name: "accepted on the first path stops the sweep",
			outcomes: map[certforge.Chain]runner.Result{
				certforge.ChainEMSign: vulnerable,
			},
			wantOutcome:  runner.OutcomeVulnerable,
			wantChains:   []certforge.Chain{certforge.ChainEMSign},
			wantRan:      []certforge.Chain{certforge.ChainEMSign},
			wantDuration: time.Second,
		},
		{
			name: "accepted on a later path is vulnerable despite an earlier rejection",
			outcomes: map[certforge.Chain]runner.Result{
				certforge.ChainEMSign:  rejected,
				certforge.ChainSectigo: vulnerable,
			},
			wantOutcome:  runner.OutcomeVulnerable,
			wantChains:   []certforge.Chain{certforge.ChainSectigo},
			wantRan:      allChains,
			wantDuration: 2 * time.Second,
		},
		{
			name: "rejected only when every path rejects",
			outcomes: map[certforge.Chain]runner.Result{
				certforge.ChainEMSign:  rejected,
				certforge.ChainSectigo: rejected,
			},
			wantOutcome:  runner.OutcomeRejected,
			wantChains:   allChains,
			wantRan:      allChains,
			wantDuration: 2 * time.Second,
		},
		{
			name: "an inconclusive path outweighs an earlier rejection",
			outcomes: map[certforge.Chain]runner.Result{
				certforge.ChainEMSign:  rejected,
				certforge.ChainSectigo: timedOut,
			},
			wantOutcome:   runner.OutcomeInconclusive,
			wantReason:    runner.ReasonTimeout,
			wantChildExit: 9,
			wantChains:    []certforge.Chain{certforge.ChainSectigo},
			wantRan:       allChains,
			wantDuration:  2 * time.Second,
		},
		{
			name: "an inconclusive path outweighs a later rejection",
			outcomes: map[certforge.Chain]runner.Result{
				certforge.ChainEMSign:  noTraffic,
				certforge.ChainSectigo: rejected,
			},
			wantOutcome:   runner.OutcomeInconclusive,
			wantReason:    runner.ReasonNoTraffic,
			wantChildExit: 7,
			wantChains:    []certforge.Chain{certforge.ChainEMSign},
			wantRan:       allChains,
			wantDuration:  2 * time.Second,
		},
		{
			name: "the reported path is the one the reason and child exit came from",
			outcomes: map[certforge.Chain]runner.Result{
				certforge.ChainEMSign:  noTraffic,
				certforge.ChainSectigo: timedOut,
			},
			wantOutcome:   runner.OutcomeInconclusive,
			wantReason:    runner.ReasonNoTraffic,
			wantChildExit: 7,
			wantChains:    []certforge.Chain{certforge.ChainEMSign},
			wantRan:       allChains,
			wantDuration:  2 * time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var ran []certforge.Chain
			run := func(_ context.Context, options runner.Options) (runner.Result, error) {
				ran = append(ran, options.Chain)
				return testCase.outcomes[options.Chain], nil
			}

			result, chains, err := runChains(context.Background(), run, runner.Options{}, allChains, nil)
			require.NoError(t, err)
			require.Equal(t, testCase.wantOutcome, result.Outcome)
			require.Equal(t, testCase.wantReason, result.Reason)
			require.Equal(t, testCase.wantChildExit, result.ChildExitCode)
			require.Equal(t, testCase.wantChains, chains)
			require.Equal(t, testCase.wantRan, ran)
			require.Equal(t, testCase.wantDuration, result.Duration)
		})
	}
}

func TestRunChainsStopsOnHarnessError(t *testing.T) {
	t.Parallel()

	calls := 0
	run := func(context.Context, runner.Options) (runner.Result, error) {
		calls++
		return runner.Result{}, errors.New("interceptor failed")
	}

	_, _, err := runChains(context.Background(), run, runner.Options{}, allChains, nil)
	require.ErrorContains(t, err, "test emsign trust path: interceptor failed")
	require.Equal(t, 1, calls)
}

func TestRunChainsDoesNotStartAnotherPathAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var ran []certforge.Chain
	run := func(_ context.Context, options runner.Options) (runner.Result, error) {
		ran = append(ran, options.Chain)
		cancel()
		return runner.Result{Outcome: runner.OutcomeRejected}, nil
	}

	_, _, err := runChains(ctx, run, runner.Options{}, allChains, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, []certforge.Chain{certforge.ChainEMSign}, ran)
}
