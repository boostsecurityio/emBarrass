// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package runner

import (
	"context"
	"testing"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/intercept"
	"github.com/stretchr/testify/require"
)

func TestChildExitWaitsForTLSHandler(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observations := make(chan intercept.Observation)
	serverDone := make(chan error, 1)
	// The child has exited, but the handler has not yet delivered its TLS alert.
	// An unbuffered send makes receipt depend on the completion loop waiting.
	go func() {
		select {
		case observations <- intercept.Observation{Kind: intercept.ObservationRejected, Host: "example.com"}:
			serverDone <- nil
		case <-ctx.Done():
		}
	}()
	result, err := finishRun(ctx, time.Now(), observationState{connected: true}, nil, observations, serverDone, nil)
	require.NoError(t, err)
	require.Equal(t, OutcomeRejected, result.Outcome)
	require.Equal(t, ReasonForgedTLSRejected, result.Reason)
}

func TestChildExitDrainsCompletedHandler(t *testing.T) {
	t.Parallel()
	observations := make(chan intercept.Observation, 1)
	observations <- intercept.Observation{Kind: intercept.ObservationAccepted, Host: "example.com"}
	serverDone := make(chan error, 1)
	serverDone <- nil
	result, err := finishRun(context.Background(), time.Now(), observationState{}, nil, observations, serverDone, nil)
	require.NoError(t, err)
	require.Equal(t, OutcomeVulnerable, result.Outcome)
}

func TestChildExitStillHonorsTimeoutAndCancellation(t *testing.T) {
	t.Parallel()
	timeout := make(chan time.Time, 1)
	timeout <- time.Now()
	result, err := finishRun(context.Background(), time.Now(), observationState{}, nil, nil, nil, timeout)
	require.NoError(t, err)
	require.Equal(t, OutcomeInconclusive, result.Outcome)
	require.Equal(t, ReasonTimeout, result.Reason)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = finishRun(ctx, time.Now(), observationState{}, nil, nil, nil, nil)
	require.ErrorIs(t, err, context.Canceled)
}
