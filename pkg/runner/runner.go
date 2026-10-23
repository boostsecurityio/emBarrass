// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package runner launches a command through the local eMudhra TLS interceptor.
package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/intercept"
	"github.com/rs/zerolog"
)

// Outcome describes whether the wrapped TLS client accepted the forged chain.
type Outcome string

const (
	// OutcomeVulnerable means the child sent application data over a TLS session
	// established with the forged eMudhra chain.
	OutcomeVulnerable Outcome = "vulnerable"
	// OutcomeRejected means the command reached the interceptor but rejected TLS.
	OutcomeRejected Outcome = "rejected"
	// OutcomeInconclusive means no definitive TLS decision was observed.
	OutcomeInconclusive Outcome = "inconclusive"
)

// Reason provides a machine-readable explanation for an outcome.
type Reason string

const (
	ReasonForgedTLSAccepted Reason = "forged_tls_accepted"
	ReasonForgedTLSRejected Reason = "forged_tls_rejected"
	ReasonNoTraffic         Reason = "no_https_proxy_traffic"
	ReasonNoTLSDecision     Reason = "no_tls_decision"
	ReasonTimeout           Reason = "timeout"
)

// ProxyTarget identifies the network namespace that must reach the local
// interceptor.
type ProxyTarget uint8

const (
	// ProxyTargetHost keeps the interceptor loopback-only for ordinary commands.
	ProxyTargetHost ProxyTarget = iota
	// ProxyTargetDockerContainer makes the authenticated interceptor reachable
	// through Docker's host.docker.internal bridge.
	ProxyTargetDockerContainer
)

// Options configures a wrapped command run.
type Options struct {
	Command              []string
	Timeout              time.Duration
	Stdout               io.Writer
	Stderr               io.Writer
	Chain                certforge.Chain
	WorkingDirectory     string
	EnvironmentOverrides map[string]string
	ProxyTarget          ProxyTarget
}

// Result records the observed outcome without retaining application traffic.
type Result struct {
	Outcome       Outcome
	Reason        Reason
	Host          string
	ChildExitCode int
	Duration      time.Duration
}

type observationState struct {
	connected bool
	rejected  bool
	handshake bool
	accepted  bool
	host      string
}

// Run starts a local interceptor, injects only proxy-routing environment
// variables, and runs the requested command until it exits or takes the bait.
func Run(ctx context.Context, options Options) (Result, error) {
	startedAt := time.Now()
	if len(options.Command) == 0 || strings.TrimSpace(options.Command[0]) == "" {
		return Result{}, errors.New("command is required")
	}
	preparedCommand, adjustments := PrepareCommand(options.Command)
	options.Command = preparedCommand
	if len(adjustments) > 0 {
		zerolog.Ctx(ctx).Debug().
			Strs("adjustments", commandAdjustmentStrings(adjustments)).
			Msg("Applied wrapped-command compatibility adjustments")
	}

	forge, err := certforge.New(certforge.Options{Chain: options.Chain})
	if err != nil {
		return Result{}, fmt.Errorf("initialize eMudhra certificate forge: %w", err)
	}
	token, err := newProxyToken()
	if err != nil {
		return Result{}, fmt.Errorf("generate proxy authorization token: %w", err)
	}
	listenHost, err := proxyListenHost(options.ProxyTarget)
	if err != nil {
		return Result{}, err
	}
	server, err := intercept.New(intercept.Options{
		Source:             forge,
		AuthorizationToken: token,
		ListenHost:         listenHost,
	})
	if err != nil {
		return Result{}, fmt.Errorf("initialize local interceptor: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = server.Close() }()

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(runCtx)
		close(serverErrors)
	}()

	proxyAddress, err := advertisedProxyAddress(server.Address(), options.ProxyTarget)
	if err != nil {
		return Result{}, err
	}
	proxyURL := (&url.URL{
		Scheme: "http",
		User:   url.UserPassword("embarass", token),
		Host:   proxyAddress,
	}).String()
	command := exec.Command(options.Command[0], options.Command[1:]...)
	commandEnvironment, err := childEnvironment(
		os.Environ(),
		mergeEnvironmentOverrides(
			compatibilityEnvironment(options.Command),
			options.EnvironmentOverrides,
		),
		proxyURL,
	)
	if err != nil {
		return Result{}, err
	}
	command.Env = commandEnvironment
	command.Dir = options.WorkingDirectory
	command.Stdin = os.Stdin
	command.Stdout = options.Stdout
	if command.Stdout == nil {
		command.Stdout = os.Stdout
	}
	command.Stderr = options.Stderr
	if command.Stderr == nil {
		command.Stderr = os.Stderr
	}
	configureCommand(command)

	zerolog.Ctx(ctx).Debug().
		Str("command", options.Command[0]).
		Str("proxy", server.Address()).
		Msg("Starting wrapped command")
	if err := command.Start(); err != nil {
		return Result{}, fmt.Errorf("start command %q: %w", options.Command[0], err)
	}

	processDone := make(chan error, 1)
	go func() {
		processDone <- command.Wait()
		close(processDone)
	}()

	var timeout <-chan time.Time
	var timer *time.Timer
	if options.Timeout > 0 {
		timer = time.NewTimer(options.Timeout)
		timeout = timer.C
		defer timer.Stop()
	}

	state := observationState{}
	for {
		select {
		case observation := <-server.Observations():
			state = applyObservation(ctx, state, observation)
			if state.accepted {
				if err := stopCommand(command); err != nil {
					return Result{}, fmt.Errorf("stop vulnerable child process: %w", err)
				}
				childErr := <-processDone
				return vulnerableResult(startedAt, state, childErr), nil
			}
		case childErr := <-processDone:
			// Stop accepting connections, then let existing handlers record the
			// child's final TLS alert. Canceling their context here would create
			// artificial handshake failures; a nonblocking drain races the alert.
			if err := server.Close(); err != nil {
				return Result{}, fmt.Errorf("close interceptor after child exit: %w", err)
			}
			return finishRun(ctx, startedAt, state, childErr, server.Observations(), serverErrors, timeout)
		case serverErr := <-serverErrors:
			if serverErr == nil {
				serverErrors = nil
				continue
			}
			if err := stopCommand(command); err != nil {
				return Result{}, fmt.Errorf("stop child after interceptor failure: %w", err)
			}
			<-processDone //nolint:errcheck // The interceptor failure takes precedence over the stopped child's exit error.
			return Result{}, fmt.Errorf("serve local interceptor: %w", serverErr)
		case <-timeout:
			state = drainObservations(ctx, state, server.Observations())
			if err := stopCommand(command); err != nil {
				return Result{}, fmt.Errorf("stop timed-out child process: %w", err)
			}
			childErr := <-processDone
			if state.accepted {
				return vulnerableResult(startedAt, state, childErr), nil
			}
			return Result{
				Outcome:       OutcomeInconclusive,
				Reason:        ReasonTimeout,
				Host:          state.host,
				ChildExitCode: exitCode(childErr),
				Duration:      time.Since(startedAt),
			}, nil
		case <-ctx.Done():
			if err := stopCommand(command); err != nil {
				return Result{}, fmt.Errorf("stop canceled child process: %w", err)
			}
			<-processDone //nolint:errcheck // The cancellation cause takes precedence over the stopped child's exit error.
			return Result{}, fmt.Errorf("run wrapped command: %w", context.Cause(ctx))
		}
	}
}

func finishRun(ctx context.Context, startedAt time.Time, state observationState, childErr error,
	observations <-chan intercept.Observation, serverErrors <-chan error, timeout <-chan time.Time,
) (Result, error) {
	for {
		select {
		case observation := <-observations:
			state = applyObservation(ctx, state, observation)
			if state.accepted {
				return vulnerableResult(startedAt, state, childErr), nil
			}
		case err := <-serverErrors:
			if err != nil {
				return Result{}, fmt.Errorf("finish local interceptor: %w", err)
			}
			state = drainObservations(ctx, state, observations)
			if state.accepted {
				return vulnerableResult(startedAt, state, childErr), nil
			}
			return completedResult(startedAt, state, childErr), nil
		case <-timeout:
			state = drainObservations(ctx, state, observations)
			if state.accepted {
				return vulnerableResult(startedAt, state, childErr), nil
			}
			return Result{Outcome: OutcomeInconclusive, Reason: ReasonTimeout, Host: state.host,
				ChildExitCode: exitCode(childErr), Duration: time.Since(startedAt)}, nil
		case <-ctx.Done():
			return Result{}, fmt.Errorf("finish wrapped command: %w", context.Cause(ctx))
		}
	}
}

func proxyListenHost(target ProxyTarget) (string, error) {
	switch target {
	case ProxyTargetHost:
		return "127.0.0.1", nil
	case ProxyTargetDockerContainer:
		return "0.0.0.0", nil
	default:
		return "", fmt.Errorf("unsupported proxy target %d", target)
	}
}

func advertisedProxyAddress(listenerAddress string, target ProxyTarget) (string, error) {
	_, port, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		return "", fmt.Errorf("parse interceptor address %q: %w", listenerAddress, err)
	}
	switch target {
	case ProxyTargetHost:
		return net.JoinHostPort("127.0.0.1", port), nil
	case ProxyTargetDockerContainer:
		return net.JoinHostPort("host.docker.internal", port), nil
	default:
		return "", fmt.Errorf("unsupported proxy target %d", target)
	}
}

func mergeEnvironmentOverrides(defaults, overrides map[string]string) map[string]string {
	if len(defaults) == 0 && len(overrides) == 0 {
		return nil
	}
	merged := make(map[string]string, len(defaults)+len(overrides))
	for key, value := range defaults {
		merged[key] = value
	}
	for key, value := range overrides {
		merged[key] = value
	}
	return merged
}

func commandAdjustmentStrings(adjustments []CommandAdjustment) []string {
	values := make([]string, 0, len(adjustments))
	for _, adjustment := range adjustments {
		values = append(values, string(adjustment))
	}
	return values
}

func newProxyToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("read system randomness: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func applyObservation(ctx context.Context, state observationState, observation intercept.Observation) observationState {
	logger := zerolog.Ctx(ctx)
	switch observation.Kind {
	case intercept.ObservationConnect:
		state.connected = true
		state.host = observation.Host
		logger.Debug().Str("host", observation.Host).Msg("Observed HTTPS CONNECT")
	case intercept.ObservationRejected:
		state.rejected = true
		state.host = observation.Host
		logger.Debug().Str("host", observation.Host).Msg("Forged TLS handshake was rejected")
	case intercept.ObservationHandshake:
		state.handshake = true
		state.host = observation.Host
		logger.Debug().Str("host", observation.Host).Msg("Forged TLS handshake completed")
	case intercept.ObservationAccepted:
		state.accepted = true
		state.host = observation.Host
		logger.Debug().Str("host", observation.Host).Msg("Forged TLS handshake was accepted")
	case intercept.ObservationUnsupported:
		logger.Debug().Msg("Observed non-CONNECT proxy traffic")
	}
	return state
}

func drainObservations(
	ctx context.Context,
	state observationState,
	observations <-chan intercept.Observation,
) observationState {
	for {
		select {
		case observation := <-observations:
			state = applyObservation(ctx, state, observation)
		default:
			return state
		}
	}
}

func vulnerableResult(startedAt time.Time, state observationState, childErr error) Result {
	return Result{
		Outcome:       OutcomeVulnerable,
		Reason:        ReasonForgedTLSAccepted,
		Host:          state.host,
		ChildExitCode: exitCode(childErr),
		Duration:      time.Since(startedAt),
	}
}

func completedResult(startedAt time.Time, state observationState, childErr error) Result {
	result := Result{
		Outcome:       OutcomeInconclusive,
		Reason:        ReasonNoTraffic,
		Host:          state.host,
		ChildExitCode: exitCode(childErr),
		Duration:      time.Since(startedAt),
	}
	if state.rejected {
		result.Outcome = OutcomeRejected
		result.Reason = ReasonForgedTLSRejected
	} else if state.connected {
		result.Reason = ReasonNoTLSDecision
	}
	return result
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
