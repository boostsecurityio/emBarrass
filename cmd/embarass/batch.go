// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/batchtest"
	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func newBatchCommand(app *application) *cobra.Command {
	invocation := app.displayedInvocation()
	command := &cobra.Command{
		Use:   "batch",
		Short: "Safely test supported CLI tools found in PATH",
		Long: `Discover supported TLS-capable tools in PATH, preview the exact read-only
commands, ask for confirmation, and run the probes sequentially.

Each probe uses a public endpoint. The intercepted request is never forwarded
upstream, child output is discarded, and cache writes use an automatically
deleted temporary workspace. The docker/git probe may pull and retain one
immutable, digest-pinned image.`,
		Example: fmt.Sprintf(`  %[1]s batch
  %[1]s batch --chain emsign
  %[1]s batch --yes --headless`, invocation),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.runBatch(cmd)
		},
	}
	command.Flags().BoolVarP(&app.batchYes, "yes", "y", false, "run the displayed probes without prompting")
	command.Flags().DurationVar(&app.timeout, "timeout", defaultTimeout, "maximum runtime per tool and trust path; 0 disables the deadline")
	command.Flags().StringVar(&app.chain, "chain", chainAll, chainFlagUsage)
	command.Flags().BoolVar(&app.headless, "headless", false, "emit compact log lines without the terminal UI")
	command.Flags().BoolVarP(&app.verbose, "verbose", "v", false, "enable debug logging")
	return command
}

func (app *application) runBatch(cmd *cobra.Command) error {
	if app.timeout < 0 {
		return fmt.Errorf("timeout must not be negative: %s", app.timeout)
	}
	chains, err := parseChains(app.chain)
	if err != nil {
		return err
	}

	plan, err := batchtest.Discover()
	if err != nil {
		return fmt.Errorf("prepare batch tests: %w", err)
	}
	if len(plan.Probes) == 0 {
		cleanupErr := plan.Cleanup()
		return errors.Join(
			errors.New("none of the supported tools were found in PATH"),
			cleanupErr,
		)
	}

	interactive := isTerminal(cmd.ErrOrStderr())
	if !interactive && !app.batchYes {
		cleanupErr := plan.Cleanup()
		return errors.Join(
			errors.New("batch confirmation requires a terminal; rerun with --yes"),
			cleanupErr,
		)
	}

	var summary batchSummary
	if app.headless || !interactive {
		summary = app.runBatchHeadless(cmd.Context(), plan, chains)
	} else {
		summary, err = app.runBatchTerminal(cmd, plan, chains)
	}
	cleanupErr := plan.Cleanup()
	if err != nil || cleanupErr != nil {
		return errors.Join(err, cleanupErr)
	}
	app.exitCode = summary.exitCode()
	return nil
}

func (app *application) runBatchTerminal(
	cmd *cobra.Command,
	plan batchtest.Plan,
	chains []certforge.Chain,
) (batchSummary, error) {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	model := newBatchModel(
		ctx,
		cancel,
		newTerminalUI(cmd.ErrOrStderr()).styles,
		plan,
		acrossChains(app.run, chains),
		app.timeout,
		app.batchYes,
	)
	program := tea.NewProgram(
		model,
		tea.WithInput(cmd.InOrStdin()),
		tea.WithOutput(cmd.ErrOrStderr()),
		tea.WithoutSignalHandler(),
	)
	finalModel, err := program.Run()
	if err != nil {
		return batchSummary{}, fmt.Errorf("run batch terminal: %w", err)
	}
	finished, ok := finalModel.(batchModel)
	if !ok {
		return batchSummary{}, errors.New("batch terminal returned an unexpected model")
	}
	return finished.summary(), nil
}

func (app *application) runBatchHeadless(
	ctx context.Context,
	plan batchtest.Plan,
	chains []certforge.Chain,
) batchSummary {
	log := zerolog.Ctx(ctx)
	available := make([]string, 0, len(plan.Probes))
	for _, probe := range plan.Probes {
		available = append(available, probe.Name)
	}
	log.Info().
		Strs("tools", available).
		Strs("unavailable", plan.Unavailable).
		Msg("BATCH PREFLIGHT: running read-only probes in an isolated temporary workspace")
	if planMayPullImage(plan) {
		log.Warn().Msg("IMAGE PULL DISCLOSURE: docker/git may pull and retain one immutable, digest-pinned image")
	}

	summary := batchSummary{skipped: len(plan.Unavailable)}
	for _, probe := range plan.Probes {
		log.Info().Str("tool", probe.Name).Str("command", probe.Preview).Msg("testing TLS trust")
		result, reportedChains, err := runChains(ctx, app.run, batchRunnerOptions(plan, probe, app.timeout), chains, nil)
		summary.record(result, err)
		logBatchResult(log, probe.Name, result, reportedChains, err)
	}
	log.Info().
		Int("embarrassed", summary.vulnerable).
		Int("held", summary.rejected).
		Int("inconclusive", summary.inconclusive).
		Int("errors", summary.failed).
		Int("unavailable", summary.skipped).
		Msg("BATCH COMPLETE")
	return summary
}

func planMayPullImage(plan batchtest.Plan) bool {
	for _, probe := range plan.Probes {
		if probe.MayPullImage {
			return true
		}
	}
	return false
}

func batchRunnerOptions(
	plan batchtest.Plan,
	probe batchtest.Probe,
	timeout time.Duration,
) runner.Options {
	proxyTarget := runner.ProxyTargetHost
	if probe.Containerized {
		proxyTarget = runner.ProxyTargetDockerContainer
	}
	return runner.Options{
		Command:              probe.Command(),
		Timeout:              timeout,
		Stdout:               io.Discard,
		Stderr:               io.Discard,
		WorkingDirectory:     plan.WorkingDirectory(),
		EnvironmentOverrides: probe.EnvironmentOverrides,
		ProxyTarget:          proxyTarget,
	}
}

func logBatchResult(log *zerolog.Logger, tool string, result runner.Result, chains []certforge.Chain, err error) {
	if err != nil {
		log.Error().Err(err).Str("tool", tool).Msg("HARNESS ERROR")
		return
	}
	chain := chainNames(chains, ",")
	event := log.Info().Str("tool", tool).Str("host", result.Host).Str("chain", chain).Dur("duration", result.Duration)
	switch result.Outcome {
	case runner.OutcomeVulnerable:
		event = log.Error().Str("tool", tool).Str("host", result.Host).Str("chain", chain).Dur("duration", result.Duration)
		event.Msg("COMPLETELY EMBARRASSED: forged certificate accepted")
	case runner.OutcomeRejected:
		event.Msg("TRUST HELD: forged certificate rejected")
	case runner.OutcomeInconclusive:
		log.Warn().
			Str("tool", tool).
			Str("reason", string(result.Reason)).
			Str("chain", chain).
			Dur("duration", result.Duration).
			Msg("NO SIGNAL: result inconclusive")
	}
}

type batchSummary struct {
	vulnerable   int
	rejected     int
	inconclusive int
	failed       int
	skipped      int
	canceled     bool
}

func (summary *batchSummary) record(result runner.Result, err error) {
	if err != nil {
		summary.failed++
		return
	}
	switch result.Outcome {
	case runner.OutcomeVulnerable:
		summary.vulnerable++
	case runner.OutcomeRejected:
		summary.rejected++
	case runner.OutcomeInconclusive:
		summary.inconclusive++
	default:
		summary.failed++
	}
}

func (summary batchSummary) exitCode() int {
	if summary.vulnerable > 0 {
		return exitVulnerable
	}
	if summary.canceled && summary.rejected+summary.inconclusive+summary.failed > 0 {
		return exitInconclusive
	}
	if summary.inconclusive > 0 || summary.failed > 0 {
		return exitInconclusive
	}
	return exitProtected
}

func (summary batchSummary) String() string {
	parts := []string{
		fmt.Sprintf("%d embarrassed", summary.vulnerable),
		fmt.Sprintf("%d held", summary.rejected),
		fmt.Sprintf("%d inconclusive", summary.inconclusive),
	}
	if summary.failed > 0 {
		parts = append(parts, fmt.Sprintf("%d errors", summary.failed))
	}
	if summary.skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d unavailable", summary.skipped))
	}
	return strings.Join(parts, " · ")
}
