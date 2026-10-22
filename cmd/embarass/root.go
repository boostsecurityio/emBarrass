// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/logger"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

const (
	exitProtected    = 0
	exitVulnerable   = 1
	exitInconclusive = 2
	defaultTimeout   = 30 * time.Second
	tagline          = "Putting the ‘em’ in MITM. Wrap any command, test its TLS trust, and find out whether you’ve been emBarrassed."
)

var errCommandRequired = errors.New("a command to test is required")

type runFunc func(ctx context.Context, options runner.Options) (runner.Result, error)

type application struct {
	run             runFunc
	exitCode        int
	verbose         bool
	headless        bool
	batchYes        bool
	terminalStarted bool
	timeout         time.Duration
	chain           string
	invocation      string
}

// Execute runs the CLI and returns its process exit code.
func Execute() int {
	app := &application{
		run:        runner.Run,
		exitCode:   exitProtected,
		invocation: displayedInvocation(os.Args[0]),
	}
	command := newRootCommand(app)
	if err := command.Execute(); err != nil {
		if app.headless {
			log := logger.Setup(app.verbose, command.ErrOrStderr())
			log.Error().Err(err).Msg("emBarrass failed")
		} else {
			ui := newTerminalUI(command.ErrOrStderr())
			if errors.Is(err, errCommandRequired) {
				_ = ui.missingCommand(app.displayedInvocation())
			} else if app.terminalStarted {
				_ = ui.failureAfterStart(err)
			} else {
				_ = ui.failure(err)
			}
		}
		return exitInconclusive
	}
	return app.exitCode
}

func newRootCommand(app *application) *cobra.Command {
	invocation := app.displayedInvocation()
	command := &cobra.Command{
		Use:   "embarass [flags] -- command [args...]",
		Short: "Wrap any command and test its TLS trust",
		// Keep shell function names independent of argv[0], while preserving
		// the copyable invocation in help (for example, ./embarass).
		Annotations: map[string]string{cobra.CommandDisplayNameAnnotation: invocation},
		Long: tagline + `

emBarrass routes one command through an authenticated local HTTPS interceptor.
The interceptor is loopback-only except for the disclosed docker/git batch probe,
which makes it reachable from that container. The tested client keeps its native
CA configuration: emBarrass does not inject a CA file, disable verification,
forward intercepted traffic, or change the host trust store.`,
		Example: fmt.Sprintf(`  # Test individual tools with public, read-only requests
  %[1]s curl --silent https://example.com/
  %[1]s git ls-remote https://github.com/actions/checkout.git HEAD
  %[1]s gh api meta --silent
  %[1]s wget --spider https://example.com/
  %[1]s npm view is-number version --registry=https://registry.npmjs.org/
  %[1]s go list -m -versions golang.org/x/text@latest
  %[1]s pip index versions pip --index-url=https://pypi.org/simple
  %[1]s docker manifest inspect docker.io/library/alpine:latest
  %[1]s crane manifest registry.k8s.io/pause:3.10

  # Preview and confirm installed-tool probes, including a container CA bundle
  %[1]s batch`, invocation),
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errCommandRequired
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			log := logger.Setup(app.verbose, cmd.ErrOrStderr())
			cmd.SetContext(log.WithContext(cmd.Context()))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runCheck(cmd, args)
		},
	}
	command.Flags().SetInterspersed(false)
	command.Flags().DurationVar(&app.timeout, "timeout", defaultTimeout, "maximum runtime per trust path; 0 disables the deadline")
	command.Flags().StringVar(&app.chain, "chain", chainAll, chainFlagUsage)
	registerChainCompletion(command)
	command.Flags().BoolVar(&app.headless, "headless", false, "emit compact log lines without the terminal UI")
	command.Flags().BoolVarP(&app.verbose, "verbose", "v", false, "enable debug logging")
	command.AddCommand(newBatchCommand(app), newVersionCommand())
	return command
}

func (app *application) displayedInvocation() string {
	if app.invocation == "" {
		return "embarass"
	}
	return app.invocation
}

func displayedInvocation(argumentZero string) string {
	if argumentZero == "" || strings.ContainsAny(argumentZero, "\x00\r\n\t") {
		return "embarass"
	}
	name := filepath.Base(argumentZero)
	if name == "." || name == string(filepath.Separator) {
		return "embarass"
	}
	// argv[0] may use either separator even when tests or compatibility layers
	// pass a launch form from a different OS. Preserve path-qualified forms so
	// help remains copy-pasteable on Unix and Windows.
	if strings.ContainsAny(argumentZero, `/\`) {
		return argumentZero
	}
	return name
}

func (app *application) runCheck(cmd *cobra.Command, args []string) error {
	if app.timeout < 0 {
		return fmt.Errorf("timeout must not be negative: %s", app.timeout)
	}
	chains, err := parseChains(app.chain)
	if err != nil {
		return err
	}
	preparedCommand, adjustments := runner.PrepareCommand(args)
	ui := newTerminalUI(cmd.ErrOrStderr())
	if !app.headless {
		if err := ui.start(args, chains, app.timeout, adjustments); err != nil {
			return err
		}
		app.terminalStarted = true
	} else if len(adjustments) > 0 {
		logHeadlessAdjustments(zerolog.Ctx(cmd.Context()), adjustments)
	}

	var beforePath func(certforge.Chain)
	if len(chains) > 1 {
		beforePath = func(chain certforge.Chain) {
			if app.headless {
				zerolog.Ctx(cmd.Context()).Info().Str("chain", string(chain)).Msg("Testing trust path")
				return
			}
			ui.pathHeader(chain)
		}
	}
	result, reportedChains, err := runChains(cmd.Context(), app.run, runner.Options{
		Command: preparedCommand,
		Timeout: app.timeout,
		Stdout:  cmd.OutOrStdout(),
		Stderr:  cmd.ErrOrStderr(),
	}, chains, beforePath)
	if err != nil {
		return err
	}

	switch result.Outcome {
	case runner.OutcomeVulnerable:
		app.exitCode = exitVulnerable
	case runner.OutcomeRejected:
		app.exitCode = exitProtected
	case runner.OutcomeInconclusive:
		app.exitCode = exitInconclusive
	default:
		return fmt.Errorf("unknown runner outcome %q", result.Outcome)
	}
	if !app.headless {
		return ui.result(result, reportedChains, app.exitCode)
	}
	logHeadlessResult(zerolog.Ctx(cmd.Context()), result, reportedChains)
	return nil
}

func logHeadlessAdjustments(log *zerolog.Logger, adjustments []runner.CommandAdjustment) {
	for _, adjustment := range adjustments {
		switch adjustment {
		case runner.AdjustmentGitHTTPSPinned:
			log.Info().Str("adjustment", string(adjustment)).
				Msg("Git HTTPS transport pinned; url.*.insteadOf rewrites bypassed")
		case runner.AdjustmentGHCredentialsIsolated:
			log.Info().Str("adjustment", string(adjustment)).
				Msg("GitHub CLI public probe isolated; user credentials bypassed")
		}
	}
}

func logHeadlessResult(log *zerolog.Logger, result runner.Result, chains []certforge.Chain) {
	switch result.Outcome {
	case runner.OutcomeVulnerable:
		log.Error().
			Str("host", result.Host).
			Str("chain", chainNames(chains, ",")).
			Dur("duration", result.Duration).
			Msg("VULNERABLE: the command accepted a forged certificate signed by the compromised eMudhra key")
	case runner.OutcomeRejected:
		log.Info().
			Str("host", result.Host).
			Str("chain", chainNames(chains, ",")).
			Dur("duration", result.Duration).
			Msg("NOT CONFIRMED: the command reached emBarrass but rejected the forged TLS connection")
	case runner.OutcomeInconclusive:
		log.Warn().
			Str("reason", string(result.Reason)).
			Str("chain", chainNames(chains, ",")).
			Int("child_exit_code", result.ChildExitCode).
			Dur("duration", result.Duration).
			Msg("INCONCLUSIVE: emBarrass could not confirm whether the command is vulnerable")
	}
}
