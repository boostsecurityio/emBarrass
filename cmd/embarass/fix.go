// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/repair"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
)

type fixOptions struct{ dryRun, yes, undo bool }

func newFixCommand(app *application) *cobra.Command {
	var options fixOptions
	command := &cobra.Command{
		Use: "fix", Short: "Apply a reversible emergency repair to supported system CA stores",
		Long: `Preview and back up a platform-specific emergency trust repair, then
challenge both eMudhra trust paths with system curl. Legitimate chains relying
solely on the affected roots will also lose trust.

macOS: remove exact root certificates from /etc/ssl/cert.pem.
Debian, Ubuntu, Alpine: deselect roots and run update-ca-certificates.
Fedora/RHEL family: add local distrust files and run update-ca-trust extract.
Linux regeneration runs installed distro hooks and may update multiple stores;
undo reverses our policy changes and rebuilds from current vendor sources.

Prefer vendor CA-package updates when available. Independent application
bundles, Apple pip, and containers need separate checks. Use batch for those.

Run as your normal user; only the file transaction requests sudo. Undo refuses
to overwrite later OS or administrator changes. No certificate is downloaded.`,
		Example: fmt.Sprintf("  %[1]s fix --dry-run\n  %[1]s fix\n  %[1]s fix --yes --headless\n  %[1]s fix --undo", app.displayedInvocation()),
		Args:    cobra.NoArgs,
		RunE:    func(cmd *cobra.Command, _ []string) error { return app.runFix(cmd, options) },
	}
	command.Flags().BoolVar(&options.dryRun, "dry-run", false, "preview the repair without writing or running probes")
	command.Flags().BoolVarP(&options.yes, "yes", "y", false, "apply the displayed repair without prompting")
	command.Flags().BoolVar(&options.undo, "undo", false, "reverse the recorded repair; trust may be reintroduced")
	command.Flags().BoolVar(&app.headless, "headless", false, "emit plain repair progress without animation")
	command.Flags().BoolVarP(&app.verbose, "verbose", "v", false, "enable debug logging")
	return command
}

// The privileged subprocess has a fixed target, no discovery/probes, and an
// expected input hash. Its caller cannot choose a file or provide replacement bytes.
func newFixCommitCommand() *cobra.Command {
	var undo bool
	command := &cobra.Command{Use: "_fix-commit expected-sha256", Hidden: true, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return errors.New("repair transaction requires administrator access")
			}
			decoded, err := hex.DecodeString(args[0])
			if err != nil || len(decoded) != 32 {
				return errors.New("invalid expected bundle hash")
			}
			store, err := repair.System()
			if err != nil {
				return fmt.Errorf("open system repair: %w", err)
			}
			receipt, err := store.Apply(args[0], undo)
			if err != nil {
				return fmt.Errorf("commit system repair: %w", err)
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(receipt); err != nil {
				return fmt.Errorf("write repair receipt: %w", err)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&undo, "undo", false, "restore recorded bundle")
	return command
}

func (app *application) runFix(cmd *cobra.Command, options fixOptions) error {
	store, err := repair.System()
	if err != nil {
		return fmt.Errorf("open system repair: %w", err)
	}
	plan, err := store.Inspect()
	if options.undo {
		plan, err = store.UndoPlan()
	}
	if err != nil {
		return fmt.Errorf("inspect repair plan: %w", err)
	}
	ui := newTerminalUI(cmd.ErrOrStderr())
	if app.headless {
		renderer := lipgloss.NewRenderer(cmd.ErrOrStderr())
		renderer.SetColorProfile(termenv.Ascii)
		ui.styles = newTerminalStyles(renderer)
	}
	interactive := ui.interactive && !app.headless
	preview := newFixModel(ui.styles, plan, options.undo, app.displayedInvocation())
	preview.dryRun = options.dryRun
	changes := options.undo || len(plan.Removed) > 0
	app.terminalStarted = true
	if options.dryRun || options.yes || !changes {
		preview.confirmed = options.yes || !changes
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), preview.View()); err != nil {
			return fmt.Errorf("write repair preview: %w", err)
		}
	} else {
		if !interactive {
			return errors.New("repair confirmation requires a terminal; use --dry-run to inspect or --yes to apply")
		}
		program := tea.NewProgram(preview, tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.ErrOrStderr()))
		final, err := program.Run()
		if err != nil {
			return fmt.Errorf("run repair preview: %w", err)
		}
		preview = final.(fixModel)
		if !preview.confirmed {
			app.exitCode = exitInconclusive
			return nil
		}
	}
	if options.dryRun {
		return nil
	}
	var commit func() (repair.Receipt, error)
	if changes {
		if os.Geteuid() == 0 {
			commit = func() (repair.Receipt, error) { return store.Apply(plan.BeforeSHA256, options.undo) }
		} else {
			// Leave raw terminal mode before sudo needs a password. The subsequent
			// transaction is noninteractive, so prompts never collide with animation.
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "\n  Administrator access is needed for the bundle transaction."); err != nil {
				return fmt.Errorf("write privilege notice: %w", err)
			}
			auth := exec.CommandContext(cmd.Context(), "/usr/bin/sudo", "-v")
			auth.Stdin, auth.Stdout, auth.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr(), cmd.ErrOrStderr()
			if err := auth.Run(); err != nil {
				return fmt.Errorf("authorize repair; bundle unchanged: %w", err)
			}
			executable, err := os.Executable()
			if err != nil {
				return fmt.Errorf("locate repair executable: %w", err)
			}
			commit = func() (repair.Receipt, error) { return commitWithSudo(executable, plan.BeforeSHA256, options.undo) }
		}
	}
	temp, err := os.MkdirTemp("", "embarass-fix-probe-*")
	if err != nil {
		return fmt.Errorf("create isolated probe directory: %w", err)
	}
	defer func() { _ = os.Remove(temp) }()
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	model := newFixModel(ui.styles, plan, options.undo, app.displayedInvocation())
	model.confirmed, model.running = true, true
	model.cancel = cancel
	model.steps = app.fixSteps(ctx, plan, temp, commit, options.undo)
	if interactive {
		program := tea.NewProgram(model, tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.ErrOrStderr()))
		final, err := program.Run()
		if err != nil {
			return fmt.Errorf("run repair display; inspect bundle and recovery record before retrying: %w", err)
		}
		model = final.(fixModel)
	} else {
		for i := range model.steps {
			result := model.steps[i].run()
			model.record(i, result)
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %s\n", model.steps[i].label, result.detail); err != nil {
				return fmt.Errorf("write repair progress: %w", err)
			}
			if model.failed {
				break
			}
		}
		model.done = true
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), model.View()); err != nil {
			return fmt.Errorf("write repair result: %w", err)
		}
	}
	app.exitCode = model.exitCode()
	return nil
}

func commitWithSudo(executable, expected string, undo bool) (repair.Receipt, error) {
	args := []string{"-n", "--", executable, "_fix-commit", expected}
	if undo {
		args = append(args, "--undo")
	}
	// Deliberately not CommandContext: cancellation must not kill a file
	// transaction halfway through. The UI waits for its durable receipt.
	command := exec.Command("/usr/bin/sudo", args...)
	var output, stderr bytes.Buffer
	command.Stdout, command.Stderr = &output, &stderr
	if err := command.Run(); err != nil {
		return repair.Receipt{}, fmt.Errorf("repair transaction: %w: %s", err, oneLine(stderr.String()))
	}
	var receipt repair.Receipt
	if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
		return receipt, fmt.Errorf("read transaction receipt; inspect bundle before retrying: %w", err)
	}
	return receipt, nil
}

func (app *application) fixSteps(ctx context.Context, plan repair.Plan, emptyCAPath string, commit func() (repair.Receipt, error), undo bool) []fixStep {
	steps := make([]fixStep, 0, 5)
	bundle := plan.BundlePath
	if bundle == "" {
		bundle = repair.BundlePath
	}
	probe := func(chain certforge.Chain, after bool) fixStep {
		prefix := "BEFORE"
		if after {
			prefix = "AFTER"
		}
		return fixStep{label: prefix + " / " + chainShortDescription(chain), after: after, run: func() fixStepResult {
			if os.Geteuid() == 0 {
				return fixStepResult{detail: "NOT TESTED · run as a normal user to verify", outcome: runner.OutcomeInconclusive}
			}
			result, err := app.run(ctx, runner.Options{
				Command: []string{"/usr/bin/curl", "-q", "--silent", "--output", "/dev/null", "--cacert", bundle,
					"--capath", emptyCAPath, "--noproxy", "", "--max-time", "12", "--retry", "0", "https://example.com/"},
				Chain: chain, Timeout: 15 * time.Second, Stdout: io.Discard, Stderr: io.Discard, WorkingDirectory: emptyCAPath,
			})
			// A generic TLS failure is not evidence of certificate rejection.
			if err != nil || (result.Outcome == runner.OutcomeRejected && result.ChildExitCode != 60) {
				return fixStepResult{detail: "NO SIGNAL · certificate decision not confirmed", outcome: runner.OutcomeInconclusive}
			}
			// Some curl TLS backends verify certificates after completing the
			// handshake, then close without an alert. For this fixed HTTPS probe,
			// exit 60 plus observed tunnel traffic is explicit peer rejection.
			if result.Outcome == runner.OutcomeInconclusive && result.Reason == runner.ReasonNoTLSDecision && result.ChildExitCode == 60 {
				return fixStepResult{detail: "REJECTED · curl certificate verification failed", outcome: runner.OutcomeRejected}
			}
			switch result.Outcome {
			case runner.OutcomeVulnerable:
				return fixStepResult{detail: "ACCEPTED · forged certificate trusted", outcome: result.Outcome}
			case runner.OutcomeRejected:
				return fixStepResult{detail: "REJECTED · forged certificate denied", outcome: result.Outcome}
			default:
				return fixStepResult{detail: "NO SIGNAL · verification inconclusive", outcome: runner.OutcomeInconclusive}
			}
		}}
	}
	if !undo && commit != nil {
		for _, chain := range allChains {
			steps = append(steps, probe(chain, false))
		}
	}
	if commit != nil {
		label := "BACKUP + ATOMIC REPAIR"
		if undo {
			label = "RESTORE ORIGINAL BUNDLE"
		}
		if plan.Refresh != "" {
			label = "UPDATE NATIVE POLICY + REBUILD"
			if undo {
				label = "REVERSE LOCAL POLICY + REBUILD"
			}
		}
		steps = append(steps, fixStep{label: label, transaction: true, run: func() fixStepResult {
			receipt, err := commit()
			if err != nil {
				return fixStepResult{detail: err.Error(), err: err, receipt: receipt}
			}
			detail := fmt.Sprintf("COMMITTED · %d certificate blocks removed", len(plan.Removed))
			if undo {
				detail = "RESTORED · original trust anchors reintroduced"
			}
			if plan.Refresh != "" {
				detail = fmt.Sprintf("REGENERATED · %d affected roots distrusted", len(plan.Removed))
				if undo {
					detail = "REBUILT · current vendor policy retained"
				}
			}
			return fixStepResult{detail: detail, receipt: receipt}
		}})
	}
	if !undo {
		for _, chain := range allChains {
			steps = append(steps, probe(chain, true))
		}
	}
	return steps
}
