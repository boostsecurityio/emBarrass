// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/repair"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type fixStep struct {
	label                        string
	after, transaction, finished bool
	run                          func() fixStepResult
	result                       fixStepResult
}

type fixStepResult struct {
	detail  string
	outcome runner.Outcome
	receipt repair.Receipt
	err     error
}

type fixTickMsg struct{}
type fixResultMsg struct {
	index  int
	result fixStepResult
}

type fixModel struct {
	styles                                                   terminalStyles
	plan                                                     repair.Plan
	invocation                                               string
	undo, dryRun, confirmed, running, done, canceled, failed bool
	cancelRequested                                          bool
	cancel                                                   context.CancelFunc
	width, frame, current                                    int
	steps                                                    []fixStep
	receipt                                                  repair.Receipt
}

func newFixModel(styles terminalStyles, plan repair.Plan, undo bool, invocation string) fixModel {
	if plan.Path == "" {
		plan.Path = repair.BundlePath
	}
	if plan.Platform == "" {
		plan.Platform = "macOS system PEM bundle"
	}
	return fixModel{styles: styles, plan: plan, undo: undo, invocation: invocation, width: 80}
}

func (model fixModel) Init() tea.Cmd {
	if !model.running {
		return nil
	}
	return tea.Batch(model.next(), fixTick())
}

func fixTick() tea.Cmd {
	return tea.Tick(90*time.Millisecond, func(time.Time) tea.Msg { return fixTickMsg{} })
}

func (model fixModel) next() tea.Cmd {
	index := model.current
	return func() tea.Msg { return fixResultMsg{index, model.steps[index].run()} }
}

func (model fixModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch message := msg.(type) {
	case tea.WindowSizeMsg:
		model.width = message.Width
	case tea.KeyMsg:
		key := strings.ToLower(message.String())
		if !model.running {
			if key == "y" {
				model.confirmed = true
				return model, tea.Quit
			}
			if key == "n" || key == "q" || key == "esc" || key == "enter" || key == "ctrl+c" {
				model.canceled = true
				return model, tea.Quit
			}
		} else if key == "q" || key == "esc" || key == "ctrl+c" {
			model.cancelRequested = true
			if model.cancel != nil {
				model.cancel()
			}
			// Wait for the current operation, especially an atomic transaction,
			// to return its receipt before leaving the UI.
		}
	case fixTickMsg:
		if model.running && !model.done {
			model.frame++
			return model, fixTick()
		}
	case fixResultMsg:
		if message.index != model.current || model.done {
			return model, nil
		}
		model.record(message.index, message.result)
		model.current++
		if model.cancelRequested || model.failed || model.current == len(model.steps) {
			model.canceled = model.cancelRequested
			model.done = true
			return model, tea.Quit
		}
		return model, model.next()
	}
	return model, nil
}

func (model *fixModel) record(index int, result fixStepResult) {
	model.steps[index].finished = true
	model.steps[index].result = result
	if result.receipt.Backup != "" {
		model.receipt = result.receipt
	}
	if result.err != nil {
		model.failed = true
	}
}

func (model fixModel) exitCode() int {
	if model.canceled || model.failed || !model.done {
		return exitInconclusive
	}
	if model.undo {
		return exitProtected
	}
	checked, unknown := 0, false
	for _, step := range model.steps {
		if !step.after {
			continue
		}
		if step.finished && step.result.outcome == runner.OutcomeVulnerable {
			return exitVulnerable
		}
		if !step.finished || step.result.outcome != runner.OutcomeRejected {
			unknown = true
		}
		checked++
	}
	if unknown || checked != len(allChains) {
		return exitInconclusive
	}
	return exitProtected
}

func (model fixModel) View() string {
	width := max(24, min(model.width-4, 88))
	inner := width - 4
	wrap := func(text string) string { return lipgloss.NewStyle().Width(inner).Render(text) }
	logo := terminalLogo
	if width < 64 {
		logo = "emBarrass // TRUST REPAIR"
	}
	logoStyle := model.styles.redBold
	if model.done && !model.undo && model.exitCode() == exitProtected {
		logoStyle = model.styles.greenBold
	}
	lines := []string{"", logoStyle.Render(logo), model.styles.muted.Render(centeredTagline(logo)), ""}
	title := "EMERGENCY TRUST REPAIR"
	if model.undo {
		title = "RESTORE ORIGINAL TRUST"
		if model.plan.Refresh != "" {
			title = "REVERSE LOCAL TRUST OVERRIDE"
		}
	}
	phase := "01 / INSPECT"
	if model.running {
		phase = "02 / REPAIR + CHALLENGE"
	}
	if model.done {
		phase = "03 / RECEIPT"
	}
	lines = append(lines, "  "+model.styles.cyanBold.Render(title), "  "+model.styles.muted.Render(phase), "")

	if !model.running {
		body := []string{
			wrap(model.styles.cyanBold.Render("TARGET") + "  " + model.plan.Path),
			model.styles.muted.Render(model.plan.Platform), "",
		}
		verb := "REMOVE"
		if model.undo {
			verb = "RESTORE"
		}
		if model.plan.Refresh != "" {
			verb = "DISTRUST"
			if model.undo {
				verb = "REVERSE OVERRIDE"
			}
		}
		for _, root := range model.plan.Removed {
			body = append(body, wrap(model.styles.redBold.Render("− "+verb)+"  "+root.Name),
				wrap(model.styles.muted.Render("SHA256 "+root.SHA256)), "")
		}
		if len(model.plan.Removed) == 0 {
			body = append(body, model.styles.cyanBold.Render("TARGET ROOTS ALREADY ABSENT"), "")
		}
		if model.plan.Refresh != "" {
			body = append(body, wrap(model.styles.muted.Render(fmt.Sprintf("%d certificates in the current TLS bundle", model.plan.Certificates))),
				wrap(model.styles.cyanBold.Render("REBUILD")+"  "+model.plan.Refresh))
		} else if !model.undo {
			body = append(body, model.styles.green.Render(fmt.Sprintf("%d other certificates preserved", model.plan.Certificates-len(model.plan.Removed))))
		} else {
			body = append(body, model.styles.yellow.Render("Restores the recorded original, including affected roots."))
		}
		lines = append(lines, model.box(strings.Join(body, "\n"), width, model.styles.cyan))
	} else {
		lines = append(lines, model.progress(width))
		for i, step := range model.steps {
			mark, style := "○", model.styles.muted
			if step.finished {
				mark, style = "✓", model.styles.green
				if step.result.err != nil || step.result.outcome == runner.OutcomeVulnerable {
					mark, style = "×", model.styles.red
				}
				if step.result.outcome == runner.OutcomeInconclusive {
					mark, style = "?", model.styles.yellow
				}
			} else if i == model.current && !model.done {
				mark, style = batchSpinnerFrames[model.frame%len(batchSpinnerFrames)], model.styles.cyanBold
			}
			lines = append(lines, "  "+style.Render(mark+"  "+step.label))
			if step.finished {
				lines = append(lines, "     "+wrap(style.Render(oneLine(step.result.detail))))
			}
		}
	}

	lines = append(lines, "")
	switch {
	case model.done:
		title, style := model.verdict()
		lines = append(lines, model.box(style.Bold(true).Render(wrap(title)), width, style))
		if model.receipt.Backup != "" {
			label := "BACKUP"
			if model.plan.Refresh != "" {
				label = "RECOVERY RECORD"
			}
			lines = append(lines, "", "  "+model.styles.cyanBold.Render(label), "  "+wrap(model.receipt.Backup))
			if !model.undo {
				lines = append(lines, "  "+model.styles.cyanBold.Render("UNDO")+"  "+model.invocation+" fix --undo")
			}
		}
		if !model.undo {
			lines = append(lines, "", "  "+wrap("Verification scope: system curl with the TLS bundle, both DV-G3B paths."))
		}
		lines = append(lines, "  "+wrap("Check other tools separately: "+model.invocation+" batch"),
			"  "+model.styles.muted.Render(fmt.Sprintf("EXIT %d", model.exitCode())))
	case model.canceled:
		lines = append(lines, "  "+model.styles.yellowBold.Render("CANCELED · bundle unchanged"))
	case model.running:
		status := "Forged TLS stays local. q stops after the current operation."
		if model.cancelRequested {
			status = "Stopping… waiting for the current operation's receipt."
		}
		lines = append(lines, "  "+wrap(model.styles.cyan.Render(status)))
	default:
		warning := "Legitimate chains relying solely on these roots will also lose trust."
		if model.undo {
			warning = "Undo reintroduces the original trust anchors and may restore exposure."
		}
		method := "Backup first · atomic replacement · conflict-aware undo"
		if model.plan.Refresh != "" {
			method = "Native updater + installed hooks · recorded changes · conflict-aware undo"
			if model.undo {
				warning = "Undo removes our overrides and rebuilds from current vendor policy. Exposure may return."
			}
		}
		lines = append(lines, "  "+wrap(model.styles.yellow.Render(warning)), "",
			"  "+wrap("Tools with private CA bundles and containers need separate checks."),
			"  "+wrap(model.styles.muted.Render(method)), "")
		if model.dryRun {
			lines = append(lines, "  "+model.styles.cyanBold.Render("DRY RUN · no changes or probes"))
		} else if model.confirmed {
			lines = append(lines, "  "+model.styles.cyanBold.Render("PLAN READY"))
		} else {
			prompt := "Apply this emergency repair?"
			if model.undo {
				prompt = "Restore the original trust bundle?"
				if model.plan.Refresh != "" {
					prompt = "Reverse our local override and rebuild trust?"
				}
			}
			lines = append(lines, "  "+wrap(model.styles.bold.Render(prompt)+" "+model.styles.yellowBold.Render("[y/N]")),
				"  "+model.styles.muted.Render("Only y proceeds. Enter, q, or esc cancels."))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func (model fixModel) box(body string, width int, style lipgloss.Style) string {
	return style.Border(lipgloss.RoundedBorder()).BorderForeground(style.GetForeground()).
		Width(width-2).Padding(0, 1).MarginLeft(2).Render(body)
}

func (model fixModel) progress(width int) string {
	completed := 0
	for _, step := range model.steps {
		if step.finished {
			completed++
		}
	}
	size := max(10, width-18)
	filled := 0
	if len(model.steps) != 0 {
		filled = size * completed / len(model.steps)
	}
	bar := model.styles.cyan.Render(strings.Repeat("━", filled)) + model.styles.muted.Render(strings.Repeat("─", size-filled))
	return fmt.Sprintf("  %s  %02d / %02d\n", bar, completed, len(model.steps))
}

func (model fixModel) verdict() (string, lipgloss.Style) {
	if model.failed {
		return "REPAIR INCOMPLETE · REVIEW THE RECEIPT", model.styles.red
	}
	if model.canceled {
		return "STOPPED · REVIEW COMPLETED STEPS", model.styles.yellow
	}
	if model.undo {
		if model.plan.Refresh != "" {
			return "LOCAL OVERRIDE REVERSED · STORE REBUILT", model.styles.yellow
		}
		return "ORIGINAL RESTORED · TRUST REINTRODUCED", model.styles.yellow
	}
	state := "BUNDLE PATCHED"
	if model.plan.Refresh != "" {
		state = "NATIVE TRUST REBUILT"
	}
	if len(model.plan.Removed) == 0 {
		state = "TARGET ROOTS ABSENT"
	}
	switch model.exitCode() {
	case exitProtected:
		return state + " · BOTH FORGERIES REJECTED", model.styles.green
	case exitVulnerable:
		return state + " · FORGERY STILL ACCEPTED", model.styles.red
	default:
		return state + " · VERIFICATION INCOMPLETE", model.styles.yellow
	}
}
