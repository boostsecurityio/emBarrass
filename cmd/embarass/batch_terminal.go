// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/batchtest"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const batchSpinnerDelay = 90 * time.Millisecond

const batchToolNameWidth = 12

var batchSpinnerFrames = []string{"◐", "◓", "◑", "◒"}

type batchItemState uint8

const (
	batchPending batchItemState = iota
	batchRunning
	batchVulnerable
	batchRejected
	batchInconclusive
	batchFailed
)

type batchItem struct {
	probe  batchtest.Probe
	state  batchItemState
	result runner.Result
	err    error
}

type batchModel struct {
	ctx       context.Context
	cancel    context.CancelFunc
	styles    terminalStyles
	plan      batchtest.Plan
	run       runFunc
	timeout   time.Duration
	items     []batchItem
	current   int
	spinner   int
	width     int
	autoStart bool
	confirmed bool
	done      bool
	canceled  bool
}

type batchStartMsg struct{}
type batchSpinnerMsg struct{}
type batchResultMsg struct {
	index  int
	result runner.Result
	err    error
}

func newBatchModel(
	ctx context.Context,
	cancel context.CancelFunc,
	styles terminalStyles,
	plan batchtest.Plan,
	run runFunc,
	timeout time.Duration,
	autoStart bool,
) batchModel {
	items := make([]batchItem, 0, len(plan.Probes))
	for _, probe := range plan.Probes {
		items = append(items, batchItem{probe: probe})
	}
	return batchModel{
		ctx:       ctx,
		cancel:    cancel,
		styles:    styles,
		plan:      plan,
		run:       run,
		timeout:   timeout,
		items:     items,
		width:     80,
		autoStart: autoStart,
	}
}

func (model batchModel) Init() tea.Cmd {
	if !model.autoStart {
		return nil
	}
	return func() tea.Msg { return batchStartMsg{} }
}

func (model batchModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width = message.Width
		return model, nil
	case tea.KeyMsg:
		key := strings.ToLower(message.String())
		if !model.confirmed {
			if key == "y" {
				return model.begin()
			}
			if key == "n" || key == "enter" || key == "q" || key == "ctrl+c" || key == "esc" {
				model.canceled = true
				model.done = true
				model.cancel()
				return model, tea.Quit
			}
			return model, nil
		}
		if key == "q" || key == "ctrl+c" || key == "esc" {
			model.canceled = true
			model.done = true
			model.cancel()
			return model, tea.Quit
		}
	case batchStartMsg:
		return model.begin()
	case batchSpinnerMsg:
		if model.done || !model.confirmed {
			return model, nil
		}
		model.spinner = (model.spinner + 1) % len(batchSpinnerFrames)
		return model, batchSpinnerTick()
	case batchResultMsg:
		if message.index < 0 || message.index >= len(model.items) {
			return model, nil
		}
		item := &model.items[message.index]
		item.result = message.result
		item.err = message.err
		item.state = batchState(message.result, message.err)

		model.current = message.index + 1
		if model.current >= len(model.items) {
			model.done = true
			return model, tea.Quit
		}
		model.items[model.current].state = batchRunning
		return model, model.runCurrent()
	}
	return model, nil
}

func (model batchModel) begin() (tea.Model, tea.Cmd) {
	model.confirmed = true
	if len(model.items) == 0 {
		model.done = true
		return model, tea.Quit
	}
	model.current = 0
	model.items[0].state = batchRunning
	return model, tea.Batch(model.runCurrent(), batchSpinnerTick())
}

func (model batchModel) runCurrent() tea.Cmd {
	index := model.current
	probe := model.items[index].probe
	return func() tea.Msg {
		result, err := model.run(
			model.ctx,
			batchRunnerOptions(model.plan, probe, model.timeout),
		)
		return batchResultMsg{index: index, result: result, err: err}
	}
}

func batchSpinnerTick() tea.Cmd {
	return tea.Tick(batchSpinnerDelay, func(time.Time) tea.Msg {
		return batchSpinnerMsg{}
	})
}

func batchState(result runner.Result, err error) batchItemState {
	if err != nil {
		return batchFailed
	}
	switch result.Outcome {
	case runner.OutcomeVulnerable:
		return batchVulnerable
	case runner.OutcomeRejected:
		return batchRejected
	case runner.OutcomeInconclusive:
		return batchInconclusive
	default:
		return batchFailed
	}
}

func (model batchModel) View() string {
	logoText := terminalLogo
	if model.width > 0 && model.width < 70 {
		logoText = "emBarrass // BATCH TLS TRUST SWEEP"
	}
	logo := model.styles.redBold.Render(logoText)
	lines := []string{
		logo,
		model.styles.muted.Render(centeredTagline(logoText)),
		"",
		"  " + model.styles.cyanBold.Render("BATCH TRUST PREFLIGHT"),
		"  " + model.styles.muted.Render("intercepted traffic stays local · temporary caches removed"),
		"",
	}
	if model.mayPullImage() {
		lines = append(lines,
			"  "+model.styles.yellowBold.Render("IMAGE")+"  "+
				model.styles.muted.Render("docker/git may pull and retain one digest-pinned image"),
			"",
		)
	}

	previewWidth := model.width - 31
	if previewWidth < 24 {
		previewWidth = 24
	}
	for _, item := range model.items {
		status, statusStyle := model.itemStatus(item)
		left := fmt.Sprintf(
			"  %s  %-*s ",
			statusStyle.Width(13).Render(status),
			batchToolNameWidth,
			item.probe.Name,
		)
		preview := model.styles.muted.Render(wrapCommand(item.probe.Preview, previewWidth))
		lines = append(lines, lipgloss.JoinHorizontal(lipgloss.Top, left, preview))
		if item.err != nil {
			lines = append(lines, "                 "+model.styles.red.Render(truncate(oneLine(item.err.Error()), previewWidth+8)))
		}
	}
	for _, name := range model.plan.Unavailable {
		lines = append(lines, fmt.Sprintf(
			"  %s  %-*s %s",
			model.styles.muted.Width(13).Render("SKIP"),
			batchToolNameWidth,
			name,
			model.styles.muted.Render("not found in PATH"),
		))
	}

	lines = append(lines, "")
	switch {
	case model.canceled:
		message := "No probes were run."
		if model.confirmed {
			message = "The active child was stopped; remaining probes were not run."
		}
		lines = append(lines, model.styles.yellowBold.Render("  CANCELED")+"  "+message)
	case !model.confirmed:
		lines = append(lines,
			"  "+model.styles.bold.Render(fmt.Sprintf("Run %d available probes?", len(model.items)))+" "+
				model.styles.yellowBold.Render("[y/N]"),
			"  "+model.styles.muted.Render("Only y starts the sweep. q or esc cancels."),
		)
	case model.done:
		summary := model.summary()
		lines = append(lines, model.batchVerdict(summary), "", "  "+summary.String())
	default:
		lines = append(lines,
			"  "+model.styles.yellowBold.Render("Testing sequentially…")+
				" "+model.styles.muted.Render("q cancels the active child and remaining probes"),
		)
	}
	return strings.Join(lines, "\n")
}

func (model batchModel) mayPullImage() bool {
	for _, item := range model.items {
		if item.probe.MayPullImage {
			return true
		}
	}
	return false
}

func (model batchModel) itemStatus(item batchItem) (string, lipgloss.Style) {
	switch item.state {
	case batchRunning:
		return batchSpinnerFrames[model.spinner] + " TESTING", model.styles.yellowBold
	case batchVulnerable:
		return "EMBARRASSED", model.styles.redBold
	case batchRejected:
		return "TRUST HELD", model.styles.greenBold
	case batchInconclusive:
		return "NO SIGNAL", model.styles.yellowBold
	case batchFailed:
		return "ERROR", model.styles.redBold
	default:
		return "READY", model.styles.cyanBold
	}
}

func (model batchModel) batchVerdict(summary batchSummary) string {
	style := model.styles.greenBold
	title := "BATCH COMPLETE"
	if summary.vulnerable > 0 {
		style = model.styles.redBold
		if summary.rejected+summary.inconclusive+summary.failed > 0 {
			title = "PARTIALLY EMBARRASSED"
		} else {
			title = "COMPLETELY EMBARRASSED"
		}
	} else if summary.inconclusive > 0 || summary.failed > 0 {
		style = model.styles.yellowBold
		title = "BATCH COMPLETE · SOME SIGNALS MISSING"
	}
	return style.
		Border(lipgloss.DoubleBorder()).
		BorderForeground(style.GetForeground()).
		Width(54).
		Align(lipgloss.Center).
		MarginLeft(2).
		Render(title)
}

func (model batchModel) summary() batchSummary {
	summary := batchSummary{skipped: len(model.plan.Unavailable), canceled: model.canceled}
	for _, item := range model.items {
		if item.state == batchPending || item.state == batchRunning {
			continue
		}
		summary.record(item.result, item.err)
	}
	return summary
}

func oneLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return line
}

func wrapCommand(value string, width int) string {
	words := strings.Fields(value)
	if len(words) == 0 || width <= 0 {
		return value
	}

	lines := make([]string, 0, 2)
	line := words[0]
	for _, word := range words[1:] {
		if len([]rune(line))+1+len([]rune(word)) <= width {
			line += " " + word
			continue
		}
		lines = append(lines, line)
		line = word
	}
	return strings.Join(append(lines, line), "\n")
}
