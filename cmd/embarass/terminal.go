// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/boostsecurityio/emBarrass/pkg/certforge"
	"github.com/boostsecurityio/emBarrass/pkg/runner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
)

const (
	terminalLogo = `╔═╗╔╦╗╔╗ ╔═╗╦═╗╦═╗╔═╗╔═╗╔═╗
║╣ ║║║╠╩╗╠═╣╠╦╝╠╦╝╠═╣╚═╗╚═╗
╚═╝╩ ╩╚═╝╩ ╩╩╚═╩╚═╩ ╩╚═╝╚═╝`

	terminalTagline       = `putting the “em” in MITM`
	ceremonyStepDelay     = 65 * time.Millisecond
	ceremonyInteriorWidth = 64
)

var ceremonySteps = []struct {
	label  string
	status string
}{
	{label: "load P-384 public point Q", status: "Q = d×G"},
	{label: `begin "advanced cryptanalysis"`, status: "TRY d = 1…255"},
	{label: "do grade-school math: 1×G, 2×G, …", status: "156×G = Q"},
	{label: `admire all ≈8 bits of "entropy"`, status: "d = 0x9c"},
	{label: "arm local TLS interceptor", status: "ARMED"},
}

type terminalUI struct {
	output      io.Writer
	styles      terminalStyles
	interactive bool
}

type terminalStyles struct {
	bold       lipgloss.Style
	muted      lipgloss.Style
	red        lipgloss.Style
	redBold    lipgloss.Style
	green      lipgloss.Style
	greenBold  lipgloss.Style
	yellow     lipgloss.Style
	yellowBold lipgloss.Style
	cyan       lipgloss.Style
	cyanBold   lipgloss.Style
}

func newTerminalUI(output io.Writer) terminalUI {
	renderer := lipgloss.NewRenderer(output)
	return terminalUI{
		output:      output,
		styles:      newTerminalStyles(renderer),
		interactive: isTerminal(output),
	}
}

func newTerminalStyles(renderer *lipgloss.Renderer) terminalStyles {
	red := lipgloss.Color("#ff4d5f")
	green := lipgloss.Color("#4ee6a8")
	yellow := lipgloss.Color("#ffc857")
	cyan := lipgloss.Color("#53d8fb")
	muted := lipgloss.Color("#758494")

	return terminalStyles{
		bold:       renderer.NewStyle().Bold(true),
		muted:      renderer.NewStyle().Foreground(muted),
		red:        renderer.NewStyle().Foreground(red),
		redBold:    renderer.NewStyle().Foreground(red).Bold(true),
		green:      renderer.NewStyle().Foreground(green),
		greenBold:  renderer.NewStyle().Foreground(green).Bold(true),
		yellow:     renderer.NewStyle().Foreground(yellow),
		yellowBold: renderer.NewStyle().Foreground(yellow).Bold(true),
		cyan:       renderer.NewStyle().Foreground(cyan),
		cyanBold:   renderer.NewStyle().Foreground(cyan).Bold(true),
	}
}

func isTerminal(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	fd := file.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func (ui terminalUI) start(
	command []string,
	chains []certforge.Chain,
	timeout time.Duration,
	adjustments []runner.CommandAdjustment,
) error {
	model := newCeremonyModel(ui.styles, command, chains, timeout, adjustments)
	if ui.interactive {
		program := tea.NewProgram(
			model,
			tea.WithOutput(ui.output),
			tea.WithInput(nil),
			tea.WithoutSignalHandler(),
		)
		if _, err := program.Run(); err != nil {
			return fmt.Errorf("run terminal ceremony: %w", err)
		}
	} else {
		model.stage = len(ceremonySteps)
		if _, err := fmt.Fprint(ui.output, model.View()); err != nil {
			return fmt.Errorf("write terminal ceremony: %w", err)
		}
	}

	if _, err := fmt.Fprintln(
		ui.output,
		"\n\n  CHILD OUTPUT "+strings.Repeat("─", 47),
	); err != nil {
		return fmt.Errorf("write terminal child output separator: %w", err)
	}
	return nil
}

func (ui terminalUI) result(result runner.Result, chains []certforge.Chain, exitCode int) error {
	var rendered string
	switch result.Outcome {
	case runner.OutcomeVulnerable:
		rendered = ui.vulnerableResult(result, chains, exitCode)
	case runner.OutcomeRejected:
		rendered = ui.rejectedResult(result, chains, exitCode)
	case runner.OutcomeInconclusive:
		rendered = ui.inconclusiveResult(result, chains, exitCode)
	default:
		return fmt.Errorf("render unknown runner outcome %q", result.Outcome)
	}

	if _, err := fmt.Fprintf(ui.output, "\n%s\n", rendered); err != nil {
		return fmt.Errorf("write terminal result: %w", err)
	}
	return nil
}

// pathHeader marks where one trust path's child output starts. A failed write
// is not fatal here; the result write that follows reports it.
func (ui terminalUI) pathHeader(chain certforge.Chain) {
	_, _ = fmt.Fprintln(ui.output, "  "+ui.styles.cyanBold.Render("PATH")+"  "+ui.styles.muted.Render(chainDescription(chain)))
}

func (ui terminalUI) vulnerableResult(
	result runner.Result,
	chains []certforge.Chain,
	exitCode int,
) string {
	lines := make([]string, 0, 9)
	lines = append(lines,
		ui.resultPanel("COMPLETELY EMBARRASSED", ui.styles.redBold),
		"",
		ui.detail(ui.styles.redBold, "PROOF", "forged certificate accepted · application data seen"),
		ui.detail(ui.styles.redBold, "STOP", "child process terminated before data left this machine"),
		ui.detail(ui.styles.redBold, "CAUSE", "eMudhra signing key had just 255 possible values"),
		"",
	)
	lines = append(lines, ui.resultMetadata(result, chains, exitCode)...)
	return strings.Join(lines, "\n")
}

func (ui terminalUI) rejectedResult(
	result runner.Result,
	chains []certforge.Chain,
	exitCode int,
) string {
	lines := make([]string, 0, 7)
	lines = append(lines,
		ui.resultPanel("TRUST HELD. CHAIN DENIED.", ui.styles.greenBold),
		"",
		"     The command reached the interceptor and rejected the forgery.",
		"",
	)
	lines = append(lines, ui.resultMetadata(result, chains, exitCode)...)
	return strings.Join(lines, "\n")
}

func (ui terminalUI) inconclusiveResult(
	result runner.Result,
	chains []certforge.Chain,
	exitCode int,
) string {
	lines := []string{
		ui.resultPanel("NO SIGNAL", ui.styles.yellowBold),
		"",
		"     " + inconclusiveDescription(result.Reason),
		ui.detail(ui.styles.yellowBold, "REASON", string(result.Reason)),
	}
	if result.ChildExitCode != 0 {
		lines = append(lines, ui.detail(
			ui.styles.yellowBold,
			"CHILD",
			fmt.Sprintf("exited with status %d", result.ChildExitCode),
		))
	}
	lines = append(lines, "")
	lines = append(lines, ui.resultMetadata(result, chains, exitCode)...)
	return strings.Join(lines, "\n")
}

func (ui terminalUI) resultMetadata(
	result runner.Result,
	chains []certforge.Chain,
	exitCode int,
) []string {
	lines := make([]string, 0, 3)
	if result.Host != "" {
		lines = append(lines, ui.detail(ui.styles.cyanBold, "HOST", result.Host))
	}
	lines = append(lines,
		ui.detail(ui.styles.cyanBold, "CHAIN", chainsDescription(chains)),
		ui.detail(
			ui.styles.bold,
			"EXIT",
			fmt.Sprintf("%d · %s", exitCode, humanDuration(result.Duration)),
		),
	)
	return lines
}

func (ui terminalUI) failure(err error) error {
	lines := []string{
		ui.styles.redBold.Render(terminalLogo),
		ui.styles.muted.Render(centeredTagline(terminalLogo)),
		"",
	}
	return ui.writeFailure(lines, err)
}

func (ui terminalUI) missingCommand(invocation string) error {
	lines := []string{
		ui.styles.redBold.Render(terminalLogo),
		ui.styles.muted.Render(centeredTagline(terminalLogo)),
		"",
		ui.resultPanel("PICK A TARGET", ui.styles.yellowBold),
		"",
		"     Wrap a command that makes a public HTTPS request:",
		"",
		"     " + ui.styles.cyanBold.Render("curl") + "   " + invocation + " curl --silent https://example.com/",
		"     " + ui.styles.cyanBold.Render("git") + "    " + invocation + " git ls-remote https://github.com/actions/checkout.git HEAD",
		"     " + ui.styles.cyanBold.Render("gh") + "     " + invocation + " gh api meta --silent",
		"     " + ui.styles.cyanBold.Render("wget") + "   " + invocation + " wget --spider https://example.com/",
		"",
		"     Or discover and safely test supported tools:",
		"     " + ui.styles.greenBold.Render(invocation+" batch"),
		"",
		"     " + ui.styles.muted.Render("More examples: "+invocation+" --help"),
		ui.detail(ui.styles.bold, "EXIT", strconv.Itoa(exitInconclusive)),
	}
	if _, err := fmt.Fprintf(ui.output, "\n%s\n", strings.Join(lines, "\n")); err != nil {
		return fmt.Errorf("write missing command help: %w", err)
	}
	return nil
}

func (ui terminalUI) failureAfterStart(err error) error {
	return ui.writeFailure(nil, err)
}

func (ui terminalUI) writeFailure(lines []string, err error) error {
	lines = append(lines,
		ui.resultPanel("HARNESS FAULT", ui.styles.redBold),
		"",
		"     "+err.Error(),
		"",
		ui.detail(ui.styles.bold, "EXIT", strconv.Itoa(exitInconclusive)),
	)
	if _, writeErr := fmt.Fprintf(ui.output, "\n%s\n", strings.Join(lines, "\n")); writeErr != nil {
		return fmt.Errorf("write terminal error: %w", writeErr)
	}
	return nil
}

func (ui terminalUI) resultPanel(title string, style lipgloss.Style) string {
	panel := style.
		Border(lipgloss.DoubleBorder()).
		BorderForeground(style.GetForeground()).
		Width(54).
		Align(lipgloss.Center).
		Padding(0, 1).
		MarginLeft(2)
	return panel.Render(title)
}

func (ui terminalUI) detail(style lipgloss.Style, label, value string) string {
	return "     " + style.Width(8).Render(label) + value
}

type ceremonyTickMsg struct{}

type ceremonyModel struct {
	styles      terminalStyles
	command     string
	chains      []certforge.Chain
	timeout     time.Duration
	adjustments []runner.CommandAdjustment
	stage       int
	width       int
}

func newCeremonyModel(
	styles terminalStyles,
	command []string,
	chains []certforge.Chain,
	timeout time.Duration,
	adjustments []runner.CommandAdjustment,
) ceremonyModel {
	commandName := "command"
	if len(command) > 0 {
		commandName = filepath.Base(command[0])
	}
	return ceremonyModel{
		styles:      styles,
		command:     truncate(commandName, 16),
		chains:      chains,
		timeout:     timeout,
		adjustments: adjustments,
		width:       80,
	}
}

func (model ceremonyModel) Init() tea.Cmd {
	return ceremonyTick()
}

func (model ceremonyModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case ceremonyTickMsg:
		model.stage++
		if model.stage >= len(ceremonySteps) {
			model.stage = len(ceremonySteps)
			return model, tea.Quit
		}
		return model, ceremonyTick()
	case tea.WindowSizeMsg:
		model.width = message.Width
	}
	return model, nil
}

func ceremonyTick() tea.Cmd {
	return tea.Tick(ceremonyStepDelay, func(time.Time) tea.Msg {
		return ceremonyTickMsg{}
	})
}

func (model ceremonyModel) View() string {
	logoText := terminalLogo
	if model.width > 0 && model.width < 66 {
		logoText = "emBarrass // TLS TRUST BREAKER"
	}
	logo := model.styles.redBold.Render(logoText)

	lines := []string{
		logo,
		model.styles.muted.Render(centeredTagline(logoText)),
		"",
		model.ceremonyPanel(),
		"  " + model.styles.yellowBold.Render("P-384: STILL SECURE") + "   " +
			model.styles.redBold.Render("KEYGEN: GOLD STAR FOR TRYING"),
		"",
		"  " + model.styles.cyanBold.Render("COMMAND") + "  " + model.command +
			model.styles.muted.Render(" · arguments hidden"),
		"  " + model.styles.cyanBold.Render("CHAIN") + "    " + chainsShortDescription(model.chains) +
			"   " + model.styles.cyanBold.Render("LIMIT") + "  " + timeoutDescription(model.timeout, len(model.chains)),
		"  " + model.styles.cyanBold.Render("MODE") + "     local-only · upstream severed",
		"",
		"                 " + model.styles.cyan.Render("CONNECT") + "             " +
			model.styles.red.Render("FORGED TLS"),
		fmt.Sprintf(
			"  [ %-10s ] ━━━━━▶ [ emBarrass ] ━━━━━▶ [ HTTPS target ]",
			model.command,
		),
		"                                  │                    " + model.styles.red.Render("╳"),
		"                                  └──── " + model.styles.muted.Render("NO UPSTREAM") + " ────┘",
	}
	for _, adjustment := range model.adjustments {
		switch adjustment {
		case runner.AdjustmentGitHTTPSPinned:
			lines = append(lines, "", "  "+model.styles.cyanBold.Render("ADJUST")+
				"  Git HTTPS pinned · insteadOf transport rewrite bypassed")
		case runner.AdjustmentGHCredentialsIsolated:
			lines = append(lines, "", "  "+model.styles.cyanBold.Render("ADJUST")+
				"  GitHub CLI public probe · user credentials bypassed")
		}
	}
	lines = append(lines, "", model.progressLine())
	return strings.Join(lines, "\n")
}

func (model ceremonyModel) ceremonyPanel() string {
	heading := "─ KEY CEREMONY REPLAY · GRADE-SCHOOL MATH "
	lines := make([]string, 0, len(ceremonySteps)+2)
	lines = append(lines,
		"  ┌"+heading+strings.Repeat(
			"─",
			ceremonyInteriorWidth-lipgloss.Width(heading),
		)+"┐",
	)
	for index, step := range ceremonySteps {
		status := "…"
		lineStyle := model.styles.muted
		if index < model.stage {
			status = step.status
			lineStyle = model.styles.green
		} else if index == model.stage {
			lineStyle = model.styles.yellow
		}
		row := fmt.Sprintf(
			"  │ [%02d/%02d] %-35s %18s │",
			index+1,
			len(ceremonySteps),
			step.label,
			status,
		)
		lines = append(lines, lineStyle.Render(row))
	}
	lines = append(lines, "  └"+strings.Repeat("─", ceremonyInteriorWidth)+"┘")
	return strings.Join(lines, "\n")
}

func (model ceremonyModel) progressLine() string {
	if model.stage < len(ceremonySteps) {
		return model.styles.yellowBold.Render("  ◉  ARMING LOCAL INTERCEPTOR_")
	}
	return model.styles.yellowBold.Render("  ◉  PRESENTING COMPROMISED TRUST PATH_") +
		"\n     Waiting for one application byte—the client’s confession."
}

func timeoutDescription(timeout time.Duration, paths int) string {
	if timeout == 0 {
		return "disabled"
	}
	if paths > 1 {
		return timeout.String() + " per path"
	}
	return timeout.String()
}

func chainShortDescription(chain certforge.Chain) string {
	switch chain {
	case certforge.ChainSectigo:
		return "Sectigo / AAA"
	case certforge.ChainEMSign:
		return "direct eMudhra"
	default:
		return string(chain)
	}
}

func chainsShortDescription(chains []certforge.Chain) string {
	descriptions := make([]string, 0, len(chains))
	for _, chain := range chains {
		descriptions = append(descriptions, chainShortDescription(chain))
	}
	return strings.Join(descriptions, " + ")
}

func truncate(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	if maximum <= 1 {
		return string(runes[:maximum])
	}
	return string(runes[:maximum-1]) + "…"
}

func chainDescription(chain certforge.Chain) string {
	switch chain {
	case certforge.ChainSectigo:
		return "sectigo (AAA Certificate Services cross-chain)"
	case certforge.ChainEMSign:
		return "emsign (direct eMudhra chain)"
	default:
		return string(chain)
	}
}

func chainsDescription(chains []certforge.Chain) string {
	if len(chains) == 1 {
		return chainDescription(chains[0])
	}
	return chainNames(chains, " + ") + " (every tested trust path)"
}

func inconclusiveDescription(reason runner.Reason) string {
	switch reason {
	case runner.ReasonNoTraffic:
		return "No HTTPS CONNECT reached the interceptor; check for SSH or proxy bypass."
	case runner.ReasonNoTLSDecision:
		return "The command connected, but no definitive TLS decision was observed."
	case runner.ReasonTimeout:
		return "The deadline expired before emBarrass could reach a verdict."
	default:
		return "emBarrass could not confirm whether the command is vulnerable."
	}
}

func humanDuration(duration time.Duration) time.Duration {
	if duration < time.Millisecond {
		return duration.Round(time.Microsecond)
	}
	return duration.Round(time.Millisecond)
}

func centeredTagline(logo string) string {
	logoWidth := 0
	for line := range strings.SplitSeq(logo, "\n") {
		logoWidth = max(logoWidth, lipgloss.Width(line))
	}
	padding := max(0, (logoWidth-lipgloss.Width(terminalTagline))/2)
	return strings.Repeat(" ", padding) + terminalTagline
}
