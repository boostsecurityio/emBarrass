// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"strings"

	"github.com/boostsecurityio/emBarrass/pkg/batchtest"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Guidance describes known trust mechanisms, not a claim that batch inspected
// a client's CA configuration or detected its installation/package manager.
type remediation struct {
	cause, coverage, remediation, details string
	commands                              []string
}

func remediationFor(probe batchtest.Probe, platform, invocation string) remediation {
	invocation = displayedInvocation(invocation)
	r := remediation{
		cause:       "Trust depends on this tool's build, runtime, and CA configuration. Batch confirms acceptance but does not identify the exact CA source.",
		coverage:    "fix repairs a supported system CA store. It does not update installed applications or their private trust stores.",
		remediation: "Update this tool through the installer or package manager you used, then rerun batch. If still exposed, check its CA overrides and runtime trust settings.",
		details:     "A package update can refresh bundled roots, a runtime, or a trust-library dependency. A better result after upgrading does not by itself prove which changed. TRUST HELD only covers the paths tested in that run.",
		commands:    []string{invocation + " batch"},
	}
	if probe.Containerized {
		r.cause = "This process uses trust inside its container. The docker/git probe deliberately uses a historical, digest-pinned vulnerable image."
		r.coverage = "Host repair and host package upgrades do not repair this container image."
		r.remediation = "For your workloads, update CA packages in the image, rebuild, and redeploy. Test the replacement image's actual client."
		r.details = "The built-in historical fixture can remain EMBARRASSED after a successful host repair. Its result is not evidence that the host repair failed."
		r.commands = nil
		return r
	}
	switch probe.Name {
	case "gcloud":
		r.cause = "The Google Cloud SDK normally supplies its own CA bundle; changing /etc/ssl/cert.pem alone need not affect it."
		r.coverage = "fix does not edit the SDK bundle. gcloud can be configured to use a repaired CA file."
		r.remediation = "Update the SDK through its original installer. Alternatively, point CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE at a verified, patched bundle that includes any required enterprise CAs."
		r.details = "Batch uses a temporary gcloud configuration to isolate credentials, so saved gcloud config properties are not loaded. It inherits the CA environment variable. An export affects this shell and its child processes; repeat the setting where you actually run gcloud."
		if platform == "darwin" {
			r.commands = []string{invocation + " fix --dry-run", "export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=/etc/ssl/cert.pem", invocation + " batch"}
			r.remediation += " For the commands below, first confirm fix --dry-run says TARGET ROOTS ALREADY ABSENT; otherwise apply fix and verify it before setting the override."
		}
	case "dotnet":
		switch platform {
		case "darwin":
			r.cause = ".NET on macOS uses Apple's native trust APIs and Keychain trust. Sharing trust anchors with Safari does not guarantee the same certificate-validation policy."
			r.coverage = "The macOS PEM repair does not change Keychain trust. SSL_CERT_FILE is not a remedy for this native trust path."
			r.remediation = "Update macOS and the .NET SDK/runtime, then recheck. If exposure remains, explicit native distrust needs a separate, reviewed Keychain change; this is not implemented by fix."
			r.details = "Acceptance here does not identify which revocation or policy check was missing. Do not assume Safari's protection covers this client, and do not disable TLS verification as a workaround."
		case "linux":
			r.cause = ".NET on Linux generally uses OpenSSL and system trust. Its configuration and container boundary still matter."
			r.coverage = "Native Linux CA-package updates or fix on a supported distribution may help this trust path. Recheck the actual client."
		default:
			r.cause = ".NET uses platform-native trust; the macOS PEM repair does not apply to Windows."
		}
	case "curl", "git", "gem", "cargo", "wget", "composer":
		if platform == "darwin" || platform == "linux" {
			r.cause = "These clients can use system/OpenSSL CA bundles. Their build and CA overrides determine whether they consult the store repaired by fix."
			r.coverage = "System-store repair may help. curl, git, gem, and cargo improved in our macOS testing; this is not a guarantee for every installation."
			r.remediation = "Prefer vendor CA-package and tool updates. For emergency mitigation, preview and apply fix on a supported system, then rerun batch. If still exposed, inspect this tool's CA configuration."
			r.commands = []string{invocation + " fix --dry-run", invocation + " fix", invocation + " batch"}
		}
	case "aws", "python", "pip", "node", "npm", "pnpm", "uv", "httpie":
		r.cause = "This tool may use bundled roots, a Python/Node runtime trust set, system trust, or an override. The choice varies by version and distribution."
		r.coverage = "A package/runtime update may be needed even after system repair. fix does not rewrite private CA bundles."
		if platform == "darwin" {
			r.remediation = "If installed with Homebrew, update Homebrew's package metadata and upgrade the installed formula/cask, then rerun batch. Otherwise use the original installer."
			formula := map[string]string{"aws": "awscli", "python": "python", "node": "node", "uv": "uv"}[probe.Name]
			if formula != "" {
				r.commands = []string{"brew update", "brew upgrade " + formula, invocation + " batch"}
				r.details += " The Homebrew commands are examples, not detected installation advice. Use your installed formula name, such as python@X.Y or node@X, when version-pinned."
			}
		}
	}
	if platform != "darwin" && platform != "linux" {
		r.coverage = "fix does not support this platform. Use OS and application trust updates, then recheck."
	}
	return r
}

func (model batchModel) exposedItems() []batchItem {
	var items []batchItem
	for _, item := range model.items {
		if item.state == batchVulnerable {
			items = append(items, item)
		}
	}
	return items
}

func (model batchModel) reviewKey(key string) (tea.Model, tea.Cmd) {
	if key == "q" || key == "enter" || key == "ctrl+c" || (key == "esc" && !model.detailsExpanded) {
		return model, tea.Quit // Reviewing a completed result is not cancellation.
	}
	if len(model.exposedItems()) == 0 {
		return model, nil
	}
	if key == "d" || key == "esc" {
		model.detailsExpanded = !model.detailsExpanded
		model.detailScroll = 0
		return model, nil
	}
	if !model.detailsExpanded {
		return model, nil
	}
	switch key {
	case "right", "tab", "n":
		model.detailIndex = (model.detailIndex + 1) % len(model.exposedItems())
		model.detailScroll = 0
	case "left", "shift+tab", "p":
		model.detailIndex = (model.detailIndex + len(model.exposedItems()) - 1) % len(model.exposedItems())
		model.detailScroll = 0
	case "down", "j":
		model.detailScroll++
	case "up", "k":
		model.detailScroll--
	case "pgdown", " ":
		model.detailScroll += model.detailPageSize()
	case "pgup":
		model.detailScroll -= model.detailPageSize()
	case "home":
		model.detailScroll = 0
	case "end":
		model.detailScroll = len(model.remediationLines())
	}
	model.detailScroll = max(0, min(model.detailScroll, len(model.remediationLines())-model.detailPageSize()))
	return model, nil
}

func (model batchModel) detailPageSize() int { return max(3, model.height-9) }

func (model batchModel) remediationLines() []string {
	items := model.exposedItems()
	item := items[model.detailIndex%len(items)]
	r := remediationFor(item.probe, model.platform, model.invocation)
	width := max(20, min(model.width-4, 90))
	wrap := lipgloss.NewStyle().Width(width).Render
	sections := []string{
		model.styles.redBold.Render("OBSERVED") + "  Forged TLS accepted; application data seen.",
		model.styles.muted.Render("Mixed results can reflect different stores. The trust path below is guidance, not a configuration audit."), "",
		model.styles.cyanBold.Render("LIKELY TRUST PATH"), r.cause, "",
		model.styles.yellowBold.Render("WHAT FIX COVERS"), r.coverage, "",
		model.styles.greenBold.Render("REMEDIATION"), r.remediation,
	}
	if len(r.commands) > 0 {
		sections = append(sections, "", model.styles.cyanBold.Render("COMMANDS TO RUN YOURSELF"))
		for _, command := range r.commands {
			sections = append(sections, model.styles.cyan.Render(command))
		}
	}
	sections = append(sections, "", model.styles.cyanBold.Render("DETAILS"), r.details)
	return strings.Split(wrap(strings.Join(sections, "\n")), "\n")
}

func (model batchModel) remediationView() string {
	items := model.exposedItems()
	item := items[model.detailIndex%len(items)]
	lines := model.remediationLines()
	start := max(0, min(model.detailScroll, len(lines)-model.detailPageSize()))
	end := min(len(lines), start+model.detailPageSize())
	heading := model.styles.cyanBold.Render("WHY STILL EXPOSED?") + "\n" +
		model.styles.redBold.Render(fmt.Sprintf("%s · %d/%d exposed tools", item.probe.Name, model.detailIndex+1, len(items)))
	body := strings.Join(lines[start:end], "\n")
	footer := model.styles.muted.Render(fmt.Sprintf("Lines %d–%d/%d · guidance only; no changes made", start+1, end, len(lines))) + "\n" +
		model.styles.cyanBold.Render("←/→ tool · ↑/↓ scroll · d/esc back · q exit")
	return lipgloss.NewStyle().Width(max(20, model.width-4)).MarginLeft(2).Render(heading + "\n\n" + body + "\n\n" + footer)
}
