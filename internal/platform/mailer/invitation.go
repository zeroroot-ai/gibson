// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mailer — invitation.go
//
// The invitation email, and the "address belongs elsewhere" notice.
//
// # One email, and it is the whole onboarding
//
// An invited person gets exactly ONE message from this install. Nothing else
// reaches them, and in particular the identity service sends nothing: the
// Zitadel setup code is minted with returnCode, never sendCode (see
// idp.AdminClient.CreateSetupLink), so AcceptInvitation hands the setup link
// back over the RPC and the accept page walks the person into it. An earlier
// version of this file, the accept page and the docs all told the invitee to
// wait for a second email from the identity service. No such email is ever
// sent.
//
// That makes this message the only onboarding surface the invitee has, so it
// carries the runbook rather than a bare link: accept, build the CLI, sign in,
// run one mission, see it land. Every command is this workspace's own, already
// filled in — the daemon knows the tenant slug and both origins, which is
// exactly what an invitee cannot guess.
//
// # Why the steps are data
//
// The plain-text and HTML parts are two renderings of one []onboardingStep.
// They used to be two hand-maintained string literals, which is how a body
// drifts from its own alternative part. Add a step once, in invitationSteps,
// and both parts carry it.
//
// # Commands are pasteable
//
// A command line in a step carries NO `$` prompt. The whole block is meant to
// be selected and pasted into a shell in one go, and a prompt character
// breaks that. Comment lines start with `#`, which a shell ignores.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"
)

// InvitationEmail carries the fields needed to render a member-invitation
// email. It is the semantic input; rendering (subject/body/HTML) lives here so
// the admin handlers stay free of presentation.
type InvitationEmail struct {
	To        string
	AcceptURL string
	TenantID  string
	Role      string
	ExpiresAt time.Time

	// AppURL is the product-surface origin (GIBSON_APP_URL, e.g.
	// https://app.example.com). AcceptURL is built on it; the runbook also
	// links the dashboard pages a new member lands on.
	AppURL string

	// APIURL is the API-plane origin (GIBSON_PUBLIC_URL, e.g.
	// https://api.example.com) — what `gibson init --gibson-url` takes.
	// Never AppURL: the product surface serves no gRPC.
	//
	// Empty is tolerated, not fatal. The terminal half of the runbook is
	// dropped and the reader is sent to Settings → CLI, which renders the
	// same commands from the dashboard's own copy of this value. An
	// invitation is still worth sending without it.
	APIURL string
}

// InvitationSender renders + sends the invitation accept-link email over an
// underlying Mailer. It satisfies the admin package's InvitationMailer
// interface (structural — no import cycle).
type InvitationSender struct {
	m Mailer
}

// NewInvitationSender wraps a Mailer.
func NewInvitationSender(m Mailer) *InvitationSender {
	return &InvitationSender{m: m}
}

// SendInvitation renders and sends the invitation email.
func (s *InvitationSender) SendInvitation(ctx context.Context, inv InvitationEmail) error {
	if s == nil || s.m == nil {
		return fmt.Errorf("mailer: invitation sender not configured")
	}
	subject := "Welcome to ZeroRoot AI"
	steps := invitationSteps(inv)
	if err := s.m.Send(ctx, Message{
		To:      inv.To,
		Subject: subject,
		Text:    invitationText(inv, steps),
		HTML:    invitationHTML(inv, steps),
	}); err != nil {
		return fmt.Errorf("mailer: send invitation: %w", err)
	}
	return nil
}

// adkCloneURL is the one repository an invitee clones. A bare binary leaves
// behind the mission templates, their ontologies, the component scaffolder and
// the agent context, which is most of what the product is.
const adkCloneURL = "https://github.com/zeroroot-ai/adk.git"

// goToolchain is the Go version adk/.tool-versions pins. It appears here only
// to tell a new person which toolchain asdf or mise will select for them, and
// it is cheap to be wrong about — but keep it in step with that file.
const goToolchain = "1.27.1"

// onboardingStep is one numbered item of the runbook: a title, prose, and an
// optional block of shell lines.
type onboardingStep struct {
	// Title is the imperative one-liner, e.g. "Clone the ADK".
	Title string
	// Body is one or more sentences saying why the step exists.
	Body string
	// Cmds are shell lines, rendered in a terminal panel. A line starting
	// with "#" is a comment and renders dimmed; an empty line is a gap.
	Cmds []string
	// After is prose that follows the command block.
	After string
	// Link, when set, renders as a link under the step.
	Link string
}

// OwnerWelcomeEmail is the input of the onboarding email that the owner of a
// workspace from self-serve signup gets once, when the tenant is ready
// (gibson#987). It is the invitation email with no accept link: the account
// already exists, so the first step is to sign in.
type OwnerWelcomeEmail struct {
	To       string
	TenantID string
	// AppURL and APIURL are the two origins, as in InvitationEmail.
	AppURL string
	APIURL string
}

// SendOwnerWelcome renders and sends the onboarding email to the owner of a
// new workspace. The text and the HTML parts come from invitationSteps, as
// for an invitation.
func (s *InvitationSender) SendOwnerWelcome(ctx context.Context, w OwnerWelcomeEmail) error {
	if s == nil || s.m == nil {
		return errors.New("mailer: invitation sender not configured")
	}
	inv := InvitationEmail{To: w.To, TenantID: w.TenantID, Role: "owner", AppURL: w.AppURL, APIURL: w.APIURL}
	steps := invitationSteps(inv)
	if err := s.m.Send(ctx, Message{
		To:      inv.To,
		Subject: "Welcome to ZeroRoot AI",
		Text:    invitationText(inv, steps),
		HTML:    invitationHTML(inv, steps),
	}); err != nil {
		return fmt.Errorf("mailer: send owner welcome: %w", err)
	}
	return nil
}

// isWelcome reports an email with no accept link: the welcome of a workspace
// owner, whose account already exists.
func (inv InvitationEmail) isWelcome() bool { return inv.AcceptURL == "" }

// lede is the opening sentence of the email.
func (inv InvitationEmail) lede() string {
	if inv.isWelcome() {
		return "You created a Gibson workspace, and it is ready. Every command below already " +
			"carries the address and the name of this workspace, so you can paste them as they are."
	}
	return fmt.Sprintf("Someone added you to a Gibson workspace as %s. Every command below already "+
		"carries the address and the name of this workspace, so you can paste them as they are.",
		roleLabel(inv.Role))
}

// footer is the closing line of the email.
func (inv InvitationEmail) footer() string {
	if inv.isWelcome() {
		return "You get this email once, because you created this workspace."
	}
	return "If you did not expect this email, ignore it. Nothing exists until you open the link."
}

// invitationSteps builds the runbook for one invitation.
//
// ONE body, whatever the role. The dashboard's invite dialog defaults to
// Editor (dashboard `components/gibson/users/InviteUserDialog.tsx`), which is
// what an invited person is in nearly every case, and a per-role body is two
// things to keep true instead of one. A deliberately-invited Viewer is not
// stranded by that: `submit` needs the writer relation, and invitationTraps
// says so unconditionally.
//
// One condition does shape the steps. With no APIURL the CLI commands cannot
// be filled in, so they are replaced by the one page that can fill them in —
// see InvitationEmail.APIURL.
func invitationSteps(inv InvitationEmail) []onboardingStep {
	app := strings.TrimRight(inv.AppURL, "/")
	api := strings.TrimRight(inv.APIURL, "/")

	first := onboardingStep{
		Title: "Accept, and set your password",
		Body: "The link below does two things. It accepts the invitation, then it takes you " +
			"to the page where you set a password. Gibson keeps no password of its own, so " +
			"this is the only place you set one. Open your authenticator app first. A second " +
			"factor is required, and sign-in does not finish without one. You have one " +
			"workspace, so you land straight on the dashboard.",
		Link: inv.AcceptURL,
	}
	if inv.isWelcome() {
		first = onboardingStep{
			Title: "Sign in to your workspace",
			Body: "Your account and your workspace exist. Sign in with the password and the " +
				"second factor that you set at signup. You have one workspace, so you land " +
				"straight on the dashboard.",
			Link: app + "/dashboard",
		}
	}
	steps := []onboardingStep{first, {
		Title: "Clone the ADK. Do not install the binary.",
		Body: "The repository is where you work. It carries the five mission templates and " +
			"their ontologies, the component scaffolder, the Go pin and the agent context. " +
			"The binary on its own carries none of that.",
		Cmds: []string{
			"git clone " + adkCloneURL,
			"cd adk",
			"make build",
			`export PATH="$PWD/gibson/bin:$PATH"`,
			"",
			"# once, for the pinned dev tools (cue, golangci-lint, deadcode)",
			"make bootstrap",
		},
		After: "The file `.tool-versions` pins Go " + goToolchain + ". If you use asdf or mise, it " +
			"picks that version up when you enter the directory.",
	}}

	if api == "" {
		steps = append(steps, onboardingStep{
			Title: "Sign the CLI in",
			Body: "Open Settings, then CLI. That page prints the sign-in command with the " +
				"address and the name of this workspace already filled in. Every member can " +
				"reach it.",
			Link: app + "/dashboard/pages/settings/cli",
		})
	} else {
		steps = append(steps, onboardingStep{
			Title: "Sign the CLI in",
			Body: "Both values below belong to this workspace. The `init` command pins the " +
				"address for this directory, so later commands need no flags.",
			Cmds: []string{
				"gibson init --gibson-url " + api,
				"gibson login --tenant " + inv.TenantID,
			},
			After: "The `login` command prints a URL and a short code. It opens a browser once, " +
				"then stores your session in `~/.gibson/auth/credentials` and refreshes it for " +
				"you. Run `gibson logout` to end it.",
		})
	}

	// No CLI means no mission from a terminal. The dashboard still works.
	if api != "" {
		steps = append(steps, onboardingStep{
			Title: "Run your first mission",
			Body: "A mission runs against a target, and the target sets the boundary. Create " +
				"the target first. The `mission new` command then reads your targets and writes " +
				"the one it finds into the file, so `submit` needs no flag.",
			Cmds: []string{
				"gibson target create --name first-target --type custom --url https://example.test",
				"gibson mission new --from-template secrets-audit -o mission.cue",
				"gibson mission validate mission.cue",
				"gibson mission submit mission.cue",
				"",
				"# the other four templates",
				"gibson mission new --list-templates",
			},
			After: "The `validate` command prints `ok` and nothing else. The `submit` command " +
				"prints the mission id, and the event stream goes to standard error.",
		})
	}

	steps = append(steps, onboardingStep{
		Title: "Watch it land",
		Body: "The run page holds the findings, the jobs, the flow and the terminal output. " +
			"Pages stay empty until a mission has run. That is correct, and not a fault.",
		Link: app + "/dashboard/results",
	})

	if api != "" {
		steps = append(steps, onboardingStep{
			Title: "Scaffold a component of your own",
			Body: "One command writes a whole component directory, with the code and the " +
				"context together.",
			Cmds: []string{"gibson component init my-agent --kind agent"},
			After: "It writes `CLAUDE.md`, `AGENTS.md`, `.claude/settings.json` and a `prompts` " +
				"folder next to the code. Your coding agent has what it needs from the first " +
				"commit. That is the real reason to clone.",
		})
	}
	return steps
}

// invitationTraps are the things a new person hits before anyone thinks to warn
// them. Each one reads as a broken install and is not one.
//
// A trap leaves this list the moment the product stops setting it. The proxy
// one did: the CLI ignored HTTPS_PROXY because deviceauth.HTTPClient built a
// bare http.Transport, which inherits none of Go's defaults, and adk#79 fixed
// it by cloning DefaultTransport and overriding only TLS. Warning a reader
// about behavior the product no longer has is worse than silence, because they
// plan around it.
//
// The list does not vary by role. The submit denial is here rather than in a
// per-role body because it is the one way a single body can stay honest for a
// Viewer: an Editor skips the line, and a Viewer gets the reason their last
// step refused instead of a mystery.
func invitationTraps() [][2]string {
	return [][2]string{
		{"gibson inspect", "This command reports on a registered component, not on you. It " +
			"fails until you register one. That is expected, and not a broken install."},
		{"permission denied on submit", "Authoring a mission needs the Editor role. If someone " +
			"invited you as a Viewer, ask them to raise it."},
		{"a private CA", "Pass the flag --ca-cert with your PEM path, or set GIBSON_CA_CERT. Do " +
			"not set SSL_CERT_FILE, because it replaces the whole trust pool."},
	}
}

// --- plain text ---------------------------------------------------------

// invitationText renders the text/plain part. Commands are indented four
// spaces, which is the plain-text equivalent of the terminal panel and still
// pastes cleanly.
func invitationText(inv InvitationEmail, steps []onboardingStep) string {
	var b strings.Builder
	b.WriteString("Hello,\n\n")
	b.WriteString(indentWrap(inv.lede(), "", 76) + "\n\n")
	if !inv.isWelcome() {
		fmt.Fprintf(&b, "The link expires %s.\n\n", expiryLabel(inv.ExpiresAt))
	}
	b.WriteString("START HERE\n")
	b.WriteString(strings.Repeat("-", 10) + "\n\n")

	for i, st := range steps {
		fmt.Fprintf(&b, "%02d. %s\n\n", i+1, st.Title)
		if st.Body != "" {
			b.WriteString(indentWrap(unmark(st.Body), "    ", 72) + "\n\n")
		}
		for _, c := range st.Cmds {
			if c == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString("    " + c + "\n")
		}
		if len(st.Cmds) > 0 {
			b.WriteString("\n")
		}
		if st.After != "" {
			b.WriteString(indentWrap(unmark(st.After), "    ", 72) + "\n\n")
		}
		if st.Link != "" {
			b.WriteString("    " + st.Link + "\n\n")
		}
	}

	b.WriteString("BEFORE YOU ASK\n")
	b.WriteString(strings.Repeat("-", 14) + "\n\n")
	for _, t := range invitationTraps() {
		b.WriteString("  " + t[0] + "\n")
		b.WriteString(indentWrap(t[1], "    ", 72) + "\n\n")
	}

	b.WriteString(indentWrap(inv.footer(), "", 76) + "\n")
	return b.String()
}

// --- HTML --------------------------------------------------------------

// Brand colors, resolved to hex from the locked "acid concrete" tokens in
// @zeroroot/brand src/css/tokens.css (ADR-0064). Hex, not oklch: a mail client
// is not a 2026 browser. Acid is a FILL and never carries type, so the step
// numbers sit on it rather than being set in it; green TEXT is cHighlight.
// Terminal panels use the brand's own Dracula palette, scoped to them.
const (
	cGround   = "#e3e3df" // --background, warm concrete
	cPanel    = "#f1f0ed" // --card
	cInk      = "#0e0d09" // --foreground
	cMuted    = "#56554f" // --muted-foreground
	cRule     = "#b8b7b2" // --border
	cAcid     = "#a8ea27" // --primary, a fill only
	cAcidInk  = "#081600" // --primary-foreground, type on acid
	cTermBg   = "#080704" // --terminal-bg
	cTermFg   = "#f8f8f2" // --dracula-fg
	cTermDim  = "#6272a4" // --dracula-comment
	fontStack = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
	monoStack = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace"
)

// invitationHTML renders the text/html part: one 600px table column on
// concrete, with every command in a dark terminal panel.
//
// Table layout and inline styles throughout, because that is what mail clients
// render. No webfont link (Gmail strips it), no flexbox, no CSS grid, and no
// dark-mode media query — the brand is one locked light theme.
func invitationHTML(inv InvitationEmail, steps []onboardingStep) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>Welcome to ZeroRoot AI</title></head>`)
	b.WriteString(`<body style="margin:0;padding:0;background:` + cGround + `;">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"` +
		` style="background:` + cGround + `;"><tr><td align="center" style="padding:24px 12px 40px;">`)
	b.WriteString(`<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"` +
		` style="width:100%;max-width:600px;">`)

	// Masthead.
	b.WriteString(`<tr><td style="padding:0 0 14px;border-bottom:2px solid ` + cInk + `;">`)
	b.WriteString(span(monoStack, "11px", cMuted, "letter-spacing:1.5px;text-transform:uppercase;", "ZeroRoot AI / Gibson"))
	b.WriteString(`<div style="font-family:` + fontStack + `;font-size:28px;line-height:1.1;font-weight:700;` +
		`letter-spacing:-0.5px;color:` + cInk + `;padding-top:6px;">Welcome to ZeroRoot AI</div>`)
	b.WriteString(`</td></tr>`)

	// Lede.
	b.WriteString(`<tr><td style="padding:18px 0 0;font-family:` + fontStack + `;font-size:15px;` +
		`line-height:1.6;color:` + cInk + `;">`)
	if inv.isWelcome() {
		b.WriteString(`Hello,<br><br>` + html.EscapeString(inv.lede()))
	} else {
		b.WriteString(`Hello,<br><br>Someone added you to a Gibson workspace as <strong>` +
			html.EscapeString(roleLabel(inv.Role)) + `</strong>. Every command below already carries ` +
			`the address and the name of this workspace, so you can paste them as they are.`)
	}
	b.WriteString(`</td></tr>`)
	if !inv.isWelcome() {
		b.WriteString(`<tr><td style="padding:10px 0 0;font-family:` + fontStack + `;font-size:13px;` +
			`line-height:1.5;color:` + cMuted + `;">The link expires ` + html.EscapeString(expiryLabel(inv.ExpiresAt)) + `.</td></tr>`)
	}

	// Section rule.
	b.WriteString(`<tr><td style="padding:30px 0 8px;border-bottom:1px solid ` + cRule + `;">`)
	b.WriteString(span(monoStack, "12px", cInk, "font-weight:700;letter-spacing:1.3px;text-transform:uppercase;",
		"Start here"))
	b.WriteString(`</td></tr>`)

	for i, st := range steps {
		b.WriteString(`<tr><td style="padding:22px 0 0;">`)
		b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>`)
		// The acid plate carries the number. A fill, never type.
		b.WriteString(`<td width="34" valign="top" style="width:34px;padding:0 12px 0 0;">`)
		b.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>`)
		b.WriteString(`<td align="center" bgcolor="` + cAcid + `" style="background:` + cAcid + `;width:26px;` +
			`height:20px;border-radius:2px;font-family:` + monoStack + `;font-size:12px;font-weight:700;` +
			`color:` + cAcidInk + `;padding:3px 0;">` + fmt.Sprintf("%02d", i+1) + `</td>`)
		b.WriteString(`</tr></table></td>`)
		b.WriteString(`<td valign="top" style="font-family:` + fontStack + `;">`)
		b.WriteString(`<div style="font-size:16px;font-weight:600;line-height:1.3;color:` + cInk + `;">` +
			html.EscapeString(st.Title) + `</div>`)
		if st.Body != "" {
			b.WriteString(`<div style="font-size:14px;line-height:1.6;color:` + cMuted + `;padding-top:5px;">` +
				inlineCode(st.Body) + `</div>`)
		}
		if len(st.Cmds) > 0 {
			b.WriteString(terminalPanel(st.Cmds))
		}
		if st.After != "" {
			b.WriteString(`<div style="font-size:13px;line-height:1.6;color:` + cMuted + `;padding-top:8px;">` +
				inlineCode(st.After) + `</div>`)
		}
		if st.Link != "" {
			b.WriteString(linkRow(st.Link, i == 0, primaryLabel(inv)))
		}
		b.WriteString(`</td></tr></table></td></tr>`)
	}

	// Traps.
	b.WriteString(`<tr><td style="padding:34px 0 8px;border-bottom:1px solid ` + cRule + `;">`)
	b.WriteString(span(monoStack, "12px", cInk, "font-weight:700;letter-spacing:1.3px;text-transform:uppercase;",
		"Before you ask"))
	b.WriteString(`</td></tr>`)
	b.WriteString(`<tr><td style="padding:14px 0 0;">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">`)
	for _, t := range invitationTraps() {
		b.WriteString(`<tr><td style="padding:0 0 12px;font-family:` + fontStack + `;font-size:13px;line-height:1.6;">`)
		b.WriteString(span(monoStack, "13px", cInk, "font-weight:500;", t[0]))
		b.WriteString(`<br><span style="color:` + cMuted + `;">` + html.EscapeString(t[1]) + `</span>`)
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</table></td></tr>`)

	// Footer.
	b.WriteString(`<tr><td style="padding:24px 0 0;border-top:1px solid ` + cRule + `;font-family:` + monoStack +
		`;font-size:11px;line-height:1.7;color:` + cMuted + `;">`)
	b.WriteString(html.EscapeString(inv.footer()))
	b.WriteString(`</td></tr>`)

	b.WriteString(`</table></td></tr></table></body></html>`)
	return b.String()
}

// terminalPanel renders shell lines in a dark panel. No `$` prompt: the block
// is meant to be selected and pasted whole.
func terminalPanel(cmds []string) string {
	var p strings.Builder
	p.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"` +
		` style="margin:12px 0 0;"><tr><td bgcolor="` + cTermBg + `" style="background:` + cTermBg +
		`;border-radius:3px;padding:13px 15px;">`)
	p.WriteString(`<pre style="margin:0;padding:0;font-family:` + monoStack + `;font-size:13px;` +
		`line-height:1.7;color:` + cTermFg + `;white-space:pre-wrap;word-break:break-all;">`)
	for i, c := range cmds {
		if i > 0 {
			p.WriteString("\n")
		}
		if strings.HasPrefix(c, "#") {
			p.WriteString(`<span style="color:` + cTermDim + `;">` + html.EscapeString(c) + `</span>`)
			continue
		}
		p.WriteString(html.EscapeString(c))
	}
	p.WriteString(`</pre></td></tr></table>`)
	return p.String()
}

// linkRow renders a step's URL. primary=true gets the acid plate (the one
// action this email asks for); the rest are plain links, so the email has
// exactly one button.
func linkRow(url string, primary bool, label string) string {
	esc := html.EscapeString(url)
	if !primary {
		return `<div style="padding:10px 0 0;font-family:` + monoStack + `;font-size:13px;word-break:break-all;">` +
			`<a href="` + esc + `" style="color:` + cInk + `;">` + esc + `</a></div>`
	}
	return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:14px 0 0;">` +
		`<tr><td bgcolor="` + cAcid + `" style="background:` + cAcid + `;border-radius:2px;">` +
		`<a href="` + esc + `" style="display:inline-block;padding:11px 20px;font-family:` + monoStack +
		`;font-size:13px;font-weight:700;letter-spacing:1px;text-transform:uppercase;` +
		`color:` + cAcidInk + `;text-decoration:none;">` + html.EscapeString(label) + `</a>` +
		`</td></tr><tr><td style="padding:8px 0 0;font-family:` + monoStack + `;font-size:11px;` +
		`word-break:break-all;color:` + cMuted + `;">` + esc + `</td></tr></table>`
}

// primaryLabel is the text of the one button of the email.
func primaryLabel(inv InvitationEmail) string {
	if inv.isWelcome() {
		return "Sign in"
	}
	return "Accept and set your password"
}

// span is the one-line helper for the mono eyebrow/label type this layout uses
// in six places.
func span(family, size, color, extra, text string) string {
	return `<span style="font-family:` + family + `;font-size:` + size + `;color:` + color + `;` + extra +
		`">` + html.EscapeString(text) + `</span>`
}

// inlineCode escapes prose and renders `backticked` spans as monospace. The
// step text is authored once for both parts, so the HTML part reads the same
// markers the text part strips.
func inlineCode(s string) string {
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 && i < len(parts)-1 {
			b.WriteString(`<code style="font-family:` + monoStack + `;font-size:0.92em;color:` + cInk + `;">` +
				html.EscapeString(p) + `</code>`)
			continue
		}
		b.WriteString(html.EscapeString(p))
	}
	return b.String()
}

// unmark strips the backtick markers for the plain-text part.
func unmark(s string) string { return strings.ReplaceAll(s, "`", "") }

// indentWrap hard-wraps prose at width and prefixes every line, so the text
// part reads in a 80-column mail client.
func indentWrap(s, prefix string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	lines = append(lines, line)
	return prefix + strings.Join(lines, "\n"+prefix)
}

// expiryLabel renders the deadline a person reads, in UTC. UTC is deliberate:
// the daemon does not know the invitee's zone, and a wrong local time is worse
// than an explicit UTC one.
func expiryLabel(t time.Time) string {
	if t.IsZero() {
		return "in seven days"
	}
	return "on " + t.UTC().Format("2 January 2006 at 15:04 MST")
}

// InvitationConflictEmail is the input for the notice sent when someone
// invites an address that already belongs to a different tenant (ADR-0093
// decision 1: one tenant per person, emails unique install-wide). It carries
// no accept link: there is nothing to accept. The inviter never sees this —
// InviteMember reports "sent" either way (hosted#203).
type InvitationConflictEmail struct {
	To string
}

// SendInvitationConflict sends the "this address already belongs elsewhere"
// notice. This is the only place the conflict is disclosed, and it goes only
// to the mailbox that owns the address — never to the inviter.
func (s *InvitationSender) SendInvitationConflict(ctx context.Context, c InvitationConflictEmail) error {
	if s == nil || s.m == nil {
		return errors.New("mailer: invitation sender not configured")
	}
	subject := "About your Gibson invitation"
	text := fmt.Sprintf(
		"Someone tried to invite this address (%s) to a Gibson workspace, but it "+
			"already belongs to a different one. An address belongs to one workspace "+
			"at a time.\n\n"+
			"You have two ways in. Use a different address, or ask the Owner of your "+
			"current workspace to remove you first.\n\n"+
			"If you did not expect this email, ignore it. Nothing changed.",
		c.To,
	)
	html := fmt.Sprintf(
		"<p>Someone tried to invite this address (%s) to a Gibson workspace, but it "+
			"already belongs to a different one. An address belongs to one workspace "+
			"at a time.</p>"+
			"<p>You have two ways in. Use a different address, or ask the Owner of your "+
			"current workspace to remove you first.</p>"+
			"<p>If you did not expect this email, ignore it. Nothing changed.</p>",
		c.To,
	)
	if err := s.m.Send(ctx, Message{To: c.To, Subject: subject, Text: text, HTML: html}); err != nil {
		return fmt.Errorf("mailer: send invitation conflict notice: %w", err)
	}
	return nil
}

// roleLabel renders an FGA relation name as the role name a person reads.
//
// The daemon speaks relations (`admin`, `writer`, `member`); ADR-0093 decision 2
// names the roles Owner, Admin, Editor and Viewer, and the dashboard renders
// those labels everywhere (dashboard `src/lib/auth/tenant-roles.ts`). This email
// is the only surface that puts a role in front of a person outside the
// dashboard, so it must use the same words. It said "a writer" and "a member",
// which name no role the invitee can find in the product.
//
// `owner` is reachable here through InviteProvisionedOwner (hosted#205), which
// issues the founding Owner's invitation; ownership never moves between
// existing members by invitation — that is TransferOwnership.
func roleLabel(role string) string {
	switch role {
	case "owner":
		return "the Owner"
	case "admin":
		return "an Admin"
	case "writer":
		return "an Editor"
	default:
		return "a Viewer"
	}
}
