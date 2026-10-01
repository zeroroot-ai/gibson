// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mailer — copyrules_test.go
//
// The owner's writing rules for customer-facing copy, as a test.
//
// These are not style preferences. They were given as corrections, twice, after
// copy shipped that "sounded like an AI", and the rules are the workspace
// standard (`.github` AGENTS.md § 12, ASD-STE100 Simplified Technical English).
// A reviewer cannot hold them in their head across a 500-line renderer, so the
// suite holds them instead.
//
// Scope: the rendered plain-text part of every message this package sends. The
// text part is the whole copy — the HTML part renders the same strings — so
// checking it checks both without parsing markup.
package mailer

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// renderedCopy returns the text part of every message this package sends, by
// name. A new message type belongs here, or the rules do not reach it.
func renderedCopy(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}

	cap1 := &verifyCaptureMailer{}
	if err := NewInvitationSender(cap1).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	out["invitation"] = cap1.sent[0].Subject + "\n\n" + cap1.sent[0].Text

	// The degraded path has copy of its own (the Settings → CLI step), which
	// the fully-configured render never reaches.
	noAPI := sampleInvitation()
	noAPI.APIURL = ""
	cap2 := &verifyCaptureMailer{}
	if err := NewInvitationSender(cap2).SendInvitation(context.Background(), noAPI); err != nil {
		t.Fatalf("SendInvitation (no API origin): %v", err)
	}
	out["invitation/no-api-origin"] = cap2.sent[0].Subject + "\n\n" + cap2.sent[0].Text

	cap3 := &verifyCaptureMailer{}
	if err := NewInvitationSender(cap3).SendInvitationConflict(context.Background(),
		InvitationConflictEmail{To: "taken@example.com"}); err != nil {
		t.Fatalf("SendInvitationConflict: %v", err)
	}
	out["invitation-conflict"] = cap3.sent[0].Subject + "\n\n" + cap3.sent[0].Text

	return out
}

// TestCopy_NoDashPunctuation: an em or en dash used as punctuation is two
// sentences wearing one coat, and it is the single clearest tell of generated
// prose. Write the two sentences.
func TestCopy_NoDashPunctuation(t *testing.T) {
	for name, body := range renderedCopy(t) {
		for _, r := range []string{"—", "–"} {
			if strings.Contains(body, r) {
				t.Errorf("%s: carries %q used as punctuation; write two sentences instead", name, r)
			}
		}
	}
}

// TestCopy_NoContractions: the house rule is to expand them.
func TestCopy_NoContractions(t *testing.T) {
	// The apostrophe forms, straight and curly. Possessives are fine, so the
	// list names contractions explicitly rather than matching every "'s".
	contraction := regexp.MustCompile(`(?i)\b(?:` +
		`[a-z]+n['\x{2019}]t|` + // don't, isn't, won't, cannot-forms
		`[a-z]+['\x{2019}](?:re|ve|ll|d|m)\b|` + // you're, we've, it'll, I'd, I'm
		`it['\x{2019}]s|that['\x{2019}]s|there['\x{2019}]s|what['\x{2019}]s|` +
		`here['\x{2019}]s|who['\x{2019}]s|let['\x{2019}]s` +
		`)`)
	for name, body := range renderedCopy(t) {
		for _, m := range contraction.FindAllString(body, -1) {
			t.Errorf("%s: contraction %q; expand it", name, m)
		}
	}
}

// TestCopy_NoColonReveal: "it carries the whole path: accept, build, sign in,
// run one mission" is the construction the owner rejected by name. A colon that
// introduces a list or a restatement mid-sentence reads as generated. A colon
// is fine after a label, so the rule fires only when prose precedes it.
//
// Command blocks and URLs are exempt: `https://`, `~/.gibson`, and a step's
// own terminal lines are not prose.
func TestCopy_NoColonReveal(t *testing.T) {
	for name, body := range renderedCopy(t) {
		for i, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommandish(trimmed) {
				continue
			}
			idx := strings.Index(trimmed, ": ")
			if idx <= 0 {
				continue
			}
			before := trimmed[:idx]
			// A label is short and has no sentence in it. Prose does.
			if strings.Count(before, " ") >= 3 {
				t.Errorf("%s line %d: colon reveal after prose (%q...); make it two sentences",
					name, i+1, firstN(trimmed, 60))
			}
		}
	}
}

// TestCopy_SentencesStayShort enforces the descriptive cap of 25 words. One
// idea per sentence is the reason, not brevity for its own sake.
func TestCopy_SentencesStayShort(t *testing.T) {
	const maxWords = 25
	for name, body := range renderedCopy(t) {
		for _, sentence := range proseSentences(body) {
			if n := len(strings.Fields(sentence)); n > maxWords {
				t.Errorf("%s: %d words in one sentence (max %d): %q",
					name, n, maxWords, firstN(sentence, 90))
			}
		}
	}
}

// TestCopy_NoMetaCommentary: copy that talks about itself ("this email", "this
// message", "the email below") puts the reader outside the thing they are
// reading. Say the thing instead. The sign-off is the one place a reference is
// legitimate, because the reader has to be told to ignore it.
func TestCopy_NoMetaCommentary(t *testing.T) {
	banned := []string{
		"this is the only email",
		"this email carries",
		"this message carries",
		"the email below",
		"in this email you will find",
		"as mentioned above",
		"please note",
		"it is important to",
	}
	for name, body := range renderedCopy(t) {
		low := strings.ToLower(body)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("%s: meta-commentary %q; say the thing instead", name, b)
			}
		}
	}
}

// TestCopy_NoMarketingAdjectives: the house list. None of these survive a
// reader who is trying to get a mission running.
//
// The time promises are here by owner instruction, 2026-10-01: do not mention
// twenty minutes at all. The copy told the reader how long their own setup
// would take, which is a promise the sender cannot keep for them — their
// network, their proxy, their authenticator app. Name the steps, not a clock.
func TestCopy_NoMarketingAdjectives(t *testing.T) {
	banned := []string{
		"seamless", "robust", "powerful", "cutting-edge", "effortless",
		"world-class", "next-generation", "revolutionary", "leverage",
		"utilize", "best-in-class", "simply", "just works", "unlock",
		"twenty minutes", "20 minutes", "five minutes", "in minutes",
	}
	for name, body := range renderedCopy(t) {
		low := strings.ToLower(body)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("%s: marketing word %q", name, b)
			}
		}
	}
}

// TestCopy_AmericanSpelling: the house rule, and the one a British-trained
// writer breaks without noticing.
func TestCopy_AmericanSpelling(t *testing.T) {
	british := []string{
		"organise", "organisation", "authorise", "authorisation", "standardise",
		"optimise", "customise", "initialise", "recognise", "colour",
		"behaviour", "licence ", "labelled", "cancelled ", "catalogue",
		"centre", "defence", "favourite", "whilst", "amongst",
	}
	for name, body := range renderedCopy(t) {
		low := strings.ToLower(body)
		for _, b := range british {
			if strings.Contains(low, b) {
				t.Errorf("%s: British spelling %q; use American", name, strings.TrimSpace(b))
			}
		}
	}
}

// TestCopy_NoNameInCopy: the owner's standing rule for every customer-facing
// surface. The product signs its own mail.
func TestCopy_NoNameInCopy(t *testing.T) {
	for name, body := range renderedCopy(t) {
		for _, n := range []string{"Anthony", "anthony@"} {
			if strings.Contains(body, n) {
				t.Errorf("%s: names a person (%q); customer copy carries no personal name", name, n)
			}
		}
	}
}

// --- helpers -------------------------------------------------------------

// isCommandish reports whether a line is a command, a URL or a path rather
// than prose. The copy rules apply to prose only.
func isCommandish(line string) bool {
	switch {
	case strings.HasPrefix(line, "http://"), strings.HasPrefix(line, "https://"):
		return true
	case strings.HasPrefix(line, "#"), strings.HasPrefix(line, "-"):
		return true
	case strings.HasPrefix(line, "gibson "), strings.HasPrefix(line, "git "),
		strings.HasPrefix(line, "cd "), strings.HasPrefix(line, "make "),
		strings.HasPrefix(line, "export "):
		return true
	case strings.Trim(line, "-") == "":
		return true
	}
	return false
}

// proseSentences splits the body into sentences, skipping command lines,
// URLs, headings and the trap labels (which are terms, not sentences).
func proseSentences(body string) []string {
	var prose []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommandish(trimmed) {
			continue
		}
		// A heading is upper-case and carries no terminal period.
		if trimmed == strings.ToUpper(trimmed) && !strings.Contains(trimmed, ".") {
			continue
		}
		prose = append(prose, trimmed)
	}
	joined := strings.Join(prose, " ")
	var out []string
	for _, s := range regexp.MustCompile(`(?:\.|\?|!)\s+`).Split(joined, -1) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
