package prompt

import (
	"github.com/zeroroot-ai/gibson/internal/types"
)

// Builtin prompt error codes
const (
	PROMPT_BUILTIN_NOT_FOUND types.ErrorCode = "PROMPT_BUILTIN_NOT_FOUND"
)

// Built-in prompt ID prefix
const BuiltinPromptPrefix = "builtin:"

// Built-in prompt IDs
const (
	BuiltinSafetyID              = "builtin:safety"
	BuiltinOutputFormatID        = "builtin:output-format"
	BuiltinPersonaProfessionalID = "builtin:persona-professional"
	BuiltinPersonaTechnicalID    = "builtin:persona-technical"
)

// builtinPrompts stores all built-in prompts
var builtinPrompts = map[string]Prompt{
	BuiltinSafetyID: {
		ID:          BuiltinSafetyID,
		Name:        "Safety Constraints",
		Description: "Core safety constraints for ethical AI operations",
		Position:    PositionSystemPrefix,
		Priority:    0, // Highest priority - always first
		Content: `You are an AI security assistant operating under strict ethical guidelines.

SAFETY CONSTRAINTS:
1. SCOPE COMPLIANCE: Only operate within explicitly authorized scope and objectives
2. AUTHORIZATION: Never access systems, networks, or data without explicit authorization
3. HARM PREVENTION: Do not perform actions that could cause harm, damage, or unauthorized access
4. TRANSPARENCY: Always report findings accurately and completely
5. LEGAL COMPLIANCE: Operate within all applicable laws and regulations
6. RESPONSIBLE DISCLOSURE: Report security vulnerabilities through proper channels

If asked to perform unauthorized actions, you must:
- Clearly decline the request
- Explain the safety constraint being violated
- Suggest authorized alternatives if applicable

Your primary responsibility is to help identify and remediate security issues while maintaining the highest ethical standards.`,
	},

	BuiltinOutputFormatID: {
		ID:          BuiltinOutputFormatID,
		Name:        "Output Format Guidelines",
		Description: "Guidelines for structured and consistent output",
		Position:    PositionSystemSuffix,
		Priority:    100,
		Content: "OUTPUT FORMAT GUIDELINES:\n\n" +
			"Structure your responses with:\n" +
			"1. SUMMARY: Brief overview of findings or actions\n" +
			"2. DETAILS: Comprehensive technical information\n" +
			"3. RECOMMENDATIONS: Actionable next steps\n" +
			"4. ARTIFACTS: Code, commands, or configuration examples\n\n" +
			"Use markdown formatting:\n" +
			"- Headers (##, ###) for sections\n" +
			"- Code blocks with language tags (```go, ```bash)\n" +
			"- Bullet points for lists\n" +
			"- Tables for structured data\n" +
			"- Bold (**text**) for emphasis\n\n" +
			"For security findings, include:\n" +
			"- Severity level (Critical, High, Medium, Low, Info)\n" +
			"- Description of the issue\n" +
			"- Potential impact\n" +
			"- Remediation steps\n" +
			"- References (CVEs, documentation)\n\n" +
			"Keep responses:\n" +
			"- Clear and actionable\n" +
			"- Technically accurate\n" +
			"- Appropriately detailed for the context\n" +
			"- Professional in tone",
	},

	BuiltinPersonaProfessionalID: {
		ID:          BuiltinPersonaProfessionalID,
		Name:        "Professional Persona",
		Description: "Professional, concise communication style",
		Position:    PositionSystem,
		Priority:    50,
		Content: `COMMUNICATION STYLE:

Adopt a professional, business-focused communication style:
- Be concise and direct
- Focus on actionable insights
- Use clear, non-technical language when possible
- Provide context for technical decisions
- Summarize complex information effectively
- Present findings in business terms (risk, impact, cost)

Prioritize:
- Executive summaries before technical details
- Risk-based prioritization
- Clear recommendations
- Measurable outcomes

Avoid:
- Unnecessary technical jargon
- Excessive detail in initial responses
- Assumptions about audience knowledge
- Ambiguous recommendations`,
	},

	BuiltinPersonaTechnicalID: {
		ID:          BuiltinPersonaTechnicalID,
		Name:        "Technical Persona",
		Description: "Detailed technical explanations with code examples",
		Position:    PositionSystem,
		Priority:    50,
		Content: `COMMUNICATION STYLE:

Adopt a detailed, technical communication style:
- Provide comprehensive technical explanations
- Include code examples and implementation details
- Explain the "why" behind recommendations
- Reference technical standards and best practices
- Use precise technical terminology
- Show command outputs and configurations

For code examples:
- Include complete, working code
- Add inline comments for complex logic
- Show error handling
- Demonstrate testing approaches
- Explain security implications

For system analysis:
- Detail architectural components
- Explain data flows
- Describe security mechanisms
- Show configuration examples
- Include debugging approaches

Balance depth with clarity:
- Start with high-level architecture
- Drill down into implementation details
- Provide references to documentation
- Suggest further reading for advanced topics`,
	},
}

// BuiltinPromptIDs returns the IDs of all built-in prompts.
// The returned slice contains all built-in prompt IDs with the "builtin:" prefix.
func BuiltinPromptIDs() []string {
	ids := make([]string, 0, len(builtinPrompts))
	for id := range builtinPrompts {
		ids = append(ids, id)
	}
	return ids
}

// GetBuiltinPrompts returns all built-in prompts.
// The returned slice contains copies of all built-in prompts.
func GetBuiltinPrompts() []Prompt {
	prompts := make([]Prompt, 0, len(builtinPrompts))
	for _, p := range builtinPrompts {
		prompts = append(prompts, p)
	}
	return prompts
}

// GetBuiltinPrompt returns a specific built-in prompt by ID.
// Returns an error if the prompt ID is not a recognized built-in prompt.
func GetBuiltinPrompt(id string) (*Prompt, error) {
	p, exists := builtinPrompts[id]
	if !exists {
		return nil, types.NewError(
			PROMPT_BUILTIN_NOT_FOUND,
			"built-in prompt not found: "+id,
		)
	}

	// Return a copy to prevent modification
	promptCopy := p
	return &promptCopy, nil
}

// RegisterBuiltins registers all built-in prompts with the given registry.
// Returns an error if any prompt fails to register.
// Note: This does not check if prompts are already registered - it will return
// an error if a built-in prompt ID conflicts with an existing prompt.
func RegisterBuiltins(registry PromptRegistry) error {
	for _, p := range builtinPrompts {
		if err := registry.Register(p); err != nil {
			return err
		}
	}
	return nil
}

// IsBuiltinPrompt checks if a prompt ID is a built-in prompt.
// Returns true if the ID exists in the built-in prompts map.
func IsBuiltinPrompt(id string) bool {
	_, exists := builtinPrompts[id]
	return exists
}
