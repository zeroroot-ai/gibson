package finding

import (
	"fmt"
	"strings"
)

// MitreMapping represents a mapping to a MITRE technique
type MitreMapping struct {
	Matrix        string   `json:"matrix"`                   // "ATT&CK" or "ATLAS"
	TacticID      string   `json:"tactic_id"`                // e.g., "TA0001"
	TacticName    string   `json:"tactic_name"`              // e.g., "Initial Access"
	TechniqueID   string   `json:"technique_id"`             // e.g., "T1566" or "AML.T0015"
	TechniqueName string   `json:"technique_name"`           // e.g., "Phishing"
	SubTechniques []string `json:"sub_techniques,omitempty"` // e.g., ["T1566.001", "T1566.002"]
}

// MitreTechnique represents a MITRE technique with full details
type MitreTechnique struct {
	ID          string   `json:"id"`   // e.g., "AML.T0015"
	Name        string   `json:"name"` // e.g., "Jailbreak"
	Description string   `json:"description"`
	TacticIDs   []string `json:"tactic_ids"` // Associated tactic IDs
	URL         string   `json:"url"`        // Reference URL
}

// MitreDatabase holds the mapping of MITRE techniques
type MitreDatabase struct {
	attackTechniques map[string]MitreTechnique
	atlasTechniques  map[string]MitreTechnique
}

// NewMitreDatabase creates a new MITRE database with embedded AI security techniques
func NewMitreDatabase() *MitreDatabase {
	db := &MitreDatabase{
		attackTechniques: make(map[string]MitreTechnique),
		atlasTechniques:  make(map[string]MitreTechnique),
	}

	// Initialize MITRE ATLAS techniques for AI/ML security
	db.initializeAtlasTechniques()

	// Initialize relevant MITRE ATT&CK techniques
	db.initializeAttackTechniques()

	return db
}

// initializeAtlasTechniques populates the ATLAS technique database
func (db *MitreDatabase) initializeAtlasTechniques() {
	atlas := []MitreTechnique{
		{
			ID:          "AML.T0015",
			Name:        "Jailbreak",
			Description: "An adversary crafts prompts intended to bypass safety measures and elicit harmful content from an LLM.",
			TacticIDs:   []string{"AML.TA0000"}, // ML Attack Staging
			URL:         "https://atlas.mitre.org/techniques/AML.T0015",
		},
		{
			ID:          "AML.T0051",
			Name:        "Prompt Injection",
			Description: "An adversary injects malicious instructions into an LLM prompt to manipulate the model's behavior.",
			TacticIDs:   []string{"AML.TA0000"}, // ML Attack Staging
			URL:         "https://atlas.mitre.org/techniques/AML.T0051",
		},
		{
			ID:          "AML.T0024",
			Name:        "Data Extraction",
			Description: "An adversary queries a trained ML model to extract sensitive information from its training data.",
			TacticIDs:   []string{"AML.TA0009"}, // Exfiltration
			URL:         "https://atlas.mitre.org/techniques/AML.T0024",
		},
		{
			ID:          "AML.T0043",
			Name:        "Model Inversion",
			Description: "An adversary uses model outputs to reconstruct sensitive training data or model internals.",
			TacticIDs:   []string{"AML.TA0009"}, // Exfiltration
			URL:         "https://atlas.mitre.org/techniques/AML.T0043",
		},
		{
			ID:          "AML.T0029",
			Name:        "Model Poisoning",
			Description: "An adversary introduces malicious data into the training process to corrupt the model.",
			TacticIDs:   []string{"AML.TA0002"}, // ML Model Access
			URL:         "https://atlas.mitre.org/techniques/AML.T0029",
		},
		{
			ID:          "AML.T0034",
			Name:        "Model Backdoor",
			Description: "An adversary embeds a backdoor trigger in the model that causes specific malicious behavior.",
			TacticIDs:   []string{"AML.TA0002"}, // ML Model Access
			URL:         "https://atlas.mitre.org/techniques/AML.T0034",
		},
		{
			ID:          "AML.T0040",
			Name:        "ML-Enabled Reconnaissance",
			Description: "An adversary uses ML to automate and enhance reconnaissance activities.",
			TacticIDs:   []string{"AML.TA0001"}, // Reconnaissance
			URL:         "https://atlas.mitre.org/techniques/AML.T0040",
		},
		{
			ID:          "AML.T0025",
			Name:        "Exfiltrate ML Model",
			Description: "An adversary steals a trained ML model through querying or direct access.",
			TacticIDs:   []string{"AML.TA0009"}, // Exfiltration
			URL:         "https://atlas.mitre.org/techniques/AML.T0025",
		},
		{
			ID:          "AML.T0054",
			Name:        "LLM Denial of Service",
			Description: "An adversary overwhelms an LLM service with requests or resource-intensive prompts.",
			TacticIDs:   []string{"AML.TA0034"}, // Impact
			URL:         "https://atlas.mitre.org/techniques/AML.T0054",
		},
		{
			ID:          "AML.T0056",
			Name:        "LLM Privilege Escalation",
			Description: "An adversary manipulates an LLM to gain unauthorized access or elevated privileges.",
			TacticIDs:   []string{"AML.TA0004"}, // Privilege Escalation
			URL:         "https://atlas.mitre.org/techniques/AML.T0056",
		},
	}

	for _, tech := range atlas {
		db.atlasTechniques[tech.ID] = tech
	}
}

// initializeAttackTechniques populates relevant ATT&CK techniques
func (db *MitreDatabase) initializeAttackTechniques() {
	attack := []MitreTechnique{
		{
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Description: "Adversaries may abuse command and script interpreters to execute commands.",
			TacticIDs:   []string{"TA0002"}, // Execution
			URL:         "https://attack.mitre.org/techniques/T1059",
		},
		{
			ID:          "T1071",
			Name:        "Application Layer Protocol",
			Description: "Adversaries may communicate using application layer protocols.",
			TacticIDs:   []string{"TA0011"}, // Command and Control
			URL:         "https://attack.mitre.org/techniques/T1071",
		},
		{
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Adversaries may exploit weaknesses in Internet-facing applications.",
			TacticIDs:   []string{"TA0001"}, // Initial Access
			URL:         "https://attack.mitre.org/techniques/T1190",
		},
		{
			ID:          "T1078",
			Name:        "Valid Accounts",
			Description: "Adversaries may obtain and abuse credentials of existing accounts.",
			TacticIDs:   []string{"TA0001", "TA0003", "TA0004"}, // Initial Access, Persistence, Privilege Escalation
			URL:         "https://attack.mitre.org/techniques/T1078",
		},
		{
			ID:          "T1552",
			Name:        "Unsecured Credentials",
			Description: "Adversaries may search for credentials in unsecured locations.",
			TacticIDs:   []string{"TA0006"}, // Credential Access
			URL:         "https://attack.mitre.org/techniques/T1552",
		},
		{
			ID:          "T1498",
			Name:        "Network Denial of Service",
			Description: "Adversaries may perform DoS attacks to degrade or block service availability.",
			TacticIDs:   []string{"TA0040"}, // Impact
			URL:         "https://attack.mitre.org/techniques/T1498",
		},
	}

	for _, tech := range attack {
		db.attackTechniques[tech.ID] = tech
	}
}

// GetTechnique retrieves a technique by ID from either ATT&CK or ATLAS
func (db *MitreDatabase) GetTechnique(id string) (*MitreTechnique, error) {
	// Check ATLAS first (starts with AML.)
	if strings.HasPrefix(id, "AML.") {
		if tech, ok := db.atlasTechniques[id]; ok {
			return &tech, nil
		}
		return nil, fmt.Errorf("ATLAS technique not found: %s", id)
	}

	// Check ATT&CK
	if tech, ok := db.attackTechniques[id]; ok {
		return &tech, nil
	}

	return nil, fmt.Errorf("ATT&CK technique not found: %s", id)
}

// FindForCategory maps finding categories to relevant MITRE techniques
func (db *MitreDatabase) FindForCategory(category FindingCategory) []MitreMapping {
	var mappings []MitreMapping

	switch category {
	case CategoryJailbreak:
		mappings = append(mappings, db.createMapping("AML.T0015", "AML.TA0000", "ML Attack Staging"))

	case CategoryPromptInjection:
		mappings = append(mappings, db.createMapping("AML.T0051", "AML.TA0000", "ML Attack Staging"))

	case CategoryDataExtraction:
		mappings = append(mappings,
			db.createMapping("AML.T0024", "AML.TA0009", "Exfiltration"),
			db.createMapping("AML.T0043", "AML.TA0009", "Exfiltration"),
		)

	case CategoryPrivilegeEscalation:
		mappings = append(mappings,
			db.createMapping("AML.T0056", "AML.TA0004", "Privilege Escalation"),
			db.createMapping("T1078", "TA0004", "Privilege Escalation"),
		)

	case CategoryDoS:
		mappings = append(mappings,
			db.createMapping("AML.T0054", "AML.TA0034", "Impact"),
			db.createMapping("T1498", "TA0040", "Impact"),
		)

	case CategoryModelManipulation:
		mappings = append(mappings,
			db.createMapping("AML.T0029", "AML.TA0002", "ML Model Access"),
			db.createMapping("AML.T0034", "AML.TA0002", "ML Model Access"),
		)

	case CategoryInformationDisclosure:
		mappings = append(mappings,
			db.createMapping("AML.T0024", "AML.TA0009", "Exfiltration"),
			db.createMapping("T1552", "TA0006", "Credential Access"),
		)
	}

	return mappings
}

// FindForKeywords searches for techniques matching given keywords
func (db *MitreDatabase) FindForKeywords(keywords []string) []MitreMapping {
	var mappings []MitreMapping
	seen := make(map[string]bool)

	for _, keyword := range keywords {
		keyword = strings.ToLower(keyword)

		// Search ATLAS techniques
		for id, tech := range db.atlasTechniques {
			if seen[id] {
				continue
			}

			if db.matchesKeyword(tech, keyword) {
				for _, tacticID := range tech.TacticIDs {
					mapping := MitreMapping{
						Matrix:        "ATLAS",
						TacticID:      tacticID,
						TacticName:    db.getTacticName(tacticID),
						TechniqueID:   tech.ID,
						TechniqueName: tech.Name,
					}
					mappings = append(mappings, mapping)
					seen[id] = true
					break // Only add once per technique
				}
			}
		}

		// Search ATT&CK techniques
		for id, tech := range db.attackTechniques {
			if seen[id] {
				continue
			}

			if db.matchesKeyword(tech, keyword) {
				for _, tacticID := range tech.TacticIDs {
					mapping := MitreMapping{
						Matrix:        "ATT&CK",
						TacticID:      tacticID,
						TacticName:    db.getTacticName(tacticID),
						TechniqueID:   tech.ID,
						TechniqueName: tech.Name,
					}
					mappings = append(mappings, mapping)
					seen[id] = true
					break // Only add once per technique
				}
			}
		}
	}

	return mappings
}

// createMapping creates a MITRE mapping from technique ID
func (db *MitreDatabase) createMapping(techniqueID, tacticID, tacticName string) MitreMapping {
	tech, err := db.GetTechnique(techniqueID)
	if err != nil {
		// Return empty mapping if technique not found
		return MitreMapping{}
	}

	matrix := "ATT&CK"
	if strings.HasPrefix(techniqueID, "AML.") {
		matrix = "ATLAS"
	}

	return MitreMapping{
		Matrix:        matrix,
		TacticID:      tacticID,
		TacticName:    tacticName,
		TechniqueID:   techniqueID,
		TechniqueName: tech.Name,
	}
}

// matchesKeyword checks if a technique matches a keyword
func (db *MitreDatabase) matchesKeyword(tech MitreTechnique, keyword string) bool {
	return strings.Contains(strings.ToLower(tech.Name), keyword) ||
		strings.Contains(strings.ToLower(tech.Description), keyword) ||
		strings.Contains(strings.ToLower(tech.ID), keyword)
}

// getTacticName returns a human-readable tactic name
func (db *MitreDatabase) getTacticName(tacticID string) string {
	// ATLAS tactics
	atlasTactics := map[string]string{
		"AML.TA0000": "ML Attack Staging",
		"AML.TA0001": "Reconnaissance",
		"AML.TA0002": "ML Model Access",
		"AML.TA0004": "Privilege Escalation",
		"AML.TA0009": "Exfiltration",
		"AML.TA0034": "Impact",
	}

	// ATT&CK tactics
	attackTactics := map[string]string{
		"TA0001": "Initial Access",
		"TA0002": "Execution",
		"TA0003": "Persistence",
		"TA0004": "Privilege Escalation",
		"TA0006": "Credential Access",
		"TA0011": "Command and Control",
		"TA0040": "Impact",
	}

	if name, ok := atlasTactics[tacticID]; ok {
		return name
	}
	if name, ok := attackTactics[tacticID]; ok {
		return name
	}

	return "Unknown"
}

// ListAllTechniques returns all available techniques
func (db *MitreDatabase) ListAllTechniques() []MitreTechnique {
	var techniques []MitreTechnique

	for _, tech := range db.atlasTechniques {
		techniques = append(techniques, tech)
	}

	for _, tech := range db.attackTechniques {
		techniques = append(techniques, tech)
	}

	return techniques
}
