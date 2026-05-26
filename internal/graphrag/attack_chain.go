package graphrag

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// AttackChain represents a sequence of attack techniques forming a chain.
// Used for attack path analysis and correlation.
type AttackChain struct {
	ID         types.ID     `json:"id"`
	Name       string       `json:"name"`
	Steps      []AttackStep `json:"steps"`
	MissionID  types.ID     `json:"mission_id"`
	Confidence float64      `json:"confidence"` // Overall chain confidence
	Severity   string       `json:"severity"`
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// AttackStep represents a single step in an attack chain.
type AttackStep struct {
	Order       int        `json:"order"`
	TechniqueID string     `json:"technique_id"`
	NodeID      types.ID   `json:"node_id"`
	Description string     `json:"description"`
	Evidence    []types.ID `json:"evidence"` // Finding IDs as evidence
	Confidence  float64    `json:"confidence"`
}

// NewAttackChain creates a new AttackChain.
func NewAttackChain(name string, missionID types.ID) *AttackChain {
	now := time.Now()
	return &AttackChain{
		ID:         types.NewID(),
		Name:       name,
		Steps:      []AttackStep{},
		MissionID:  missionID,
		Confidence: 1.0,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// AddStep adds a step to the attack chain.
func (ac *AttackChain) AddStep(step AttackStep) {
	step.Order = len(ac.Steps) + 1
	ac.Steps = append(ac.Steps, step)
	ac.UpdatedAt = time.Now()
}
