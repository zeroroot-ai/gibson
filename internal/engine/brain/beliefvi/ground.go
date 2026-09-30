// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"fmt"
	"sort"
	"strings"
)

// groundSeparator is the fully-qualified ground-name separator, mirroring
// ground.SEPARATOR.
const groundSeparator = "::"

// GroundName returns the fully-qualified ground factor-variable name for
// (nodeID, variable), mirroring ground.ground_name.
func GroundName(nodeID, variable string) (string, error) {
	if strings.Contains(nodeID, groundSeparator) {
		return "", fmt.Errorf("beliefvi: node id %q must not contain %q", nodeID, groundSeparator)
	}
	if strings.Contains(variable, groundSeparator) {
		return "", fmt.Errorf("beliefvi: variable name %q must not contain %q", variable, groundSeparator)
	}
	return nodeID + groundSeparator + variable, nil
}

// VariableSpec is one node's declared belief variable (grounded from
// ontology.BeliefVariable), mirroring ground.VariableSpec: DependsOn maps
// another variable NAME ON THE SAME NODE to the noisy-OR strength that
// variable contributes when true; Leak is the background P(this
// variable=true) with every cause (intra-node and cross-node) absent.
type VariableSpec struct {
	DependsOn map[string]float64
	Leak      float64
}

// NodeSpec is one slice node (a grounded AttackGraphNode), mirroring
// ground.NodeSpec: its id and its own declared variables by name.
type NodeSpec struct {
	NodeID    string
	Variables map[string]VariableSpec
}

// EnablementCause is one enablement edge's contribution to a target
// variable, mirroring ground.EnablementCause: compromising (SourceNode,
// SourceVariable) is one more independent noisy-OR cause of (TargetNode,
// TargetVariable), at the given Strength.
type EnablementCause struct {
	SourceNode     string
	SourceVariable string
	TargetNode     string
	TargetVariable string
	Strength       float64
}

// GroundSlice builds the whole-slice ground factor set: every node's own
// variables, each wired via noisy-OR to its intra-node DependsOn parents and
// any incoming enablement causes that target it, mirroring ground.ground_slice
// exactly, including its determinism discipline — node/variable/cause
// iteration is always over an explicitly sorted key, never map iteration
// order, so the same slice always grounds to the same factor set regardless
// of what order the caller listed its nodes, variables or enablement causes
// in.
func GroundSlice(nodes []NodeSpec, enablement []EnablementCause) ([]Factor, error) {
	type targetKey struct{ node, variable string }
	byTarget := make(map[targetKey][]EnablementCause)
	for _, c := range enablement {
		k := targetKey{c.TargetNode, c.TargetVariable}
		byTarget[k] = append(byTarget[k], c)
	}
	for k, causes := range byTarget {
		sort.Slice(causes, func(i, j int) bool {
			if causes[i].SourceNode != causes[j].SourceNode {
				return causes[i].SourceNode < causes[j].SourceNode
			}
			return causes[i].SourceVariable < causes[j].SourceVariable
		})
		byTarget[k] = causes
	}

	sortedNodes := append([]NodeSpec(nil), nodes...)
	sort.Slice(sortedNodes, func(i, j int) bool { return sortedNodes[i].NodeID < sortedNodes[j].NodeID })

	var factors []Factor
	for _, node := range sortedNodes {
		varNames := make([]string, 0, len(node.Variables))
		for v := range node.Variables {
			varNames = append(varNames, v)
		}
		sort.Strings(varNames)

		for _, varName := range varNames {
			spec := node.Variables[varName]
			gname, err := GroundName(node.NodeID, varName)
			if err != nil {
				return nil, err
			}

			depNames := make([]string, 0, len(spec.DependsOn))
			for d := range spec.DependsOn {
				depNames = append(depNames, d)
			}
			sort.Strings(depNames)

			var causes []NoisyOrCause
			for _, dep := range depNames {
				pname, err := GroundName(node.NodeID, dep)
				if err != nil {
					return nil, err
				}
				causes = append(causes, NoisyOrCause{Parent: pname, Strength: spec.DependsOn[dep]})
			}
			for _, c := range byTarget[targetKey{node.NodeID, varName}] {
				pname, err := GroundName(c.SourceNode, c.SourceVariable)
				if err != nil {
					return nil, err
				}
				causes = append(causes, NoisyOrCause{Parent: pname, Strength: c.Strength})
			}

			built, err := NoisyOrFactors(gname, causes, spec.Leak)
			if err != nil {
				return nil, err
			}
			factors = append(factors, built...)
		}
	}
	return factors, nil
}

// VariableBelief is one variable's posterior, mirroring the
// {"true": p, "false": 1-p} shape ground.solve_slice returns per variable.
type VariableBelief struct {
	True  float64
	False float64
}

// SolveSlice grounds the slice and returns every declared variable's
// posterior, keyed by node id then variable name, via exact variable
// elimination (never sampling — ADR-0005 SS2 still holds), mirroring
// ground.solve_slice exactly.
//
// evidence maps a ground name (GroundName(nodeID, variable)) to an observed
// state ("true"/"false"); an observed variable reports probability 1.0 for
// its observed state without needing a query.
func SolveSlice(nodes []NodeSpec, enablement []EnablementCause, evidence map[string]string) (map[string]map[string]VariableBelief, error) {
	factors, err := GroundSlice(nodes, enablement)
	if err != nil {
		return nil, err
	}

	sortedNodes := append([]NodeSpec(nil), nodes...)
	sort.Slice(sortedNodes, func(i, j int) bool { return sortedNodes[i].NodeID < sortedNodes[j].NodeID })

	out := make(map[string]map[string]VariableBelief, len(sortedNodes))
	for _, node := range sortedNodes {
		varNames := make([]string, 0, len(node.Variables))
		for v := range node.Variables {
			varNames = append(varNames, v)
		}
		sort.Strings(varNames)

		nodeOut := make(map[string]VariableBelief, len(varNames))
		for _, varName := range varNames {
			gname, err := GroundName(node.NodeID, varName)
			if err != nil {
				return nil, err
			}
			if observed, ok := evidence[gname]; ok {
				vb := VariableBelief{}
				if observed == "true" {
					vb.True = 1.0
				} else {
					vb.False = 1.0
				}
				nodeOut[varName] = vb
				continue
			}
			qEv := make(map[string]string, len(evidence))
			for k, v := range evidence {
				if k != gname {
					qEv[k] = v
				}
			}
			result, err := Query(factors, gname, qEv)
			if err != nil {
				return nil, err
			}
			nodeOut[varName] = VariableBelief{True: result["true"], False: result["false"]}
		}
		out[node.NodeID] = nodeOut
	}
	return out, nil
}
