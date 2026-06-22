//go:build ignore
// +build ignore

package main

import (
	"fmt"

	"github.com/zeroroot.ai/opensource/gibson/internal/engine/mission"
)

func main() {
	yamlData := `
name: Test Mission
version: 1.0.0
description: A test mission

nodes:
  - id: node1
    type: agent
    agent: test-agent
    task:
      target: example.com
  - id: node2
    type: tool
    tool: nmap
    depends_on:
      - node1
    input:
      port_range: "1-1024"
`

	def, err := mission.ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	fmt.Printf("✓ Parsed mission: %s (version %s)\n", def.Name, def.Version)
	fmt.Printf("✓ Nodes: %d\n", len(def.Nodes))
	fmt.Printf("✓ Edges: %d\n", len(def.Edges))
	fmt.Printf("✓ Entry points: %v\n", def.EntryPoints)
	fmt.Printf("✓ Exit points: %v\n", def.ExitPoints)

	// Test map format
	yamlMapData := `
name: Test Map Mission
nodes:
  recon:
    type: agent
    agent: recon-agent
  scan:
    type: tool
    tool: nmap
    depends_on: [recon]
`

	def2, err := mission.ParseDefinitionFromBytes([]byte(yamlMapData))
	if err != nil {
		fmt.Printf("Parse error (map format): %v\n", err)
		return
	}

	fmt.Printf("✓ Parsed map format mission: %s\n", def2.Name)
	fmt.Printf("✓ Nodes: %d\n", len(def2.Nodes))

	fmt.Println("\n✓ All parser verification tests passed!")
}
