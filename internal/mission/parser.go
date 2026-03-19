package mission

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/api/gen/workflowpb"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

// ParseError represents a mission parsing error with source location information.
// It provides detailed context about where errors occur in YAML mission files.
type ParseError struct {
	// Message is the human-readable error message
	Message string
	// Line is the line number where the error occurred (1-indexed)
	Line int
	// Column is the column number where the error occurred (1-indexed)
	Column int
	// NodeID is the ID of the node being parsed when the error occurred (if applicable)
	NodeID string
	// Err is the underlying error, if any
	Err error
}

// Error implements the error interface
func (e *ParseError) Error() string {
	if e.NodeID != "" {
		return fmt.Sprintf("parse error at line %d:%d (node %s): %s", e.Line, e.Column, e.NodeID, e.Message)
	}
	if e.Line > 0 {
		return fmt.Sprintf("parse error at line %d:%d: %s", e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("parse error: %s", e.Message)
}

// Unwrap returns the underlying error for error wrapping support
func (e *ParseError) Unwrap() error {
	return e.Err
}

// yamlMissionData represents the mission YAML structure with all sections
type yamlMissionData struct {
	Name         string               `yaml:"name"`
	Description  string               `yaml:"description"`
	Version      string               `yaml:"version"`
	Target       *yamlTargetSpec      `yaml:"target,omitempty"`
	Nodes        yaml.Node            `yaml:"nodes"` // Can be array or map
	Dependencies *MissionDependencies `yaml:"dependencies,omitempty"`
	Workspace    *yamlWorkspaceData   `yaml:"workspace,omitempty"`
	Metadata     map[string]any       `yaml:"metadata,omitempty"`
}

// yamlTargetSpec represents target configuration
type yamlTargetSpec struct {
	Reference string `yaml:"-"` // For string form
	Name      string `yaml:"name,omitempty"`
	Type      string `yaml:"type,omitempty"`
}

// UnmarshalYAML implements custom YAML unmarshaling for target
func (t *yamlTargetSpec) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try as string reference first
	var str string
	if err := unmarshal(&str); err == nil {
		t.Reference = str
		return nil
	}

	// Otherwise unmarshal as object
	type rawTarget yamlTargetSpec
	var raw rawTarget
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*t = yamlTargetSpec(raw)
	return nil
}

// yamlNodeData represents a single node definition with all possible fields
type yamlNodeData struct {
	ID          string                 `yaml:"id"`
	Type        string                 `yaml:"type"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	DependsOn   []string               `yaml:"depends_on,omitempty"`
	Timeout     string                 `yaml:"timeout,omitempty"`
	Retry       *yamlRetryData         `yaml:"retry,omitempty"`
	DataPolicy  *DataPolicy            `yaml:"data_policy,omitempty"`
	Agent       string                 `yaml:"agent,omitempty"`
	Task        map[string]interface{} `yaml:"task,omitempty"`
	Tool        string                 `yaml:"tool,omitempty"`
	Input       map[string]interface{} `yaml:"input,omitempty"`
	Plugin      string                 `yaml:"plugin,omitempty"`
	Method      string                 `yaml:"method,omitempty"`
	Params      map[string]interface{} `yaml:"params,omitempty"`
	Condition   *yamlConditionData     `yaml:"condition,omitempty"`
	SubNodes    []yamlNodeData         `yaml:"sub_nodes,omitempty"`
	Metadata    map[string]interface{} `yaml:"metadata,omitempty"`
}

// yamlRetryData represents retry policy configuration
type yamlRetryData struct {
	MaxRetries   int     `yaml:"max_retries"`
	Backoff      string  `yaml:"backoff"`
	InitialDelay string  `yaml:"initial_delay"`
	MaxDelay     string  `yaml:"max_delay,omitempty"`
	Multiplier   float64 `yaml:"multiplier,omitempty"`
}

// yamlConditionData represents conditional branching configuration
type yamlConditionData struct {
	Expression  string   `yaml:"expression"`
	TrueBranch  []string `yaml:"true_branch,omitempty"`
	FalseBranch []string `yaml:"false_branch,omitempty"`
}

// yamlWorkspaceData represents workspace configuration from YAML
type yamlWorkspaceData struct {
	Repositories      []yamlRepositoryData  `yaml:"repositories,omitempty"`
	CleanupOnComplete bool                  `yaml:"cleanup_on_complete,omitempty"`
	UseWorktrees      bool                  `yaml:"use_worktrees,omitempty"`
	LSPEnabled        bool                  `yaml:"lsp_enabled,omitempty"`
	LSPTimeout        string                `yaml:"lsp_timeout,omitempty"`
	BaseDirectory     string                `yaml:"base_directory,omitempty"`
}

// yamlRepositoryData represents a repository configuration from YAML
type yamlRepositoryData struct {
	Name           string   `yaml:"name"`
	URL            string   `yaml:"url"`
	Branch         string   `yaml:"branch,omitempty"`
	CredentialName string   `yaml:"credential_name,omitempty"`
	Shallow        bool     `yaml:"shallow,omitempty"`
	DependsOn      []string `yaml:"depends_on,omitempty"`
}

// ParseDefinition parses a mission definition from a YAML file.
// It supports both mission.yaml (new) and workflow.yaml (legacy) file names.
//
// Parameters:
//   - path: File system path to the YAML mission file
//
// Returns:
//   - *MissionDefinition: The parsed mission definition
//   - error: Detailed parse error with line numbers, or nil on success
//
// Example usage:
//
//	def, err := ParseDefinition("missions/recon.yaml")
//	if err != nil {
//	    var parseErr *ParseError
//	    if errors.As(err, &parseErr) {
//	        fmt.Printf("Error at line %d: %s\n", parseErr.Line, parseErr.Message)
//	    }
//	    return err
//	}
func ParseDefinition(path string) (*MissionDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ParseError{
			Message: fmt.Sprintf("failed to read mission file: %v", err),
			Err:     err,
		}
	}

	def, err := ParseDefinitionFromBytes(data)
	if err != nil {
		return nil, err
	}

	return def, nil
}

// ParseDefinitionFromBytes parses a mission definition from raw YAML bytes.
// This function is useful for testing and for parsing mission definitions
// that are generated dynamically or stored in databases.
//
// The parser performs comprehensive validation including:
//   - Required fields presence
//   - Node type validity
//   - Dependency graph validity (no dangling references)
//   - Duration format validation
//   - Retry policy validation
//
// Parameters:
//   - data: Raw YAML bytes containing the mission definition
//
// Returns:
//   - *MissionDefinition: The parsed mission definition structure
//   - error: Detailed parse error with line numbers, or nil on success
//
// Example usage:
//
//	yamlData := []byte(`
//	name: Test Mission
//	nodes:
//	  - id: node1
//	    type: agent
//	    agent: test-agent
//	`)
//	def, err := ParseDefinitionFromBytes(yamlData)
func ParseDefinitionFromBytes(data []byte) (*MissionDefinition, error) {
	// First pass: unmarshal into a yaml.Node to preserve position information
	var rootNode yaml.Node
	if err := yaml.Unmarshal(data, &rootNode); err != nil {
		return nil, &ParseError{
			Message: "invalid YAML syntax",
			Err:     err,
		}
	}

	// Second pass: unmarshal into our data structure
	var missionData yamlMissionData
	if err := yaml.Unmarshal(data, &missionData); err != nil {
		return nil, &ParseError{
			Message: "failed to parse mission structure",
			Err:     err,
		}
	}

	// Validate required fields
	if missionData.Name == "" {
		return nil, &ParseError{
			Message: "mission 'name' field is required",
			Line:    getFieldLine(&rootNode, "name"),
		}
	}

	// Create mission definition structure
	def := &MissionDefinition{
		ID:           types.NewID(),
		Name:         missionData.Name,
		Description:  missionData.Description,
		Version:      missionData.Version,
		Nodes:        make(map[string]*MissionNode),
		Edges:        []MissionEdge{},
		Metadata:     missionData.Metadata,
		Dependencies: missionData.Dependencies,
		CreatedAt:    time.Now(),
	}

	// Extract target reference
	if missionData.Target != nil {
		if missionData.Target.Reference != "" {
			def.TargetRef = missionData.Target.Reference
		} else if missionData.Target.Name != "" {
			def.TargetRef = missionData.Target.Name
		}
	}

	// Parse workspace configuration
	if missionData.Workspace != nil {
		workspaceConfig, err := parseWorkspaceConfig(missionData.Workspace, &rootNode)
		if err != nil {
			return nil, err
		}
		def.Workspace = workspaceConfig
	}

	// Parse nodes - handle both array and map formats
	nodesArray, err := parseNodesField(&missionData.Nodes, &rootNode)
	if err != nil {
		return nil, err
	}

	if len(nodesArray) == 0 {
		return nil, &ParseError{
			Message: "mission must contain at least one node",
			Line:    getFieldLine(&rootNode, "nodes"),
		}
	}

	// Build node ID set for validation
	nodeIDs := make(map[string]bool)
	nodeLines := make(map[string]int)

	for i, nodeData := range nodesArray {
		if nodeData.ID == "" {
			return nil, &ParseError{
				Message: "node 'id' field is required",
				Line:    getNodeLineFromArray(&rootNode, i),
			}
		}

		if nodeIDs[nodeData.ID] {
			return nil, &ParseError{
				Message: fmt.Sprintf("duplicate node ID: %s", nodeData.ID),
				Line:    getNodeLineFromArray(&rootNode, i),
				NodeID:  nodeData.ID,
			}
		}

		nodeIDs[nodeData.ID] = true
		nodeLines[nodeData.ID] = getNodeLineFromArray(&rootNode, i)
	}

	// Parse all nodes
	for i, nodeData := range nodesArray {
		node, err := parseNode(&nodeData, getNodeLineFromArray(&rootNode, i))
		if err != nil {
			if parseErr, ok := err.(*ParseError); ok {
				parseErr.NodeID = nodeData.ID
				return nil, parseErr
			}
			return nil, &ParseError{
				Message: err.Error(),
				Line:    getNodeLineFromArray(&rootNode, i),
				NodeID:  nodeData.ID,
				Err:     err,
			}
		}

		def.Nodes[node.ID] = node
	}

	// Build edges from dependencies and validate references
	for _, nodeData := range nodesArray {
		for _, depID := range nodeData.DependsOn {
			if !nodeIDs[depID] {
				return nil, &ParseError{
					Message: fmt.Sprintf("node depends on non-existent node '%s'", depID),
					Line:    nodeLines[nodeData.ID],
					NodeID:  nodeData.ID,
				}
			}

			def.Edges = append(def.Edges, MissionEdge{
				From: depID,
				To:   nodeData.ID,
			})
		}
	}

	// Calculate entry and exit points
	def.EntryPoints = calculateEntryPoints(def)
	def.ExitPoints = calculateExitPoints(def)

	return def, nil
}

// parseNodesField handles both array and map node formats
func parseNodesField(nodesNode *yaml.Node, rootNode *yaml.Node) ([]yamlNodeData, error) {
	if nodesNode.Kind == 0 {
		// Nodes field not present
		return nil, &ParseError{
			Message: "mission must contain 'nodes' field",
			Line:    1,
		}
	}

	// Handle array format: nodes: [...]
	if nodesNode.Kind == yaml.SequenceNode {
		var nodesArray []yamlNodeData
		if err := nodesNode.Decode(&nodesArray); err != nil {
			return nil, &ParseError{
				Message: "failed to parse nodes array",
				Line:    nodesNode.Line,
				Err:     err,
			}
		}
		return nodesArray, nil
	}

	// Handle map format: nodes: {id1: {...}, id2: {...}}
	if nodesNode.Kind == yaml.MappingNode {
		var nodesMap map[string]yamlNodeData
		if err := nodesNode.Decode(&nodesMap); err != nil {
			return nil, &ParseError{
				Message: "failed to parse nodes map",
				Line:    nodesNode.Line,
				Err:     err,
			}
		}

		// Convert map to array, filling in IDs
		nodesArray := make([]yamlNodeData, 0, len(nodesMap))
		for id, node := range nodesMap {
			// Set ID from map key if not already set
			if node.ID == "" {
				node.ID = id
			}
			nodesArray = append(nodesArray, node)
		}
		return nodesArray, nil
	}

	return nil, &ParseError{
		Message: "nodes field must be an array or map",
		Line:    nodesNode.Line,
	}
}

// parseNode converts a YAML node definition to a MissionNode
func parseNode(nodeData *yamlNodeData, line int) (*MissionNode, error) {
	if nodeData.Type == "" {
		return nil, &ParseError{
			Message: "node 'type' field is required",
			Line:    line,
		}
	}

	node := &MissionNode{
		ID:           nodeData.ID,
		Name:         nodeData.Name,
		Description:  nodeData.Description,
		Dependencies: nodeData.DependsOn,
		Metadata:     nodeData.Metadata,
		DataPolicy:   nodeData.DataPolicy,
	}

	// Parse timeout - supports both string durations ("10m") and numeric nanoseconds (600000000000)
	if nodeData.Timeout != "" {
		timeout, err := time.ParseDuration(nodeData.Timeout)
		if err != nil {
			// Try parsing as nanoseconds (for JSON-serialized time.Duration)
			if ns, numErr := strconv.ParseInt(nodeData.Timeout, 10, 64); numErr == nil {
				node.Timeout = time.Duration(ns)
			} else {
				return nil, &ParseError{
					Message: fmt.Sprintf("invalid timeout format '%s': must be a valid Go duration (e.g., '30s', '5m')", nodeData.Timeout),
					Line:    line,
					Err:     err,
				}
			}
		} else {
			node.Timeout = timeout
		}
	}

	// Parse retry policy
	if nodeData.Retry != nil {
		retryPolicy, err := parseRetryPolicy(nodeData.Retry, line)
		if err != nil {
			return nil, err
		}
		node.RetryPolicy = retryPolicy
	}

	// Parse node type-specific fields
	var err error
	switch strings.ToLower(nodeData.Type) {
	case "agent":
		err = parseAgentNode(nodeData, node, line)
		node.Type = NodeTypeAgent
	case "tool":
		err = parseToolNode(nodeData, node, line)
		node.Type = NodeTypeTool
	case "plugin":
		err = parsePluginNode(nodeData, node, line)
		node.Type = NodeTypePlugin
	case "condition":
		err = parseConditionNode(nodeData, node, line)
		node.Type = NodeTypeCondition
	case "parallel":
		err = parseParallelNode(nodeData, node, line)
		node.Type = NodeTypeParallel
	case "join":
		node.Type = NodeTypeJoin
	default:
		return nil, &ParseError{
			Message: fmt.Sprintf("invalid node type '%s': must be one of: agent, tool, plugin, condition, parallel, join", nodeData.Type),
			Line:    line,
		}
	}

	if err != nil {
		return nil, err
	}

	return node, nil
}

// parseAgentNode parses agent-specific fields
func parseAgentNode(nodeData *yamlNodeData, node *MissionNode, line int) error {
	if nodeData.Agent == "" {
		return &ParseError{
			Message: "agent nodes require 'agent' field",
			Line:    line,
		}
	}

	node.AgentName = nodeData.Agent

	// Parse task definition
	if nodeData.Task != nil {
		task := agent.Task{
			ID:          types.NewID(),
			Name:        node.Name,
			Description: node.Description,
			Goal:        node.Description, // Default goal to description
			Input:       nodeData.Task,
			Timeout:     node.Timeout,
			CreatedAt:   time.Now(),
			Priority:    0,
			Tags:        []string{},
		}

		// Extract known task fields
		if name, ok := nodeData.Task["name"].(string); ok {
			task.Name = name
		}
		if desc, ok := nodeData.Task["description"].(string); ok {
			task.Description = desc
		}
		if goal, ok := nodeData.Task["goal"].(string); ok {
			task.Goal = goal
		}
		if context, ok := nodeData.Task["context"].(map[string]interface{}); ok {
			task.Context = context
		}
		if priority, ok := nodeData.Task["priority"].(int); ok {
			task.Priority = priority
		}
		if tagsRaw, ok := nodeData.Task["tags"].([]interface{}); ok {
			tags := make([]string, 0, len(tagsRaw))
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					tags = append(tags, str)
				}
			}
			task.Tags = tags
		}

		node.AgentTask = &task
	}

	return nil
}

// parseToolNode parses tool-specific fields
func parseToolNode(nodeData *yamlNodeData, node *MissionNode, line int) error {
	if nodeData.Tool == "" {
		return &ParseError{
			Message: "tool nodes require 'tool' field",
			Line:    line,
		}
	}

	node.ToolName = nodeData.Tool
	node.ToolInput = nodeData.Input
	return nil
}

// parsePluginNode parses plugin-specific fields
func parsePluginNode(nodeData *yamlNodeData, node *MissionNode, line int) error {
	if nodeData.Plugin == "" {
		return &ParseError{
			Message: "plugin nodes require 'plugin' field",
			Line:    line,
		}
	}
	if nodeData.Method == "" {
		return &ParseError{
			Message: "plugin nodes require 'method' field",
			Line:    line,
		}
	}

	node.PluginName = nodeData.Plugin
	node.PluginMethod = nodeData.Method
	node.PluginParams = nodeData.Params
	return nil
}

// parseConditionNode parses condition-specific fields
func parseConditionNode(nodeData *yamlNodeData, node *MissionNode, line int) error {
	if nodeData.Condition == nil {
		return &ParseError{
			Message: "condition nodes require 'condition' field",
			Line:    line,
		}
	}
	if nodeData.Condition.Expression == "" {
		return &ParseError{
			Message: "condition nodes require 'condition.expression' field",
			Line:    line,
		}
	}

	node.Condition = &NodeCondition{
		Expression:  nodeData.Condition.Expression,
		TrueBranch:  nodeData.Condition.TrueBranch,
		FalseBranch: nodeData.Condition.FalseBranch,
	}

	return nil
}

// parseParallelNode parses parallel-specific fields
func parseParallelNode(nodeData *yamlNodeData, node *MissionNode, line int) error {
	if len(nodeData.SubNodes) == 0 {
		return &ParseError{
			Message: "parallel nodes must contain at least one sub_node",
			Line:    line,
		}
	}

	subNodes := make([]*MissionNode, 0, len(nodeData.SubNodes))
	for i, subNodeData := range nodeData.SubNodes {
		// Auto-generate sub-node IDs if not provided
		if subNodeData.ID == "" {
			subNodeData.ID = fmt.Sprintf("%s_sub_%d", nodeData.ID, i)
		}

		subNode, err := parseNode(&subNodeData, line)
		if err != nil {
			if parseErr, ok := err.(*ParseError); ok {
				parseErr.Message = fmt.Sprintf("sub-node %d: %s", i, parseErr.Message)
				return parseErr
			}
			return &ParseError{
				Message: fmt.Sprintf("sub-node %d: %v", i, err),
				Line:    line,
				Err:     err,
			}
		}

		subNodes = append(subNodes, subNode)
	}

	node.SubNodes = subNodes
	return nil
}

// parseRetryPolicy parses and validates retry configuration
func parseRetryPolicy(retryData *yamlRetryData, line int) (*RetryPolicy, error) {
	if retryData.MaxRetries < 0 {
		return nil, &ParseError{
			Message: "retry.max_retries must be non-negative",
			Line:    line,
		}
	}

	policy := &RetryPolicy{
		MaxRetries: retryData.MaxRetries,
		Multiplier: retryData.Multiplier,
	}

	// Parse backoff strategy
	switch strings.ToLower(retryData.Backoff) {
	case "constant":
		policy.BackoffStrategy = BackoffConstant
	case "linear":
		policy.BackoffStrategy = BackoffLinear
	case "exponential":
		policy.BackoffStrategy = BackoffExponential
	default:
		return nil, &ParseError{
			Message: fmt.Sprintf("invalid retry.backoff '%s': must be one of: constant, linear, exponential", retryData.Backoff),
			Line:    line,
		}
	}

	// Parse initial delay
	if retryData.InitialDelay != "" {
		initialDelay, err := time.ParseDuration(retryData.InitialDelay)
		if err != nil {
			return nil, &ParseError{
				Message: fmt.Sprintf("invalid retry.initial_delay '%s': must be a valid Go duration", retryData.InitialDelay),
				Line:    line,
				Err:     err,
			}
		}
		policy.InitialDelay = initialDelay
	}

	// Parse max delay
	if retryData.MaxDelay != "" {
		maxDelay, err := time.ParseDuration(retryData.MaxDelay)
		if err != nil {
			return nil, &ParseError{
				Message: fmt.Sprintf("invalid retry.max_delay '%s': must be a valid Go duration", retryData.MaxDelay),
				Line:    line,
				Err:     err,
			}
		}
		policy.MaxDelay = maxDelay
	}

	// Validate exponential backoff requirements
	if policy.BackoffStrategy == BackoffExponential {
		if policy.Multiplier <= 0 {
			return nil, &ParseError{
				Message: "retry.multiplier must be positive for exponential backoff",
				Line:    line,
			}
		}
		if policy.MaxDelay == 0 {
			return nil, &ParseError{
				Message: "retry.max_delay is required for exponential backoff",
				Line:    line,
			}
		}
	}

	return policy, nil
}

// parseWorkspaceConfig parses and validates workspace configuration
func parseWorkspaceConfig(workspaceData *yamlWorkspaceData, rootNode *yaml.Node) (*WorkspaceConfig, error) {
	if workspaceData == nil {
		return nil, nil
	}

	config := &WorkspaceConfig{
		Repositories: make([]RepositoryConfig, 0, len(workspaceData.Repositories)),
		Settings: WorkspaceSettings{
			CleanupOnComplete: workspaceData.CleanupOnComplete,
			UseWorktrees:      workspaceData.UseWorktrees,
			LSPEnabled:        workspaceData.LSPEnabled,
			BaseDirectory:     workspaceData.BaseDirectory,
		},
	}

	// Parse LSP timeout if specified
	if workspaceData.LSPTimeout != "" {
		timeout, err := time.ParseDuration(workspaceData.LSPTimeout)
		if err != nil {
			return nil, &ParseError{
				Message: fmt.Sprintf("invalid workspace.lsp_timeout '%s': must be a valid Go duration", workspaceData.LSPTimeout),
				Line:    getFieldLine(rootNode, "workspace"),
				Err:     err,
			}
		}
		config.Settings.LSPTimeout = timeout
	}

	// Parse repositories
	for i, repoData := range workspaceData.Repositories {
		repo := RepositoryConfig{
			Name:           repoData.Name,
			URL:            repoData.URL,
			Branch:         repoData.Branch,
			CredentialName: repoData.CredentialName,
			Shallow:        repoData.Shallow,
			DependsOn:      repoData.DependsOn,
		}

		// Validate required fields
		if repo.Name == "" {
			return nil, &ParseError{
				Message: fmt.Sprintf("repository at index %d: 'name' field is required", i),
				Line:    getFieldLine(rootNode, "workspace"),
			}
		}
		if repo.URL == "" {
			return nil, &ParseError{
				Message: fmt.Sprintf("repository '%s': 'url' field is required", repo.Name),
				Line:    getFieldLine(rootNode, "workspace"),
			}
		}

		config.Repositories = append(config.Repositories, repo)
	}

	// Validate the entire workspace configuration
	if err := config.Validate(); err != nil {
		return nil, &ParseError{
			Message: fmt.Sprintf("workspace validation failed: %v", err),
			Line:    getFieldLine(rootNode, "workspace"),
			Err:     err,
		}
	}

	return config, nil
}

// calculateEntryPoints identifies nodes with no incoming edges
func calculateEntryPoints(def *MissionDefinition) []string {
	hasIncoming := make(map[string]bool)
	for _, edge := range def.Edges {
		hasIncoming[edge.To] = true
	}

	entryPoints := []string{}
	for id := range def.Nodes {
		if !hasIncoming[id] {
			entryPoints = append(entryPoints, id)
		}
	}

	return entryPoints
}

// calculateExitPoints identifies nodes with no outgoing edges
func calculateExitPoints(def *MissionDefinition) []string {
	hasOutgoing := make(map[string]bool)
	for _, edge := range def.Edges {
		hasOutgoing[edge.From] = true
	}

	// Handle condition nodes
	for id, node := range def.Nodes {
		if node.Type == NodeTypeCondition && node.Condition != nil {
			if len(node.Condition.TrueBranch) > 0 || len(node.Condition.FalseBranch) > 0 {
				hasOutgoing[id] = true
			}
		}
	}

	exitPoints := []string{}
	for id := range def.Nodes {
		if !hasOutgoing[id] {
			exitPoints = append(exitPoints, id)
		}
	}

	return exitPoints
}

// getFieldLine attempts to find the line number of a specific field in the YAML
func getFieldLine(node *yaml.Node, fieldName string) int {
	if node == nil || node.Kind != yaml.DocumentNode {
		return 0
	}

	// Document node contains the root content
	if len(node.Content) == 0 {
		return 0
	}

	return findFieldInMapping(node.Content[0], fieldName)
}

// getNodeLineFromArray attempts to find the line number of a node in the nodes array
func getNodeLineFromArray(rootNode *yaml.Node, index int) int {
	if rootNode == nil || rootNode.Kind != yaml.DocumentNode {
		return 0
	}

	if len(rootNode.Content) == 0 {
		return 0
	}

	mappingNode := rootNode.Content[0]
	if mappingNode.Kind != yaml.MappingNode {
		return 0
	}

	// Find the "nodes" key
	for i := 0; i < len(mappingNode.Content)-1; i += 2 {
		key := mappingNode.Content[i]
		value := mappingNode.Content[i+1]

		if key.Value == "nodes" {
			// Handle array format
			if value.Kind == yaml.SequenceNode {
				if index < len(value.Content) {
					return value.Content[index].Line
				}
			}
			// Handle map format
			if value.Kind == yaml.MappingNode {
				// For maps, get the line of the nth key-value pair
				pairIndex := index * 2
				if pairIndex < len(value.Content) {
					return value.Content[pairIndex].Line
				}
			}
		}
	}

	return 0
}

// findFieldInMapping searches for a field in a YAML mapping node
func findFieldInMapping(node *yaml.Node, fieldName string) int {
	if node == nil || node.Kind != yaml.MappingNode {
		return 0
	}

	for i := 0; i < len(node.Content)-1; i += 2 {
		key := node.Content[i]
		if key.Value == fieldName {
			return key.Line
		}
	}

	return 0
}

// LoadMissionFromFileOrName is a convenience function that tries to load a mission
// definition from multiple sources in priority order:
// 1. If path is an absolute or relative file path that exists, load from file
// 2. If path looks like a file name, check for mission.yaml and workflow.yaml
// 3. Otherwise, assume it's a mission name and look in ~/.gibson/missions/{name}/
//
// This function supports both the new mission.yaml format and legacy workflow.yaml.
func LoadMissionFromFileOrName(pathOrName string) (*MissionDefinition, error) {
	// Check if it's a file path that exists
	if _, err := os.Stat(pathOrName); err == nil {
		return ParseDefinition(pathOrName)
	}

	// Check for mission.yaml or workflow.yaml in current directory
	if !filepath.IsAbs(pathOrName) && !strings.Contains(pathOrName, string(filepath.Separator)) {
		// Try mission.yaml first (new format)
		if _, err := os.Stat("mission.yaml"); err == nil {
			return ParseDefinition("mission.yaml")
		}
		// Fall back to workflow.yaml (legacy)
		if _, err := os.Stat("workflow.yaml"); err == nil {
			return ParseDefinition("workflow.yaml")
		}
	}

	// Try to load from ~/.gibson/missions/{name}/
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	// Try mission.yaml first
	missionPath := filepath.Join(homeDir, ".gibson", "missions", pathOrName, "mission.yaml")
	if _, err := os.Stat(missionPath); err == nil {
		return ParseDefinition(missionPath)
	}

	// Fall back to workflow.yaml for backward compatibility
	workflowPath := filepath.Join(homeDir, ".gibson", "missions", pathOrName, "workflow.yaml")
	if _, err := os.Stat(workflowPath); err == nil {
		return ParseDefinition(workflowPath)
	}

	return nil, fmt.Errorf("mission not found: %s (checked file paths and ~/.gibson/missions/)", pathOrName)
}

// ParseDefinitionProto parses a mission definition from a YAML file and returns
// a proto WorkflowDefinition with validation.
//
// This function:
// 1. Parses YAML to JSON
// 2. Uses protojson to unmarshal JSON to proto WorkflowDefinition
// 3. Validates proto message structure
//
// This is the preferred method for parsing workflows when proto validation is needed.
//
// Parameters:
//   - path: File system path to the YAML workflow file
//
// Returns:
//   - *workflowpb.WorkflowDefinition: The validated proto workflow definition
//   - error: Detailed parse error with validation messages, or nil on success
func ParseDefinitionProto(path string) (*workflowpb.WorkflowDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ParseError{
			Message: fmt.Sprintf("failed to read workflow file: %v", err),
			Err:     err,
		}
	}

	return ParseDefinitionProtoFromBytes(data)
}

// ParseDefinitionProtoFromBytes parses a mission definition from raw YAML bytes
// and returns a proto WorkflowDefinition with validation.
//
// The parser performs:
// 1. YAML to JSON conversion (preserving structure)
// 2. JSON to proto unmarshaling using protojson
// 3. Proto validation (required fields, enum values, message structure)
//
// This provides stronger type safety and validation than the YAML-only parser.
//
// Parameters:
//   - data: Raw YAML bytes containing the workflow definition
//
// Returns:
//   - *workflowpb.WorkflowDefinition: The validated proto workflow definition
//   - error: Detailed parse error with validation messages, or nil on success
//
// Example usage:
//
//	yamlData := []byte(`
//	name: Test Workflow
//	version: 1.0.0
//	nodes:
//	  node1:
//	    type: agent
//	    agent: test-agent
//	`)
//	def, err := ParseDefinitionProtoFromBytes(yamlData)
func ParseDefinitionProtoFromBytes(data []byte) (*workflowpb.WorkflowDefinition, error) {
	// First parse YAML into a generic map
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return nil, &ParseError{
			Message: "invalid YAML syntax",
			Err:     err,
		}
	}

	// Convert map to JSON bytes
	jsonData, err := json.Marshal(yamlData)
	if err != nil {
		return nil, &ParseError{
			Message: "failed to convert YAML to JSON",
			Err:     err,
		}
	}

	// Unmarshal JSON to proto using protojson
	// This provides validation and proper enum conversion
	var workflowDef workflowpb.WorkflowDefinition
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: false, // Strict mode - fail on unknown fields
		AllowPartial:   false, // Require all required fields
	}

	if err := unmarshaler.Unmarshal(jsonData, &workflowDef); err != nil {
		return nil, &ParseError{
			Message: fmt.Sprintf("proto validation failed: %v", err),
			Err:     err,
		}
	}

	// Additional validation: check that we have at least one node
	if len(workflowDef.Nodes) == 0 {
		return nil, &ParseError{
			Message: "workflow must have at least one node",
		}
	}

	// Validate node types and configurations
	for nodeID, node := range workflowDef.Nodes {
		if node.Type == workflowpb.NodeType_NODE_TYPE_UNSPECIFIED {
			return nil, &ParseError{
				Message: fmt.Sprintf("node %s has unspecified type", nodeID),
				NodeID:  nodeID,
			}
		}

		// Validate that node has appropriate config for its type
		switch node.Type {
		case workflowpb.NodeType_NODE_TYPE_AGENT:
			if node.GetAgentConfig() == nil {
				return nil, &ParseError{
					Message: fmt.Sprintf("agent node %s missing agent_config", nodeID),
					NodeID:  nodeID,
				}
			}
		case workflowpb.NodeType_NODE_TYPE_TOOL:
			if node.GetToolConfig() == nil {
				return nil, &ParseError{
					Message: fmt.Sprintf("tool node %s missing tool_config", nodeID),
					NodeID:  nodeID,
				}
			}
		case workflowpb.NodeType_NODE_TYPE_PLUGIN:
			if node.GetPluginConfig() == nil {
				return nil, &ParseError{
					Message: fmt.Sprintf("plugin node %s missing plugin_config", nodeID),
					NodeID:  nodeID,
				}
			}
		case workflowpb.NodeType_NODE_TYPE_CONDITION:
			if node.GetConditionConfig() == nil {
				return nil, &ParseError{
					Message: fmt.Sprintf("condition node %s missing condition_config", nodeID),
					NodeID:  nodeID,
				}
			}
		case workflowpb.NodeType_NODE_TYPE_PARALLEL:
			if node.GetParallelConfig() == nil {
				return nil, &ParseError{
					Message: fmt.Sprintf("parallel node %s missing parallel_config", nodeID),
					NodeID:  nodeID,
				}
			}
		}
	}

	// Validate edges reference valid nodes
	for i, edge := range workflowDef.Edges {
		if _, ok := workflowDef.Nodes[edge.From]; !ok {
			return nil, &ParseError{
				Message: fmt.Sprintf("edge %d references non-existent source node: %s", i, edge.From),
			}
		}
		if _, ok := workflowDef.Nodes[edge.To]; !ok {
			return nil, &ParseError{
				Message: fmt.Sprintf("edge %d references non-existent target node: %s", i, edge.To),
			}
		}
	}

	return &workflowDef, nil
}
