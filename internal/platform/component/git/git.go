package git

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// GitOperations defines the interface for git operations
type GitOperations interface {
	// Clone clones a repository to the specified destination
	Clone(url, dest string, opts CloneOptions) error

	// Pull performs a git pull in the specified directory
	Pull(dir string) error

	// GetVersion returns the current commit hash of the repository
	GetVersion(dir string) (string, error)

	// ParseRepoURL extracts component information from a repository URL
	ParseRepoURL(url string) (*RepoInfo, error)
}

// CloneOptions contains options for cloning a repository
type CloneOptions struct {
	// Depth specifies the depth for shallow clones (0 for full clone)
	Depth int

	// Branch specifies the branch to clone
	Branch string

	// Tag specifies the tag to clone
	Tag string
}

// RepoInfo contains parsed information from a repository URL
type RepoInfo struct {
	// Host is the git hosting service (e.g., github.com)
	Host string

	// Owner is the repository owner or organization
	Owner string

	// Repo is the full repository name (e.g., gibson-agent-scanner)
	Repo string
}

// DefaultGitOperations implements GitOperations using os/exec
type DefaultGitOperations struct{}

// NewDefaultGitOperations creates a new DefaultGitOperations instance
func NewDefaultGitOperations() GitOperations {
	return &DefaultGitOperations{}
}

// Clone clones a repository to the specified destination
func (g *DefaultGitOperations) Clone(url, dest string, opts CloneOptions) error {
	args := []string{"clone"}

	// Add depth option for shallow clone
	if opts.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", opts.Depth))
	}

	// Add branch option
	if opts.Branch != "" {
		args = append(args, "--branch", opts.Branch)
	}

	// Add tag option (tags can be checked out like branches)
	if opts.Tag != "" {
		args = append(args, "--branch", opts.Tag)
	}

	args = append(args, url, dest)

	cmd := exec.Command("git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// Pull performs a git pull in the specified directory
func (g *DefaultGitOperations) Pull(dir string) error {
	cmd := exec.Command("git", "pull")
	cmd.Dir = dir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git pull failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// GetVersion returns the current commit hash of the repository
func (g *DefaultGitOperations) GetVersion(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git rev-parse failed: %w (output: %s)", err, string(output))
	}

	// Trim whitespace from output
	hash := strings.TrimSpace(string(output))
	if hash == "" {
		return "", fmt.Errorf("git rev-parse returned empty hash")
	}

	return hash, nil
}

// ParseRepoURL extracts component information from a repository URL
func (g *DefaultGitOperations) ParseRepoURL(url string) (*RepoInfo, error) {
	if url == "" {
		return nil, fmt.Errorf("repository URL cannot be empty")
	}

	// Patterns to match:
	// https://github.com/org/repo-name.git
	// git@github.com:org/repo-name.git
	// https://github.com/org/repo-name

	var host, owner, repo string

	// Try HTTPS pattern first
	httpsPattern := regexp.MustCompile(`^https?://([^/]+)/([^/]+)/([^/]+?)(?:\.git)?$`)
	if matches := httpsPattern.FindStringSubmatch(url); matches != nil {
		host = matches[1]
		owner = matches[2]
		repo = matches[3]
	} else {
		// Try SSH pattern
		sshPattern := regexp.MustCompile(`^git@([^:]+):([^/]+)/([^/]+?)(?:\.git)?$`)
		if matches := sshPattern.FindStringSubmatch(url); matches != nil {
			host = matches[1]
			owner = matches[2]
			repo = matches[3]
		} else {
			return nil, fmt.Errorf("unable to parse repository URL: %s", url)
		}
	}

	return &RepoInfo{
		Host:  host,
		Owner: owner,
		Repo:  repo,
	}, nil
}

// String returns a string representation of RepoInfo
func (r *RepoInfo) String() string {
	return fmt.Sprintf("%s/%s/%s", r.Host, r.Owner, r.Repo)
}

// ToURL converts RepoInfo to an HTTPS URL
func (r *RepoInfo) ToURL() string {
	return fmt.Sprintf("https://%s/%s/%s.git", r.Host, r.Owner, r.Repo)
}

// ToSSHURL converts RepoInfo to an SSH URL
func (r *RepoInfo) ToSSHURL() string {
	return fmt.Sprintf("git@%s:%s/%s.git", r.Host, r.Owner, r.Repo)
}
