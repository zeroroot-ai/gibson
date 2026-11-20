// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package referenceenv validates the manifests of the reference environment
// (gibson#1490) with no cluster. It checks that each image is pinned by digest,
// that each service has a health signal, and that each flaw of flaws.yaml is
// present in the manifest of its service.
package referenceenv

import (
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// HealthAnnotation names the health URL of a Deployment.
const HealthAnnotation = "refenv.zeroroot.ai/health-url"

// The kinds of check that find a flaw.
const (
	CheckAttack = "attack"
	CheckScan   = "scan"
	CheckTool   = "tool"
)

var (
	digestImage = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	attackID    = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	docSplit    = regexp.MustCompile(`(?m)^---[ \t]*$`)
)

// Doc is one Kubernetes object of the environment.
type Doc struct {
	File string
	Kind string
	Name string
	Obj  map[string]any
}

// Flaw is one row of flaws.yaml.
type Flaw struct {
	ID             string `json:"id"`
	Service        string `json:"service"`
	Check          string `json:"check"`
	Predicate      string `json:"predicate,omitempty"`
	Category       string `json:"category,omitempty"`
	Destructive    *bool  `json:"destructive,omitempty"`
	Tool           string `json:"tool,omitempty"`
	ConnectorClass string `json:"connector_class,omitempty"`
	Technique      string `json:"technique"`
	Fix            string `json:"fix"`
	HealthSignal   string `json:"health_signal"`
}

// Load reads each manifest of the kustomization and the flaw list from fsys.
func Load(fsys fs.FS) (docs []Doc, flaws []Flaw, err error) {
	for _, dir := range []string{"apps", "base"} {
		files, err := fs.Glob(fsys, path.Join(dir, "*.yaml"))
		if err != nil {
			return nil, nil, fmt.Errorf("list %s: %w", dir, err)
		}
		for _, file := range files {
			data, err := fs.ReadFile(fsys, file)
			if err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", file, err)
			}
			parsed, err := ParseDocs(file, data)
			if err != nil {
				return nil, nil, err
			}
			docs = append(docs, parsed...)
		}
	}
	raw, err := fs.ReadFile(fsys, "flaws.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("read flaws.yaml: %w", err)
	}
	var list struct {
		Flaws []Flaw `json:"flaws"`
	}
	if err := yaml.UnmarshalStrict(raw, &list); err != nil {
		return nil, nil, fmt.Errorf("parse flaws.yaml: %w", err)
	}
	return docs, list.Flaws, nil
}

// ParseDocs splits one YAML file into its objects.
func ParseDocs(file string, data []byte) ([]Doc, error) {
	var out []Doc
	for i, part := range docSplit.Split(string(data), -1) {
		if strings.TrimSpace(part) == "" {
			continue
		}
		var obj map[string]any
		if err := yaml.Unmarshal([]byte(part), &obj); err != nil {
			return nil, fmt.Errorf("parse %s, document %d: %w", file, i, err)
		}
		if len(obj) == 0 {
			continue
		}
		kind, _ := obj["kind"].(string)
		name, _ := get(obj, "metadata", "name").(string)
		if kind == "" || name == "" {
			return nil, fmt.Errorf("%s, document %d: kind and metadata.name are required", file, i)
		}
		out = append(out, Doc{File: file, Kind: kind, Name: name, Obj: obj})
	}
	return out, nil
}

// Validate returns each defect of the environment. An empty result is a pass.
func Validate(docs []Doc, flaws []Flaw) []error {
	var errs []error
	errs = append(errs, checkImages(docs)...)
	errs = append(errs, checkHealth(docs)...)
	errs = append(errs, checkFlaws(docs, flaws)...)
	return errs
}

func checkImages(docs []Doc) []error {
	var errs []error
	for _, d := range docs {
		for _, c := range containers(d) {
			image, _ := c["image"].(string)
			if !digestImage.MatchString(image) {
				errs = append(errs, fmt.Errorf("%s %s: image %q is not pinned by digest", d.Kind, d.Name, image))
			}
		}
	}
	return errs
}

// checkHealth requires, for each Deployment, a health URL, a readiness probe
// on the path of that URL, a Service of the same name, and a target in the
// Prometheus config.
func checkHealth(docs []Doc) []error {
	var errs []error
	services := map[string]bool{}
	var prom string
	for _, d := range docs {
		if d.Kind == "Service" {
			services[d.Name] = true
		}
		if d.Kind == "ConfigMap" && d.Name == "prometheus-config" {
			prom, _ = get(d.Obj, "data", "prometheus.yml").(string)
		}
	}
	if prom == "" {
		errs = append(errs, fmt.Errorf("the ConfigMap prometheus-config holds no prometheus.yml"))
	}
	for _, d := range docs {
		if d.Kind != "Deployment" {
			continue
		}
		raw, _ := get(d.Obj, "metadata", "annotations", HealthAnnotation).(string)
		u, err := url.Parse(raw)
		if raw == "" || err != nil {
			errs = append(errs, fmt.Errorf("Deployment %s: the annotation %s is missing or invalid", d.Name, HealthAnnotation))
			continue
		}
		if !services[d.Name] {
			errs = append(errs, fmt.Errorf("Deployment %s: no Service of the same name", d.Name))
		}
		if !strings.Contains(prom, `"`+raw+`"`) {
			errs = append(errs, fmt.Errorf("Deployment %s: the health URL %s is not a target of prometheus-config", d.Name, raw))
		}
		probe := ""
		for _, c := range containers(d) {
			if p, ok := get(c, "readinessProbe", "httpGet", "path").(string); ok {
				probe = p
			}
		}
		if probe != u.Path {
			errs = append(errs, fmt.Errorf("Deployment %s: the readiness probe path %q differs from the health URL path %q",
				d.Name, probe, u.Path))
		}
	}
	return errs
}

func checkFlaws(docs []Doc, flaws []Flaw) []error {
	var errs []error
	deployments := map[string]Doc{}
	for _, d := range docs {
		if d.Kind == "Deployment" {
			deployments[d.Name] = d
		}
	}
	seen := map[string]bool{}
	checks := map[string]bool{}
	for _, f := range flaws {
		errs = append(errs, checkFlawFields(f, seen)...)
		checks[f.Check] = true
		if _, ok := deployments[f.Service]; !ok {
			errs = append(errs, fmt.Errorf("flaw %s: no Deployment %q", f.ID, f.Service))
			continue
		}
		present, known := presence[f.ID]
		switch {
		case !known:
			errs = append(errs, fmt.Errorf("flaw %s: the validator has no presence check for it", f.ID))
		case !present(docs, f.Service):
			errs = append(errs, fmt.Errorf("flaw %s: the manifest of %s does not hold the flaw", f.ID, f.Service))
		}
	}
	for _, kind := range []string{CheckAttack, CheckScan, CheckTool} {
		if !checks[kind] {
			errs = append(errs, fmt.Errorf("no flaw has the check %q", kind))
		}
	}
	return errs
}

func checkFlawFields(f Flaw, seen map[string]bool) []error {
	var errs []error
	bad := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("flaw %s: "+format, append([]any{f.ID}, args...)...))
	}
	if f.ID == "" {
		bad("id is empty")
	}
	if seen[f.ID] {
		bad("duplicate id")
	}
	seen[f.ID] = true
	if !attackID.MatchString(f.Technique) {
		bad("technique %q is not an ATT&CK id", f.Technique)
	}
	if f.Fix == "" || f.HealthSignal == "" {
		bad("fix and health_signal are required")
	}
	switch f.Check {
	case CheckAttack:
		if f.Predicate == "" || f.Category == "" || f.Destructive == nil {
			bad("an attack needs predicate, category and destructive")
		}
	case CheckScan:
		if f.Tool == "" {
			bad("a scan needs tool")
		}
	case CheckTool:
		if f.ConnectorClass == "" {
			bad("a tool read needs connector_class")
		}
	default:
		bad("check %q is not attack, scan or tool", f.Check)
	}
	return errs
}

// presence holds one function for each flaw. It reports whether the manifest
// of the service still holds the flaw. A fix makes it false.
var presence = map[string]func(docs []Doc, service string) bool{
	"unauthenticated-admin-endpoint": func(docs []Doc, service string) bool {
		conf, _ := get(find(docs, "ConfigMap", service+"-nginx"), "data", "default.conf").(string)
		return strings.Contains(conf, "location /admin/") && !strings.Contains(conf, "auth_basic") &&
			!strings.Contains(conf, "return 401")
	},
	"credential-in-environment": func(docs []Doc, service string) bool {
		for _, c := range containers(find(docs, "Deployment", service)) {
			for _, e := range list(c["env"]) {
				if name, _ := e["name"].(string); strings.HasSuffix(name, "_PASSWORD") || strings.HasSuffix(name, "_KEY") {
					if _, plain := e["value"]; plain {
						return true
					}
				}
			}
		}
		return false
	},
	"privileged-container": func(docs []Doc, service string) bool {
		for _, c := range containers(find(docs, "Deployment", service)) {
			if v, _ := get(c, "securityContext", "privileged").(bool); v {
				return true
			}
		}
		return false
	},
	"node-token-readable": func(docs []Doc, service string) bool {
		for _, v := range list(get(find(docs, "Deployment", service), "spec", "template", "spec", "volumes")) {
			if p, _ := get(v, "hostPath", "path").(string); strings.HasPrefix(p, "/var/lib/kubelet/pods") {
				return true
			}
		}
		return false
	},
	"wide-rbac-binding": func(docs []Doc, service string) bool {
		rb := find(docs, "RoleBinding", service)
		role, _ := get(rb, "roleRef", "name").(string)
		return role == "edit" || role == "admin" || role == "cluster-admin"
	},
	"vulnerable-package-in-image": func(docs []Doc, service string) bool {
		// The scan finds a package of this image. The test pins the image
		// digest of nginx 1.18.0. A fix changes the digest.
		for _, c := range containers(find(docs, "Deployment", service)) {
			if image, _ := c["image"].(string); image == vulnerableNginx {
				return true
			}
		}
		return false
	},
	"committed-secret": func(docs []Doc, _ string) bool {
		script, _ := get(find(docs, "ConfigMap", "seed-script"), "data", "seed.sh").(string)
		return strings.Contains(script, "config/ci.env") && strings.Contains(script, "AWS_ACCESS_KEY_ID")
	},
}

// vulnerableNginx is the digest of nginx 1.18.0, an image with known
// vulnerable packages.
const vulnerableNginx = "nginx@sha256:e90ac5331fe095cea01b121a3627174b2e33e06e83720e9a934c7b8ccc9c55a0"

func find(docs []Doc, kind, name string) Doc {
	for _, d := range docs {
		if d.Kind == kind && d.Name == name {
			return d
		}
	}
	return Doc{}
}

// containers returns the containers and init containers of a workload.
func containers(d Doc) []map[string]any {
	var out []map[string]any
	if d.Kind != "Deployment" && d.Kind != "Job" {
		return nil
	}
	spec := get(d.Obj, "spec", "template", "spec")
	for _, key := range []string{"initContainers", "containers"} {
		out = append(out, list(get(spec, key))...)
	}
	return out
}

func list(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// get walks a path of map keys. A Doc starts at its object. A missing key
// gives nil.
func get(v any, keys ...string) any {
	if d, ok := v.(Doc); ok {
		v = d.Obj
	}
	for _, key := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}
