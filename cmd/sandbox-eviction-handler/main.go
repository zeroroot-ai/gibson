// sandbox-eviction-handler is a node-local sidecar binary that watches for
// AWS spot-interruption notices and cordons its own Kubernetes node so no
// new sandbox pods land on a node about to be terminated. In-flight pods
// continue to run until kubelet terminates them at the AWS deadline.
//
// Spec: setec-sandbox-prod-default §C7 / NFR-R1.
//
// Design decision: gibson#211 (S9 of PRD gibson#202) chose Option B —
// the sidecar is fully independent of the gibson daemon. The daemon never
// learns about evictions; spot-eviction is treated symmetrically with
// every other node-lifecycle event (kubelet OOM-kill, upgrade restart,
// node-NotReady). Per ADR-0023, the gibson daemon binary never consumes
// the Kubernetes API; this sidecar is the one place where node cordon
// logic lives.
//
// Usage:
//
//	sandbox-eviction-handler --node-name <name> [--notice-file <path>] [--dry-run]
//
// The notice file is populated by aws-node-termination-handler (typically
// at /var/run/aws/spot-interruption-notice) on each sandbox-host node. The
// handler polls the path every 2s. On appearance, the node is cordoned
// (Spec.Unschedulable=true) via a strategic-merge patch on the Node
// resource. After cordon, the handler stays in a wait loop until ctx
// cancellation so the DaemonSet does not flap into a restart spiral.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// defaultNoticeFile is the hostPath populated by
	// aws-node-termination-handler when a spot-interruption notice arrives.
	defaultNoticeFile = "/var/run/aws/spot-interruption-notice"

	// pollInterval is how frequently the handler stats the notice file.
	// stat(2) is cheap; 2s is well within the AWS 120s notice window.
	pollInterval = 2 * time.Second
)

// nodeCordonner is the minimal Kubernetes Node-patch surface the handler
// needs. Satisfied by a real kubernetes.Interface and by fakes in tests.
type nodeCordonner interface {
	cordon(ctx context.Context, nodeName string) error
}

// kubeCordonner patches the Node resource with Spec.Unschedulable=true via
// a strategic-merge patch — the same wire shape as `kubectl cordon`.
type kubeCordonner struct{ cs kubernetes.Interface }

func (k *kubeCordonner) cordon(ctx context.Context, nodeName string) error {
	payload, err := json.Marshal(struct {
		Spec struct {
			Unschedulable bool `json:"unschedulable"`
		} `json:"spec"`
	}{Spec: struct {
		Unschedulable bool `json:"unschedulable"`
	}{Unschedulable: true}})
	if err != nil {
		return fmt.Errorf("marshal cordon patch: %w", err)
	}
	_, err = k.cs.CoreV1().Nodes().Patch(
		ctx, nodeName, types.StrategicMergePatchType, payload, metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("cordon node %q: %w", nodeName, err)
	}
	return nil
}

// fileExists is the signal that the spot-interruption notice has arrived.
type fileExistsFunc func(path string) bool

func defaultFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runConfig captures the dependencies of run. Production wires real K8s
// and filesystem; tests inject fakes.
type runConfig struct {
	nodeName   string
	noticeFile string
	cordonner  nodeCordonner
	exists     fileExistsFunc
	tick       <-chan time.Time
	logger     *slog.Logger
}

// run polls noticeFile on every tick. On notice appearance it cordons the
// node and stays in a wait loop until ctx is cancelled — exiting cleanly
// would let the DaemonSet restart this sidecar into a cordon-already-done
// loop, generating noisy logs and unnecessary K8s API traffic.
func run(ctx context.Context, cfg runConfig) error {
	cfg.logger.Info("sandbox-eviction-handler watching for spot-interruption notice",
		"node", cfg.nodeName, "notice_file", cfg.noticeFile)

	cordoned := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-cfg.tick:
			if cordoned {
				continue
			}
			if !cfg.exists(cfg.noticeFile) {
				continue
			}
			cfg.logger.Warn("spot-interruption notice present; cordoning node",
				"node", cfg.nodeName)
			if err := cfg.cordonner.cordon(ctx, cfg.nodeName); err != nil {
				cfg.logger.Error("cordon failed; will retry on next tick",
					"node", cfg.nodeName, "err", err)
				continue
			}
			cordoned = true
			cfg.logger.Info("node cordoned; staying alive until termination",
				"node", cfg.nodeName)
		}
	}
}

func main() {
	var (
		nodeName   = flag.String("node-name", os.Getenv("NODE_NAME"), "Kubernetes node name (defaults to $NODE_NAME from the downward API)")
		noticeFile = flag.String("notice-file", defaultNoticeFile, "Path to the spot-interruption notice hostPath file")
		kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig (defaults to in-cluster config)")
		dryRun     = flag.Bool("dry-run", false, "Log the cordon action but do not call the K8s API")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *nodeName == "" {
		logger.Error("--node-name (or $NODE_NAME via the downward API) is required")
		os.Exit(1)
	}

	var cordonner nodeCordonner
	if *dryRun {
		cordonner = noopCordonner{logger: logger}
	} else {
		client, err := buildKubeClient(*kubeconfig)
		if err != nil {
			logger.Error("build kubernetes client", "err", err)
			os.Exit(1)
		}
		cordonner = &kubeCordonner{cs: client}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	if err := run(ctx, runConfig{
		nodeName:   *nodeName,
		noticeFile: *noticeFile,
		cordonner:  cordonner,
		exists:     defaultFileExists,
		tick:       ticker.C,
		logger:     logger,
	}); err != nil {
		logger.Error("sandbox-eviction-handler exited with error", "err", err)
		os.Exit(1)
	}
}

func buildKubeClient(kubeconfig string) (kubernetes.Interface, error) {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kube config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes clientset: %w", err)
	}
	return cs, nil
}

// noopCordonner is the --dry-run implementation. It logs the call and
// returns nil so the rest of the run loop exercises its happy path.
type noopCordonner struct{ logger *slog.Logger }

func (n noopCordonner) cordon(_ context.Context, nodeName string) error {
	n.logger.Info("dry-run: would cordon node", "node", nodeName)
	return nil
}

// Compile-time check that the cordon implementations satisfy nodeCordonner.
var (
	_ nodeCordonner = (*kubeCordonner)(nil)
	_ nodeCordonner = noopCordonner{}
)
