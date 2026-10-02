package main

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/kubeovn/kube-ovn/pkg/cnp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: cnp-upgrade <plan|prepare|verify-controller|open|migrate|verify|rollback-plan|rollback|finalize|crd> [flags]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	u := &cnp.Upgrade{}
	var kubeconfig, contextName, journal, outputDir string
	flags.StringVar(&kubeconfig, "kubeconfig", "", "Kubeconfig path; defaults to the normal client-go loading rules")
	flags.StringVar(&contextName, "context", "", "Kubeconfig context")
	flags.StringVar(&u.Namespace, "namespace", "kube-system", "Controller and upgrade evidence namespace")
	flags.StringVar(&u.Deployment, "deployment", "kube-ovn-controller", "Controller Deployment name")
	flags.StringVar(&u.Image, "controller-image", "", "Verified compatible controller image, pinned by digest")
	flags.DurationVar(&u.Timeout, "timeout", 2*time.Minute, "Per-object application verification timeout")
	flags.BoolVar(&u.WritersFrozen, "writers-frozen", false, "Acknowledge external CNP/schema writers are frozen and declarations coordinated")
	flags.BoolVar(&u.RollbackGuarded, "rollback-guarded", false, "Acknowledge CD/Helm rollback cannot resurrect a legacy controller")
	flags.StringVar(&journal, "journal", "", "Append-only JSONL migration journal (required for migrate/rollback)")
	flags.StringVar(&outputDir, "output-dir", "yamls/cnp", "CRD artifact directory for the crd command")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if command == "crd" {
		return writeCRDs(outputDir)
	}
	if u.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	loading.ExplicitPath = kubeconfig
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{CurrentContext: contextName}).ClientConfig()
	if err != nil {
		return err
	}
	if u.Dynamic, err = dynamic.NewForConfig(config); err != nil {
		return err
	}
	if u.Kube, err = kubernetes.NewForConfig(config); err != nil {
		return err
	}
	if command == "migrate" || command == "rollback" {
		if journal == "" {
			return fmt.Errorf("--journal is required")
		}
		file, err := os.OpenFile(journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		u.Journal = func(plan *cnp.ObjectPlan) error {
			if err := json.MarshalWrite(file, plan); err != nil {
				return err
			}
			if _, err := file.WriteString("\n"); err != nil {
				return err
			}
			return file.Sync()
		}
	}
	return execute(context.Background(), command, u)
}

func execute(ctx context.Context, command string, u *cnp.Upgrade) error {
	switch command {
	case "plan", "rollback-plan":
		plan, err := u.Plan(ctx, command == "rollback-plan")
		if err != nil {
			return err
		}
		return json.MarshalWrite(os.Stdout, plan, json.Deterministic(true))
	case "prepare":
		return u.Prepare(ctx)
	case "verify-controller":
		record, err := u.VerifyController(ctx)
		if err != nil {
			return err
		}
		return json.MarshalWrite(os.Stdout, record)
	case "open":
		return u.OpenNative(ctx)
	case "migrate", "rollback":
		return u.Migrate(ctx, command == "rollback")
	case "verify":
		return u.Verify(ctx)
	case "finalize":
		return u.Finalize(ctx)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func writeCRDs(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, mode := range []string{"legacy-only", "dual", "native"} {
		obj, err := cnp.Schema(mode)
		if err != nil {
			return err
		}
		data, err := yaml.Marshal(obj.Object)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, mode+".yaml"), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
