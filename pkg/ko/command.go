package ko

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/kubeovn/kube-ovn/versions"
)

// Application owns configuration and clients for one invocation.
type Application struct {
	root             *cobra.Command
	config           *genericclioptions.ConfigFlags
	streams          genericiooptions.IOStreams
	namespace        string
	discoveryTimeout time.Duration
	timeout          time.Duration
	client           *Client
	// newClient is replaced by tests to exercise command parsing without a cluster.
	newClient func() (*Client, error)
}

// New constructs a command tree without accessing kubeconfig or the API server.
func New(streams genericiooptions.IOStreams) *Application {
	a := &Application{streams: streams, config: genericclioptions.NewConfigFlags(true)}
	a.root = &cobra.Command{
		Use: "kubectl-ko", Short: "Operate and diagnose Kube-OVN through the Kubernetes API",
		SilenceErrors: true, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	a.root.SetIn(streams.In)
	a.root.SetOut(streams.Out)
	a.root.SetErr(streams.ErrOut)
	flags := a.root.PersistentFlags()
	a.config.AddFlags(flags)
	flags.BoolP("help", "h", false, "Help for kubectl-ko")
	flags.StringVar(&a.namespace, "kube-ovn-namespace", cmp.Or(os.Getenv("KUBE_OVN_NS"), "kube-system"), "Namespace containing Kube-OVN components")
	flags.DurationVar(&a.discoveryTimeout, "discovery-timeout", 10*time.Second, "Time to wait for a unique ready target")
	flags.DurationVar(&a.timeout, "timeout", 0, "Overall command timeout (zero allows long-running streams)")
	a.newClient = a.connect
	a.addControlCommands()
	a.addDatabaseCommands()
	a.addNetworkCommands()
	a.addDiagnosticCommands()
	a.addPerformanceCommand()
	a.addACLCommands()
	a.root.AddCommand(&cobra.Command{
		Use: "version", Short: "Print the client build version without contacting a cluster", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(streams.Out, "kubectl-ko %s (%s)\n", versions.VERSION, versions.COMMIT)
			return err
		},
	})
	return a
}

// Execute parses only the global prefix before allowing leaf commands to consume argv.
// In particular, remote --help, --timeout and OVN transaction separators stay intact.
func (a *Application) Execute(ctx context.Context, args []string) error {
	flags := a.root.PersistentFlags()
	flags.SetInterspersed(false)
	if err := flags.Parse(args); err != nil {
		return &usageError{err}
	}
	if a.discoveryTimeout <= 0 || a.timeout < 0 {
		return &usageError{errors.New("timeouts must be positive (overall timeout may be zero)")}
	}
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	a.root.SetArgs(flags.Args())
	return a.root.ExecuteContext(ctx)
}

func (a *Application) connect() (*Client, error) {
	config, err := a.config.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes configuration: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	namespace, _, err := a.config.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return nil, err
	}
	return &Client{
		Kubernetes: client, Dynamic: dynamicClient, Executor: &remoteExecutor{client: client, config: config},
		Namespace: a.namespace, WorkloadNamespace: namespace, DiscoveryTimeout: a.discoveryTimeout,
	}, nil
}

func (a *Application) run(handler func(context.Context, *Client, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if a.client == nil {
			var err error
			a.client, err = a.newClient()
			if err != nil {
				return err
			}
		}
		return handler(cmd.Context(), a.client, args)
	}
}

func (a *Application) outputStreams() Streams {
	return Streams{Out: a.streams.Out, ErrOut: a.streams.ErrOut}
}

func (a *Application) addControlCommands() {
	for name, role := range map[string]string{"nbctl": "nb", "sbctl": "sb", "icnbctl": "ic-nb", "icsbctl": "ic-sb"} {
		binary := "ovn-" + name
		if role == "ic-nb" {
			binary = "ovn-ic-nbctl"
		}
		if role == "ic-sb" {
			binary = "ovn-ic-sbctl"
		}
		a.root.AddCommand(&cobra.Command{
			Use: name + " [remote arguments...]", Short: "Invoke " + binary + " on its leader", DisableFlagParsing: true,
			RunE: a.run(func(ctx context.Context, client *Client, args []string) error {
				target, err := client.leader(ctx, role)
				if err != nil {
					return err
				}
				return client.Executor.Exec(ctx, target, append([]string{binary}, args...), a.outputStreams())
			}),
		})
	}
	for _, name := range []string{"vsctl", "ofctl", "dpctl", "appctl"} {
		a.root.AddCommand(&cobra.Command{
			Use: name + " NODE [remote arguments...]", Short: "Invoke ovs-" + name + " on a node", DisableFlagParsing: true, Args: cobra.MinimumNArgs(1),
			RunE: a.run(func(ctx context.Context, client *Client, args []string) error {
				target, err := client.nodeTarget(ctx, args[0], "ovs")
				if err != nil {
					return err
				}
				return client.Executor.Exec(ctx, target, append([]string{"ovs-" + name}, args[1:]...), a.outputStreams())
			}),
		})
	}
}
