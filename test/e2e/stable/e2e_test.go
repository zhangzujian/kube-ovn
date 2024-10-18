package stable

import (
	"encoding/json"
	"flag"
	"math/rand/v2"
	"net/url"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	commontest "k8s.io/kubernetes/test/e2e/common"
	k8sframework "k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/kubeovn/kube-ovn/pkg/util"
	"github.com/kubeovn/kube-ovn/test/e2e/framework"
	"github.com/kubeovn/kube-ovn/test/e2e/framework/http"
	"github.com/kubeovn/kube-ovn/test/e2e/framework/rpc"
)

const rpcAddr = "127.0.0.1:17070"

type RPCNotify struct {
	ch chan struct{}
}

func (r *RPCNotify) ProcessExit(_ struct{}, _ *struct{}) error {
	select {
	case r.ch <- struct{}{}:
	default:
	}
	return nil
}

func init() {
	klog.SetOutput(ginkgo.GinkgoWriter)

	// Register flags.
	config.CopyFlags(config.Flags, flag.CommandLine)
	k8sframework.RegisterCommonFlags(flag.CommandLine)
	k8sframework.RegisterClusterFlags(flag.CommandLine)
}

func TestE2E(t *testing.T) {
	k8sframework.AfterReadingAllFlags(&k8sframework.TestContext)

	logs.InitLogs()
	defer logs.FlushLogs()
	klog.EnableContextualLogging(true)

	gomega.RegisterFailHandler(k8sframework.Fail)

	// Run tests through the Ginkgo runner with output to console + JUnit for Jenkins
	suiteConfig, reporterConfig := k8sframework.CreateGinkgoConfig()
	klog.Infof("Starting e2e run %q on Ginkgo node %d", k8sframework.RunID, suiteConfig.ParallelProcess)
	ginkgo.RunSpecs(t, "Kube-OVN e2e suite", suiteConfig, reporterConfig)
}

type suiteContext struct {
	HostIP   string
	NodePort int32
}

var suiteCtx suiteContext

var _ = ginkgo.SynchronizedBeforeSuite(func() []byte {
	// Reference common test to make the import valid.
	commontest.CurrentSuite = commontest.E2E

	namespaceName := "ns-" + framework.RandomSuffix()
	serviceName := "service-" + framework.RandomSuffix()
	deploymentName := "deploy-" + framework.RandomSuffix()

	cs, err := k8sframework.LoadClientset()
	framework.ExpectNoError(err)
	namespaceClient := framework.NewNamespaceClient(cs)
	deploymentClient := framework.NewDeploymentClient(cs, namespaceName)
	serviceClient := framework.NewServiceClient(cs, namespaceName)

	ginkgo.By("Creating namespace " + namespaceName)
	_ = namespaceClient.Create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}})

	ginkgo.By("Creating deplpyment " + deploymentName)
	podLabels := map[string]string{"app": deploymentName}
	port := 8000 + rand.Int32N(1000)
	portStr := strconv.Itoa(int(port))
	args := []string{"netexec", "--http-port", portStr}
	deploy := framework.MakeDeployment(deploymentName, 1, podLabels, nil, "server", framework.AgnhostImage, "")
	deploy.Spec.Template.Spec.Containers[0].Args = args
	deploy = deploymentClient.CreateSync(deploy)

	pods, err := deploymentClient.GetPods(deploy)
	framework.ExpectNoError(err)
	framework.ExpectNotNil(pods)
	framework.ExpectNotEmpty(pods.Items, "no pod found in deployment "+deploymentName)
	suiteCtx.HostIP = pods.Items[0].Status.HostIP

	ginkgo.By("Creating service " + serviceName)
	ports := []corev1.ServicePort{{
		Name:       "tcp",
		Protocol:   corev1.ProtocolTCP,
		Port:       port,
		TargetPort: intstr.FromInt32(port),
	}}
	service := framework.MakeService(serviceName, corev1.ServiceTypeNodePort, nil, podLabels, ports, "")
	service = serviceClient.CreateSync(service, func(s *corev1.Service) (bool, error) {
		return len(s.Spec.Ports) != 0 && s.Spec.Ports[0].NodePort != 0, nil
	}, "node port is allocated")
	suiteCtx.NodePort = service.Spec.Ports[0].NodePort

	ginkgo.DeferCleanup(func() {
		ginkgo.By("Deleting service " + serviceName)
		serviceClient.DeleteSync(serviceName)

		ginkgo.By("Deleting deployment " + deploymentName)
		deploymentClient.DeleteSync(deploymentName)

		ginkgo.By("Deleting namespace " + namespaceName)
		namespaceClient.DeleteSync(namespaceName)
	})

	data, err := json.Marshal(&suiteCtx)
	framework.ExpectNoError(err)
	return data
}, func(data []byte) {
	err := json.Unmarshal(data, &suiteCtx)
	framework.ExpectNoError(err)
	framework.Logf("suite context: %#v", suiteCtx)
})

var _ = framework.Describe("[group:stable]", func() {
	var server *rpc.Server
	var notify *RPCNotify

	ginkgo.BeforeEach(ginkgo.OncePerOrdered, func() {
		ginkgo.By("Creating RPC server listening on " + rpcAddr + " to receive ginkgo process notification")
		var err error
		notify = &RPCNotify{ch: make(chan struct{}, 1)}
		server, err = rpc.NewServer(rpcAddr, notify)
		framework.ExpectNoError(err)
	})
	ginkgo.AfterEach(ginkgo.OncePerOrdered, func() {
		ginkgo.By("Closing RPC server")
		framework.ExpectNoError(server.Close())
	})

	ginkgo.It("NodePort test demo", func() {
		u := url.URL{
			Scheme: "http",
			Host:   util.JoinHostPort(suiteCtx.HostIP, suiteCtx.NodePort),
			Path:   "/clientip",
		}
		ginkgo.By("GET " + u.String())
		reports, err := http.Loop(nil, "NodePort", u.String(), "GET", 300, 100, 500, 200, notify.ch)
		framework.ExpectNoError(err)

		for _, r := range reports {
			framework.Logf("index = %03d, timestamp = %v, message = %v", r.Index, r.Timestamp, r.Attachments)
		}
	})
})

var _ = framework.OrderedDescribe("[group:stable]", func() {
	ginkgo.BeforeAll(func() {
		ginkgo.By("Waiting 3s")
		time.Sleep(3 * time.Second)
	})

	ginkgo.AfterAll(func() {
		ginkgo.By("Waiting 3s")
		time.Sleep(3 * time.Second)

		ginkgo.By("Notify ginkgo process exit")
		reply := &struct{}{}
		err := rpc.Call(rpcAddr, "RPCNotify.ProcessExit", struct{}{}, reply)
		framework.ExpectNoError(err)
	})

	framework.DisruptiveIt("wip test demo 1", func() {
		ginkgo.By("demo 1 - sleep 2s")
		time.Sleep(2 * time.Second)
	})

	framework.DisruptiveIt("wip test demo 2", func() {
		ginkgo.By("demo 2 - sleep 3s")
		time.Sleep(3 * time.Second)
	})

	framework.DisruptiveIt("wip test demo 3", func() {
		ginkgo.By("demo 3 - sleep 4s")
		time.Sleep(4 * time.Second)
	})
})
