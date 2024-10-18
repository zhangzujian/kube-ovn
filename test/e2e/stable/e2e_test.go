package stable

import (
	"encoding/json"
	"flag"
	"testing"
	"time"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e"
	k8sframework "k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	"github.com/onsi/ginkgo/v2"

	"github.com/kubeovn/kube-ovn/test/e2e/framework"
	"github.com/kubeovn/kube-ovn/test/e2e/framework/http"
)

func init() {
	klog.SetOutput(ginkgo.GinkgoWriter)

	// Register flags.
	config.CopyFlags(config.Flags, flag.CommandLine)
	k8sframework.RegisterCommonFlags(flag.CommandLine)
	k8sframework.RegisterClusterFlags(flag.CommandLine)
}

func TestE2E(t *testing.T) {
	k8sframework.AfterReadingAllFlags(&k8sframework.TestContext)
	e2e.RunE2ETests(t)
}

var f *framework.Framework
var cs clientset.Interface
var serviceClient *framework.ServiceClient
var podClient *framework.PodClient
var namespaceName, serviceName, hostPodName string

// namespaceName, serviceName string
// service                    *appsv1.Service

var _ = ginkgo.BeforeSuite(func() {
	f = framework.NewDefaultFramework("stable")

	// namespaceN

	// var subnetClient *framework.SubnetClient
	// var namespaceName, serviceName, hostPodName string

	// ginkgo.BeforeEach(func() {
	cs = f.ClientSet
	serviceClient = f.ServiceClient()
	podClient = f.PodClient()
	// subnetClient = f.SubnetClient()
	namespaceName = f.Namespace.Name
	serviceName = "service-" + framework.RandomSuffix()
	// podName = "pod-" + framework.RandomSuffix()
	hostPodName = "pod-" + framework.RandomSuffix()
	// subnetName = "subnet-" + framework.RandomSuffix()
	// cidr = framework.RandomCIDR(f.ClusterIPFamily)
	// })
	// ginkgo.AfterEach(func() {

})

// f.SkipNamespaceCreation = false

// dbRunner = db.NewRunner()
// Expect(dbRunner.Start()).To(Succeed())

// dbClient = db.NewClient()
// Expect(dbClient.Connect(dbRunner.Address())).To(Succeed())
// })

var _ = ginkgo.AfterSuite(func() {
	// Expect(dbRunner.Stop()).To(Succeed())

	ginkgo.By("Deleting service " + serviceName)
	serviceClient.DeleteSync(serviceName)

	// ginkgo.By("Deleting pod " + podName)
	// podClient.DeleteSync(podName)

	ginkgo.By("Deleting pod " + hostPodName)
	podClient.DeleteSync(hostPodName)

	// ginkgo.By("Deleting subnet " + subnetName)
	// subnetClient.DeleteSync(subnetName)
})

var _ = framework.Describe("[group:stable]", func() {
	f := framework.NewDefaultFramework("stable")
	f.SkipNamespaceCreation = true

	// ginkgo.BeforeEach(func() {
	// })

	framework.ConformanceIt("stable test demo", func() {
		ginkgo.By("GET http://192.168.152.146:9000/zjzhang/3.18.0/")
		result, err := http.Loop(nil, "test", "http://192.168.152.146:9000/zjzhang/3.18.0", "GET", 100, 100, 500, 200)
		framework.ExpectNoError(err)

		for _, record := range result {
			buf, _ := json.MarshalIndent(record, "", "  ")
			framework.Logf(string(buf))
		}
	})

	ginkgo.Context("", ginkgo.Ordered, func() {
		ginkgo.BeforeEach(ginkgo.OncePerOrdered, func() {
			// wait the test app is ready to serve http requests
			// and then wait extra 5 seconds
		})

		framework.ConformanceIt("wip test demo 1", func() {
			ginkgo.By("demo 1 - sleep 2s")
			time.Sleep(3 * time.Second)
		})

		framework.ConformanceIt("wip test demo 2", func() {
			ginkgo.By("demo 2 - sleep 3s")
			time.Sleep(3 * time.Second)
		})

		framework.ConformanceIt("wip test demo 3", func() {
			ginkgo.By("demo 3 - sleep 4s")
			time.Sleep(3 * time.Second)
		})
	})
})
