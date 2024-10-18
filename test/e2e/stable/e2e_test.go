package stable

import (
	"encoding/json"
	"flag"
	"testing"

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

var _ = framework.Describe("[group:stable]", func() {
	f := framework.NewDefaultFramework("stable")
	f.SkipNamespaceCreation = true

	// var cs clientset.Interface
	// ginkgo.BeforeEach(func() {
	// f.SkipVersionPriorTo(1, 9, "Support for listening on Pod IP was introduced in v1.9")
	// cs = f.ClientSet
	// })

	framework.ConformanceIt("stable test demo", func() {
		ginkgo.By("GET http://172.18.0.2:31745/metrics")
		result, err := http.Loop(nil, "test", "http://172.18.0.2:31745/metricsx", "GET", 3, 100, 500, 200)
		framework.ExpectNoError(err)

		for _, record := range result {
			buf, _ := json.MarshalIndent(record, "", "  ")
			framework.Logf(string(buf))
		}
	})
})
