package cnp_upgrade

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kubeovn/kube-ovn/test/e2e/framework"
)

// A controller-only release exercises real Helm failure/rollback while keeping
// CNP CRDs outside its ownership, as required by both production chart paths.
// Copy the installed Deployment so flags, volumes and source configuration are
// preserved. The two production charts' rollout values have separate tests.
type controllerHelm struct {
	chart string
}

func newControllerHelm(f *framework.Framework, source string) *controllerHelm {
	deployment, err := f.ClientSet.AppsV1().Deployments("kube-system").Get(context.Background(), "kube-ovn-controller", metav1.GetOptions{})
	framework.ExpectNoError(err)
	deployment.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{
		MaxSurge: new(intstr.FromInt32(1)), MaxUnavailable: new(intstr.FromInt32(0)),
	}}
	// Helm computes expected ready replicas as replicas - maxUnavailable.
	// A one-replica fixture therefore needs zero unavailable and a schedulable
	// surge node, or --atomic can report success for an image that never starts.
	delete(deployment.Spec.Template.Spec.NodeSelector, "kube-ovn/role")
	// Initial Helm adoption preserves live fields absent from its first
	// manifest. Remove the placement constraint from the live Deployment too,
	// and wait for the source rollout before recording revision 1.
	ginkgo.By("Preparing schedulable source controller placement before Helm adoption")
	deployment, err = f.ClientSet.AppsV1().Deployments("kube-system").Update(context.Background(), deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err)
	waitDeployment(f, deployment.Name, *deployment.Spec.Replicas)
	deployment.TypeMeta = metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}
	deployment.ObjectMeta = metav1.ObjectMeta{Name: deployment.Name, Namespace: deployment.Namespace, Labels: deployment.Labels}
	deployment.Status = appsv1.DeploymentStatus{}
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == "kube-ovn-controller" {
			deployment.Spec.Template.Spec.Containers[i].Image = "__CNP_TEST_IMAGE__"
		}
	}
	data, err := json.Marshal(deployment)
	framework.ExpectNoError(err)
	template := strings.Replace(string(data), `"__CNP_TEST_IMAGE__"`, `{{ .Values.image | quote }}`, 1)
	framework.ExpectEqual(strings.Contains(template, "{{ .Values.image | quote }}"), true)
	directory, err := os.MkdirTemp("", "cnp-controller-helm-")
	framework.ExpectNoError(err)
	ginkgo.DeferCleanup(func() { framework.ExpectNoError(os.RemoveAll(directory)) })
	framework.ExpectNoError(os.Mkdir(filepath.Join(directory, "templates"), 0o700))
	framework.ExpectNoError(os.WriteFile(filepath.Join(directory, "Chart.yaml"), []byte("apiVersion: v2\nname: cnp-controller\nversion: 0.1.0\n"), 0o600))
	framework.ExpectNoError(os.WriteFile(filepath.Join(directory, "templates", "controller.yaml"), []byte(template), 0o600))
	helm := &controllerHelm{chart: directory}
	framework.ExpectNoError(helm.upgrade(source))
	return helm
}

func (h *controllerHelm) run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args = append(args, "--namespace=kube-system", "--kube-context=kind-kube-ovn")
	output, err := exec.CommandContext(ctx, "helm", args...).CombinedOutput()
	framework.Logf("Helm %v: %s", args, output)
	if err != nil {
		return fmt.Errorf("Helm %v: %s: %w", args, output, err)
	}
	return nil
}

func (h *controllerHelm) upgrade(image string) error {
	return h.run("upgrade", "--install", "cnp-controller", h.chart, "--take-ownership", "--atomic", "--timeout=90s", "--set-string", "image="+image)
}

func (h *controllerHelm) failAndRollback(f *framework.Framework, expectedImage string) {
	// This digest is absent from the disposable registry. It must fail to pull,
	// so --atomic has to restore the last successful release rather than succeed.
	image := "localhost:5001/cnp-upgrade@sha256:" + strings.Repeat("0", 64)
	framework.ExpectError(h.upgrade(image), "the deliberately unavailable image must trigger atomic rollback")
	deployment, err := f.ClientSet.AppsV1().Deployments("kube-system").Get(context.Background(), "kube-ovn-controller", metav1.GetOptions{})
	framework.ExpectNoError(err)
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == "kube-ovn-controller" {
			framework.ExpectEqual(container.Image, expectedImage, "Helm must roll back to the last compatible image")
		}
	}
	waitDeployment(f, deployment.Name, *deployment.Spec.Replicas)
}
