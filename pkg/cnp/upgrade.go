package cnp

import (
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const UpgradeStateName = "kube-ovn-cnp-upgrade"

var crdResource = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

type Upgrade struct {
	Dynamic    dynamic.Interface
	Kube       kubernetes.Interface
	Namespace  string
	Deployment string
	Image      string
	Timeout    time.Duration
	// These acknowledgements describe the operator's external GitOps/CD gate.
	// Kubernetes cannot discover or fence every external writer or helm rollback.
	WritersFrozen   bool
	RollbackGuarded bool
	Journal         func(*ObjectPlan) error
}

type UpgradePlan struct {
	SchemaMode   string        `json:"schemaMode"`
	SchemaDigest string        `json:"schemaDigest"`
	Legacy       bool          `json:"toLegacy"`
	Objects      []*ObjectPlan `json:"objects"`
}

func (u *Upgrade) Plan(ctx context.Context, legacy bool) (*UpgradePlan, error) {
	crd, err := u.Dynamic.Resource(crdResource).Get(ctx, CRDName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	mode, digest, err := IdentifySchema(crd)
	if err != nil {
		return nil, err
	}
	objects, err := u.Dynamic.Resource(Resource).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	plan := &UpgradePlan{SchemaMode: mode, SchemaDigest: digest, Legacy: legacy}
	for i := range objects.Items {
		obj, err := PlanObject(&objects.Items[i], legacy)
		if err != nil {
			return nil, fmt.Errorf("CNP %s: %w", objects.Items[i].GetName(), err)
		}
		plan.Objects = append(plan.Objects, obj)
	}
	slices.SortFunc(plan.Objects, func(a, b *ObjectPlan) int { return strings.Compare(a.Name, b.Name) })
	return plan, nil
}

// Prepare is the only mutating stage allowed before controller replacement.
// All objects must remain legacy and the schema must be positively identified.
func (u *Upgrade) Prepare(ctx context.Context) error {
	plan, err := u.Plan(ctx, true)
	if err != nil {
		return err
	}
	if plan.SchemaMode != "legacy" && plan.SchemaMode != "legacy-only" {
		return fmt.Errorf("prepare requires a legacy schema, found %s", plan.SchemaMode)
	}
	for _, obj := range plan.Objects {
		if len(obj.Patch) != 0 {
			return fmt.Errorf("%s already uses native fields; cannot prepare for legacy controllers", obj.Name)
		}
	}
	return u.replaceSchema(ctx, plan.SchemaDigest, "legacy-only")
}

func (u *Upgrade) requireExternalGate() error {
	if !u.WritersFrozen || !u.RollbackGuarded {
		return errors.New("freeze all CNP/schema writers and prevent legacy controller rollback before acknowledging both external gates")
	}
	if !strings.Contains(u.Image, "@sha256:") {
		return errors.New("a verified compatible controller image pinned by digest is required")
	}
	return nil
}

// VerifyController checks desired templates, every owned Pod (including
// terminating Pods), scaled ReplicaSets and the active leader's capability.
func (u *Upgrade) VerifyController(ctx context.Context) (*Receipt, error) {
	if !strings.Contains(u.Image, "@sha256:") {
		return nil, errors.New("--controller-image must be pinned by digest")
	}
	deployment, err := u.Kube.AppsV1().Deployments(u.Namespace).Get(ctx, u.Deployment, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if err := verifyDeployment(deployment, u.Image); err != nil {
		return nil, err
	}
	sets, err := u.Kube.AppsV1().ReplicaSets(u.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	owned := map[types.UID]bool{}
	for _, set := range sets.Items {
		if !hasOwner(set.OwnerReferences, deployment.UID) {
			continue
		}
		owned[set.UID] = true
		if set.Spec.Replicas != nil && *set.Spec.Replicas != 0 {
			if err := verifyTemplate(set.Spec.Template, u.Image); err != nil {
				return nil, fmt.Errorf("ReplicaSet %s: %w", set.Name, err)
			}
		}
	}
	// Listing every Pod avoids excluding an old replica because labels changed.
	pods, err := u.Kube.CoreV1().Pods(u.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	lease, err := u.Kube.CoordinationV1().Leases(u.Namespace).Get(ctx, "kube-ovn-controller", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if lease.Spec.HolderIdentity == nil || lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil || time.Since(lease.Spec.RenewTime.Time) > time.Duration(*lease.Spec.LeaseDurationSeconds)*time.Second {
		return nil, errors.New("no current controller leader")
	}
	var leader *corev1.Pod
	count := int32(0)
	for i := range pods.Items {
		pod := &pods.Items[i]
		belongs := pod.Name == *lease.Spec.HolderIdentity || pod.Labels["app"] == "kube-ovn-controller" || pod.Labels["app.kubernetes.io/name"] == "kube-ovn-controller"
		for _, owner := range pod.OwnerReferences {
			belongs = belongs || owned[owner.UID]
		}
		if !belongs {
			continue
		}
		if err := verifyPod(pod, u.Image); err != nil {
			return nil, err
		}
		count++
		if pod.Name == *lease.Spec.HolderIdentity {
			leader = pod
		}
	}
	if leader == nil || deployment.Spec.Replicas == nil || count != *deployment.Spec.Replicas {
		return nil, errors.New("controller rollout is not stable")
	}
	cm, err := u.Kube.CoreV1().ConfigMaps(u.Namespace).Get(ctx, CapabilityName(leader.UID), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("leader capability unavailable: %w", err)
	}
	var record Receipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &record); err != nil {
		return nil, err
	}
	if record.Capability != Capability || record.Leader != leader.Name || record.PodUID != string(leader.UID) || record.Session == "" || !sameDigest(record.ImageID, u.Image) {
		return nil, errors.New("leader has not published compatible, cache-synchronized capability")
	}
	return &record, nil
}

func verifyDeployment(deployment *appsv1.Deployment, image string) error {
	if deployment.Spec.Paused || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas == 0 || deployment.Status.ObservedGeneration != deployment.Generation || deployment.Status.UpdatedReplicas != *deployment.Spec.Replicas || deployment.Status.AvailableReplicas != *deployment.Spec.Replicas {
		return errors.New("controller Deployment has not completed its rollout")
	}
	return verifyTemplate(deployment.Spec.Template, image)
}

func verifyTemplate(template corev1.PodTemplateSpec, image string) error {
	for _, container := range template.Spec.Containers {
		if container.Name == "kube-ovn-controller" {
			if container.Image != image {
				return fmt.Errorf("controller template does not use the verified image %s", image)
			}
			enabled := false
			for _, arg := range container.Args {
				if strings.HasPrefix(arg, "--enable-anp=") {
					enabled = arg == "--enable-anp=true"
				}
			}
			if !enabled {
				return errors.New("--enable-anp=true must remain enabled throughout upgrade")
			}
			return nil
		}
	}
	return errors.New("controller container not found")
}

func verifyPod(pod *corev1.Pod, image string) error {
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return fmt.Errorf("controller Pod %s is not stable", pod.Name)
	}
	if err := verifyTemplate(corev1.PodTemplateSpec{Spec: pod.Spec}, image); err != nil {
		return fmt.Errorf("controller Pod %s: %w", pod.Name, err)
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "kube-ovn-controller" && status.Ready && sameDigest(status.ImageID, image) {
			return nil
		}
	}
	return fmt.Errorf("controller Pod %s has not started the verified digest", pod.Name)
}

func hasOwner(owners []metav1.OwnerReference, uid types.UID) bool {
	for _, owner := range owners {
		if owner.UID == uid && owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

func sameDigest(a, b string) bool {
	_, ad, aok := strings.Cut(a, "@sha256:")
	_, bd, bok := strings.Cut(b, "@sha256:")
	return aok && bok && len(ad) == 64 && ad == bd
}

func (u *Upgrade) replaceSchema(ctx context.Context, expectedDigest, mode string) error {
	client := u.Dynamic.Resource(crdResource)
	current, err := client.Get(ctx, CRDName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	_, actualDigest, err := IdentifySchema(current)
	if err != nil {
		return err
	}
	if actualDigest != expectedDigest {
		return errors.New("CNP schema changed during upgrade")
	}
	target, err := Schema(mode)
	if err != nil {
		return err
	}
	objects, err := u.Dynamic.Resource(Resource).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	if err := ValidateSchemaObjects(ctx, target, objects.Items); err != nil {
		return err
	}
	annotations := maps.Clone(current.GetAnnotations())
	if annotations == nil {
		annotations = map[string]string{}
	}
	maps.Copy(annotations, target.GetAnnotations())
	versions := target.Object["spec"].(map[string]any)["versions"]
	patch, err := json.Marshal([]PatchOperation{
		{Op: "test", Path: "/metadata/uid", Value: string(current.GetUID())},
		{Op: "test", Path: "/metadata/resourceVersion", Value: current.GetResourceVersion()},
		{Op: "replace", Path: "/spec/versions", Value: versions},
		{Op: "add", Path: "/metadata/annotations", Value: annotations},
	})
	if err != nil {
		return err
	}
	// Validate the CRD on the API server before making the update.
	if _, err := client.Patch(ctx, CRDName, types.JSONPatchType, patch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		return err
	}
	if _, err := client.Patch(ctx, CRDName, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}
	readBack, err := client.Get(ctx, CRDName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	found, _, err := IdentifySchema(readBack)
	if err != nil {
		return err
	}
	if found != mode {
		return errors.New("CNP schema update was not observed")
	}
	if err := wait.PollUntilContextTimeout(ctx, time.Second, u.Timeout, true, func(ctx context.Context) (bool, error) {
		return u.probeSchema(ctx, mode)
	}); err != nil {
		return fmt.Errorf("target CNP admission schema has not converged: %w", err)
	}
	return u.saveState(ctx, "schema-"+mode, "")
}

// Dry-run creation observes active admission behavior, not only the CRD stored
// in etcd. It checks that legacy fields survive and the mixed-version gate works.
func (u *Upgrade) probeSchema(ctx context.Context, mode string) (bool, error) {
	for _, legacy := range []bool{false, true} {
		if mode == "native" && legacy {
			continue
		}
		rule := map[string]any{"action": "Deny", "from": []any{map[string]any{"namespaces": map[string]any{}}}}
		fieldName := "protocols"
		if legacy {
			fieldName = "ports"
			rule[fieldName] = []any{map[string]any{"portNumber": map[string]any{"port": int64(80)}}}
		} else {
			rule[fieldName] = []any{map[string]any{"tcp": map[string]any{"destinationPort": map[string]any{"number": int64(80)}}}}
		}
		probe := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": Resource.GroupVersion().String(), "kind": "ClusterNetworkPolicy",
			"metadata": map[string]any{"name": "kube-ovn-schema-probe-" + strings.ToLower(rand.Text())},
			"spec":     map[string]any{"tier": "Admin", "priority": int64(0), "subject": map[string]any{"namespaces": map[string]any{}}, "ingress": []any{rule}},
		}}
		observed, err := u.Dynamic.Resource(Resource).Create(ctx, probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if mode == "legacy-only" && !legacy {
			if apierrors.IsInvalid(err) {
				continue
			}
			if err != nil {
				return false, err
			}
			return false, nil
		}
		if apierrors.IsInvalid(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		rules, _, err := unstructured.NestedSlice(observed.Object, "spec", "ingress")
		if err != nil || len(rules) != 1 {
			return false, err
		}
		if _, present := rules[0].(map[string]any)[fieldName]; !present {
			return false, nil
		}
	}
	return true, nil
}

func (u *Upgrade) OpenNative(ctx context.Context) error {
	if err := u.requireExternalGate(); err != nil {
		return err
	}
	plan, err := u.Plan(ctx, false)
	if err != nil {
		return err
	}
	if plan.SchemaMode != "legacy-only" && plan.SchemaMode != "dual" {
		return errors.New("open requires legacy-only or dual schema")
	}
	if err := u.Verify(ctx); err != nil {
		return err
	}
	current, err := u.Plan(ctx, false)
	if err != nil {
		return err
	}
	if !sameInventory(plan, current) {
		return errors.New("CNP inventory changed before opening native writes")
	}
	return u.replaceSchema(ctx, plan.SchemaDigest, "dual")
}

// Verify requests fresh NB read-back from the current leader for every object.
// All decisions are invalidated if leadership, schema, spec or identity changes.
func (u *Upgrade) Verify(ctx context.Context) error {
	plan, err := u.Plan(ctx, false)
	if err != nil {
		return err
	}
	for _, obj := range plan.Objects {
		if err := u.verifyObject(ctx, obj); err != nil {
			return err
		}
	}
	if _, err := u.VerifyController(ctx); err != nil {
		return err
	}
	current, err := u.Plan(ctx, false)
	if err != nil {
		return err
	}
	if current.SchemaDigest != plan.SchemaDigest || !sameInventory(plan, current) {
		return errors.New("CNP inventory/schema changed during verification; re-plan")
	}
	return nil
}

func sameInventory(a, b *UpgradePlan) bool {
	if len(a.Objects) != len(b.Objects) {
		return false
	}
	for i, obj := range a.Objects {
		current := b.Objects[i]
		if obj.Name != current.Name || obj.UID != current.UID || obj.Generation != current.Generation || obj.SemanticDigest != current.SemanticDigest {
			return false
		}
	}
	return true
}

func (u *Upgrade) verifyObject(ctx context.Context, plan *ObjectPlan) error {
	leader, err := u.VerifyController(ctx)
	if err != nil {
		return err
	}
	client := u.Dynamic.Resource(Resource)
	raw, err := client.Get(ctx, plan.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := verifyIdentity(raw, plan); err != nil {
		return err
	}
	request := rand.Text()
	annotations := maps.Clone(raw.GetAnnotations())
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[VerifyAnnotation] = request
	patch, err := json.Marshal([]PatchOperation{
		{Op: "test", Path: "/metadata/uid", Value: plan.UID},
		{Op: "test", Path: "/metadata/resourceVersion", Value: raw.GetResourceVersion()},
		{Op: "add", Path: "/metadata/annotations", Value: annotations},
	})
	if err != nil {
		return err
	}
	if _, err := client.Patch(ctx, plan.Name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}
	err = wait.PollUntilContextTimeout(ctx, time.Second, u.Timeout, true, func(ctx context.Context) (bool, error) {
		cm, err := u.Kube.CoreV1().ConfigMaps(u.Namespace).Get(ctx, ReceiptName(types.UID(plan.UID)), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		var record Receipt
		if err := json.Unmarshal([]byte(cm.Data["receipt"]), &record); err != nil {
			return false, err
		}
		if record.Error != "" && record.Generation == plan.Generation {
			return false, fmt.Errorf("CNP %s application failed: %s", plan.Name, record.Error)
		}
		return record.Request == request && record.Error == "" && record.PolicyUID == plan.UID && record.Generation == plan.Generation && record.SemanticDigest == plan.SemanticDigest && record.OVNDigest != "" && record.Session == leader.Session && record.PodUID == leader.PodUID && record.Capability == Capability && sameDigest(record.ImageID, u.Image), nil
	})
	if err != nil {
		return fmt.Errorf("CNP %s not verified: %w", plan.Name, err)
	}
	currentLeader, err := u.VerifyController(ctx)
	if err != nil {
		return err
	}
	if currentLeader.Session != leader.Session {
		return fmt.Errorf("leader changed while verifying %s; retry verification", plan.Name)
	}
	current, err := client.Get(ctx, plan.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return verifyIdentity(current, plan)
}

func verifyIdentity(raw *unstructured.Unstructured, plan *ObjectPlan) error {
	if string(raw.GetUID()) != plan.UID || raw.GetGeneration() != plan.Generation || raw.GetDeletionTimestamp() != nil {
		return fmt.Errorf("CNP %s identity/generation changed; re-plan from current objects", plan.Name)
	}
	policy, err := Normalize(raw)
	if err != nil {
		return err
	}
	digest, err := Digest(policy)
	if err != nil {
		return err
	}
	if digest != plan.SemanticDigest {
		return fmt.Errorf("CNP %s semantics changed", plan.Name)
	}
	return nil
}

func (u *Upgrade) checkSchema(ctx context.Context, expectedDigest string) error {
	crd, err := u.Dynamic.Resource(crdResource).Get(ctx, CRDName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	_, digest, err := IdentifySchema(crd)
	if err != nil {
		return err
	}
	if digest != expectedDigest {
		return errors.New("CNP schema changed during operation")
	}
	return nil
}

// Migrate stops at the first conflict. Re-running re-plans from live objects and
// skips already converted rules; successfully migrated objects stay in place.
func (u *Upgrade) Migrate(ctx context.Context, legacy bool) error {
	if err := u.requireExternalGate(); err != nil {
		return err
	}
	if u.Journal == nil {
		return errors.New("an append-only object migration journal is required")
	}
	plan, err := u.Plan(ctx, legacy)
	if err != nil {
		return err
	}
	if plan.SchemaMode == "native" && legacy {
		if _, err := u.VerifyController(ctx); err != nil {
			return err
		}
		if err := u.replaceSchema(ctx, plan.SchemaDigest, "dual"); err != nil {
			return err
		}
		plan, err = u.Plan(ctx, legacy)
		if err != nil {
			return err
		}
	}
	if plan.SchemaMode != "dual" {
		return errors.New("object migration requires the dual schema")
	}
	for _, obj := range plan.Objects {
		if _, err := u.VerifyController(ctx); err != nil {
			return err
		}
		if err := u.checkSchema(ctx, plan.SchemaDigest); err != nil {
			return err
		}
		current, err := u.Dynamic.Resource(Resource).Get(ctx, obj.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err := verifyIdentity(current, obj); err != nil {
			return err
		}
		// Metadata-only verification can change resourceVersion. Re-plan only
		// after confirming the UID, generation and semantics are still identical.
		fresh, err := PlanObject(current, legacy)
		if err != nil {
			return err
		}
		if err := u.Journal(fresh); err != nil {
			return err
		}
		if len(fresh.Patch) != 0 {
			patch, err := fresh.PatchBytes()
			if err != nil {
				return err
			}
			updated, err := u.Dynamic.Resource(Resource).Patch(ctx, obj.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
			if err != nil {
				return fmt.Errorf("CNP %s migration conflict or validation error: %w", obj.Name, err)
			}
			fresh, err = PlanObject(updated, legacy)
			if err != nil {
				return err
			}
			if len(fresh.Patch) != 0 || fresh.UID != obj.UID || fresh.SemanticDigest != obj.SemanticDigest {
				return fmt.Errorf("CNP %s migration read-back mismatch", obj.Name)
			}
		}
		if err := u.verifyObject(ctx, fresh); err != nil {
			return err
		}
		if err := u.Journal(fresh); err != nil {
			return err
		}
		if err := u.saveState(ctx, "migrating", fresh.UID+":"+fresh.SemanticDigest); err != nil {
			return err
		}
	}
	if err := u.Verify(ctx); err != nil {
		return err
	}
	finalPlan, err := u.Plan(ctx, legacy)
	if err != nil {
		return err
	}
	for _, obj := range finalPlan.Objects {
		if len(obj.Patch) != 0 {
			return fmt.Errorf("unconverted fields reappeared in %s", obj.Name)
		}
	}
	if legacy {
		return u.replaceSchema(ctx, finalPlan.SchemaDigest, "legacy-only")
	}
	return u.saveState(ctx, "migrated", "")
}

func (u *Upgrade) Finalize(ctx context.Context) error {
	if err := u.requireExternalGate(); err != nil {
		return err
	}
	plan, err := u.Plan(ctx, false)
	if err != nil {
		return err
	}
	if plan.SchemaMode != "dual" && plan.SchemaMode != "native" {
		return errors.New("finalize requires dual or native schema")
	}
	for _, obj := range plan.Objects {
		if len(obj.Patch) != 0 {
			return fmt.Errorf("legacy fields remain in %s", obj.Name)
		}
	}
	if err := u.Verify(ctx); err != nil {
		return err
	}
	current, err := u.Plan(ctx, false)
	if err != nil {
		return err
	}
	if !sameInventory(plan, current) {
		return errors.New("CNP inventory changed before finalize")
	}
	return u.replaceSchema(ctx, plan.SchemaDigest, "native")
}

func (u *Upgrade) saveState(ctx context.Context, phase, object string) error {
	client := u.Kube.CoreV1().ConfigMaps(u.Namespace)
	cm, err := client.Get(ctx, UpgradeStateName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		cm = &corev1.ConfigMap{Name: UpgradeStateName, Labels: map[string]string{"kube-ovn.io/cnp-upgrade": "true"}}
	case err != nil:
		return err
	case cm.Labels["kube-ovn.io/cnp-upgrade"] != "true":
		return errors.New("refusing to overwrite unrelated upgrade ConfigMap")
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["phase"], cm.Data["controllerImage"] = phase, u.Image
	cm.Data["lastObject"], cm.Data["updatedAt"] = object, time.Now().UTC().Format(time.RFC3339)
	if cm.ResourceVersion == "" {
		_, err = client.Create(ctx, cm, metav1.CreateOptions{})
	} else {
		_, err = client.Update(ctx, cm, metav1.UpdateOptions{})
	}
	return err
}
