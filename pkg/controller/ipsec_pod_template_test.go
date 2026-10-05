package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func ipsecTestAPITokenVolume(name string) corev1.Volume {
	return corev1.Volume{Name: name, Projected: &corev1.ProjectedVolumeSource{
		DefaultMode: new(int32(0o644)), Sources: []corev1.VolumeProjection{
			{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: new(int64(3607))}},
			{ConfigMap: &corev1.ConfigMapProjection{Name: "kube-root-ca.crt", Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
			{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}},
		},
	}}
}

func TestIPsecPodTemplateRejectsPrivateAccessChanges(t *testing.T) {
	ds := &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "cni-server", Image: "candidate"}},
		InitContainers: []corev1.Container{{
			Name: "ipsec-cleanup", Image: "candidate", RestartPolicy: new(corev1.ContainerRestartPolicyAlways),
			VolumeMounts: []corev1.VolumeMount{{Name: "private", MountPath: "/var/lib/kube-ovn/ipsec"}},
		}},
		Volumes: []corev1.Volume{{Name: "private", HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kube-ovn/ipsec", Type: new(corev1.HostPathDirectoryOrCreate)}}},
	}}}}
	pod := &corev1.Pod{Spec: *ds.Spec.Template.Spec.DeepCopy()}
	pod.Spec.Volumes = append(pod.Spec.Volumes, ipsecTestAPITokenVolume("kube-api-access-test"))
	tokenMount := corev1.VolumeMount{Name: "kube-api-access-test", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, tokenMount)
	pod.Spec.InitContainers[0].VolumeMounts = append(pod.Spec.InitContainers[0].VolumeMounts, tokenMount)
	require.NoError(t, verifyIPsecPodTemplate(pod, ds))
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"changed-host-path", func(p *corev1.Pod) { p.Spec.Volumes[0].HostPath.Path = "/foreign" }},
		{"sibling-key-mount", func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, p.Spec.InitContainers[0].VolumeMounts[0])
		}},
		{"injected-sibling", func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "reader"}) }},
		{"injected-init", func(p *corev1.Pod) {
			p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: "reader"})
		}},
		{"ephemeral-reader", func(p *corev1.Pod) { p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{Name: "reader"}} }},
		{"fake-token-secret", func(p *corev1.Pod) {
			p.Spec.Volumes[1].Projected.Sources = append(p.Spec.Volumes[1].Projected.Sources, corev1.VolumeProjection{Secret: &corev1.SecretProjection{Name: "foreign"}})
		}},
		{"token-writable", func(p *corev1.Pod) { p.Spec.InitContainers[0].VolumeMounts[1].ReadOnly = false }},
		{"token-sub-path", func(p *corev1.Pod) { p.Spec.InitContainers[0].VolumeMounts[1].SubPath = "token" }},
		{"token-wrong-source", func(p *corev1.Pod) { p.Spec.Volumes[1].Projected.Sources[1].ConfigMap.Name = "foreign" }},
		{"token-private-path", func(p *corev1.Pod) { p.Spec.Volumes[1].Projected.Sources[0].ServiceAccountToken.Path = "private" }},
		{"token-other-audience", func(p *corev1.Pod) { p.Spec.Volumes[1].Projected.Sources[0].ServiceAccountToken.Audience = "foreign" }},
		{"token-with-host-path", func(p *corev1.Pod) { p.Spec.Volumes[1].HostPath = &corev1.HostPathVolumeSource{Path: "/foreign"} }},
		{"token-missing-volume", func(p *corev1.Pod) { p.Spec.Volumes = p.Spec.Volumes[:1] }},
		{"extra-token-volume", func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, ipsecTestAPITokenVolume("kube-api-access-extra"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := pod.DeepCopy()
			tc.change(changed)
			require.Error(t, verifyIPsecPodTemplate(changed, ds))
		})
	}
	// Explicitly frozen token-like names are private volumes, not injection.
	explicit := ds.DeepCopy()
	explicit.Spec.Template.Spec.Volumes[0].Name = "kube-api-access-private"
	changed := &corev1.Pod{Spec: *explicit.Spec.Template.Spec.DeepCopy()}
	changed.Spec.Volumes[0] = ipsecTestAPITokenVolume("kube-api-access-private")
	require.Error(t, verifyIPsecPodTemplate(changed, explicit))
}
