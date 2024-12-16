package main

import (
	"context"
	"os"

	"github.com/hashicorp/memberlist"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		panic("Failed to get in-cluster config: " + err.Error())
	}

	cfg.QPS = 1000
	cfg.Burst = 2000
	cfg.ContentType = "application/vnd.kubernetes.protobuf"
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		panic("Failed to create kube client: " + err.Error())
	}

	w, err := cs.CoreV1().Pods(os.Getenv("POD_NAMESPACE")).Watch(context.TODO(), metav1.ListOptions{LabelSelector: "app=vpc-gateway"})
	if err != nil {
		panic("Failed to watch pods: " + err.Error())
	}

	ml, err := memberlist.Create(memberlist.DefaultLANConfig())
	if err != nil {
		panic("Failed to create memberlist: " + err.Error())
	}

	peersChan := make(chan *corev1.Pod, 10)

	go func() {
		for result := range w.ResultChan() {
			switch result.Type {
			case watch.Added, watch.Modified:
				peersChan <- result.Object.(*corev1.Pod)
			case watch.Error:
				panic("Error watching pods: " + result.Object.(*metav1.Status).Message)
			case watch.Deleted, watch.Bookmark:
			default:
				klog.Warningf("Unknown watch event: %v", result.Type)
			}
		}
	}()

	for pod := range peersChan {
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, c := range pod.Status.Conditions {
			if c.Type != corev1.PodReady {
				continue
			}
			if c.Status == corev1.ConditionTrue {
				_, err := ml.Join([]string{pod.Status.PodIP})
				if err != nil {
					klog.Errorf("Failed to join memberlist: %v", err)
				}
			}
			break
		}
	}
}
