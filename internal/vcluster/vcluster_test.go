package vcluster

import (
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRender(t *testing.T) {
	objs, err := Render(Options{
		Release: "cluster", Namespace: "inst", Kubernetes: "1.34", HostMinor: 37,
		PodLabels: map[string]string{"brokelabs.io/machine": "cluster"},
		ExtraSANs: []string{"cluster.inst.svc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	var deploy *unstructured.Unstructured
	for _, o := range objs {
		kinds = append(kinds, o.GetKind())
		if o.GetNamespace() != "inst" {
			t.Errorf("%s %s in namespace %q", o.GetKind(), o.GetName(), o.GetNamespace())
		}
		if o.GetKind() == "Deployment" {
			deploy = o
		}
	}
	slices.Sort(kinds)
	// No Role, RoleBinding or anything cluster-scoped: the operator binds its own role.
	if want := []string{"Deployment", "Secret", "Service", "ServiceAccount", "ServiceAccount"}; !slices.Equal(kinds, want) {
		t.Fatalf("kinds = %v, want %v (a StatefulSet would mean a volume claim)", kinds, want)
	}
	spec, _, _ := unstructured.NestedMap(deploy.Object, "spec", "template", "spec")
	text := strings.Join(containerImages(spec), " ")
	for _, want := range []string{"ghcr.io/loft-sh/vcluster-oss:", "ghcr.io/loft-sh/kubernetes:v1.34.13"} {
		if !strings.Contains(text, want) {
			t.Errorf("images %q lack %q", text, want)
		}
	}
	labels, _, _ := unstructured.NestedStringMap(deploy.Object, "spec", "template", "metadata", "labels")
	if labels["brokelabs.io/machine"] != "cluster" {
		t.Errorf("pod labels = %v", labels)
	}
	if nonRoot, _, _ := unstructured.NestedBool(spec, "securityContext", "runAsNonRoot"); !nonRoot {
		t.Error("the control plane must run as non-root")
	}
	found := false
	for _, o := range objs {
		if o.GetKind() == "ServiceAccount" && o.GetName() == ServiceAccount("cluster") {
			found = true
		}
	}
	if !found {
		t.Errorf("no ServiceAccount %s to bind", ServiceAccount("cluster"))
	}
}

func containerImages(spec map[string]any) []string {
	var images []string
	for _, key := range []string{"initContainers", "containers"} {
		list, _, _ := unstructured.NestedSlice(spec, key)
		for _, c := range list {
			if img, ok := c.(map[string]any)["image"].(string); ok {
				images = append(images, img)
			}
		}
	}
	return images
}

func TestRenderRefusesUnknownKubernetes(t *testing.T) {
	if _, err := Render(Options{Release: "c", Namespace: "n", Kubernetes: "1.20", HostMinor: 37}); err == nil {
		t.Fatal("rendered an unsupported Kubernetes version")
	}
}

func TestRoleRules(t *testing.T) {
	rules, err := RoleRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if slices.Contains(r.Resources, "pods") && slices.Contains(r.Verbs, "create") {
			return
		}
	}
	t.Fatalf("rules %v do not let the syncer create pods", rules)
}
