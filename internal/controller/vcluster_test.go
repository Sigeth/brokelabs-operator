package controller

import (
	"encoding/json"
	"slices"
	"testing"
	"testing/fstest"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
	"github.com/Sigeth/brokelabs-core-go/pkg/checkerio"
)

func vclusterPackage() *v1alpha1.ChallengePackage {
	return &v1alpha1.ChallengePackage{Spec: v1alpha1.ChallengePackageSpec{Machines: []v1alpha1.Machine{
		{Name: "cluster", Runtime: v1alpha1.RuntimeVCluster, Kubernetes: "1.35", Seed: []string{"setup/manifests"}},
		{Name: "workstation", Runtime: v1alpha1.RuntimePod, Image: "ws:1", KubeconfigFor: "cluster"},
	}}}
}

var vclusterConfig = Config{
	SystemNamespace: "brokelabs-system", VClusterRole: "brokelabs-vcluster", HostMinor: 37,
	OperatorPods: map[string]string{"app": "operator"},
}

func TestVClusterInstanceResources(t *testing.T) {
	inst := &v1alpha1.ChallengeInstance{ObjectMeta: metav1.ObjectMeta{Name: "i", Namespace: "students"}}
	pkg := vclusterPackage()
	objs, err := instanceResources(vclusterConfig, inst, pkg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		if _, ok := o.(*corev1.Pod); ok {
			t.Errorf("pod %s created before the kubeconfig it mounts", o.GetName())
		}
		if _, ok := o.(*corev1.Service); ok && o.GetName() == "cluster" {
			t.Error("a machine Service would clash with the vcluster Service")
		}
		if q, ok := o.(*corev1.ResourceQuota); ok {
			if pods := q.Spec.Hard[corev1.ResourcePods]; pods.Value() != int64(vclusterMaxPods+4) {
				t.Errorf("pod quota = %s", pods.String())
			}
		}
		if s, ok := o.(*corev1.Secret); ok && s.Name == TargetsSecret {
			var targets checkerio.Targets
			if err := json.Unmarshal(s.Data[TargetsKey], &targets); err != nil {
				t.Fatal(err)
			}
			if f := targets.Machines["cluster"].KubeconfigFile; f != KubeconfigMountPath+"/cluster" {
				t.Errorf("checker kubeconfig = %q", f)
			}
		}
	}

	vobjs, err := vclusterResources(vclusterConfig, inst, pkg, []apiServer{{ip: "192.168.1.33", port: 6443}})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	var policies []*networkingv1.NetworkPolicy
	for _, o := range vobjs {
		kinds = append(kinds, kindOf(o))
		if o.GetLabels()[LabelInstance] != "i" {
			t.Errorf("%s %s lacks the instance labels", kindOf(o), o.GetName())
		}
		switch v := o.(type) {
		case *rbacv1.RoleBinding:
			if v.RoleRef.Name != "brokelabs-vcluster" || v.Subjects[0].Name != "vc-cluster" {
				t.Errorf("role binding = %+v", v)
			}
		case *networkingv1.NetworkPolicy:
			policies = append(policies, v)
		}
	}
	for _, want := range []string{"Deployment", "RoleBinding", "Service", "Secret"} {
		if !slices.Contains(kinds, want) {
			t.Errorf("no %s in %v", want, kinds)
		}
	}
	if len(policies) != 2 {
		t.Fatalf("network policies = %d, want the control plane's and the workloads'", len(policies))
	}
	// The control plane reaches the API server and nothing else outside the namespace.
	for _, rule := range policies[0].Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR != "192.168.1.33/32" {
				t.Errorf("control plane egress to %s", peer.IPBlock.CIDR)
			}
			if peer.NamespaceSelector != nil {
				t.Error("control plane egress to another namespace")
			}
		}
	}
	// Synced pods stay in the namespace.
	for _, rule := range policies[1].Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil || peer.NamespaceSelector != nil {
				t.Errorf("workload egress leaves the namespace: %+v", peer)
			}
		}
	}
}

func kindOf(o client.Object) string {
	if k := o.GetObjectKind().GroupVersionKind().Kind; k != "" {
		return k
	}
	switch o.(type) {
	case *rbacv1.RoleBinding:
		return "RoleBinding"
	case *networkingv1.NetworkPolicy:
		return "NetworkPolicy"
	}
	return "?"
}

func TestKubeconfigMachinePod(t *testing.T) {
	pod := machinePod(metav1.ObjectMeta{Name: "workstation"}, vclusterPackage().Spec.Machines[1])
	c := pod.Spec.Containers[0]
	if len(c.Env) != 1 || c.Env[0].Value != KubeconfigMountPath+"/"+KubeconfigKey {
		t.Errorf("env = %+v", c.Env)
	}
	if v := pod.Spec.Volumes[0].Secret; v == nil || v.SecretName != KubeconfigSecret("cluster") {
		t.Errorf("volumes = %+v", pod.Spec.Volumes)
	}
}

func TestSeedDocuments(t *testing.T) {
	files := fstest.MapFS{
		"setup/manifests/b.yaml":   {Data: []byte("# comment\n---\napiVersion: v1\nkind: Namespace\nmetadata: {name: b}\n---\n")},
		"setup/manifests/a.yml":    {Data: []byte("apiVersion: v1\nkind: Namespace\nmetadata: {name: a}\n---\napiVersion: v1\nkind: ServiceAccount\nmetadata: {name: sa, namespace: a}\n")},
		"setup/manifests/notes.md": {Data: []byte("not a manifest")},
		"extra.yaml":               {Data: []byte("apiVersion: v1\nkind: Namespace\nmetadata: {name: c}\n")},
	}
	docs, err := seedDocuments(files, []string{"setup/manifests", "./extra.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 4 {
		t.Fatalf("documents = %d, want 4 (a.yml has two, b.yaml one, extra.yaml one): %q", len(docs), docs)
	}
	if _, err := seedDocuments(files, []string{"missing"}); err == nil {
		t.Error("a missing seed path was accepted")
	}
}
