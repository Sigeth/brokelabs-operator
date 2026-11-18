package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

func TestInstanceNamespacePodSecurity(t *testing.T) {
	inst := &v1alpha1.ChallengeInstance{ObjectMeta: metav1.ObjectMeta{Name: "i", Namespace: "students"}}
	for _, tc := range []struct {
		runtimes       []v1alpha1.Runtime
		level          string
		userNamespaces bool
	}{
		{[]v1alpha1.Runtime{v1alpha1.RuntimePod}, "restricted", false},
		{[]v1alpha1.Runtime{v1alpha1.RuntimePod, v1alpha1.RuntimeVM}, "restricted", false},
		{[]v1alpha1.Runtime{v1alpha1.RuntimePod, v1alpha1.RuntimeUserns}, "baseline", true},
		{[]v1alpha1.Runtime{v1alpha1.RuntimeVCluster, v1alpha1.RuntimePod}, "baseline", true},
	} {
		pkg := &v1alpha1.ChallengePackage{}
		for _, r := range tc.runtimes {
			pkg.Spec.Machines = append(pkg.Spec.Machines, v1alpha1.Machine{Name: string(r), Runtime: r})
		}
		labels := instanceNamespace(inst, pkg).Labels
		for _, mode := range []string{"enforce", "audit", "warn"} {
			if got := labels["pod-security.kubernetes.io/"+mode]; got != tc.level {
				t.Errorf("%v: %s = %q, want %q", tc.runtimes, mode, got, tc.level)
			}
		}
		// A baseline namespace without the label would run root pods on the host's users.
		if got := labels[v1alpha1.LabelUserNamespaces] == "true"; got != tc.userNamespaces {
			t.Errorf("%v: user namespaces label = %v, want %v", tc.runtimes, got, tc.userNamespaces)
		}
	}
}
