package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
)

func ownerUIDs(refs []metav1.OwnerReference, kind string) []types.UID {
	var uids []types.UID
	for _, ref := range refs {
		if ref.Kind == kind && ref.APIVersion == v1alpha1.GroupVersion.String() {
			uids = append(uids, ref.UID)
		}
	}
	return uids
}

func TestCatalogChallengesBelongToTheirSource(t *testing.T) {
	cs := catalogSource("unused")
	cs.UID = "source-uid"
	ch := &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "hello", Generation: 1, UID: "challenge-uid"},
		Spec: v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{
			Catalog: &v1alpha1.CatalogPackageRef{Source: "official", Name: "hello", Version: "0.1.0"},
		}},
	}
	c := newClient(t, cs, ch)
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: &fakeRegistry{}}
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)
	got := get(t, c, key, &v1alpha1.Challenge{})
	if uids := ownerUIDs(got.OwnerReferences, "CatalogSource"); len(uids) != 1 || uids[0] != "source-uid" {
		t.Fatalf("owners = %+v", got.OwnerReferences)
	}
	// Reconciling again changes nothing.
	rv := got.ResourceVersion
	doReconcile(t, r, key)
	if again := get(t, c, key, &v1alpha1.Challenge{}); again.ResourceVersion != rv {
		t.Fatalf("a second reconciliation updated the challenge: owners = %+v", again.OwnerReferences)
	}

	// Installed from elsewhere: the source no longer owns it.
	got.Spec.Source = v1alpha1.ChallengeSource{OCI: &v1alpha1.OCIPackageRef{Ref: "registry.example/hello:0.1.0", Trust: unsigned}}
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	if got = get(t, c, key, &v1alpha1.Challenge{}); len(ownerUIDs(got.OwnerReferences, "CatalogSource")) != 0 {
		t.Fatalf("owners = %+v", got.OwnerReferences)
	}
}

func TestInstancesBelongToTheirChallenge(t *testing.T) {
	ch, cm := inlineChallenge(t, testManifest)
	ch.UID = "challenge-uid"
	inst := &v1alpha1.ChallengeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "hello-1", Namespace: instancesNS, CreationTimestamp: metav1.Now()},
		Spec:       v1alpha1.ChallengeInstanceSpec{Challenge: "hello", Owner: v1alpha1.InstanceOwner{UserID: "u1"}},
	}
	c := newClient(t, ch, cm, inst)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: testConfig}
	doReconcile(t, r, types.NamespacedName{Namespace: instancesNS, Name: "hello-1"})
	got := get(t, c, types.NamespacedName{Namespace: instancesNS, Name: "hello-1"}, &v1alpha1.ChallengeInstance{})
	if uids := ownerUIDs(got.OwnerReferences, "Challenge"); len(uids) != 1 || uids[0] != "challenge-uid" || len(got.Finalizers) != 1 {
		t.Fatalf("owners = %+v, finalizers = %v", got.OwnerReferences, got.Finalizers)
	}
}
