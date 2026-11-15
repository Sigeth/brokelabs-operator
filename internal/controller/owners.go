package controller

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
)

// Removal cascades through owner references, handled by the Kubernetes
// garbage collector: a CatalogSource owns the Challenges installed from it,
// and a Challenge owns its ChallengeInstances. Removing a catalog source
// removes its challenges and their instances; scores stay in the database.

// setOwner makes owner (kind) the only owner of that kind of obj, or removes
// every owner of that kind when owner is nil. It reports whether obj changed.
func setOwner(obj client.Object, kind string, owner client.Object) bool {
	refs := obj.GetOwnerReferences()
	kept := slices.DeleteFunc(slices.Clone(refs), func(ref metav1.OwnerReference) bool {
		return ref.APIVersion == v1alpha1.GroupVersion.String() && ref.Kind == kind &&
			(owner == nil || ref.UID != owner.GetUID())
	})
	if owner != nil && !slices.ContainsFunc(kept, func(ref metav1.OwnerReference) bool { return ref.UID == owner.GetUID() }) {
		kept = append(kept, metav1.OwnerReference{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       kind,
			Name:       owner.GetName(),
			UID:        owner.GetUID(),
		})
	}
	if slices.Equal(refs, kept) {
		return false
	}
	obj.SetOwnerReferences(kept)
	return true
}
