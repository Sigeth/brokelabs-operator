package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/catalog"
)

// DefaultSyncInterval is how often a catalog index is fetched again.
const DefaultSyncInterval = time.Hour

// IndexRegistry reads catalog indexes from OCI registries.
type IndexRegistry interface {
	// FetchIndex resolves ref and reads the index it points to, with the
	// Sigstore bundles attached to it.
	FetchIndex(ctx context.Context, ref string) (*catalog.Index, [][]byte, error)
}

// CatalogSourceReconciler syncs catalog indexes: it fetches the index,
// verifies its signature against the trust policy of the source and lists
// its packages in the status. When a sync fails, the packages of the last
// verified index stay listed.
type CatalogSourceReconciler struct {
	client.Client
	Registry    IndexRegistry
	TrustedRoot TrustedRoot
	// Now returns the current time (tests).
	Now func() time.Time
}

// +kubebuilder:rbac:groups=opslab.io,resources=catalogsources,verbs=get;list;watch
// +kubebuilder:rbac:groups=opslab.io,resources=catalogsources/status,verbs=get;update;patch

// Reconcile implements reconcile.Reconciler.
func (r *CatalogSourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cs v1alpha1.CatalogSource
	if err := r.Get(ctx, req.NamespacedName, &cs); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	interval := DefaultSyncInterval
	if cs.Spec.SyncInterval != nil && cs.Spec.SyncInterval.Duration > 0 {
		interval = cs.Spec.SyncInterval.Duration
	}

	status := cs.Status.DeepCopy()
	if cs.Spec.Suspend {
		status.ObservedGeneration = cs.Generation
		setCondition(&status.Conditions, cs.Generation, metav1.ConditionFalse, "Suspended", "syncing is suspended")
		return ctrl.Result{}, r.updateStatus(ctx, &cs, status)
	}
	// Synced for this generation and not due yet.
	if last := cs.Status.LastSyncTime; last != nil && cs.Status.ObservedGeneration == cs.Generation && isReady(cs.Status.Conditions) {
		if next := last.Add(interval); now.Before(next) {
			return ctrl.Result{RequeueAfter: next.Sub(now)}, nil
		}
	}

	status.ObservedGeneration = cs.Generation
	result := ctrl.Result{RequeueAfter: interval}
	idx, signer, err := r.sync(ctx, &cs)
	if err != nil {
		reason := "Untrusted"
		if errors.As(err, new(fetchError)) {
			reason = "FetchFailed"
		}
		if retry := fetchRetry; retry < interval {
			result.RequeueAfter = retry
		}
		msg := err.Error()
		if len(status.Packages) > 0 {
			msg += " (the packages of the last verified index stay listed)"
		}
		setCondition(&status.Conditions, cs.Generation, metav1.ConditionFalse, reason, msg)
	} else {
		status.Packages = idx.Index.Packages
		status.IndexDigest = idx.Descriptor.Digest.String()
		status.Signer = signer
		status.LastSyncTime = &metav1.Time{Time: now.Truncate(time.Second)}
		setCondition(&status.Conditions, cs.Generation, metav1.ConditionTrue, "Synced",
			fmt.Sprintf("%d packages listed", len(idx.Index.Packages)))
	}
	if err := r.updateStatus(ctx, &cs, status); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("catalog source synced", "ok", err == nil, "packages", len(status.Packages))
	return result, nil
}

// sync fetches and verifies the index of cs.
func (r *CatalogSourceReconciler) sync(ctx context.Context, cs *v1alpha1.CatalogSource) (*catalog.Index, string, error) {
	if r.Registry == nil {
		return nil, "", errors.New("this operator has no registry access")
	}
	idx, bundles, err := r.Registry.FetchIndex(ctx, cs.Spec.Ref)
	if err != nil {
		return nil, "", fetchError{fmt.Errorf("fetching %s: %w", cs.Spec.Ref, err)}
	}
	verifier, err := newVerifier(ctx, r.TrustedRoot, cs.Spec.Trust)
	if err != nil {
		return nil, "", err
	}
	signer, err := verifier.Verify(cs.Spec.Trust, idx.OCIManifest, bundles)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", cs.Spec.Ref, err)
	}
	return idx, signer, nil
}

func (r *CatalogSourceReconciler) updateStatus(ctx context.Context, cs *v1alpha1.CatalogSource, status *v1alpha1.CatalogSourceStatus) error {
	if apiEqual(&cs.Status, status) {
		return nil
	}
	cs.Status = *status
	return r.Status().Update(ctx, cs) // a conflict is retried by the controller
}

func isReady(conditions []metav1.Condition) bool {
	for _, c := range conditions {
		if c.Type == v1alpha1.ConditionReady {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}

// SetupWithManager registers the reconciler.
func (r *CatalogSourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Status updates do not trigger a sync: syncs follow spec changes and
	// the sync interval.
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.CatalogSource{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("catalogsource").
		Complete(r)
}
