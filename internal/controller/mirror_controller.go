package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
	"github.com/Sigeth/brokelabs-core-go/pkg/catalog"
	"github.com/Sigeth/brokelabs-core-go/pkg/ocipkg"
	"github.com/Sigeth/brokelabs-core-go/pkg/signing"
	"github.com/Sigeth/brokelabs-operator/internal/vcluster"
)

// ConditionMirrored reports whether a challenge is in the registry mirror.
const ConditionMirrored = "Mirrored"

const (
	// mirrorTimeout bounds the copy of one challenge (VM disks are large).
	mirrorTimeout = 30 * time.Minute
	// mirrorRetry is how long the operator waits after a failed copy.
	mirrorRetry = 5 * time.Minute
)

// Copier copies artifacts into the registry mirror.
type Copier interface {
	// Copy copies the artifact at ref (pinned by digest) to mirror, under the
	// repository <registry>/<repository> of ref, as nodes ask for it
	// (D39). With signatures, the Sigstore bundles attached to it are copied
	// too; other referrers (solutions) never are.
	Copy(ctx context.Context, mirror, ref string, signatures bool) error
}

// MirrorRef is where ref is stored in mirror:
// mirror/<registry>/<repository>@digest. A port in the registry becomes
// "_<port>" ("registry.school:5000" is stored as "registry.school_5000"),
// since repository names cannot hold a colon.
func MirrorRef(mirror, ref string) (string, error) {
	parsed, err := ocipkg.ParseImage(ref)
	if err != nil {
		return "", err
	}
	d, err := parsed.Digest()
	if err != nil {
		return "", fmt.Errorf("%s: only references pinned by digest are mirrored", ref)
	}
	return mirror + "/" + strings.ReplaceAll(parsed.Registry, ":", "_") + "/" + parsed.Repository + "@" + d.String(), nil
}

// RemoteCopier copies from upstream registries to the mirror.
type RemoteCopier struct {
	// Upstream reaches the registries artifacts come from.
	Upstream ocipkg.Remote
	// Mirror reaches the mirror, with push credentials.
	Mirror ocipkg.Remote
}

// Copy implements Copier.
func (c RemoteCopier) Copy(ctx context.Context, mirror, ref string, signatures bool) error {
	src, parsed, err := c.Upstream.Repository(ref)
	if err != nil {
		return err
	}
	d, err := parsed.Digest()
	if err != nil {
		return fmt.Errorf("%s: only references pinned by digest are mirrored", ref)
	}
	target, err := MirrorRef(mirror, ref)
	if err != nil {
		return err
	}
	dst, _, err := c.Mirror.Repository(target)
	if err != nil {
		return err
	}
	root, err := src.Resolve(ctx, d.String())
	if err != nil {
		return err
	}
	if !signatures {
		return oras.CopyGraph(ctx, src, dst, root, oras.DefaultCopyGraphOptions)
	}
	opts := oras.DefaultExtendedCopyGraphOptions
	opts.FindPredecessors = func(ctx context.Context, s content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.Digest != root.Digest {
			return nil, nil
		}
		return registry.Referrers(ctx, s, desc, signing.BundleMediaType)
	}
	return oras.ExtendedCopyGraph(ctx, src, dst, root, opts)
}

// MirrorReconciler copies installed challenges, their signatures and every
// image they use into the registry mirror (PlatformConfig.registryMirror),
// so that instances start without the internet once a challenge is
// installed. It runs apart from the Challenge controller: copying a VM disk
// takes minutes, and pulls fall back to the upstream registry meanwhile.
type MirrorReconciler struct {
	client.Client
	Copier Copier
}

// Reconcile implements reconcile.Reconciler.
func (r *MirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ch v1alpha1.Challenge
	if err := r.Get(ctx, req.NamespacedName, &ch); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	platform, err := getPlatformConfig(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	mirror := platform.Spec.RegistryMirror
	st := ch.Status
	if mirror == "" || r.Copier == nil || st.Package == nil || st.Digest == "" || st.Mirrored {
		return ctrl.Result{}, nil
	}
	ref, err := r.packageRef(ctx, &ch)
	if err != nil {
		return ctrl.Result{}, r.setMirrored(ctx, &ch, st.Digest, metav1.ConditionFalse, "NotMirrored", err.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, mirrorTimeout)
	defer cancel()
	copyErr := r.Copier.Copy(ctx, mirror, ref, true)
	images := ocipkg.Images(st.Package)
	for _, m := range st.Package.Spec.Machines {
		if m.Runtime == v1alpha1.RuntimeVCluster {
			for _, image := range vcluster.Images(m.Kubernetes) {
				if !slices.Contains(images, image) {
					images = append(images, image)
				}
			}
		}
	}
	for _, image := range images {
		if copyErr != nil {
			break
		}
		if err := r.Copier.Copy(ctx, mirror, image, false); err != nil {
			copyErr = fmt.Errorf("%s: %w", image, err)
		}
	}
	if copyErr != nil {
		log.FromContext(ctx).Error(copyErr, "mirroring failed", "mirror", mirror)
		if err := r.setMirrored(ctx, &ch, st.Digest, metav1.ConditionFalse, "MirrorFailed", copyErr.Error()); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: mirrorRetry}, nil
	}
	log.FromContext(ctx).Info("challenge mirrored", "mirror", mirror, "images", len(images))
	return ctrl.Result{}, r.setMirrored(ctx, &ch, st.Digest, metav1.ConditionTrue, "Mirrored",
		fmt.Sprintf("the package and %d images are in %s", len(images), mirror))
}

// errInline is returned for packages without a registry to copy from.
var errInline = errors.New("inline packages are not mirrored (local development)")

// packageRef returns the reference of the installed package, pinned by digest.
func (r *MirrorReconciler) packageRef(ctx context.Context, ch *v1alpha1.Challenge) (string, error) {
	src := ch.Spec.Source
	var from string
	switch {
	case src.OCI != nil:
		from = src.OCI.Ref
	case src.Catalog != nil:
		var cs v1alpha1.CatalogSource
		if err := r.Get(ctx, types.NamespacedName{Name: src.Catalog.Source}, &cs); err != nil {
			return "", err
		}
		listed, ok := catalog.Find(cs.Status.Packages, src.Catalog.Name, src.Catalog.Version)
		if !ok {
			return "", fmt.Errorf("%s %s is no longer listed by catalog source %q", src.Catalog.Name, src.Catalog.Version, src.Catalog.Source)
		}
		from = listed.Ref
	default:
		return "", errInline
	}
	parsed, err := ocipkg.ParseImage(from)
	if err != nil {
		return "", err
	}
	return parsed.Registry + "/" + parsed.Repository + "@" + ch.Status.Digest, nil
}

// setMirrored records the outcome for digest, unless another version was
// installed meanwhile.
func (r *MirrorReconciler) setMirrored(ctx context.Context, ch *v1alpha1.Challenge, digest string, status metav1.ConditionStatus, reason, message string) error {
	var latest v1alpha1.Challenge
	if err := r.Get(ctx, client.ObjectKeyFromObject(ch), &latest); err != nil {
		return client.IgnoreNotFound(err)
	}
	if latest.Status.Digest != digest {
		return nil
	}
	before := latest.Status.DeepCopy()
	latest.Status.Mirrored = status == metav1.ConditionTrue
	cond := metav1.Condition{Type: ConditionMirrored, Status: status, Reason: reason, Message: message, ObservedGeneration: latest.Generation}
	meta.SetStatusCondition(&latest.Status.Conditions, cond)
	if apiEqual(before, &latest.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, &latest); err != nil && !apierrors.IsConflict(err) {
		return err
	}
	return nil
}

// SetupWithManager registers the reconciler.
func (r *MirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	all := func(ctx context.Context, _ client.Object) []reconcile.Request {
		var list v1alpha1.ChallengeList
		if err := r.List(ctx, &list); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for _, ch := range list.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: ch.Name}})
		}
		return reqs
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Challenge{}).
		Watches(&v1alpha1.PlatformConfig{}, handler.EnqueueRequestsFromMapFunc(all)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}).
		Named("mirror").
		Complete(r)
}
