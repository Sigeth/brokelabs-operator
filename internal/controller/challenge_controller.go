package controller

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing/fstest"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
)

// ChallengeReconciler installs challenges: it resolves and validates the
// package, stores its files and reports whether this cluster can run it.
// Inline (local development) and OCI sources are supported.
type ChallengeReconciler struct {
	client.Client
	Config Config
	// Registry reads OCI packages. Nil refuses OCI sources.
	Registry PackageRegistry
	// TrustedRoot verifies keyless signatures. Nil refuses them.
	TrustedRoot TrustedRoot
}

// fetchRetry is how long the operator waits before fetching a package again
// after a registry failure.
const fetchRetry = time.Minute

// +kubebuilder:rbac:groups=opslab.io,resources=challenges,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=opslab.io,resources=challenges/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=opslab.io,resources=platformconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=opslab.io,resources=catalogsources,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile implements reconcile.Reconciler.
func (r *ChallengeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ch v1alpha1.Challenge
	if err := r.Get(ctx, req.NamespacedName, &ch); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// A catalog challenge belongs to its source: removing the source removes
	// the challenge, and with it its instances.
	owned := false
	if src := ch.Spec.Source.Catalog; src == nil {
		owned = setOwner(&ch, "CatalogSource", nil)
	} else {
		var cs v1alpha1.CatalogSource
		switch err := r.Get(ctx, types.NamespacedName{Name: src.Source}, &cs); {
		case err == nil:
			owned = setOwner(&ch, "CatalogSource", &cs)
		case apierrors.IsNotFound(err):
			// The source is gone or not created yet: keep a reference to it,
			// so the garbage collector removes the challenge with its source.
			owned = keepOwnersNamed(&ch, "CatalogSource", src.Source)
		default:
			return ctrl.Result{}, err
		}
	}
	if owned {
		if err := r.Update(ctx, &ch); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}
	platform, err := getPlatformConfig(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	status := ch.Status.DeepCopy()
	status.ObservedGeneration = ch.Generation
	result := ctrl.Result{}
	inst, resolveErr := r.resolve(ctx, &ch)
	if resolveErr != nil {
		status.Package, status.Digest, status.Signer, status.FilesConfigMap, status.Runnable = nil, "", "", "", false
		status.Permissions, status.Mirrored = nil, false
		meta.RemoveStatusCondition(&status.Conditions, ConditionMirrored)
		status.UnrunnableReason = ""
		reason := "Invalid"
		if errors.As(resolveErr, new(fetchError)) {
			reason, result.RequeueAfter = "FetchFailed", fetchRetry
		}
		setCondition(&status.Conditions, ch.Generation, metav1.ConditionFalse, reason, resolveErr.Error())
	} else {
		pkg := inst.pkg
		status.Package, status.Digest, status.Signer, status.FilesConfigMap = pkg, inst.digest, inst.signer, inst.filesConfigMap
		status.Permissions = inst.perms
		if inst.digest != ch.Status.Digest {
			// Another version: the mirror controller copies it again.
			status.Mirrored = false
			meta.RemoveStatusCondition(&status.Conditions, ConditionMirrored)
		}
		status.UnrunnableReason = unrunnableReason(r.Config, pkg, inst.perms, platform)
		status.Runnable = status.UnrunnableReason == ""
		setCondition(&status.Conditions, ch.Generation, metav1.ConditionTrue, "Installed",
			fmt.Sprintf("%s %s installed", pkg.Metadata.Name, pkg.Metadata.Version))
	}

	if apiEqual(&ch.Status, status) {
		return result, nil
	}
	ch.Status = *status
	if err := r.Status().Update(ctx, &ch); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("challenge reconciled", "installed", resolveErr == nil, "runnable", status.Runnable)
	return result, nil
}

// resolve returns the validated and defaulted package, with its digest and
// the ConfigMap holding its files.
func (r *ChallengeReconciler) resolve(ctx context.Context, ch *v1alpha1.Challenge) (*resolvedPackage, error) {
	src := ch.Spec.Source
	switch {
	case src.Inline != nil:
		return r.resolveInline(ctx, ch)
	case src.OCI != nil:
		return r.resolveRef(ctx, ch, src.OCI.Ref, src.OCI.Trust, nil)
	case src.Catalog != nil:
		return r.resolveCatalog(ctx, ch)
	default:
		return nil, errors.New("the Challenge has no source")
	}
}

// resolveInline installs an inline package (local development).
func (r *ChallengeReconciler) resolveInline(ctx context.Context, ch *v1alpha1.Challenge) (*resolvedPackage, error) {
	inline := ch.Spec.Source.Inline
	pkg := inline.Package.DeepCopy()
	bundle, err := inlineFiles(ctx, r.Client, r.Config.SystemNamespace, inline)
	if err != nil {
		return nil, err
	}
	if errs := challenge.Validate(pkg, mapFS(bundle)); len(errs) > 0 {
		return nil, fmt.Errorf("invalid package: %v", errs.ToAggregate())
	}
	if pkg.Metadata.Name != ch.Name {
		return nil, fmt.Errorf("the Challenge must be named after its package %q", pkg.Metadata.Name)
	}
	digest, err := challenge.Digest(pkg, bundle)
	if err != nil {
		return nil, err
	}
	perms, err := challenge.Permissions(pkg, bundle)
	if err != nil {
		return nil, fmt.Errorf("invalid package: %w", err)
	}
	challenge.SetDefaults(pkg)
	return &resolvedPackage{pkg: pkg, digest: digest, perms: perms, filesConfigMap: inline.FilesConfigMap}, nil
}

// inlineFiles reads the files of an inline package from its ConfigMap.
func inlineFiles(ctx context.Context, c client.Reader, namespace string, inline *v1alpha1.InlinePackage) (map[string][]byte, error) {
	files := map[string][]byte{}
	if inline.FilesConfigMap == "" {
		return files, nil
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: inline.FilesConfigMap}, &cm); err != nil {
		return nil, fmt.Errorf("reading package files from ConfigMap %s/%s: %w", namespace, inline.FilesConfigMap, err)
	}
	for key, content := range cm.Data {
		files[challenge.ConfigMapPath(key)] = []byte(content)
	}
	for key, content := range cm.BinaryData {
		files[challenge.ConfigMapPath(key)] = content
	}
	return files, nil
}

func mapFS(files map[string][]byte) fs.FS {
	m := fstest.MapFS{}
	for name, content := range files {
		m[name] = &fstest.MapFile{Data: content, Mode: 0o644}
	}
	return m
}

// apiEqual compares API objects semantically (quantities, times...).
func apiEqual(a, b any) bool { return equality.Semantic.DeepEqual(a, b) }

// unrunnableReason explains why the cluster cannot run a package, or is empty.
// unrunnableReason explains why this cluster cannot run a package: what the
// operator cannot provision yet, then what the platform policy refuses (D41).
// Both are evaluated again whenever the PlatformConfig changes.
func unrunnableReason(cfg Config, pkg *v1alpha1.ChallengePackage, perms *v1alpha1.RequiredPermissions, platform *v1alpha1.PlatformConfig) string {
	var reasons []string
	for _, m := range pkg.Spec.Machines {
		switch {
		case m.Runtime == v1alpha1.RuntimeVM && !cfg.Supports(m.Runtime):
			reasons = append(reasons, fmt.Sprintf("machine %s: the vm runtime needs KubeVirt, which is not installed", m.Name))
		case !cfg.Supports(m.Runtime):
			reasons = append(reasons, fmt.Sprintf("machine %s: the %s runtime is not supported yet", m.Name, m.Runtime))
		}
	}
	if perms.Egress == v1alpha1.EgressAllowlist {
		reasons = append(reasons, "egress allowlists need FQDN network policies, not supported yet")
	}
	if len(pkg.Spec.ExtraManifests) > 0 {
		reasons = append(reasons, "extraManifests are not supported yet")
	}
	for _, v := range challenge.PolicyViolations(perms, platform.Spec) {
		reasons = append(reasons, "refused by the platform policy: "+v)
	}
	return strings.Join(reasons, "; ")
}

// getPlatformConfig returns the PlatformConfig, or an empty one (defaults)
// when it does not exist.
func getPlatformConfig(ctx context.Context, c client.Reader) (*v1alpha1.PlatformConfig, error) {
	var pc v1alpha1.PlatformConfig
	err := c.Get(ctx, types.NamespacedName{Name: v1alpha1.PlatformConfigName}, &pc)
	if apierrors.IsNotFound(err) {
		return &v1alpha1.PlatformConfig{}, nil
	}
	return &pc, err
}

func setCondition(conds *[]metav1.Condition, generation int64, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type:               v1alpha1.ConditionReady,
		Status:             status,
		ObservedGeneration: generation,
		Reason:             reason,
		Message:            message,
	})
}

// SetupWithManager registers the reconciler.
func (r *ChallengeReconciler) SetupWithManager(mgr ctrl.Manager) error {
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
	fromCatalog := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var reqs []reconcile.Request
		for _, req := range all(ctx, obj) {
			var ch v1alpha1.Challenge
			if r.Get(ctx, req.NamespacedName, &ch) == nil && ch.Spec.Source.Catalog != nil && ch.Spec.Source.Catalog.Source == obj.GetName() {
				reqs = append(reqs, req)
			}
		}
		return reqs
	}
	usingConfigMap := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var reqs []reconcile.Request
		for _, req := range all(ctx, obj) {
			var ch v1alpha1.Challenge
			if r.Get(ctx, req.NamespacedName, &ch) == nil && ch.Spec.Source.Inline != nil &&
				ch.Spec.Source.Inline.FilesConfigMap == obj.GetName() && obj.GetNamespace() == r.Config.SystemNamespace {
				reqs = append(reqs, req)
			}
		}
		return reqs
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Challenge{}).
		Owns(&corev1.ConfigMap{}).
		Watches(&v1alpha1.PlatformConfig{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&v1alpha1.CatalogSource{}, handler.EnqueueRequestsFromMapFunc(fromCatalog)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(usingConfigMap)).
		Named("challenge").
		Complete(r)
}
