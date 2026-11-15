package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/catalog"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/ocipkg"
	"github.com/Sigeth/opslab-core-go/pkg/project"
	"github.com/Sigeth/opslab-core-go/pkg/signing"
)

// PackageRegistry reads packages from OCI registries.
type PackageRegistry interface {
	// Fetch resolves ref and reads the package it points to, with the
	// Sigstore bundles attached to it.
	Fetch(ctx context.Context, ref string) (*ocipkg.Package, [][]byte, error)
}

// RemoteRegistry reads packages from remote registries.
type RemoteRegistry struct {
	Remote ocipkg.Remote
}

// Fetch implements PackageRegistry.
func (r RemoteRegistry) Fetch(ctx context.Context, ref string) (*ocipkg.Package, [][]byte, error) {
	repo, parsed, err := r.Remote.Repository(ref)
	if err != nil {
		return nil, nil, err
	}
	if parsed.Reference == "" {
		return nil, nil, fmt.Errorf("%s: name a tag or a digest", ref)
	}
	desc, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		return nil, nil, err
	}
	pkg, err := ocipkg.Fetch(ctx, repo, desc)
	if err != nil {
		return nil, nil, err
	}
	bundles, err := signing.Bundles(ctx, repo, desc)
	if err != nil {
		return nil, nil, err
	}
	return pkg, bundles, nil
}

// FetchIndex implements IndexRegistry.
func (r RemoteRegistry) FetchIndex(ctx context.Context, ref string) (*catalog.Index, [][]byte, error) {
	repo, parsed, err := r.Remote.Repository(ref)
	if err != nil {
		return nil, nil, err
	}
	if parsed.Reference == "" {
		return nil, nil, fmt.Errorf("%s: name a tag or a digest", ref)
	}
	desc, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		return nil, nil, err
	}
	idx, err := catalog.Fetch(ctx, repo, desc)
	if err != nil {
		return nil, nil, err
	}
	bundles, err := signing.Bundles(ctx, repo, desc)
	if err != nil {
		return nil, nil, err
	}
	return idx, bundles, nil
}

// TrustedRoot returns the Sigstore trusted root for keyless signatures. It
// is only called for sources trusting keyless identities, so key-only and
// air-gapped installs never need it.
type TrustedRoot func(ctx context.Context) (root.TrustedMaterial, error)

// SigstoreTrustedRoot loads the trusted root from path when set (air-gapped
// installs), or else from the Sigstore public-good TUF repository (kept in
// memory and refreshed by sigstore-go). A failed load is retried at the next
// call.
func SigstoreTrustedRoot(path string) TrustedRoot {
	var (
		mu     sync.Mutex
		loaded root.TrustedMaterial
	)
	return func(context.Context) (root.TrustedMaterial, error) {
		mu.Lock()
		defer mu.Unlock()
		if loaded != nil {
			return loaded, nil
		}
		var err error
		if path != "" {
			loaded, err = root.NewTrustedRootFromPath(path)
		} else {
			loaded, err = root.NewLiveTrustedRoot(tuf.DefaultOptions().WithDisableLocalCache())
		}
		if err != nil {
			loaded = nil
			return nil, fmt.Errorf("loading the Sigstore trusted root: %w", err)
		}
		return loaded, nil
	}
}

// fetchError is a failure to reach a registry: the operator retries.
type fetchError struct{ error }

func (e fetchError) Unwrap() error { return e.error }

// resolvedPackage is a resolved package, ready for instances.
type resolvedPackage struct {
	pkg            *v1alpha1.ChallengePackage // defaulted
	digest         string
	signer         string
	filesConfigMap string
}

// packageConfigMapName is the ConfigMap holding the files of a challenge
// installed from a registry.
func packageConfigMapName(challengeName string) string {
	return "challenge-" + challengeName + "-package"
}

// resolveCatalog installs a version listed by a CatalogSource, from the last
// index it verified, with the trust policy of that source.
func (r *ChallengeReconciler) resolveCatalog(ctx context.Context, ch *v1alpha1.Challenge) (*resolvedPackage, error) {
	src := ch.Spec.Source.Catalog
	var cs v1alpha1.CatalogSource
	if err := r.Get(ctx, types.NamespacedName{Name: src.Source}, &cs); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("catalog source %q not found", src.Source)
		}
		return nil, err
	}
	if src.Name != ch.Name {
		return nil, fmt.Errorf("the Challenge must be named after its package %q", src.Name)
	}
	ref, ok := catalog.Find(cs.Status.Packages, src.Name, src.Version)
	if !ok {
		return nil, fmt.Errorf("%s %s is not listed by catalog source %q", src.Name, src.Version, src.Source)
	}
	return r.resolveRef(ctx, ch, ref, cs.Spec.Trust)
}

// resolveRef installs the package at ref, verified against trust. The
// package is fetched once per generation of the Challenge: later
// reconciliations keep the digest that was installed, so a moved tag never
// changes a challenge behind the admin's back. A ref pinned to another digest
// is always fetched.
func (r *ChallengeReconciler) resolveRef(ctx context.Context, ch *v1alpha1.Challenge, ref string, trust v1alpha1.TrustPolicy) (*resolvedPackage, error) {
	name := packageConfigMapName(ch.Name)
	if st := ch.Status; st.ObservedGeneration == ch.Generation && st.Package != nil && st.Digest != "" && st.FilesConfigMap == name &&
		pinnedTo(ref, st.Digest) {
		var cm corev1.ConfigMap
		err := r.Get(ctx, types.NamespacedName{Namespace: r.Config.SystemNamespace, Name: name}, &cm)
		if err == nil && cm.Annotations[v1alpha1.PackageDigestAnnotation] == st.Digest {
			return &resolvedPackage{pkg: st.Package, digest: st.Digest, signer: st.Signer, filesConfigMap: name}, nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		}
	}

	if r.Registry == nil {
		return nil, errors.New("this operator has no registry access")
	}
	fetched, bundles, err := r.Registry.Fetch(ctx, ref)
	if err != nil {
		return nil, fetchError{fmt.Errorf("fetching %s: %w", ref, err)}
	}
	verifier, err := newVerifier(ctx, r.TrustedRoot, trust)
	if err != nil {
		return nil, err
	}
	signer, err := verifier.Verify(trust, fetched.OCIManifest, bundles)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	pkg, files := fetched.Manifest, fetched.Files
	if pkg.Metadata.Name != ch.Name {
		return nil, fmt.Errorf("the Challenge must be named after its package %q", pkg.Metadata.Name)
	}
	if errs := challenge.Validate(pkg, mapFS(files)); len(errs) > 0 {
		return nil, fmt.Errorf("invalid package: %v", errs.ToAggregate())
	}
	if unpinned := ocipkg.Unpinned(pkg); len(unpinned) > 0 {
		return nil, fmt.Errorf("images must be pinned by digest (built with '%s challenge build'): %s", project.Name, strings.Join(unpinned, ", "))
	}
	digest := fetched.Descriptor.Digest.String()
	if err := r.writePackageFiles(ctx, ch, name, digest, files); err != nil {
		return nil, err
	}
	challenge.SetDefaults(pkg)
	return &resolvedPackage{pkg: pkg, digest: digest, signer: signer, filesConfigMap: name}, nil
}

// newVerifier returns a signature verifier for trust, loading the Sigstore
// trusted root only when trust lists keyless identities.
func newVerifier(ctx context.Context, trustedRoot TrustedRoot, trust v1alpha1.TrustPolicy) (signing.Verifier, error) {
	if len(trust.Keyless) == 0 {
		return signing.Verifier{}, nil
	}
	if trustedRoot == nil {
		return signing.Verifier{}, errors.New("this operator cannot verify keyless signatures (no Sigstore trusted root)")
	}
	tm, err := trustedRoot(ctx)
	if err != nil {
		return signing.Verifier{}, fetchError{err}
	}
	return signing.Verifier{TrustedRoot: tm}, nil
}

// pinnedTo reports whether ref names no digest or the given one.
func pinnedTo(ref, digest string) bool {
	parsed, err := ocipkg.ParseImage(ref)
	if err != nil {
		return false
	}
	d, err := parsed.Digest()
	return err != nil || d.String() == digest
}

// writePackageFiles stores the files of an installed package in a ConfigMap
// of the system namespace, owned by the Challenge.
//
// RBAC: updating ConfigMaps of the system namespace is granted by a Role of
// the chart (opslab-operator-packages), not by a marker, since it is
// namespaced.
func (r *ChallengeReconciler) writePackageFiles(ctx context.Context, ch *v1alpha1.Challenge, name, digest string, files map[string][]byte) error {
	data, binaryData, err := challenge.ConfigMapData(files)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.Config.SystemNamespace}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Labels = map[string]string{LabelManagedBy: ManagedBy, LabelChallenge: ch.Name}
		cm.Annotations = map[string]string{v1alpha1.PackageDigestAnnotation: digest}
		cm.Data, cm.BinaryData = data, binaryData
		return controllerutil.SetControllerReference(ch, cm, r.Scheme())
	})
	if err != nil {
		return fmt.Errorf("storing the package files: %w", err)
	}
	return nil
}

// installedFiles returns the files of the package installed by ch, as the
// instances of the current status.Digest must see them.
func installedFiles(ctx context.Context, c client.Reader, namespace string, ch *v1alpha1.Challenge) (map[string][]byte, error) {
	name := ch.Status.FilesConfigMap
	files := map[string][]byte{}
	if name == "" {
		return files, nil
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &cm); err != nil {
		return nil, fmt.Errorf("reading package files from ConfigMap %s/%s: %w", namespace, name, err)
	}
	if d, ok := cm.Annotations[v1alpha1.PackageDigestAnnotation]; ok && d != ch.Status.Digest {
		return nil, fmt.Errorf("the files of %s are being updated (ConfigMap %s has %s, want %s)", ch.Name, name, d, ch.Status.Digest)
	}
	for key, content := range cm.Data {
		files[challenge.ConfigMapPath(key)] = []byte(content)
	}
	for key, content := range cm.BinaryData {
		files[challenge.ConfigMapPath(key)] = content
	}
	return files, nil
}
