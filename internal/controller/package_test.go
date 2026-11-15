package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2/content/memory"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/ocipkg"
	"github.com/Sigeth/opslab-core-go/pkg/signing"
)

var pinnedImage = "docker.io/library/debian:13-slim@" + digest.FromString("debian").String()

// fakeRegistry serves packages packed in memory, by reference.
type fakeRegistry struct {
	packages map[string]*ocipkg.Package
	bundles  map[string][][]byte
	err      error
	fetches  int
}

func (f *fakeRegistry) Fetch(_ context.Context, ref string) (*ocipkg.Package, [][]byte, error) {
	f.fetches++
	if f.err != nil {
		return nil, nil, f.err
	}
	p, ok := f.packages[ref]
	if !ok {
		return nil, nil, errors.New("not found")
	}
	return p, f.bundles[ref], nil
}

// sign attaches a signature of the package at ref made with kp.
func (f *fakeRegistry) sign(t *testing.T, ref string, kp *signing.KeyPair) {
	t.Helper()
	b, err := signing.Sign(f.packages[ref].OCIManifest, kp, sign.BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if f.bundles == nil {
		f.bundles = map[string][][]byte{}
	}
	f.bundles[ref] = append(f.bundles[ref], b)
}

func newKey(t *testing.T) (*signing.KeyPair, string) {
	t.Helper()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.GetPublicKeyPem()
	if err != nil {
		t.Fatal(err)
	}
	return kp, pub
}

// publish packs manifest with files and serves it at ref.
func (f *fakeRegistry) publish(t *testing.T, ref, manifest string, files map[string][]byte) *ocipkg.Package {
	t.Helper()
	ctx := context.Background()
	pkg, err := challenge.Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	desc, err := ocipkg.Pack(ctx, store, pkg, files)
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := ocipkg.Fetch(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	if f.packages == nil {
		f.packages = map[string]*ocipkg.Package{}
	}
	f.packages[ref] = fetched
	return fetched
}

var helloFiles = map[string][]byte{"setup/setup.sh": []byte("echo broken > /tmp/state\n"), "instructions/en.md": []byte("# Hello\n")}

func ociChallenge(ref string, trust v1alpha1.TrustPolicy) *v1alpha1.Challenge {
	return &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "hello", Generation: 1},
		Spec: v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{
			OCI: &v1alpha1.OCIPackageRef{Ref: ref, Trust: trust},
		}},
	}
}

var unsigned = v1alpha1.TrustPolicy{AllowUnsigned: true}

func readyCondition(t *testing.T, ch *v1alpha1.Challenge) *metav1.Condition {
	t.Helper()
	cond := meta.FindStatusCondition(ch.Status.Conditions, v1alpha1.ConditionReady)
	if cond == nil {
		t.Fatalf("no Ready condition in %+v", ch.Status)
	}
	return cond
}

func TestChallengeInstallFromOCI(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	reg := &fakeRegistry{}
	published := reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	c := newClient(t, ociChallenge(ref, unsigned))
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)

	got := get(t, c, key, &v1alpha1.Challenge{})
	st := got.Status
	if cond := readyCondition(t, got); cond.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v", cond)
	}
	if st.Digest != published.Descriptor.Digest.String() || st.FilesConfigMap != "challenge-hello-package" || !st.Runnable {
		t.Fatalf("status = %+v", st)
	}
	if st.Package.Spec.Lifetime == nil {
		t.Error("the package must be defaulted")
	}

	cm := get(t, c, types.NamespacedName{Namespace: systemNS, Name: st.FilesConfigMap}, &corev1.ConfigMap{})
	if cm.Annotations[v1alpha1.PackageDigestAnnotation] != st.Digest {
		t.Errorf("annotations = %v", cm.Annotations)
	}
	if len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Name != "hello" || cm.OwnerReferences[0].Kind != "Challenge" {
		t.Errorf("owner references = %+v", cm.OwnerReferences)
	}
	files, err := installedFiles(context.Background(), c, systemNS, got)
	if err != nil || string(files["setup/setup.sh"]) != string(helloFiles["setup/setup.sh"]) {
		t.Fatalf("installed files = %v, %v", files, err)
	}

	// The installed digest is kept: no fetch until the Challenge changes.
	doReconcile(t, r, key)
	if reg.fetches != 1 {
		t.Fatalf("fetched %d times, want 1", reg.fetches)
	}
	got.Generation = 2
	got.Spec.Disabled = true
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	if reg.fetches != 2 {
		t.Fatalf("fetched %d times after a change, want 2", reg.fetches)
	}
}

func TestChallengeFromOCIRefusals(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	cases := map[string]struct {
		manifest string
		trust    v1alpha1.TrustPolicy
		want     string
		fetches  int
	}{
		"unsigned packages": {
			strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1),
			v1alpha1.TrustPolicy{Keys: []string{"key"}}, "not signed", 1,
		},
		"keyless without a trusted root": {
			strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1),
			v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{{Issuer: "https://issuer", SubjectRegExp: ".*"}}},
			"no Sigstore trusted root", 1,
		},
		"unpinned images": {testManifest, unsigned, "pinned by digest", 1},
		"name mismatch": {
			strings.Replace(strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), "name: hello", "name: other", 1),
			unsigned, "named after", 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			reg := &fakeRegistry{}
			reg.publish(t, ref, tc.manifest, helloFiles)
			c := newClient(t, ociChallenge(ref, tc.trust))
			r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
			res := doReconcile(t, r, types.NamespacedName{Name: "hello"})
			got := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
			cond := readyCondition(t, got)
			if cond.Status != metav1.ConditionFalse || cond.Reason != "Invalid" || !strings.Contains(cond.Message, tc.want) {
				t.Fatalf("condition = %+v", cond)
			}
			if res.RequeueAfter != 0 || reg.fetches != tc.fetches || got.Status.FilesConfigMap != "" {
				t.Fatalf("requeue = %v, fetches = %d, status = %+v", res.RequeueAfter, reg.fetches, got.Status)
			}
		})
	}
}

func TestChallengeFromOCIRetriesRegistryFailures(t *testing.T) {
	reg := &fakeRegistry{err: errors.New("connection refused")}
	c := newClient(t, ociChallenge("registry.example/hello:0.1.0", unsigned))
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	res := doReconcile(t, r, types.NamespacedName{Name: "hello"})
	cond := readyCondition(t, get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{}))
	if cond.Reason != "FetchFailed" || res.RequeueAfter != fetchRetry {
		t.Fatalf("condition = %+v, requeue = %v", cond, res.RequeueAfter)
	}
}

func TestInstalledFilesRefuseAnotherDigest(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "challenge-hello-package", Namespace: systemNS,
			Annotations: map[string]string{v1alpha1.PackageDigestAnnotation: "sha256:old"}},
	}
	ch := &v1alpha1.Challenge{ObjectMeta: metav1.ObjectMeta{Name: "hello"},
		Status: v1alpha1.ChallengeStatus{Digest: "sha256:new", FilesConfigMap: cm.Name}}
	if _, err := installedFiles(context.Background(), newClient(t, cm), systemNS, ch); err == nil ||
		!strings.Contains(err.Error(), "being updated") {
		t.Fatalf("error = %v", err)
	}
}

func TestChallengeFromOCIVerifiesSignatures(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	manifest := strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1)
	author, authorPub := newKey(t)
	stranger, _ := newKey(t)
	fingerprint, _ := signing.KeyFingerprint(author.GetPublicKey())
	key := types.NamespacedName{Name: "hello"}

	// Signed by a stranger only: refused.
	reg := &fakeRegistry{}
	reg.publish(t, ref, manifest, helloFiles)
	reg.sign(t, ref, stranger)
	c := newClient(t, ociChallenge(ref, v1alpha1.TrustPolicy{Keys: []string{authorPub}}))
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	doReconcile(t, r, key)
	got := get(t, c, key, &v1alpha1.Challenge{})
	if cond := readyCondition(t, got); cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "no signature matches") {
		t.Fatalf("condition = %+v", cond)
	}

	// Also signed by the author: installed, and the signer is reported.
	reg.sign(t, ref, author)
	got.Generation = 2
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	got = get(t, c, key, &v1alpha1.Challenge{})
	if cond := readyCondition(t, got); cond.Status != metav1.ConditionTrue || got.Status.Signer != "key "+fingerprint {
		t.Fatalf("condition = %+v, signer = %q", cond, got.Status.Signer)
	}
}

func TestChallengeFromOCIRetriesTrustedRootFailures(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	reg := &fakeRegistry{}
	reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	trust := v1alpha1.TrustPolicy{Keyless: []v1alpha1.KeylessIdentity{{Issuer: "https://issuer", SubjectRegExp: ".*"}}}
	c := newClient(t, ociChallenge(ref, trust))
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg,
		TrustedRoot: func(context.Context) (root.TrustedMaterial, error) { return nil, errors.New("tuf unreachable") }}
	res := doReconcile(t, r, types.NamespacedName{Name: "hello"})
	cond := readyCondition(t, get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{}))
	if cond.Reason != "FetchFailed" || !strings.Contains(cond.Message, "tuf unreachable") || res.RequeueAfter != fetchRetry {
		t.Fatalf("condition = %+v, requeue = %v", cond, res.RequeueAfter)
	}
}

func TestChallengePermissionsAndPolicy(t *testing.T) {
	ch, cm := inlineChallenge(t, testManifest)
	cpu := resource.MustParse("100m")
	platform := &v1alpha1.PlatformConfig{
		ObjectMeta: metav1.ObjectMeta{Name: v1alpha1.PlatformConfigName},
		Spec:       v1alpha1.PlatformConfigSpec{MaxInstanceResources: &v1alpha1.InstanceResources{CPU: &cpu}},
	}
	c := newClient(t, ch, cm, platform)
	r := &ChallengeReconciler{Client: c, Config: testConfig}
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)
	got := get(t, c, key, &v1alpha1.Challenge{})
	perms := got.Status.Permissions
	if perms == nil || perms.CPU.String() != "250m" || len(perms.Runtimes) != 1 || perms.Egress != v1alpha1.EgressNone {
		t.Fatalf("permissions = %+v", perms)
	}
	if got.Status.Runnable || !strings.Contains(got.Status.UnrunnableReason, "refused by the platform policy: an instance requests 250m CPU") {
		t.Fatalf("runnable = %v, reason = %q", got.Status.Runnable, got.Status.UnrunnableReason)
	}

	// Loosening the policy makes it runnable, without reinstalling.
	cpu = resource.MustParse("1")
	platform = get(t, c, types.NamespacedName{Name: v1alpha1.PlatformConfigName}, &v1alpha1.PlatformConfig{})
	platform.Spec.MaxInstanceResources.CPU = &cpu
	if err := c.Update(context.Background(), platform); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	if got = get(t, c, key, &v1alpha1.Challenge{}); !got.Status.Runnable {
		t.Fatalf("reason = %q", got.Status.UnrunnableReason)
	}
}

func TestChallengeFromCatalogRefusesOtherPermissions(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	kp, pub := newKey(t)
	reg := &fakeRegistry{}
	reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	reg.sign(t, ref, kp)
	indexes := publishIndex(t, reg, ref, kp)
	// The catalog lists less than the package needs.
	indexes.index.Index.Packages[0].Versions[0].Permissions.CPU = resource.MustParse("1m")
	cs := catalogSource(pub)
	c := newClient(t, cs)
	doReconcile(t, &CatalogSourceReconciler{Client: c, Registry: indexes}, types.NamespacedName{Name: "official"})
	ch := &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "hello", Generation: 1},
		Spec: v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{
			Catalog: &v1alpha1.CatalogPackageRef{Source: "official", Name: "hello", Version: "0.1.0"},
		}},
	}
	if err := c.Create(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}, types.NamespacedName{Name: "hello"})
	cond := readyCondition(t, get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{}))
	if cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "other permissions than its catalog lists") {
		t.Fatalf("condition = %+v", cond)
	}
}
