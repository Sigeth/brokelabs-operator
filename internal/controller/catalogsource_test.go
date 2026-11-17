package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/sign"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2/content/memory"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
	"github.com/Sigeth/brokelabs-core-go/pkg/catalog"
	"github.com/Sigeth/brokelabs-core-go/pkg/signing"
)

// fakeIndexes serves catalog indexes packed in memory.
type fakeIndexes struct {
	index   *catalog.Index
	bundles [][]byte
	err     error
	fetches int
}

func (f *fakeIndexes) FetchIndex(context.Context, string) (*catalog.Index, [][]byte, error) {
	f.fetches++
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.index, f.bundles, nil
}

// publishIndex lists the package of reg at ref in a new index, signed with kp.
func publishIndex(t *testing.T, reg *fakeRegistry, ref string, kp *signing.KeyPair) *fakeIndexes {
	t.Helper()
	ctx := context.Background()
	idx := catalog.New()
	pkg := reg.packages[ref]
	pinned := "registry.example/hello@" + pkg.Descriptor.Digest.String()
	reg.packages[pinned] = pkg
	reg.bundles[pinned] = reg.bundles[ref]
	if err := catalog.Add(idx, pkg.Manifest, pkg.Files, pinned); err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	desc, err := catalog.Pack(ctx, store, idx)
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := catalog.Fetch(ctx, store, desc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signing.Sign(fetched.OCIManifest, kp, sign.BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIndexes{index: fetched, bundles: [][]byte{b}}
}

func catalogSource(pub string) *v1alpha1.CatalogSource {
	return &v1alpha1.CatalogSource{
		ObjectMeta: metav1.ObjectMeta{Name: "official", Generation: 1},
		Spec: v1alpha1.CatalogSourceSpec{Ref: "registry.example/catalog:latest",
			Trust: v1alpha1.TrustPolicy{Keys: []string{pub}}, SyncInterval: &metav1.Duration{Duration: time.Hour}},
	}
}

func TestCatalogSourceSync(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	kp, pub := newKey(t)
	reg := &fakeRegistry{}
	reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	reg.sign(t, ref, kp)
	indexes := publishIndex(t, reg, ref, kp)

	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	c := newClient(t, catalogSource(pub))
	r := &CatalogSourceReconciler{Client: c, Registry: indexes, Now: func() time.Time { return now }}
	key := types.NamespacedName{Name: "official"}
	res := doReconcile(t, r, key)
	cs := get(t, c, key, &v1alpha1.CatalogSource{})
	fingerprint, _ := signing.KeyFingerprint(kp.GetPublicKey())
	if cond := readyConditionOf(t, cs.Status.Conditions); cond.Status != metav1.ConditionTrue || cond.Reason != "Synced" {
		t.Fatalf("condition = %+v", cond)
	}
	if len(cs.Status.Packages) != 1 || cs.Status.Signer != "key "+fingerprint || cs.Status.IndexDigest == "" || res.RequeueAfter != time.Hour {
		t.Fatalf("status = %+v, requeue = %v", cs.Status, res.RequeueAfter)
	}

	// Not due: no fetch, requeued for the remaining time.
	now = now.Add(20 * time.Minute)
	res = doReconcile(t, r, key)
	if indexes.fetches != 1 || res.RequeueAfter != 40*time.Minute {
		t.Fatalf("fetches = %d, requeue = %v", indexes.fetches, res.RequeueAfter)
	}

	// Due, but the registry fails: the packages stay listed.
	now = now.Add(time.Hour)
	indexes.err = errors.New("connection refused")
	res = doReconcile(t, r, key)
	cs = get(t, c, key, &v1alpha1.CatalogSource{})
	if cond := readyConditionOf(t, cs.Status.Conditions); cond.Reason != "FetchFailed" || !strings.Contains(cond.Message, "stay listed") {
		t.Fatalf("condition = %+v", cond)
	}
	if len(cs.Status.Packages) != 1 || res.RequeueAfter != fetchRetry {
		t.Fatalf("packages = %d, requeue = %v", len(cs.Status.Packages), res.RequeueAfter)
	}

	// The package installs from the catalog, verified with its trust policy.
	ch := &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: "hello", Generation: 1},
		Spec: v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{
			Catalog: &v1alpha1.CatalogPackageRef{Source: "official", Name: "hello", Version: "0.1.0"},
		}},
	}
	if err := c.Create(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	cr := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	doReconcile(t, cr, types.NamespacedName{Name: "hello"})
	got := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
	if cond := readyCondition(t, got); cond.Status != metav1.ConditionTrue || got.Status.Signer != "key "+fingerprint {
		t.Fatalf("condition = %+v, status = %+v", cond, got.Status)
	}
}

func TestCatalogSourceRefusesUntrustedIndexes(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	author, _ := newKey(t)
	_, strangerPub := newKey(t)
	reg := &fakeRegistry{}
	reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	reg.sign(t, ref, author)
	c := newClient(t, catalogSource(strangerPub))
	r := &CatalogSourceReconciler{Client: c, Registry: publishIndex(t, reg, ref, author)}
	doReconcile(t, r, types.NamespacedName{Name: "official"})
	cs := get(t, c, types.NamespacedName{Name: "official"}, &v1alpha1.CatalogSource{})
	if cond := readyConditionOf(t, cs.Status.Conditions); cond.Reason != "Untrusted" || len(cs.Status.Packages) != 0 {
		t.Fatalf("condition = %+v, packages = %d", cond, len(cs.Status.Packages))
	}
}

func TestChallengeFromCatalogRefusals(t *testing.T) {
	cases := map[string]struct {
		ref  v1alpha1.CatalogPackageRef
		want string
	}{
		"missing source":   {v1alpha1.CatalogPackageRef{Source: "nope", Name: "hello", Version: "0.1.0"}, "not found"},
		"unlisted version": {v1alpha1.CatalogPackageRef{Source: "official", Name: "hello", Version: "9.9.9"}, "not listed"},
		"other name":       {v1alpha1.CatalogPackageRef{Source: "official", Name: "other", Version: "0.1.0"}, "named after"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ch := &v1alpha1.Challenge{
				ObjectMeta: metav1.ObjectMeta{Name: "hello", Generation: 1},
				Spec:       v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{Catalog: &tc.ref}},
			}
			c := newClient(t, ch, catalogSource("unused"))
			r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: &fakeRegistry{}}
			doReconcile(t, r, types.NamespacedName{Name: "hello"})
			cond := readyCondition(t, get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{}))
			if cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, tc.want) {
				t.Fatalf("condition = %+v", cond)
			}
		})
	}
}

func readyConditionOf(t *testing.T, conds []metav1.Condition) metav1.Condition {
	t.Helper()
	for _, c := range conds {
		if c.Type == v1alpha1.ConditionReady {
			return c
		}
	}
	t.Fatalf("no Ready condition in %+v", conds)
	return metav1.Condition{}
}
