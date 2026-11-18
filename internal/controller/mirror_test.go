package controller

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
	"github.com/Sigeth/brokelabs-core-go/pkg/ocipkg"
	"github.com/Sigeth/brokelabs-operator/internal/vcluster"
)

type copied struct {
	mirror, ref string
	signatures  bool
}

type fakeCopier struct {
	copies []copied
	err    error
}

func (f *fakeCopier) Copy(_ context.Context, mirror, ref string, signatures bool) error {
	f.copies = append(f.copies, copied{mirror, ref, signatures})
	return f.err
}

const testMirror = "brokelabs-mirror.brokelabs-system.svc:5000"

func mirrorSetup(t *testing.T, ch *v1alpha1.Challenge) (*MirrorReconciler, *fakeCopier) {
	t.Helper()
	platform := &v1alpha1.PlatformConfig{ObjectMeta: metav1.ObjectMeta{Name: v1alpha1.PlatformConfigName},
		Spec: v1alpha1.PlatformConfigSpec{RegistryMirror: testMirror}}
	copier := &fakeCopier{}
	return &MirrorReconciler{Client: newClient(t, ch, platform), Copier: copier}, copier
}

// installedOCI is a challenge installed from a registry.
func installedOCI(t *testing.T) *v1alpha1.Challenge {
	t.Helper()
	const ref = "registry.example/hello:0.1.0"
	reg := &fakeRegistry{}
	pub := reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	ch := ociChallenge(ref, unsigned)
	ch.Status = v1alpha1.ChallengeStatus{Package: pub.Manifest, Digest: pub.Descriptor.Digest.String()}
	return ch
}

func TestMirrorCopiesThePackageAndItsImages(t *testing.T) {
	ch := installedOCI(t)
	r, copier := mirrorSetup(t, ch)
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)
	want := []copied{
		{testMirror, "registry.example/hello@" + ch.Status.Digest, true},
		{testMirror, pinnedImage, false},
	}
	if len(copier.copies) != 2 || copier.copies[0] != want[0] || copier.copies[1] != want[1] {
		t.Fatalf("copies = %+v, want %+v", copier.copies, want)
	}
	got := get(t, r.Client, key, &v1alpha1.Challenge{})
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionMirrored)
	if !got.Status.Mirrored || cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("status = %+v", got.Status)
	}
	// Mirrored: nothing is copied again.
	doReconcile(t, r, key)
	if len(copier.copies) != 2 {
		t.Fatalf("copied again: %+v", copier.copies)
	}
}

func TestMirrorFailuresAreRetried(t *testing.T) {
	ch := installedOCI(t)
	r, copier := mirrorSetup(t, ch)
	copier.err = errors.New("no space left on device")
	res := doReconcile(t, r, types.NamespacedName{Name: "hello"})
	got := get(t, r.Client, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionMirrored)
	if got.Status.Mirrored || cond == nil || cond.Reason != "MirrorFailed" || res.RequeueAfter != mirrorRetry {
		t.Fatalf("status = %+v, requeue = %v", got.Status, res.RequeueAfter)
	}
}

func TestMirrorSkipsInlinePackagesAndClustersWithoutMirror(t *testing.T) {
	ch, cm := inlineChallenge(t, testManifest)
	c := newClient(t, ch, cm, &v1alpha1.PlatformConfig{ObjectMeta: metav1.ObjectMeta{Name: v1alpha1.PlatformConfigName},
		Spec: v1alpha1.PlatformConfigSpec{RegistryMirror: testMirror}})
	doReconcile(t, &ChallengeReconciler{Client: c, Config: testConfig}, types.NamespacedName{Name: "hello"})
	copier := &fakeCopier{}
	doReconcile(t, &MirrorReconciler{Client: c, Copier: copier}, types.NamespacedName{Name: "hello"})
	got := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
	if cond := meta.FindStatusCondition(got.Status.Conditions, ConditionMirrored); len(copier.copies) != 0 || cond == nil || cond.Reason != "NotMirrored" {
		t.Fatalf("copies = %v, conditions = %+v", copier.copies, got.Status.Conditions)
	}

	// Without a mirror, nothing happens.
	r, copier2 := mirrorSetup(t, installedOCI(t))
	platform := get(t, r.Client, types.NamespacedName{Name: v1alpha1.PlatformConfigName}, &v1alpha1.PlatformConfig{})
	platform.Spec.RegistryMirror = ""
	if err := r.Update(context.Background(), platform); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, types.NamespacedName{Name: "hello"})
	if len(copier2.copies) != 0 {
		t.Fatalf("copies = %v", copier2.copies)
	}
}

func TestANewVersionIsMirroredAgain(t *testing.T) {
	const ref = "registry.example/hello:0.1.0"
	reg := &fakeRegistry{}
	reg.publish(t, ref, strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), helloFiles)
	ch := ociChallenge(ref, unsigned)
	c := newClient(t, ch)
	r := &ChallengeReconciler{Client: c, Config: testConfig, Registry: reg}
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)
	got := get(t, c, key, &v1alpha1.Challenge{})
	got.Status.Mirrored = true
	if err := c.Status().Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key) // same digest: stays mirrored
	if got = get(t, c, key, &v1alpha1.Challenge{}); !got.Status.Mirrored {
		t.Fatal("the same version must stay mirrored")
	}

	reg.publish(t, ref, strings.Replace(strings.Replace(testManifest, "debian:13-slim", pinnedImage, 1), "0.1.0", "0.2.0", 1), helloFiles)
	got.Generation = 2
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	if got = get(t, c, key, &v1alpha1.Challenge{}); got.Status.Mirrored {
		t.Fatal("a new version must be mirrored again")
	}
}

func TestMirrorRef(t *testing.T) {
	got, err := MirrorRef(testMirror, pinnedImage)
	if err != nil || got != testMirror+"/docker.io/library/debian@"+pinnedImage[strings.Index(pinnedImage, "@")+1:] {
		t.Fatalf("MirrorRef = %q, %v", got, err)
	}
	withPort, _ := MirrorRef(testMirror, "registry.school:5000/x/y@"+pinnedImage[strings.Index(pinnedImage, "@")+1:])
	if !strings.HasPrefix(withPort, testMirror+"/registry.school_5000/x/y@") {
		t.Fatalf("MirrorRef = %q", withPort)
	}
	if _, err := MirrorRef(testMirror, "ghcr.io/x/y:1.0"); err == nil {
		t.Fatal("tags must not be mirrored")
	}
}

// TestRemoteCopier copies a real image into a test registry:
// BROKELABS_TEST_MIRROR=127.0.0.1:5057 BROKELABS_TEST_MIRROR_AUTH=user:password BROKELABS_TEST_IMAGE=ghcr.io/...@sha256:...
func TestRemoteCopier(t *testing.T) {
	mirror, image := os.Getenv("BROKELABS_TEST_MIRROR"), os.Getenv("BROKELABS_TEST_IMAGE")
	if mirror == "" || image == "" {
		t.Skip("set BROKELABS_TEST_MIRROR and BROKELABS_TEST_IMAGE")
	}
	user, password, _ := strings.Cut(os.Getenv("BROKELABS_TEST_MIRROR_AUTH"), ":")
	c := RemoteCopier{Mirror: ocipkg.Remote{
		PlainHTTP: func(string) bool { return true },
		Credential: func(context.Context, string) (auth.Credential, error) {
			return auth.Credential{Username: user, Password: password}, nil
		},
	}}
	if err := c.Copy(context.Background(), mirror, image, false); err != nil {
		t.Fatal(err)
	}
	target, _ := MirrorRef(mirror, image)
	if _, err := c.Mirror.Resolve(context.Background(), target); err != nil {
		t.Fatalf("%s: %v", target, err)
	}
}

func TestMirrorCopiesVClusterImages(t *testing.T) {
	ch := installedOCI(t)
	ch.Status.Package.Spec.Machines = append(ch.Status.Package.Spec.Machines,
		v1alpha1.Machine{Name: "cluster", Runtime: v1alpha1.RuntimeVCluster, Kubernetes: "1.34"})
	r, copier := mirrorSetup(t, ch)
	doReconcile(t, r, types.NamespacedName{Name: "hello"})
	var refs []string
	for _, c := range copier.copies {
		refs = append(refs, c.ref)
	}
	for _, want := range vcluster.Images("1.34") {
		if !slices.Contains(refs, want) {
			t.Errorf("%s not mirrored: %v", want, refs)
		}
	}
}
