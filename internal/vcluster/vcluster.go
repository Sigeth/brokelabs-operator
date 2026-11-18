// Package vcluster renders the virtual clusters of vcluster machines (D48)
// from the open-source vcluster chart, embedded at a pinned version. The
// operator creates the rendered objects itself (no Helm release): instances
// never change after creation and their namespace holds everything.
package vcluster

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"helm.sh/helm/v4/pkg/chart/common"
	"helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/engine"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// ChartVersion is the vcluster chart embedded in the operator.
const ChartVersion = "0.37.7"

//go:embed chart/vcluster-0.37.7.tgz
var chartArchive []byte

// Kubernetes maps the Kubernetes versions a package may ask for to the
// images of the chart's k8s distro.
// 1.37 waits for a vcluster release supporting it: up to 0.38.0, vcluster
// disables the cloud-node-lifecycle controller, which kube-controller-manager
// 1.37 no longer knows, and the control plane crashes (tested 2026-11-18).
// The host cluster may run any version: the virtual one is independent.
var Kubernetes = map[string]string{
	"1.33": "v1.33.13",
	"1.34": "v1.34.13",
	"1.35": "v1.35.10",
	"1.36": "v1.36.6",
}

// DefaultKubernetes is used when a package sets no version.
const DefaultKubernetes = "1.36"

// Images of a virtual cluster, pinned so that the registry mirror can hold
// them (the Kubernetes image depends on the version).
const (
	ControlPlaneImage = "ghcr.io/loft-sh/vcluster-oss:" + ChartVersion
	KubernetesImage   = "ghcr.io/loft-sh/kubernetes"
	CoreDNSImage      = "docker.io/coredns/coredns:1.14.1"
)

// Images lists the images of a virtual cluster running a Kubernetes version
// (DefaultKubernetes when empty), or nil when the version is not supported.
func Images(kubernetes string) []string {
	if kubernetes == "" {
		kubernetes = DefaultKubernetes
	}
	tag, ok := Kubernetes[kubernetes]
	if !ok {
		return nil
	}
	return []string{ControlPlaneImage, KubernetesImage + ":" + tag, CoreDNSImage}
}

// Port is where the control plane serves the virtual API (the Service maps
// 443 to it).
const Port = 8443

// What the control plane and CoreDNS take out of the machine's budget; the
// rest is left to the student's workloads.
var (
	ControlPlaneCPU              = resource.MustParse("750m")
	ControlPlaneCPURequest       = resource.MustParse("200m")
	ControlPlaneMemory           = resource.MustParse("768Mi")
	CoreDNSCPU                   = resource.MustParse("100m")
	CoreDNSCPURequest            = resource.MustParse("20m")
	CoreDNSMemory                = resource.MustParse("128Mi")
	controlPlaneUID        int64 = 12345
	coreDNSUID             int64 = 1001
)

// Options describe one virtual cluster.
type Options struct {
	// Release names the objects, like a Helm release: the machine name.
	Release   string
	Namespace string
	// Kubernetes is a key of Kubernetes (DefaultKubernetes when empty).
	Kubernetes string
	// HostMinor is the minor version of the host cluster (templates depend on it).
	HostMinor int
	// PodLabels are added to the control plane pod.
	PodLabels map[string]string
	// ExtraSANs are more names the API certificate is valid for.
	ExtraSANs []string
}

// ServiceAccount is the account of the control plane of a release, which
// the operator binds to the vcluster role in the instance namespace.
func ServiceAccount(release string) string { return "vc-" + release }

// KubeconfigSecret is where vcluster writes its admin kubeconfig (key
// "config"), once the control plane runs.
func KubeconfigSecret(release string) string { return "vc-" + release }

// Render returns the objects of a virtual cluster, without the chart's Role
// and RoleBinding: the operator binds the vcluster ClusterRole instead.
func Render(o Options) ([]*unstructured.Unstructured, error) {
	k8s := o.Kubernetes
	if k8s == "" {
		k8s = DefaultKubernetes
	}
	tag, ok := Kubernetes[k8s]
	if !ok {
		return nil, fmt.Errorf("kubernetes %s is not supported (supported: %s)", k8s, strings.Join(Supported(), ", "))
	}
	return render(o, values(o, tag, false))
}

// RoleRules are the namespaced permissions the control plane needs, as the
// chart grants them: the operator's manifests turn them into a ClusterRole.
func RoleRules() ([]rbacv1.PolicyRule, error) {
	o := Options{Release: "rules", Namespace: "rules", HostMinor: 36}
	objs, err := render(o, values(o, Kubernetes[DefaultKubernetes], true))
	if err != nil {
		return nil, err
	}
	for _, obj := range objs {
		if obj.GetKind() == "Role" {
			var role rbacv1.Role
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &role); err != nil {
				return nil, err
			}
			return role.Rules, nil
		}
	}
	return nil, fmt.Errorf("the chart rendered no Role")
}

// Supported lists the Kubernetes versions, oldest first.
func Supported() []string { return slices.Sorted(maps.Keys(Kubernetes)) }

// values hardens the chart's defaults: the open-source image, no volume
// claim (instances are ephemeral), no cluster-scoped RBAC or sync, NetworkPolicy
// sync on, non-root control plane and CoreDNS, no telemetry.
func values(o Options, tag string, role bool) map[string]any {
	restricted := func(uid int64) map[string]any {
		return map[string]any{
			"allowPrivilegeEscalation": false,
			"runAsNonRoot":             true,
			"runAsUser":                uid,
			"runAsGroup":               uid,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
			"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
		}
	}
	podSecurity := func(uid int64) map[string]any {
		return map[string]any{
			"runAsNonRoot":   true,
			"runAsUser":      uid,
			"runAsGroup":     uid,
			"fsGroup":        uid,
			"seccompProfile": map[string]any{"type": "RuntimeDefault"},
		}
	}
	resources := func(cpu, cpuRequest, memory resource.Quantity) map[string]any {
		return map[string]any{
			"limits":   map[string]any{"cpu": cpu.String(), "memory": memory.String()},
			"requests": map[string]any{"cpu": cpuRequest.String(), "memory": memory.String()},
		}
	}
	coreDNSContainer := restricted(coreDNSUID)
	coreDNSContainer["capabilities"] = map[string]any{"drop": []any{"ALL"}, "add": []any{"NET_BIND_SERVICE"}}
	podLabels := map[string]any{}
	for k, v := range o.PodLabels {
		podLabels[k] = v
	}
	sans := make([]any, 0, len(o.ExtraSANs))
	for _, s := range o.ExtraSANs {
		sans = append(sans, s)
	}
	return map[string]any{
		"controlPlane": map[string]any{
			"distro": map[string]any{"k8s": map[string]any{
				"enabled":         true,
				"image":           map[string]any{"tag": tag},
				"securityContext": restricted(controlPlaneUID),
			}},
			"coredns": map[string]any{
				"security": map[string]any{
					"podSecurityContext":       podSecurity(coreDNSUID),
					"containerSecurityContext": coreDNSContainer,
				},
				"deployment": map[string]any{
					"image":     CoreDNSImage,
					"resources": resources(CoreDNSCPU, CoreDNSCPURequest, CoreDNSMemory),
				},
			},
			"proxy": map[string]any{"extraSANs": sans},
			"statefulSet": map[string]any{
				"image":       map[string]any{"repository": "loft-sh/vcluster-oss"},
				"persistence": map[string]any{"volumeClaim": map[string]any{"enabled": false}},
				"security": map[string]any{
					"podSecurityContext":       podSecurity(controlPlaneUID),
					"containerSecurityContext": restricted(controlPlaneUID),
				},
				"resources": resources(ControlPlaneCPU, ControlPlaneCPURequest, ControlPlaneMemory),
				"pods":      map[string]any{"labels": podLabels},
			},
		},
		"sync": map[string]any{
			"toHost": map[string]any{
				"networkPolicies":        map[string]any{"enabled": true},
				"persistentVolumeClaims": map[string]any{"enabled": false},
				"pods":                   map[string]any{"rewriteHosts": map[string]any{"enabled": false}},
			},
			"fromHost": map[string]any{"volumeSnapshotClasses": map[string]any{"enabled": false}},
		},
		"rbac": map[string]any{
			"role":        map[string]any{"enabled": role},
			"clusterRole": map[string]any{"enabled": false},
		},
		"telemetry": map[string]any{"enabled": false},
	}
}

func render(o Options, vals map[string]any) ([]*unstructured.Unstructured, error) {
	chrt, err := loader.LoadArchive(bytes.NewReader(chartArchive))
	if err != nil {
		return nil, fmt.Errorf("loading the vcluster chart: %w", err)
	}
	caps := common.DefaultCapabilities.Copy()
	caps.KubeVersion = common.KubeVersion{
		Version: fmt.Sprintf("v1.%d.0", o.HostMinor),
		Major:   "1",
		Minor:   fmt.Sprint(o.HostMinor),
	}
	rv, err := util.ToRenderValues(chrt, vals, common.ReleaseOptions{Name: o.Release, Namespace: o.Namespace, IsInstall: true}, caps)
	if err != nil {
		return nil, err
	}
	files, err := engine.Render(chrt, rv)
	if err != nil {
		return nil, fmt.Errorf("rendering the vcluster chart: %w", err)
	}
	var objs []*unstructured.Unstructured
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(files[name]), 4096)
		for {
			obj := map[string]any{}
			if err := dec.Decode(&obj); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if len(obj) == 0 {
				continue
			}
			u := &unstructured.Unstructured{Object: obj}
			if u.GetNamespace() == "" {
				u.SetNamespace(o.Namespace)
			}
			objs = append(objs, u)
		}
	}
	return objs, nil
}
