package controller

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
	"github.com/Sigeth/brokelabs-core-go/pkg/project"
	"github.com/Sigeth/brokelabs-operator/internal/vcluster"
)

// vcluster machines (D48). The operator renders the embedded vcluster chart
// into the instance namespace, binds the vcluster ClusterRole to its control
// plane, and once it runs: copies its admin kubeconfig into a Secret per
// machine (for kubeconfigFor machines and the checker), applies the seed
// manifests, then creates the machines that wait for that kubeconfig.
// The control plane keeps its state in memory: if its pod is replaced, the
// virtual cluster is lost and the instance fails.

// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=list

const (
	// RoleVCluster labels the control plane pod of a vcluster machine.
	RoleVCluster = "vcluster"
	// KubeconfigKey is the key of a kubeconfig Secret.
	KubeconfigKey = "config"
	// KubeconfigMountPath is where kubeconfigFor machines find theirs
	// (KUBECONFIG points at it), and the checker the ones of every
	// vcluster machine (one file per machine name).
	KubeconfigMountPath = "/etc/" + project.Name + "/kube"
	// vclusterMaxPods is how many pods a virtual cluster may run on the host,
	// its control plane and CoreDNS included.
	vclusterMaxPods = 30
	// seedTimeout bounds the application of the seed manifests.
	seedTimeout = 2 * time.Minute
)

// KubeconfigSecret holds the kubeconfig of a vcluster machine.
func KubeconfigSecret(machine string) string {
	return project.Name + "-kubeconfig-" + machine
}

func hasVCluster(pkg *v1alpha1.ChallengePackage) bool {
	return slices.ContainsFunc(pkg.Spec.Machines, func(m v1alpha1.Machine) bool { return m.Runtime == v1alpha1.RuntimeVCluster })
}

// vclusterAddress is the address of the virtual API server (port 443): the
// machine address, which the certificate covers through extra SANs.
func vclusterAddress(machine, ns string) string { return machineAddress(machine, ns) }

// apiServer is where the host API server listens, read from its EndpointSlices.
type apiServer struct {
	ip   string
	port int32
}

// hostAPIServers lists the host API server endpoints: vcluster control planes
// may only reach these (D51).
func hostAPIServers(ctx context.Context, c client.Reader) ([]apiServer, error) {
	var slices discoveryv1.EndpointSliceList
	if err := c.List(ctx, &slices, client.InNamespace(metav1.NamespaceDefault),
		client.MatchingLabels{discoveryv1.LabelServiceName: "kubernetes"}); err != nil {
		return nil, err
	}
	var out []apiServer
	for _, s := range slices.Items {
		for _, p := range s.Ports {
			if p.Port == nil {
				continue
			}
			for _, e := range s.Endpoints {
				for _, ip := range e.Addresses {
					out = append(out, apiServer{ip: ip, port: *p.Port})
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no endpoint for the host API server")
	}
	return out, nil
}

// vclusterResources renders the objects of the vcluster machines of a package,
// with the RoleBinding of their control plane and their network policies.
func vclusterResources(cfg Config, inst *v1alpha1.ChallengeInstance, pkg *v1alpha1.ChallengePackage, apiServers []apiServer) ([]client.Object, error) {
	ns := InstanceNamespace(inst.Name)
	labels := instanceLabels(inst)
	var objs []client.Object
	for _, m := range pkg.Spec.Machines {
		if m.Runtime != v1alpha1.RuntimeVCluster {
			continue
		}
		podLabels := withLabels(withLabels(instanceLabels(inst), LabelMachine, m.Name), LabelRole, RoleVCluster)
		addr := vclusterAddress(m.Name, ns)
		rendered, err := vcluster.Render(vcluster.Options{
			Release:    m.Name,
			Namespace:  ns,
			Kubernetes: m.Kubernetes,
			HostMinor:  cfg.HostMinor,
			PodLabels:  podLabels,
			ExtraSANs:  []string{addr, addr + ".cluster.local"},
		})
		if err != nil {
			return nil, fmt.Errorf("machine %s: %w", m.Name, err)
		}
		for _, obj := range rendered {
			l := obj.GetLabels()
			if l == nil {
				l = map[string]string{}
			}
			for k, v := range labels {
				l[k] = v
			}
			obj.SetLabels(withLabels(l, LabelMachine, m.Name))
			objs = append(objs, obj)
		}
		meta := metav1.ObjectMeta{Name: project.Name + "-vcluster-" + m.Name, Namespace: ns, Labels: labels}
		objs = append(objs,
			roleBinding(meta, cfg.VClusterRole, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: vcluster.ServiceAccount(m.Name), Namespace: ns}),
			&networkingv1.NetworkPolicy{ObjectMeta: meta, Spec: controlPlaneNetworkPolicy(cfg, m.Name, apiServers)},
		)
	}
	if len(objs) > 0 {
		objs = append(objs, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: project.Name + "-vcluster-workloads", Namespace: ns, Labels: labels},
			Spec:       workloadsNetworkPolicy(),
		})
	}
	return objs, nil
}

// controlPlaneNetworkPolicy lets the namespace's pods and the operator (seed)
// reach a control plane, and the control plane reach only the host API
// server and the namespace's pods (its CoreDNS, and the webhooks or API
// services the student runs: D51).
func controlPlaneNetworkPolicy(cfg Config, machine string, apiServers []apiServer) networkingv1.NetworkPolicySpec {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(vcluster.Port)
	namespacePods := networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{}}
	from := []networkingv1.NetworkPolicyPeer{namespacePods}
	if len(cfg.OperatorPods) > 0 {
		from = append(from, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": cfg.SystemNamespace}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: cfg.OperatorPods},
		})
	}
	egress := []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{namespacePods}}}
	for _, s := range apiServers {
		p := intstr.FromInt32(s.port)
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: hostCIDR(s.ip)}}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &p}},
		})
	}
	return networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{LabelMachine: machine, LabelRole: RoleVCluster}},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From:  from,
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
		}},
		Egress: egress,
	}
}

// workloadsNetworkPolicy keeps the pods synced from virtual clusters inside
// the namespace. The student's own policies can only narrow it (D51).
func workloadsNetworkPolicy() networkingv1.NetworkPolicySpec {
	namespacePods := []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}
	return networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "vcluster.loft.sh/managed-by", Operator: metav1.LabelSelectorOpExists,
		}}},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: namespacePods}},
		Egress:      []networkingv1.NetworkPolicyEgressRule{{To: namespacePods}},
	}
}

func hostCIDR(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

// kubeconfigVolume mounts the kubeconfig of a vcluster machine into a
// kubeconfigFor machine.
func kubeconfigVolume(m v1alpha1.Machine) (corev1.Volume, corev1.VolumeMount, corev1.EnvVar) {
	return corev1.Volume{Name: "kubeconfig", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: KubeconfigSecret(m.KubeconfigFor),
			Items:      []corev1.KeyToPath{{Key: KubeconfigKey, Path: KubeconfigKey}},
		}}},
		corev1.VolumeMount{Name: "kubeconfig", MountPath: KubeconfigMountPath, ReadOnly: true},
		corev1.EnvVar{Name: "KUBECONFIG", Value: KubeconfigMountPath + "/" + KubeconfigKey}
}

// checkerKubeconfigs mounts the kubeconfig of every vcluster machine into the
// checker, one file per machine.
func checkerKubeconfigs(machines []string) corev1.Volume {
	var sources []corev1.VolumeProjection
	for _, m := range machines {
		sources = append(sources, corev1.VolumeProjection{Secret: &corev1.SecretProjection{
			LocalObjectReference: corev1.LocalObjectReference{Name: KubeconfigSecret(m)},
			Items:                []corev1.KeyToPath{{Key: KubeconfigKey, Path: m}},
		}})
	}
	return corev1.Volume{Name: "kubeconfig", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: sources}}}
}

func vclusterNames(pkg *v1alpha1.ChallengePackage) []string {
	var names []string
	for _, m := range pkg.Spec.Machines {
		if m.Runtime == v1alpha1.RuntimeVCluster {
			names = append(names, m.Name)
		}
	}
	return names
}

// vclusterQuota is what the vcluster machines add to the namespace's pod count.
func vclusterQuota(pkg *v1alpha1.ChallengePackage) resource.Quantity {
	return *resource.NewQuantity(int64(len(vclusterNames(pkg))*vclusterMaxPods), resource.DecimalSI)
}

// vclusterMachine reports whether a virtual cluster is ready: its control
// plane runs, its kubeconfig is stored and its seed applied.
func (r *ChallengeInstanceReconciler) vclusterMachine(ctx context.Context, inst *v1alpha1.ChallengeInstance, m v1alpha1.Machine, pkg *v1alpha1.ChallengePackage) (bool, string, error) {
	ns := inst.Status.Namespace
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{LabelMachine: m.Name, LabelRole: RoleVCluster}); err != nil {
		return false, "", err
	}
	var pod *corev1.Pod
	for i := range pods.Items {
		if pods.Items[i].DeletionTimestamp.IsZero() {
			pod = &pods.Items[i]
		}
	}
	if pod == nil {
		if inst.Status.Phase == v1alpha1.InstanceReady {
			return false, "", &fatalError{fmt.Sprintf("machine %s: the control plane is gone, with the virtual cluster", m.Name)}
		}
		return false, "creating", nil
	}
	if pod.Annotations[AnnotationSetupDone] == string(pod.UID) {
		return podReady(pod), "restarting", nil
	}
	if inst.Status.Phase == v1alpha1.InstanceReady {
		return false, "", &fatalError{fmt.Sprintf("machine %s: the control plane was replaced, losing the virtual cluster", m.Name)}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if problem := waitingProblem(cs); problem != "" {
			return false, problem, nil
		}
	}
	if !podReady(pod) {
		return false, "starting", nil
	}

	kubeconfig, err := r.storeKubeconfig(ctx, ns, m.Name)
	if err != nil || kubeconfig == nil {
		return false, "starting", err
	}
	if len(m.Seed) > 0 {
		files, err := r.packageFiles(ctx, ns)
		if err != nil {
			return false, "", err
		}
		docs, err := seedDocuments(files, m.Seed)
		if err != nil {
			return false, "", &fatalError{fmt.Sprintf("machine %s: seed: %v", m.Name, err)}
		}
		restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
		if err != nil {
			return false, "", err
		}
		log.FromContext(ctx).Info("applying seed", "machine", m.Name, "objects", len(docs))
		sctx, cancel := context.WithTimeout(ctx, seedTimeout)
		err = applySeed(sctx, restConfig, docs)
		cancel()
		if err != nil {
			var fatal *fatalError
			if errors.As(err, &fatal) {
				return false, "", &fatalError{fmt.Sprintf("machine %s: seed: %s", m.Name, fatal.msg)}
			}
			return false, "", fmt.Errorf("machine %s: seed: %w", m.Name, err)
		}
	}
	patch := client.MergeFrom(pod.DeepCopy())
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationSetupDone] = string(pod.UID)
	return true, "", r.Patch(ctx, pod, patch)
}

// createKubeconfigMachine creates the pod of a kubeconfigFor machine once the
// kubeconfig of its virtual cluster is stored, and reports whether it did.
func (r *ChallengeInstanceReconciler) createKubeconfigMachine(ctx context.Context, inst *v1alpha1.ChallengeInstance, m v1alpha1.Machine) (bool, error) {
	ns := inst.Status.Namespace
	err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: ns, Name: KubeconfigSecret(m.KubeconfigFor)}, &corev1.Secret{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pod := machinePod(metav1.ObjectMeta{Name: m.Name, Namespace: ns, Labels: instanceLabels(inst)}, m)
	if err := r.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
		return false, err
	}
	return true, nil
}

func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// storeKubeconfig copies the admin kubeconfig vcluster wrote into the Secret
// of the machine, pointing at the machine address with the default namespace.
// It returns nil until vcluster has written it.
func (r *ChallengeInstanceReconciler) storeKubeconfig(ctx context.Context, ns, machine string) ([]byte, error) {
	var stored corev1.Secret
	err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: ns, Name: KubeconfigSecret(machine)}, &stored)
	if err == nil {
		return stored.Data[KubeconfigKey], nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	var admin corev1.Secret
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: ns, Name: vcluster.KubeconfigSecret(machine)}, &admin); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	cfg, err := clientcmd.Load(admin.Data[KubeconfigKey])
	if err != nil {
		return nil, fmt.Errorf("machine %s: reading the vcluster kubeconfig: %w", machine, err)
	}
	server := "https://" + vclusterAddress(machine, ns) + ":443"
	for _, c := range cfg.Clusters {
		c.Server = server
	}
	for _, c := range cfg.Contexts {
		c.Namespace = metav1.NamespaceDefault
	}
	data, err := clientcmd.Write(*cfg)
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: KubeconfigSecret(machine), Namespace: ns, Labels: admin.Labels},
		Data:       map[string][]byte{KubeconfigKey: data},
	}
	if err := r.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	return data, nil
}

// seedDocuments reads the seed manifests: files, or every .yaml, .yml and
// .json file under a directory, in path order.
func seedDocuments(files fs.FS, seed []string) ([][]byte, error) {
	var docs [][]byte
	for _, entry := range seed {
		entry = path.Clean(strings.TrimPrefix(entry, "./"))
		var paths []string
		err := fs.WalkDir(files, entry, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch path.Ext(p) {
			case ".yaml", ".yml", ".json":
				paths = append(paths, p)
			default:
				if p == entry {
					paths = append(paths, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		slices.Sort(paths)
		for _, p := range paths {
			content, err := fs.ReadFile(files, p)
			if err != nil {
				return nil, err
			}
			docs = append(docs, splitYAML(content)...)
		}
	}
	return docs, nil
}

// splitYAML splits a multi-document YAML file, dropping empty documents.
func splitYAML(content []byte) [][]byte {
	var docs [][]byte
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(content)))
	for {
		doc, err := reader.Read()
		if err != nil {
			return docs
		}
		if strings.TrimSpace(stripComments(string(doc))) != "" {
			docs = append(docs, doc)
		}
	}
}

func stripComments(doc string) string {
	var b strings.Builder
	for _, line := range strings.Split(doc, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") && t != "---" {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// applySeed applies manifests to a virtual cluster with server-side apply.
// Objects whose kind is unknown yet (custom resources of a CRD in the seed)
// are retried after the others, a few times.
func applySeed(ctx context.Context, cfg *rest.Config, docs [][]byte) error {
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	pending := make([]*unstructured.Unstructured, 0, len(docs))
	for i, doc := range docs {
		obj := &unstructured.Unstructured{}
		if err := utilyaml.Unmarshal(doc, &obj.Object); err != nil {
			return &fatalError{fmt.Sprintf("document %d: %v", i+1, err)}
		}
		if obj.GetKind() == "" || obj.GetAPIVersion() == "" {
			return &fatalError{fmt.Sprintf("document %d has no apiVersion or kind", i+1)}
		}
		pending = append(pending, obj)
	}
	for attempt := 0; len(pending) > 0; attempt++ {
		var unknown []*unstructured.Unstructured
		for _, obj := range pending {
			gvk := obj.GroupVersionKind()
			mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
			if meta.IsNoMatchError(err) {
				unknown = append(unknown, obj)
				continue
			}
			if err != nil {
				return err
			}
			var res dynamic.ResourceInterface = dyn.Resource(mapping.Resource)
			if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
				if obj.GetNamespace() == "" {
					obj.SetNamespace(metav1.NamespaceDefault)
				}
				res = dyn.Resource(mapping.Resource).Namespace(obj.GetNamespace())
			}
			_, err = res.Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{FieldManager: project.Name, Force: true})
			switch {
			case apierrors.IsInvalid(err) || apierrors.IsBadRequest(err):
				return &fatalError{fmt.Sprintf("%s %s: %v", gvk.Kind, obj.GetName(), err)}
			case err != nil:
				return fmt.Errorf("%s %s: %w", gvk.Kind, obj.GetName(), err)
			}
		}
		if len(unknown) == len(pending) && attempt >= 5 {
			var kinds []string
			for _, obj := range unknown {
				kinds = append(kinds, obj.GetAPIVersion()+" "+obj.GetKind())
			}
			return &fatalError{"unknown kinds: " + strings.Join(kinds, ", ")}
		}
		pending = unknown
		if len(pending) > 0 {
			mapper.Reset()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil
}
