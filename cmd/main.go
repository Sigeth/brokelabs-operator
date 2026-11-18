// Command operator runs the BrokeLabs controllers.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
	"github.com/Sigeth/brokelabs-core-go/pkg/kubeexec"
	"github.com/Sigeth/brokelabs-core-go/pkg/ocipkg"
	"github.com/Sigeth/brokelabs-core-go/pkg/project"
	"github.com/Sigeth/brokelabs-core-go/pkg/sshexec"
	"github.com/Sigeth/brokelabs-operator/internal/controller"
)

func main() {
	var (
		metricsAddr       string
		probeAddr         string
		leaderElect       bool
		gateway           string
		operatorPods      string
		gatewayPods       string
		plainHTTP         string
		trustedRoot       string
		mirrorCredentials string
		cfg               controller.Config
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address of the metrics endpoint; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address of the health and readiness probes.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election (required with several replicas).")
	flag.StringVar(&cfg.SystemNamespace, "system-namespace", os.Getenv("POD_NAMESPACE"), "Namespace of the operator, holding inline package files (default: $POD_NAMESPACE).")
	flag.StringVar(&cfg.CheckerImage, "checker-image", project.ImageRegistry+"/"+project.Name+"-checker:latest", "Image of the built-in checker.")
	flag.StringVar(&gateway, "gateway-service-account", project.Name+"-system/"+project.Name+"-gateway", "Service account of the gateway (namespace/name), allowed to open terminals.")
	flag.StringVar(&cfg.GatewayExecRole, "gateway-exec-role", project.Name+"-gateway-exec", "ClusterRole bound to the gateway in instance namespaces.")
	flag.StringVar(&cfg.CheckerExecRole, "checker-exec-role", project.Name+"-checker-exec", "ClusterRole bound to the checker in instance namespaces.")
	flag.StringVar(&cfg.VClusterRole, "vcluster-role", project.Name+"-vcluster", "ClusterRole bound to the control plane of vcluster machines in instance namespaces.")
	flag.StringVar(&operatorPods, "operator-pod-labels", "app.kubernetes.io/name=operator", "Labels of the operator's pods (k=v,...), allowed to reach vm machines over SSH.")
	flag.StringVar(&gatewayPods, "gateway-pod-labels", "app.kubernetes.io/name=gateway", "Labels of the gateway's pods (k=v,...), allowed to reach vm machines over SSH.")
	flag.StringVar(&plainHTTP, "plain-http-registries", "", "Registries reached over plain HTTP (host:port,...), for local test registries only.")
	flag.StringVar(&trustedRoot, "sigstore-trusted-root", "", "Sigstore trusted root (JSON) verifying keyless signatures, for air-gapped installs. Default: fetched from the Sigstore public-good TUF repository when first needed.")
	flag.StringVar(&mirrorCredentials, "mirror-credentials", "", "Directory with the push credentials of the registry mirror (files \"username\" and \"password\"), read at every copy.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	if cfg.SystemNamespace == "" {
		must(fmt.Errorf("--system-namespace or $POD_NAMESPACE is required"), "reading flags")
	}
	ns, name, ok := strings.Cut(gateway, "/")
	if !ok {
		must(fmt.Errorf("--gateway-service-account must be namespace/name, got %q", gateway), "reading flags")
	}
	cfg.Gateway = types.NamespacedName{Namespace: ns, Name: name}
	pods, err := labels.ConvertSelectorToLabelsMap(operatorPods)
	must(err, "reading --operator-pod-labels")
	cfg.OperatorPods = pods
	if cfg.GatewayPods, err = labels.ConvertSelectorToLabelsMap(gatewayPods); err != nil {
		must(err, "reading --gateway-pod-labels")
	}

	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme), "registering Kubernetes types")
	must(v1alpha1.AddToScheme(scheme), "registering BrokeLabs types")
	must(kubevirtv1.AddToScheme(scheme), "registering KubeVirt types")

	restConfig := ctrl.GetConfigOrDie()
	cfg.Runtimes = []v1alpha1.Runtime{v1alpha1.RuntimePod}
	kubevirt, err := hasKubeVirt(restConfig)
	must(err, "detecting KubeVirt")
	if kubevirt {
		cfg.Runtimes = append(cfg.Runtimes, v1alpha1.RuntimeVM)
	}
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "operator." + project.APIGroup,
		Cache:                  cacheOptions(cfg.SystemNamespace, kubevirt),
	})
	must(err, "creating manager")

	exec, err := kubeexec.New(restConfig)
	must(err, "creating the exec client")
	clientset, err := kubernetes.NewForConfig(restConfig)
	must(err, "creating the Kubernetes client")
	policies, err := hasAdmissionPolicies(context.Background(), clientset)
	must(err, "detecting the platform admission policies")
	if policies {
		cfg.Runtimes = append(cfg.Runtimes, v1alpha1.RuntimeUserns, v1alpha1.RuntimeVCluster)
	} else {
		log.Info("platform admission policies not found: userns and vcluster runtimes disabled",
			"policies", []string{v1alpha1.UserNamespacesPolicy, v1alpha1.NetworkPoliciesPolicy})
	}
	version, err := clientset.Discovery().ServerVersion()
	must(err, "reading the Kubernetes version")
	cfg.HostMinor, err = strconv.Atoi(strings.TrimRight(version.Minor, "+"))
	must(err, "reading the Kubernetes minor version "+version.Minor)

	plainHTTPRegistries := strings.Split(plainHTTP, ",")
	registry := controller.RemoteRegistry{Remote: ocipkg.Remote{
		PlainHTTP: func(host string) bool { return host != "" && slices.Contains(plainHTTPRegistries, host) },
	}}
	trustedRootLoader := controller.SigstoreTrustedRoot(trustedRoot)
	// The mirror is reached in the cluster over plain HTTP, with push
	// credentials; pulls are pinned by digest, so nothing it serves can be
	// swapped.
	copier := controller.RemoteCopier{Upstream: registry.Remote, Mirror: ocipkg.Remote{
		PlainHTTP: func(string) bool { return true },
		Credential: func(context.Context, string) (auth.Credential, error) {
			if mirrorCredentials == "" {
				return auth.EmptyCredential, nil
			}
			user, err := os.ReadFile(filepath.Join(mirrorCredentials, "username"))
			if err != nil {
				return auth.EmptyCredential, err
			}
			password, err := os.ReadFile(filepath.Join(mirrorCredentials, "password"))
			if err != nil {
				return auth.EmptyCredential, err
			}
			return auth.Credential{Username: strings.TrimSpace(string(user)), Password: strings.TrimSpace(string(password))}, nil
		},
	}}
	must((&controller.MirrorReconciler{Client: mgr.GetClient(), Copier: copier}).SetupWithManager(mgr), "setting up the mirror controller")
	must((&controller.CatalogSourceReconciler{Client: mgr.GetClient(), Registry: registry, TrustedRoot: trustedRootLoader}).
		SetupWithManager(mgr), "setting up CatalogSource controller")
	must((&controller.ChallengeReconciler{Client: mgr.GetClient(), Config: cfg, Registry: registry,
		TrustedRoot: trustedRootLoader}).SetupWithManager(mgr), "setting up Challenge controller")
	must((&controller.ChallengeInstanceReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg, Exec: exec, SSH: sshexec.New(),
	}).SetupWithManager(mgr), "setting up ChallengeInstance controller")
	must((&controller.CheckRunReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg, Logs: podLogs{clientset},
	}).SetupWithManager(mgr), "setting up CheckRun controller")

	must(mgr.AddHealthzCheck("healthz", healthz.Ping), "adding health check")
	must(mgr.AddReadyzCheck("readyz", healthz.Ping), "adding readiness check")

	log.Info("starting operator", "systemNamespace", cfg.SystemNamespace, "checkerImage", cfg.CheckerImage, "runtimes", cfg.Runtimes)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager stopped")
		os.Exit(1)
	}
}

// hasKubeVirt reports whether KubeVirt serves VirtualMachineInstances. It is
// checked once: installing KubeVirt later needs an operator restart.
func hasKubeVirt(config *rest.Config) (bool, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return false, err
	}
	list, err := dc.ServerResourcesForGroupVersion(kubevirtv1.SchemeGroupVersion.String())
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, r := range list.APIResources {
		if r.Name == "virtualmachineinstances" {
			return true, nil
		}
	}
	return false, nil
}

// hasAdmissionPolicies reports whether the chart installed the admission
// policies root runtimes need: the user namespace policies (D50), without
// which their namespaces would enforce only the baseline Pod Security
// Standard, and the network policy guard (D51). Every policy and binding must
// exist.
func hasAdmissionPolicies(ctx context.Context, cs kubernetes.Interface) (bool, error) {
	ar, opts := cs.AdmissionregistrationV1(), metav1.GetOptions{}
	userns, netpol := v1alpha1.UserNamespacesPolicy, v1alpha1.NetworkPoliciesPolicy
	_, mutating := ar.MutatingAdmissionPolicies().Get(ctx, userns, opts)
	_, mutatingBinding := ar.MutatingAdmissionPolicyBindings().Get(ctx, userns, opts)
	_, validating := ar.ValidatingAdmissionPolicies().Get(ctx, userns, opts)
	_, validatingBinding := ar.ValidatingAdmissionPolicyBindings().Get(ctx, userns, opts)
	_, network := ar.ValidatingAdmissionPolicies().Get(ctx, netpol, opts)
	_, networkBinding := ar.ValidatingAdmissionPolicyBindings().Get(ctx, netpol, opts)
	for _, err := range []error{mutating, mutatingBinding, validating, validatingBinding, network, networkBinding} {
		if apierrors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}
	}
	return true, nil
}

// cacheOptions keeps only BrokeLabs objects in memory: instance pods and VMs,
// checker jobs, and the ConfigMaps of the operator namespace.
func cacheOptions(systemNamespace string, kubevirt bool) cache.Options {
	has := func(key string) labels.Selector {
		req, err := labels.NewRequirement(key, selection.Exists, nil)
		must(err, "building a label selector")
		return labels.NewSelector().Add(*req)
	}
	byObject := map[client.Object]cache.ByObject{
		&corev1.Pod{}:       {Label: has(controller.LabelInstance)},
		&batchv1.Job{}:      {Label: has(controller.LabelCheckRun)},
		&corev1.ConfigMap{}: {Namespaces: map[string]cache.Config{systemNamespace: {}}},
	}
	if kubevirt {
		byObject[&kubevirtv1.VirtualMachineInstance{}] = cache.ByObject{Label: has(controller.LabelInstance)}
	}
	return cache.Options{ByObject: byObject}
}

// podLogs reads container logs through the API server.
type podLogs struct{ client kubernetes.Interface }

func (p podLogs) Logs(ctx context.Context, namespace, pod, container string) (string, error) {
	limit := int64(1 << 20)
	data, err := p.client.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, LimitBytes: &limit}).DoRaw(ctx)
	return string(data), err
}

func must(err error, what string) {
	if err != nil {
		ctrl.Log.WithName("setup").Error(err, what)
		os.Exit(1)
	}
}
