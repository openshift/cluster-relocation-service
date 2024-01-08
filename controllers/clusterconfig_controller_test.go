package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"

	bmh_v1alpha1 "github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift-kni/lifecycle-agent/ibu-imager/clusterinfo"
	relocationv1alpha1 "github.com/openshift/cluster-relocation-service/api/v1alpha1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Reconcile", func() {
	var (
		c               client.Client
		dataDir         string
		r               *ClusterConfigReconciler
		ctx             = context.Background()
		configName      = "test-config"
		configNamespace = "test-namespace"
	)

	BeforeEach(func() {
		c = fakeclient.NewClientBuilder().
			WithScheme(scheme.Scheme).
			WithStatusSubresource(&relocationv1alpha1.ClusterConfig{}).
			Build()
		var err error
		dataDir, err = os.MkdirTemp("", "clusterconfig_controller_test_data")
		Expect(err).NotTo(HaveOccurred())

		r = &ClusterConfigReconciler{
			Client:  c,
			Scheme:  scheme.Scheme,
			Log:     logrus.New(),
			BaseURL: "http://service.namespace",
			Options: &ClusterConfigReconcilerOptions{
				ServiceName:      "service",
				ServiceNamespace: "namespace",
				ServiceScheme:    "http",
				DataDir:          dataDir,
			},
		}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
	})

	outputFilePath := func(elem ...string) string {
		last := filepath.Join(elem...)
		return filepath.Join(dataDir, "namespaces", configNamespace, configName, "files", last)
	}

	validateExtraManifestContent := func(file string, data string) {
		content, err := os.ReadFile(outputFilePath(extraManifestsDir, file))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(content)).To(Equal(data))
	}

	It("creates the correct cluster info manifest", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				ClusterInfo: clusterinfo.ClusterInfo{
					Domain:          "example.com",
					ClusterName:     "thingcluster",
					MasterIP:        "192.0.2.1",
					ReleaseRegistry: "registry.example.com",
					Hostname:        "thing.example.com",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		content, err := os.ReadFile(outputFilePath(clusterConfigDir, "manifest.json"))
		Expect(err).NotTo(HaveOccurred())
		info := &clusterinfo.ClusterInfo{}
		Expect(json.Unmarshal(content, info)).To(Succeed())

		Expect(*info).To(Equal(config.Spec.ClusterInfo))
	})

	It("creates the pull secret", func() {
		pullSecretData := map[string][]byte{"pullsecret": []byte("pullsecret")}
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pull-secret",
				Namespace: configNamespace,
			},
			Data: pullSecretData,
		}
		Expect(c.Create(ctx, s)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				PullSecretRef: &corev1.LocalObjectReference{
					Name: "my-pull-secret",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		content, err := os.ReadFile(outputFilePath(clusterConfigDir, "manifests", "pull-secret-secret.json"))
		Expect(err).NotTo(HaveOccurred())
		secret := &corev1.Secret{}
		Expect(json.Unmarshal(content, secret)).To(Succeed())

		Expect(secret.Namespace).To(Equal("openshift-config"))
		Expect(secret.Name).To(Equal("pull-secret"))
		Expect(secret.Data).To(Equal(pullSecretData))
	})

	It("creates the ca bundle", func() {
		caData := map[string]string{caBundleFileName: "mycabundle"}
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-bundle",
				Namespace: "test-namespace",
			},
			Data: caData,
		}
		Expect(c.Create(ctx, cm)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				CABundleRef: &corev1.LocalObjectReference{
					Name: "ca-bundle",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		content, err := os.ReadFile(outputFilePath(clusterConfigDir, caBundleFileName))
		Expect(err).NotTo(HaveOccurred())

		Expect(content).To(Equal([]byte("mycabundle")))
	})

	It("creates files for referenced nmconnection files", func() {
		netConfigName := "netconfig"
		netConfigData := map[string]string{
			"eth0.nmconnection": "some\nconnection\nstring",
			"eth1.nmconnection": "other\nconnection\nstring",
			"file":              "stuff",
		}
		s := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      netConfigName,
				Namespace: "test-namespace",
			},
			Data: netConfigData,
		}
		Expect(c.Create(ctx, s)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				NetworkConfigRef: &corev1.LocalObjectReference{
					Name: netConfigName,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		content, err := os.ReadFile(outputFilePath(networkConfigDir, "eth0.nmconnection"))
		Expect(err).NotTo(HaveOccurred())
		Expect(content).To(Equal([]byte("some\nconnection\nstring")))

		content, err = os.ReadFile(outputFilePath(networkConfigDir, "eth1.nmconnection"))
		Expect(err).NotTo(HaveOccurred())
		Expect(content).To(Equal([]byte("other\nconnection\nstring")))

		_, err = os.Stat(outputFilePath(networkConfigDir, "file"))
		Expect(os.IsNotExist(err)).To(BeTrue())
	})

	It("creates extra manifests", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "manifests",
				Namespace: configNamespace,
			},
			Data: map[string]string{
				"manifest1.yaml": "thing: stuff",
				"manifest2.yaml": "other: foo",
			},
		}
		Expect(c.Create(ctx, cm)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				ExtraManifestsRefs: []corev1.LocalObjectReference{
					{Name: "manifests"},
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		validateExtraManifestContent("manifest1.yaml", "thing: stuff")
		validateExtraManifestContent("manifest2.yaml", "other: foo")
	})

	It("validates extra manifests", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "manifests",
				Namespace: configNamespace,
			},
			Data: map[string]string{
				"manifest1.yaml": "thing: \"st\"uff",
			},
		}
		Expect(c.Create(ctx, cm)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				ExtraManifestsRefs: []corev1.LocalObjectReference{
					{Name: "manifests"},
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).To(HaveOccurred())
	})

	It("creates certificates", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				ClusterInfo: clusterinfo.ClusterInfo{
					Domain: "other-test-sno.redhat.com",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		// Verify the kubeconfig secret
		kubeconfigSecret := &corev1.Secret{}
		err = r.Client.Get(ctx, client.ObjectKey{Namespace: configNamespace, Name: config.Spec.ClusterName + "-admin-kubeconfig"}, kubeconfigSecret)
		Expect(err).NotTo(HaveOccurred())
		kubeconfigSecretData, exists := kubeconfigSecret.Data["kubeconfig"]
		Expect(exists).To(BeTrue())
		kubeconfig, err := clientcmd.Load(kubeconfigSecretData)
		Expect(err).NotTo(HaveOccurred())
		// verify the cluster URL
		Expect(kubeconfig.Clusters["cluster"].Server).To(Equal(fmt.Sprintf("https://api.%s:6443", config.Spec.Domain)))

		// Verify the kubeconfig file
		kubeconfigPath := outputFilePath(certificatesDir, "kubeconfig")
		_, err = os.Stat(kubeconfigPath)
		Expect(err).NotTo(HaveOccurred())

		// Load the kubeconfig file
		kubeconifgFromFile, err := clientcmd.LoadFromFile(kubeconfigPath)
		Expect(err).NotTo(HaveOccurred())
		// verify the cluster URL
		Expect(kubeconifgFromFile.Clusters["cluster"].Server).To(Equal(fmt.Sprintf("https://api.%s:6443", config.Spec.Domain)))

		signerKeyFileNames := []string{
			"loadbalancer-serving-signer.key",
			"localhost-serving-signer.key",
			"service-network-serving-signer.key",
			"ingresskey-ingress-operator.key",
		}
		for _, fileName := range signerKeyFileNames {
			// verify all signer keys exists
			_, err = os.Stat(outputFilePath(certificatesDir, fileName))
			Expect(err).NotTo(HaveOccurred())
		}
		// verify the admin client CA cert exists
		_, err = os.Stat(outputFilePath(certificatesDir, "admin-kubeconfig-client-ca.crt"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures a referenced BMH", func() {
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
			Status: bmh_v1alpha1.BareMetalHostStatus{
				Provisioning: bmh_v1alpha1.ProvisionStatus{
					State: bmh_v1alpha1.StateAvailable,
				},
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: configNamespace,
				Name:      configName,
			},
		}
		res, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		key := types.NamespacedName{
			Namespace: bmh.Namespace,
			Name:      bmh.Name,
		}
		Expect(c.Get(ctx, key, bmh)).To(Succeed())
		Expect(bmh.Spec.Image).NotTo(BeNil())
		Expect(bmh.Spec.Image.URL).To(Equal(fmt.Sprintf("http://service.namespace/images/%s/%s.iso", configNamespace, configName)))
		Expect(bmh.Spec.Image.DiskFormat).To(HaveValue(Equal("live-iso")))
		Expect(bmh.Spec.Online).To(BeTrue())
		Expect(bmh.Annotations).ToNot(HaveKey(detachedAnnotation))
	})

	It("sets the BMH ref in the cluster config status", func() {
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
			Status: bmh_v1alpha1.BareMetalHostStatus{
				Provisioning: bmh_v1alpha1.ProvisionStatus{
					State: bmh_v1alpha1.StateAvailable,
				},
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: configNamespace,
				Name:      configName,
			},
		}
		res, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		key := types.NamespacedName{
			Namespace: config.Namespace,
			Name:      config.Name,
		}
		Expect(c.Get(ctx, key, config)).To(Succeed())
		Expect(config.Status.BareMetalHostRef).To(HaveValue(Equal(*config.Spec.BareMetalHostRef)))
	})

	It("sets detached on a referenced BMH after it is provisioned", func() {
		liveISO := "live-iso"
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
			Spec: bmh_v1alpha1.BareMetalHostSpec{
				Image: &bmh_v1alpha1.Image{
					URL:        fmt.Sprintf("http://service.namespace/images/%s/%s.iso", configNamespace, configName),
					DiskFormat: &liveISO,
				},
				Online: true,
			},
			Status: bmh_v1alpha1.BareMetalHostStatus{
				Provisioning: bmh_v1alpha1.ProvisionStatus{
					State: bmh_v1alpha1.StateProvisioned,
				},
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: configNamespace,
				Name:      configName,
			},
		}
		res, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		key := types.NamespacedName{
			Namespace: bmh.Namespace,
			Name:      bmh.Name,
		}
		Expect(c.Get(ctx, key, bmh)).To(Succeed())
		Expect(bmh.Annotations[detachedAnnotation]).To(Equal("clusterconfig-controller"))
	})

	It("doesn't error for a missing clusterconfig", func() {
		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))
	})

	It("sets the image ready condition", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				ClusterInfo: clusterinfo.ClusterInfo{
					Domain: "thing.example.com",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		Expect(c.Get(ctx, key, config)).To(Succeed())
		cond := meta.FindStatusCondition(config.Status.Conditions, relocationv1alpha1.ImageReadyCondition)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal(relocationv1alpha1.ImageReadyReason))
		Expect(cond.Message).To(Equal(relocationv1alpha1.ImageReadyMessage))
	})

	It("sets the host configured condition when the host can be configured", func() {
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
			Status: bmh_v1alpha1.BareMetalHostStatus{
				Provisioning: bmh_v1alpha1.ProvisionStatus{
					State: bmh_v1alpha1.StateAvailable,
				},
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		Expect(c.Get(ctx, key, config)).To(Succeed())
		cond := meta.FindStatusCondition(config.Status.Conditions, relocationv1alpha1.HostConfiguredCondition)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal(relocationv1alpha1.HostConfiguraionSucceededReason))
		Expect(cond.Message).To(Equal(relocationv1alpha1.HostConfigurationSucceededMessage))
	})

	It("sets the host configured condition to false when the host is missing", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      "test-bmh",
					Namespace: "test-bmh-namespace",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		key := types.NamespacedName{
			Namespace: configNamespace,
			Name:      configName,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		Expect(err).To(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		Expect(c.Get(ctx, key, config)).To(Succeed())
		cond := meta.FindStatusCondition(config.Status.Conditions, relocationv1alpha1.HostConfiguredCondition)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(relocationv1alpha1.HostConfiguraionFailedReason))
	})

	It("removes the image from a BMH when the reference is removed", func() {
		liveISO := "live-iso"
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
			Spec: bmh_v1alpha1.BareMetalHostSpec{
				Image: &bmh_v1alpha1.Image{
					URL:        fmt.Sprintf("http://service.namespace/images/%s/%s.iso", configNamespace, configName),
					DiskFormat: &liveISO,
				},
				Online: true,
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Status: relocationv1alpha1.ClusterConfigStatus{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: configNamespace,
				Name:      configName,
			},
		}
		res, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		key := types.NamespacedName{
			Namespace: bmh.Namespace,
			Name:      bmh.Name,
		}
		Expect(c.Get(ctx, key, bmh)).To(Succeed())
		Expect(bmh.Spec.Image).To(BeNil())
	})

	It("removes the reference and configures a new BMH when the reference is changed", func() {
		liveISO := "live-iso"
		oldBMH := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "old-bmh",
				Namespace: "test-bmh-namespace",
			},
			Spec: bmh_v1alpha1.BareMetalHostSpec{
				Image: &bmh_v1alpha1.Image{
					URL:        fmt.Sprintf("http://service.namespace/images/%s/%s.iso", configNamespace, configName),
					DiskFormat: &liveISO,
				},
				Online: true,
			},
		}
		Expect(c.Create(ctx, oldBMH)).To(Succeed())

		newBMH := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bmh",
				Namespace: "test-bmh-namespace",
			},
		}
		Expect(c.Create(ctx, newBMH)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      newBMH.Name,
					Namespace: newBMH.Namespace,
				},
			},
			Status: relocationv1alpha1.ClusterConfigStatus{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      oldBMH.Name,
					Namespace: oldBMH.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		req := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: configNamespace,
				Name:      configName,
			},
		}
		res, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(ctrl.Result{}))

		oldKey := types.NamespacedName{
			Namespace: oldBMH.Namespace,
			Name:      oldBMH.Name,
		}
		Expect(c.Get(ctx, oldKey, oldBMH)).To(Succeed())
		Expect(oldBMH.Spec.Image).To(BeNil())

		newKey := types.NamespacedName{
			Namespace: newBMH.Namespace,
			Name:      newBMH.Name,
		}
		Expect(c.Get(ctx, newKey, newBMH)).To(Succeed())
		Expect(newBMH.Spec.Image).ToNot(BeNil())
	})
})

var _ = Describe("mapBMHToCC", func() {
	var (
		c               client.Client
		r               *ClusterConfigReconciler
		ctx             = context.Background()
		configName      = "test-config"
		configNamespace = "test-namespace"
	)

	BeforeEach(func() {
		c = fakeclient.NewClientBuilder().
			WithScheme(scheme.Scheme).
			WithStatusSubresource(&relocationv1alpha1.ClusterConfig{}).
			Build()

		r = &ClusterConfigReconciler{
			Client: c,
			Scheme: scheme.Scheme,
			Log:    logrus.New(),
		}
	})

	It("returns a request for the cluster config referencing the given BMH", func() {
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configName,
				Namespace: configNamespace,
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		config = &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-config",
				Namespace: configNamespace,
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		requests := r.mapBMHToCC(ctx, bmh)
		Expect(len(requests)).To(Equal(1))
		Expect(requests[0].NamespacedName).To(Equal(types.NamespacedName{
			Name:      configName,
			Namespace: configNamespace,
		}))
	})

	It("returns an empty list when no cluster config matches", func() {
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configName,
				Namespace: configNamespace,
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      "other-bmh",
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		config = &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-config",
				Namespace: configNamespace,
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())
		requests := r.mapBMHToCC(ctx, bmh)
		Expect(len(requests)).To(Equal(0))
	})
})

var _ = Describe("serviceURL", func() {
	It("creates the correct url without a port", func() {
		opts := &ClusterConfigReconcilerOptions{
			ServiceName:      "name",
			ServiceNamespace: "namespace",
			ServiceScheme:    "http",
		}
		Expect(serviceURL(opts)).To(Equal("http://name.namespace"))
	})
	It("creates the correct url with a port", func() {
		opts := &ClusterConfigReconcilerOptions{
			ServiceName:      "name",
			ServiceNamespace: "namespace",
			ServiceScheme:    "http",
			ServicePort:      "8080",
		}
		Expect(serviceURL(opts)).To(Equal("http://name.namespace:8080"))
	})
})

var _ = Describe("handleFinalizer", func() {
	var (
		c               client.Client
		dataDir         string
		r               *ClusterConfigReconciler
		ctx             = context.Background()
		configName      = "test-config"
		configNamespace = "test-namespace"
	)

	BeforeEach(func() {
		c = fakeclient.NewClientBuilder().
			WithScheme(scheme.Scheme).
			WithStatusSubresource(&relocationv1alpha1.ClusterConfig{}).
			Build()
		var err error
		dataDir, err = os.MkdirTemp("", "clusterconfig_controller_test_data")
		Expect(err).NotTo(HaveOccurred())

		r = &ClusterConfigReconciler{
			Client: c,
			Scheme: scheme.Scheme,
			Log:    logrus.New(),
			Options: &ClusterConfigReconcilerOptions{
				DataDir: dataDir,
			},
		}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dataDir)).To(Succeed())
	})

	It("adds the finalizer if the config is not being deleted", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configName,
				Namespace: configNamespace,
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())
		res, stop, err := r.handleFinalizer(ctx, r.Log, config)
		Expect(res).To(Equal(ctrl.Result{Requeue: true}))
		Expect(stop).To(BeTrue())
		Expect(err).ToNot(HaveOccurred())

		key := types.NamespacedName{
			Name:      configName,
			Namespace: configNamespace,
		}
		Expect(c.Get(ctx, key, config)).To(Succeed())
		Expect(config.GetFinalizers()).To(ContainElement(clusterConfigFinalizerName))
	})

	It("noops if the finalizer is already present", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())
		res, stop, err := r.handleFinalizer(ctx, r.Log, config)
		Expect(res).To(Equal(ctrl.Result{}))
		Expect(stop).To(BeFalse())
		Expect(err).ToNot(HaveOccurred())
	})

	It("deletes the local files when the config is deleted", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		// mark config as deleted to call the finalizer handler
		now := metav1.Now()
		config.ObjectMeta.DeletionTimestamp = &now

		filesDir := filepath.Join(dataDir, "namespaces", config.Namespace, config.Name, "files")
		testFilePath := filepath.Join(filesDir, "testfile")
		Expect(os.MkdirAll(filesDir, 0700)).To(Succeed())
		Expect(os.WriteFile(testFilePath, []byte("stuff"), 0644)).To(Succeed())

		res, stop, err := r.handleFinalizer(ctx, r.Log, config)
		Expect(res).To(Equal(ctrl.Result{}))
		Expect(stop).To(BeTrue())
		Expect(err).ToNot(HaveOccurred())

		_, err = os.Stat(testFilePath)
		Expect(os.IsNotExist(err)).To(BeTrue())

		key := types.NamespacedName{
			Name:      configName,
			Namespace: configNamespace,
		}
		Expect(c.Get(ctx, key, config)).To(Succeed())
		Expect(config.GetFinalizers()).ToNot(ContainElement(clusterConfigFinalizerName))
	})

	It("removes the BMH image url when the config is deleted", func() {
		bmh := &bmh_v1alpha1.BareMetalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-bmh",
				Namespace: "test-bmh-namespace",
			},
			Spec: bmh_v1alpha1.BareMetalHostSpec{
				Image: &bmh_v1alpha1.Image{
					URL: "https://service.example.com/namespace/name.iso",
				},
			},
		}
		Expect(c.Create(ctx, bmh)).To(Succeed())

		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      bmh.Name,
					Namespace: bmh.Namespace,
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		// mark config as deleted to call the finalizer handler
		now := metav1.Now()
		config.ObjectMeta.DeletionTimestamp = &now

		res, stop, err := r.handleFinalizer(ctx, r.Log, config)
		Expect(res).To(Equal(ctrl.Result{}))
		Expect(stop).To(BeTrue())
		Expect(err).ToNot(HaveOccurred())

		bmhKey := types.NamespacedName{
			Name:      bmh.Name,
			Namespace: bmh.Namespace,
		}
		Expect(c.Get(ctx, bmhKey, bmh)).To(Succeed())
		Expect(bmh.Spec.Image).To(BeNil())

		configKey := types.NamespacedName{
			Name:      configName,
			Namespace: configNamespace,
		}
		Expect(c.Get(ctx, configKey, config)).To(Succeed())
		Expect(config.GetFinalizers()).ToNot(ContainElement(clusterConfigFinalizerName))
	})

	It("removes the finalizer if the referenced BMH doesn't exist", func() {
		config := &relocationv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:       configName,
				Namespace:  configNamespace,
				Finalizers: []string{clusterConfigFinalizerName},
			},
			Spec: relocationv1alpha1.ClusterConfigSpec{
				BareMetalHostRef: &relocationv1alpha1.BareMetalHostReference{
					Name:      "test-bmh",
					Namespace: "test-bmh-namespace",
				},
			},
		}
		Expect(c.Create(ctx, config)).To(Succeed())

		// mark config as deleted to call the finalizer handler
		now := metav1.Now()
		config.ObjectMeta.DeletionTimestamp = &now

		res, stop, err := r.handleFinalizer(ctx, r.Log, config)
		Expect(res).To(Equal(ctrl.Result{}))
		Expect(stop).To(BeTrue())
		Expect(err).ToNot(HaveOccurred())

		configKey := types.NamespacedName{
			Name:      configName,
			Namespace: configNamespace,
		}
		Expect(c.Get(ctx, configKey, config)).To(Succeed())
		Expect(config.GetFinalizers()).ToNot(ContainElement(clusterConfigFinalizerName))
	})
})
