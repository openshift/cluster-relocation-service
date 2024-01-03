/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	bmh_v1alpha1 "github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
	"github.com/openshift-kni/lifecycle-agent/ibu-imager/clusterinfo"
	relocationv1alpha1 "github.com/openshift/cluster-relocation-service/api/v1alpha1"
	"github.com/openshift/cluster-relocation-service/internal/certs"
	"github.com/openshift/cluster-relocation-service/internal/filelock"
	"github.com/sirupsen/logrus"
)

type ClusterConfigReconcilerOptions struct {
	ServiceName      string `envconfig:"SERVICE_NAME"`
	ServiceNamespace string `envconfig:"SERVICE_NAMESPACE"`
	ServicePort      string `envconfig:"SERVICE_PORT"`
	ServiceScheme    string `envconfig:"SERVICE_SCHEME"`
	DataDir          string `envconfig:"DATA_DIR" default:"/data"`
}

// ClusterConfigReconciler reconciles a ClusterConfig object
type ClusterConfigReconciler struct {
	client.Client
	Log     logrus.FieldLogger
	Scheme  *runtime.Scheme
	Options *ClusterConfigReconcilerOptions
	BaseURL string
}

const (
	detachedAnnotation         = "baremetalhost.metal3.io/detached"
	clusterConfigDir           = "cluster-configuration"
	extraManifestsDir          = "extra-manifests"
	manifestsDir               = "manifests"
	networkConfigDir           = "network-configuration"
	certificatesDir            = "certs"
	clusterConfigFinalizerName = "clusterconfig." + relocationv1alpha1.Group + "/deprovision"
	caBundleFileName           = "tls-ca-bundle.pem"
)

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=relocation.openshift.io,resources=clusterconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=relocation.openshift.io,resources=clusterconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=relocation.openshift.io,resources=clusterconfigs/finalizers,verbs=update
//+kubebuilder:rbac:groups=metal3.io,resources=baremetalhosts,verbs=get;list;watch;update;patch

func (r *ClusterConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithFields(logrus.Fields{"name": req.Name, "namespace": req.Namespace})
	log.Info("Running reconcile ...")
	defer log.Info("Reconcile complete")

	config := &relocationv1alpha1.ClusterConfig{}
	if err := r.Get(ctx, req.NamespacedName, config); err != nil {
		log.WithError(err).Error("failed to get cluster config")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if res, stop, err := r.handleFinalizer(ctx, log, config); !res.IsZero() || stop || err != nil {
		if err != nil {
			log.Error(err)
		}
		return res, err
	}

	if res, err := r.writeInputData(ctx, log, config); !res.IsZero() || err != nil {
		if err != nil {
			if updateErr := r.setImageReadyCondition(ctx, config, err); updateErr != nil {
				log.WithError(updateErr).Error("failed to update cluster config status")
			}
			log.Error(err)
		}
		return res, err
	}

	url, err := url.JoinPath(r.BaseURL, "images", req.Namespace, fmt.Sprintf("%s.iso", req.Name))
	if err != nil {
		log.WithError(err).Error("failed to create image url")
		if updateErr := r.setImageReadyCondition(ctx, config, err); updateErr != nil {
			log.WithError(updateErr).Error("failed to update cluster config status")
		}
		return ctrl.Result{}, err
	}

	if err := r.setImageReadyCondition(ctx, config, nil); err != nil {
		log.WithError(err).Error("failed to update cluster config status")
		return ctrl.Result{}, err
	}

	if config.Status.BareMetalHostRef != nil && !relocationv1alpha1.BMHRefsMatch(config.Spec.BareMetalHostRef, config.Status.BareMetalHostRef) {
		if err := r.removeBMHImage(ctx, config.Status.BareMetalHostRef); client.IgnoreNotFound(err) != nil {
			log.WithError(err).Errorf("failed to remove image from BareMetalHost %s/%s", config.Status.BareMetalHostRef.Namespace, config.Status.BareMetalHostRef.Name)
			return ctrl.Result{}, err
		}
	}

	if config.Spec.BareMetalHostRef != nil {
		if err := r.setBMHImage(ctx, config.Spec.BareMetalHostRef, url); err != nil {
			log.WithError(err).Error("failed to set BareMetalHost image")
			if updateErr := r.setHostConfiguredCondition(ctx, config, err); updateErr != nil {
				log.WithError(updateErr).Error("failed to update cluster config status")
			}
			return ctrl.Result{}, err
		}
		if err := r.setHostConfiguredCondition(ctx, config, nil); err != nil {
			log.WithError(err).Error("failed to update cluster config status")
			return ctrl.Result{}, err
		}

		patch := client.MergeFrom(config.DeepCopy())
		config.Status.BareMetalHostRef = config.Spec.BareMetalHostRef.DeepCopy()
		if err := r.Status().Patch(ctx, config, patch); err != nil {
			log.WithError(err).Error("failed to set Status.BareMetalHostRef")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *ClusterConfigReconciler) setImageReadyCondition(ctx context.Context, config *relocationv1alpha1.ClusterConfig, err error) error {
	cond := metav1.Condition{
		Type:    relocationv1alpha1.ImageReadyCondition,
		Status:  metav1.ConditionTrue,
		Reason:  relocationv1alpha1.ImageReadyReason,
		Message: relocationv1alpha1.ImageReadyMessage,
	}

	if err != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = relocationv1alpha1.ImageNotReadyReason
		cond.Message = err.Error()
	}

	patch := client.MergeFrom(config.DeepCopy())
	meta.SetStatusCondition(&config.Status.Conditions, cond)
	return r.Status().Patch(ctx, config, patch)
}

func (r *ClusterConfigReconciler) setHostConfiguredCondition(ctx context.Context, config *relocationv1alpha1.ClusterConfig, err error) error {
	cond := metav1.Condition{
		Type:    relocationv1alpha1.HostConfiguredCondition,
		Status:  metav1.ConditionTrue,
		Reason:  relocationv1alpha1.HostConfiguraionSucceededReason,
		Message: relocationv1alpha1.HostConfigurationSucceededMessage,
	}

	if err != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = relocationv1alpha1.HostConfiguraionFailedReason
		cond.Message = err.Error()
	}

	patch := client.MergeFrom(config.DeepCopy())
	meta.SetStatusCondition(&config.Status.Conditions, cond)
	return r.Status().Patch(ctx, config, patch)
}

func (r *ClusterConfigReconciler) mapBMHToCC(ctx context.Context, obj client.Object) []reconcile.Request {
	bmh := &bmh_v1alpha1.BareMetalHost{}
	bmhName := obj.GetName()
	bmhNamespace := obj.GetNamespace()

	if err := r.Get(ctx, types.NamespacedName{Name: bmhName, Namespace: bmhNamespace}, bmh); err != nil {
		return []reconcile.Request{}
	}
	ccList := &relocationv1alpha1.ClusterConfigList{}
	if err := r.List(ctx, ccList); err != nil {
		return []reconcile.Request{}
	}
	if len(ccList.Items) == 0 {
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}
	for _, cc := range ccList.Items {
		if cc.Spec.BareMetalHostRef == nil {
			continue
		}
		if cc.Spec.BareMetalHostRef.Name == bmhName && cc.Spec.BareMetalHostRef.Namespace == bmhNamespace {
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: cc.Namespace,
					Name:      cc.Name,
				},
			}
			requests = append(requests, req)
		}
	}
	if len(requests) > 1 {
		r.Log.Warn("found multiple ClusterConfigs referencing BaremetalHost %s/%s", bmhNamespace, bmhName)
	}
	return requests
}

func serviceURL(opts *ClusterConfigReconcilerOptions) string {
	host := fmt.Sprintf("%s.%s", opts.ServiceName, opts.ServiceNamespace)
	if opts.ServicePort != "" {
		host = fmt.Sprintf("%s:%s", host, opts.ServicePort)
	}
	u := url.URL{
		Scheme: opts.ServiceScheme,
		Host:   host,
	}
	return u.String()
}

func (r *ClusterConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Options.ServiceName == "" || r.Options.ServiceNamespace == "" || r.Options.ServiceScheme == "" {
		return fmt.Errorf("SERVICE_NAME, SERVICE_NAMESPACE, and SERVICE_SCHEME must be set")
	}
	r.BaseURL = serviceURL(r.Options)

	return ctrl.NewControllerManagedBy(mgr).
		For(&relocationv1alpha1.ClusterConfig{}).
		WatchesRawSource(source.Kind(mgr.GetCache(), &bmh_v1alpha1.BareMetalHost{}), handler.EnqueueRequestsFromMapFunc(r.mapBMHToCC)).
		Complete(r)
}

func (r *ClusterConfigReconciler) setBMHImage(ctx context.Context, bmhRef *relocationv1alpha1.BareMetalHostReference, url string) error {
	bmh := &bmh_v1alpha1.BareMetalHost{}
	key := types.NamespacedName{
		Name:      bmhRef.Name,
		Namespace: bmhRef.Namespace,
	}
	if err := r.Get(ctx, key, bmh); err != nil {
		return err
	}
	patch := client.MergeFrom(bmh.DeepCopy())

	dirty := false
	if !bmh.Spec.Online {
		bmh.Spec.Online = true
		dirty = true
	}
	if bmh.Spec.Image == nil {
		bmh.Spec.Image = &bmh_v1alpha1.Image{}
		dirty = true
	}
	if bmh.Spec.Image.URL != url {
		bmh.Spec.Image.URL = url
		dirty = true
	}
	liveIso := "live-iso"
	if bmh.Spec.Image.DiskFormat == nil || *bmh.Spec.Image.DiskFormat != liveIso {
		bmh.Spec.Image.DiskFormat = &liveIso
		dirty = true
	}

	if bmh.Status.Provisioning.State == bmh_v1alpha1.StateProvisioned {
		if bmh.ObjectMeta.Annotations == nil {
			bmh.ObjectMeta.Annotations = make(map[string]string)
		}
		bmh.ObjectMeta.Annotations[detachedAnnotation] = "clusterconfig-controller"
		dirty = true
	}

	if dirty {
		if err := r.Patch(ctx, bmh, patch); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterConfigReconciler) removeBMHImage(ctx context.Context, bmhRef *relocationv1alpha1.BareMetalHostReference) error {
	bmh := &bmh_v1alpha1.BareMetalHost{}
	key := types.NamespacedName{
		Name:      bmhRef.Name,
		Namespace: bmhRef.Namespace,
	}
	if err := r.Get(ctx, key, bmh); err != nil {
		return err
	}
	patch := client.MergeFrom(bmh.DeepCopy())

	dirty := false
	if bmh.Spec.Image != nil {
		bmh.Spec.Image = nil
		dirty = true
	}

	if dirty {
		if err := r.Patch(ctx, bmh, patch); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterConfigReconciler) configDirs(config *relocationv1alpha1.ClusterConfig) (string, string, error) {
	lockDir := filepath.Join(r.Options.DataDir, "namespaces", config.Namespace, config.Name)
	filesDir := filepath.Join(lockDir, "files")
	if err := os.MkdirAll(filesDir, 0700); err != nil {
		return "", "", err
	}

	return lockDir, filesDir, nil
}

// writeInputData writes the required info based on the cluster config to the config cache dir
func (r *ClusterConfigReconciler) writeInputData(ctx context.Context, log logrus.FieldLogger, config *relocationv1alpha1.ClusterConfig) (ctrl.Result, error) {
	lockDir, filesDir, err := r.configDirs(config)
	if err != nil {
		return ctrl.Result{}, err
	}
	clusterConfigPath := filepath.Join(filesDir, clusterConfigDir)
	if err := os.MkdirAll(clusterConfigPath, 0700); err != nil {
		return ctrl.Result{}, err
	}

	locked, lockErr, funcErr := filelock.WithWriteLock(lockDir, func() error {
		if err := r.writeClusterInfo(&config.Spec.ClusterInfo, filepath.Join(clusterConfigPath, "manifest.json")); err != nil {
			return err
		}

		if err := r.writeCABundle(ctx, config.Spec.CABundleRef, config.Namespace, filepath.Join(clusterConfigPath, caBundleFileName)); err != nil {
			return fmt.Errorf("failed to write ca bundle: %w", err)
		}

		manifestsPath := filepath.Join(clusterConfigPath, manifestsDir)
		if err := os.MkdirAll(manifestsPath, 0700); err != nil {
			return err
		}

		if err := r.writePullSecretToFile(ctx, config.Spec.PullSecretRef, config.Namespace, filepath.Join(manifestsPath, "pull-secret-secret.json")); err != nil {
			return fmt.Errorf("failed to write pull secret: %w", err)
		}

		if config.Spec.ExtraManifestsRefs != nil {
			extraManifestsPath := filepath.Join(filesDir, extraManifestsDir)
			if err := os.MkdirAll(extraManifestsPath, 0700); err != nil {
				return err
			}

			for _, cmRef := range config.Spec.ExtraManifestsRefs {
				cm := &corev1.ConfigMap{}
				key := types.NamespacedName{Name: cmRef.Name, Namespace: config.Namespace}
				if err := r.Get(ctx, key, cm); err != nil {
					return err
				}

				for name, content := range cm.Data {
					var y interface{}
					if err := yaml.Unmarshal([]byte(content), &y); err != nil {
						return fmt.Errorf("failed to validate manifest file %s: %w", name, err)
					}
					if err := os.WriteFile(filepath.Join(extraManifestsPath, name), []byte(content), 0644); err != nil {
						return fmt.Errorf("failed to write extra manifest file: %w", err)
					}
				}
			}
		}

		if config.Spec.NetworkConfigRef != nil {
			networkConfigPath := filepath.Join(filesDir, networkConfigDir)
			if err := os.MkdirAll(networkConfigPath, 0700); err != nil {
				return err
			}

			cm := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: config.Spec.NetworkConfigRef.Name, Namespace: config.Namespace}
			if err := r.Get(ctx, key, cm); err != nil {
				return err
			}

			for name, content := range cm.Data {
				if !strings.HasSuffix(name, ".nmconnection") {
					r.Log.Warnf("Ignoring file name %s without .nmconnection suffix", name)
					continue
				}
				if err := os.WriteFile(filepath.Join(networkConfigPath, name), []byte(content), 0644); err != nil {
					return fmt.Errorf("failed to write network connection file: %w", err)
				}
			}
		}
		certificatesPath := filepath.Join(filesDir, certificatesDir)
		if err := os.MkdirAll(certificatesPath, 0700); err != nil {
			return err
		}

		certManager := certs.KubeConfigCertManager{CertificatesDir: certificatesPath}
		// TODO: handle user provided API and ingress certs
		if err := certManager.GenerateAllCertificates(); err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}
		kubeconfigBytes, err := certManager.GenerateKubeConfig(config.Spec.Domain)
		if err != nil {
			return fmt.Errorf("failed to generate kubeconfig: %w", err)
		}
		err = r.CreateKubeconfigSecret(ctx, config, kubeconfigBytes)
		if err != nil {
			return err
		}
		// This isn't required, it's just might be useful
		kubeconfigFile := filepath.Join(certificatesPath, "kubeconfig")
		err = os.WriteFile(kubeconfigFile, kubeconfigBytes, 0644)
		if err != nil {
			return err
		}
		return nil
	})
	if lockErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to acquire file lock: %w", lockErr)
	}
	if funcErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to write input data: %w", funcErr)
	}
	if !locked {
		r.Log.Info("requeuing due to lock contention")
		if updateErr := r.setImageReadyCondition(ctx, config, fmt.Errorf("could not acquire lock for image data")); updateErr != nil {
			r.Log.WithError(updateErr).Error("failed to update cluster config status")
		}
		return ctrl.Result{RequeueAfter: time.Second * 5}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ClusterConfigReconciler) CreateKubeconfigSecret(ctx context.Context, config *relocationv1alpha1.ClusterConfig, kubeconfigBytes []byte) error {
	kubeconfigSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.Spec.ClusterName + "-admin-kubeconfig",
			Namespace: config.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
	}
	mutateFn := func() error {
		// Update the Secret object with the desired data
		kubeconfigSecret.Data = map[string][]byte{
			"kubeconfig": kubeconfigBytes,
		}
		return nil
	}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, kubeconfigSecret, mutateFn)
	if err != nil {
		return fmt.Errorf("failed to create kubeconfig secret: %w", err)
	}
	r.Log.Infof("kubeconfig secret %s", op)
	return nil
}

func (r *ClusterConfigReconciler) writeClusterInfo(info *clusterinfo.ClusterInfo, file string) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster info: %w", err)
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		return fmt.Errorf("failed to write cluster info: %w", err)
	}

	return nil
}

func (r *ClusterConfigReconciler) writeCABundle(ctx context.Context, ref *corev1.LocalObjectReference, ns string, file string) error {
	if ref == nil {
		return nil
	}

	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: ref.Name, Namespace: ns}
	if err := r.Get(ctx, key, cm); err != nil {
		return err
	}

	data, ok := cm.Data[caBundleFileName]
	if !ok {
		return fmt.Errorf("%s key missing from CABundle config map", caBundleFileName)
	}

	return os.WriteFile(file, []byte(data), 0644)
}

func (r *ClusterConfigReconciler) writePullSecretToFile(ctx context.Context, ref *corev1.LocalObjectReference, ns string, file string) error {
	if ref == nil {
		return nil
	}

	s := &corev1.Secret{}
	key := types.NamespacedName{Name: ref.Name, Namespace: ns}
	if err := r.Get(ctx, key, s); err != nil {
		return err
	}

	// override name and namespace
	s.Name = "pull-secret"
	s.Namespace = "openshift-config"

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		return err
	}

	return nil
}

func (r *ClusterConfigReconciler) handleFinalizer(ctx context.Context, log logrus.FieldLogger, config *relocationv1alpha1.ClusterConfig) (ctrl.Result, bool, error) {
	if config.DeletionTimestamp.IsZero() {
		patch := client.MergeFrom(config.DeepCopy())
		if controllerutil.AddFinalizer(config, clusterConfigFinalizerName) {
			// update and requeue if the finalizer was added
			return ctrl.Result{Requeue: true}, true, r.Patch(ctx, config, patch)
		}
		return ctrl.Result{}, false, nil
	}

	removeFinalizer := func() error {
		log.Info("removing cluster config finalizer")
		patch := client.MergeFrom(config.DeepCopy())
		if controllerutil.RemoveFinalizer(config, clusterConfigFinalizerName) {
			return r.Patch(ctx, config, patch)
		}
		return nil
	}

	lockDir, _, err := r.configDirs(config)
	if err != nil {
		return ctrl.Result{}, true, err
	}

	if _, err := os.Stat(lockDir); err == nil {
		locked, lockErr, funcErr := filelock.WithWriteLock(lockDir, func() error {
			log.Info("removing files for cluster config")
			return os.RemoveAll(lockDir)
		})
		if lockErr != nil {
			return ctrl.Result{}, true, fmt.Errorf("failed to acquire file lock: %w", lockErr)
		}
		if funcErr != nil {
			return ctrl.Result{}, true, fmt.Errorf("failed to write input data: %w", funcErr)
		}
		if !locked {
			log.Info("requeueing due to lock contention")
			return ctrl.Result{RequeueAfter: time.Second * 5}, true, nil
		}
	} else if !os.IsNotExist(err) {
		return ctrl.Result{}, true, fmt.Errorf("failed to stat config directory %s: %w", lockDir, err)
	}

	if bmhRef := config.Spec.BareMetalHostRef; bmhRef != nil {
		bmh := &bmh_v1alpha1.BareMetalHost{}
		key := types.NamespacedName{
			Name:      bmhRef.Name,
			Namespace: bmhRef.Namespace,
		}
		if err := r.Get(ctx, key, bmh); err != nil {
			if !errors.IsNotFound(err) {
				return ctrl.Result{}, true, fmt.Errorf("failed to get BareMetalHost %s: %w", key, err)
			}
			log.Warnf("Referenced BareMetalHost %s does not exist", key)
			return ctrl.Result{}, true, removeFinalizer()
		}
		patch := client.MergeFrom(bmh.DeepCopy())
		if bmh.Spec.Image != nil {
			log.Info("removing image from BareMetalHost %s", key)
			bmh.Spec.Image = nil
			if err := r.Patch(ctx, bmh, patch); err != nil {
				return ctrl.Result{}, true, fmt.Errorf("failed to patch BareMetalHost %s: %w", key, err)
			}
		}
	}

	return ctrl.Result{}, true, removeFinalizer()
}
