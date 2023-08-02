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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cro "github.com/RHsyseng/cluster-relocation-operator/api/v1beta1"
	bmh_v1alpha1 "github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
	relocationv1alpha1 "github.com/openshift/cluster-relocation-service/api/v1alpha1"
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
	detachedAnnotation    = "baremetalhost.metal3.io/detached"
	clusterRelocationName = "cluster"
	relocationNamespace   = "cluster-relocation"
	clusterConfigDir      = "cluster-configuration"
	manifestsDir          = "extra-manifests"
	networkConfigDir      = "network-configuration"
)

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
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
		log.WithError(err).Error("failed to get referenced cluster config")
		return ctrl.Result{}, err
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

	u, err := url.JoinPath(r.BaseURL, "images", req.Namespace, fmt.Sprintf("%s.iso", req.Name))
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

	if config.Spec.BareMetalHostRef != nil {
		if err := r.setBMHImage(ctx, config.Spec.BareMetalHostRef, u); err != nil {
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

// writeInputData writes the required info based on the cluster config to the config cache dir
func (r *ClusterConfigReconciler) writeInputData(ctx context.Context, log logrus.FieldLogger, config *relocationv1alpha1.ClusterConfig) (ctrl.Result, error) {
	configDir := filepath.Join(r.Options.DataDir, "namespaces", config.Namespace, config.Name)
	clusterConfigPath := filepath.Join(configDir, "files", clusterConfigDir)
	if err := os.MkdirAll(clusterConfigPath, 0700); err != nil {
		return ctrl.Result{}, err
	}

	locked, lockErr, funcErr := filelock.WithWriteLock(configDir, func() error {
		if err := r.writeNamespace(filepath.Join(clusterConfigPath, "namespace.json")); err != nil {
			return err
		}

		if err := r.writeClusterRelocation(config, filepath.Join(clusterConfigPath, "cluster-relocation.json")); err != nil {
			return err
		}

		if err := r.writeClusterRelocation(config, filepath.Join(clusterConfigPath, "cluster-relocation.json")); err != nil {
			return err
		}

		if err := r.writeSecretToFile(ctx, config.Spec.APICertRef, filepath.Join(clusterConfigPath, "api-cert-secret.json")); err != nil {
			return fmt.Errorf("failed to write api cert secret: %w", err)
		}

		if err := r.writeSecretToFile(ctx, config.Spec.IngressCertRef, filepath.Join(clusterConfigPath, "ingress-cert-secret.json")); err != nil {
			return fmt.Errorf("failed to write ingress cert secret: %w", err)
		}

		if err := r.writeSecretToFile(ctx, config.Spec.PullSecretRef, filepath.Join(clusterConfigPath, "pull-secret-secret.json")); err != nil {
			return fmt.Errorf("failed to write pull secret: %w", err)
		}

		if config.Spec.ACMRegistration != nil {
			if err := r.writeSecretToFile(ctx, &config.Spec.ACMRegistration.ACMSecret, filepath.Join(clusterConfigPath, "acm-secret.json")); err != nil {
				return fmt.Errorf("failed to write ACM secret: %w", err)
			}
		}

		if config.Spec.ExtraManifestsRef != nil {
			manifestsPath := filepath.Join(configDir, "files", manifestsDir)
			if err := os.MkdirAll(manifestsPath, 0700); err != nil {
				return err
			}

			cm := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: config.Spec.ExtraManifestsRef.Name, Namespace: config.Namespace}
			if err := r.Get(ctx, key, cm); err != nil {
				return err
			}

			for name, content := range cm.Data {
				var y interface{}
				if err := yaml.Unmarshal([]byte(content), &y); err != nil {
					return fmt.Errorf("failed to validate manifest file %s: %w", name, err)
				}
				if err := os.WriteFile(filepath.Join(manifestsPath, name), []byte(content), 0644); err != nil {
					return fmt.Errorf("failed to write extra manifest file: %w", err)
				}
			}
		}

		if config.Spec.NetworkConfigRef != nil {
			networkConfigPath := filepath.Join(configDir, "files", networkConfigDir)
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

		return nil
	})
	if lockErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to acquire file lock: %w", lockErr)
	}
	if funcErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to write input data: %w", funcErr)
	}
	if !locked {
		log.Info("requeueing due to lock contention")
		if updateErr := r.setImageReadyCondition(ctx, config, fmt.Errorf("could not acquire lock for image data")); updateErr != nil {
			log.WithError(updateErr).Error("failed to update cluster config status")
		}
		return ctrl.Result{RequeueAfter: time.Second * 5}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ClusterConfigReconciler) typeMetaForObject(o runtime.Object) (*metav1.TypeMeta, error) {
	gvks, unversioned, err := r.Scheme.ObjectKinds(o)
	if err != nil {
		return nil, err
	}
	if unversioned || len(gvks) == 0 {
		return nil, fmt.Errorf("unable to find API version for object")
	}
	// if there are multiple assume the last is the most recent
	gvk := gvks[len(gvks)-1]
	return &metav1.TypeMeta{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
	}, nil
}

func (r *ClusterConfigReconciler) writeNamespace(file string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: relocationNamespace,
		},
	}

	typeMeta, err := r.typeMetaForObject(ns)
	if err != nil {
		return err
	}
	ns.TypeMeta = *typeMeta

	data, err := json.Marshal(ns)
	if err != nil {
		return fmt.Errorf("failed to marshal namespace: %w", err)
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		return fmt.Errorf("failed to write namespace: %w", err)
	}

	return nil
}

func (r *ClusterConfigReconciler) writeClusterRelocation(config *relocationv1alpha1.ClusterConfig, file string) error {
	cr := &cro.ClusterRelocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterRelocationName,
			Namespace: config.Namespace,
		},
		// initialize with a deep copy to avoid changing the secret ref values of the original config
		Spec: *config.Spec.ClusterRelocationSpec.DeepCopy(),
	}

	typeMeta, err := r.typeMetaForObject(cr)
	if err != nil {
		return err
	}
	cr.TypeMeta = *typeMeta

	// override ClusterRelocation and Secret reference namespaces
	cr.Namespace = relocationNamespace
	if cr.Spec.ACMRegistration != nil {
		cr.Spec.ACMRegistration.ACMSecret.Namespace = relocationNamespace
	}
	if cr.Spec.APICertRef != nil {
		cr.Spec.APICertRef.Namespace = relocationNamespace
	}
	if cr.Spec.IngressCertRef != nil {
		cr.Spec.IngressCertRef.Namespace = relocationNamespace
	}
	if cr.Spec.PullSecretRef != nil {
		cr.Spec.PullSecretRef.Namespace = relocationNamespace
	}

	data, err := json.Marshal(cr)
	if err != nil {
		return fmt.Errorf("failed to marshal cluster relocation: %w", err)
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		return fmt.Errorf("failed to write cluster relocation: %w", err)
	}

	return nil
}

func (r *ClusterConfigReconciler) writeSecretToFile(ctx context.Context, ref *corev1.SecretReference, file string) error {
	if ref == nil {
		return nil
	}

	s := &corev1.Secret{}
	key := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, key, s); err != nil {
		return err
	}

	// override namespace
	s.Namespace = relocationNamespace

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		return err
	}

	return nil
}
