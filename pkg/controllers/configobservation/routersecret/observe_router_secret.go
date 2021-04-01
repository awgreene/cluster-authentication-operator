package routersecret

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func ObserveRouterSecret(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	namedCertificatesPath := []string{"servingInfo", "namedCertificates"}
	defer func() {
		ret = configobserver.Pruned(ret, namedCertificatesPath)
	}()

	listers := genericlisters.(configobservation.Listers)
	errs := []error{}

	routerSecret, err := listers.SecretsLister.Secrets("openshift-authentication").Get("v4-0-config-system-router-certs")
	if err != nil {
		return existingConfig, append(errs, err)
	}

	observedNamedCertificates, err := routerSecretToSNI(routerSecret, "/var/config/system/secrets/v4-0-config-system-router-certs/", "/var/config/system/secrets/v4-0-config-system-router-certs/")
	if err != nil {
		return existingConfig, append(errs, err)
	}

	// attempt to get custom serving certs
	routerSecret, err = listers.SecretsLister.Secrets("openshift-authentication").Get("v4-0-config-system-custom-router-certs")
	if err != nil && !errors.IsNotFound(err) {
		return existingConfig, append(errs, err)
	}

	// If no error occured, add optional custom serving certs
	if err == nil {
		customNamedCertificates, err := routerSecretToSNI(routerSecret, "/var/config/system/secrets/v4-0-config-system-custom-router-certs/", "/var/config/system/secrets/v4-0-config-system-custom-router-certs/")
		if err != nil {
			return existingConfig, append(errs, err)
		}
		observedNamedCertificates = append(observedNamedCertificates, customNamedCertificates...)
	}

	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedSlice(
		observedConfig,
		observedNamedCertificates,
		namedCertificatesPath...,
	); err != nil {
		return existingConfig, append(errs, err)
	}

	currentNamedCertificates, _, err := unstructured.NestedSlice(existingConfig, namedCertificatesPath...)
	if err != nil {
		// continue on read error from existing config in an attempt to fix it
		errs = append(errs, err)
	}

	if !equality.Semantic.DeepEqual(currentNamedCertificates, observedNamedCertificates) {
		recorder.Eventf("ObserveRouterSecret", "namedCertificates changed to %#v", observedNamedCertificates)
	}

	return observedConfig, errs
}

func routerSecretToSNI(routerSecret *corev1.Secret, certFile string, keyFile string) ([]interface{}, error) {
	certs := []interface{}{}
	// make sure the output slice of named certs is sorted by domain so that the generated config is deterministic
	for _, domain := range sets.StringKeySet(routerSecret.Data).List() {
		certs = append(certs, map[string]interface{}{
			"names":    []interface{}{"*." + domain}, // ingress domain is always a wildcard
			"certFile": interface{}(certFile + domain),
			"keyFile":  interface{}(keyFile + domain),
		})
	}
	return certs, nil
}
