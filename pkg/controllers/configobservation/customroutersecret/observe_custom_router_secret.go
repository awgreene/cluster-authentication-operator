package customroutersecret

import (
	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/cluster-authentication-operator/pkg/controllers/configobservation"
)

func NewObserveCustomRouterSecret() func(configobserver.Listers, events.Recorder, map[string]interface{}) (map[string]interface{}, []error) {
	return (&customRouterObserver{
		configPaths: [][]string{{"servingInfo", "componentRoutes"}},
		destSecret:  "v4-0-config-system-custom-router-certs",
		componentRoute: types.NamespacedName{
			Namespace: "openshift-authentication",
			Name:      "oauth",
		},
		resourceType: corev1.Secret{},
	}).observe
}

type customRouterObserver struct {
	configPaths    [][]string
	destSecret     string
	componentRoute types.NamespacedName
	resourceType   interface{}
}

// extractPreviouslyObservedConfig extracts the previously observed config from the existing config.
func extractPreviouslyObservedConfig(existing map[string]interface{}, paths ...[]string) (map[string]interface{}, []error) {
	var errs []error
	previous := map[string]interface{}{}
	for _, fields := range paths {
		value, found, err := unstructured.NestedFieldCopy(existing, fields...)
		if !found {
			continue
		}
		if err != nil {
			errs = append(errs, err)
		}
		err = unstructured.SetNestedField(previous, value, fields...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return previous, errs
}

func (c *customRouterObserver) observe(genericlisters configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (ret map[string]interface{}, _ []error) {
	listers := genericlisters.(configobservation.Listers)
	errs := []error{}

	// pick the correct resource sync function
	resourceSync := listers.ResourceSyncer().SyncSecret
	if _, ok := c.resourceType.(corev1.ConfigMap); ok {
		resourceSync = listers.ResourceSyncer().SyncConfigMap
	}

	previouslyObservedConfig, errs := extractPreviouslyObservedConfig(existingConfig, c.configPaths...)

	ingress, err := listers.IngressLister.Get("cluster")
	// if something went wrong, keep the previously observed config and resources
	if err != nil {
		return previouslyObservedConfig, append(errs, err)
	}

	observedComponentRoutes, observedResources, err := c.componentRouteSecret(listers, ingress)
	if err != nil {
		return previouslyObservedConfig, append(errs, err)
	}

	observedConfig := map[string]interface{}{}
	if err := unstructured.SetNestedField(observedConfig, observedComponentRoutes, c.configPaths[0]...); err != nil {
		return previouslyObservedConfig, append(errs, err)
	}

	errs = append(errs, syncObservedResources(resourceSync, observedResources)...)
	return observedConfig, errs
}

// resourceSyncFunc syncs a resource from the source location to the destination location.
type resourceSyncFunc func(destination, source resourcesynccontroller.ResourceLocation) error

// syncActionRules rules define source resource names indexed by destination resource names.
// Empty value means to delete the destination.
type syncActionRules map[string]string

// syncObservedResources copies or deletes resources, sources in GlobalUserSpecifiedConfigNamespace and destinations in OperatorNamespace namespace.
// Errors are collected, i.e. it's not failing on first error.
func syncObservedResources(syncResource resourceSyncFunc, syncRules syncActionRules) []error {
	var errs []error
	for to, from := range syncRules {
		var source resourcesynccontroller.ResourceLocation
		if len(from) > 0 {
			source = resourcesynccontroller.ResourceLocation{Namespace: "openshift-config", Name: from}
		}
		// if 'from' is empty, then it means we want to delete
		destination := resourcesynccontroller.ResourceLocation{Namespace: "openshift-authentication", Name: to}
		if err := syncResource(destination, source); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (c *customRouterObserver) componentRouteSecret(lister configobservation.Listers, ingress *configv1.Ingress) ([]interface{}, syncActionRules, error) {
	componentRoutes := []interface{}{}

	rules := syncActionRules{}

	// make sure the output slice of named certs is sorted by domain so that the generated config is deterministic
	for _, componentRoute := range ingress.Spec.ComponentRoutes {
		if componentRoute.Name == c.componentRoute.Name &&
			componentRoute.Namespace == c.componentRoute.Namespace {
			if _, err := lister.SecretsLister.Secrets("openshift-config").Get(componentRoute.ServingCertKeyPairSecret.Name); err != nil ||
				componentRoute.ServingCertKeyPairSecret.Name == "" {
				rules[c.destSecret] = ""
			} else {
				componentRoutes = append(componentRoutes, map[string]interface{}{
					"secret":   interface{}(componentRoute.ServingCertKeyPairSecret.Name),
					"hostname": interface{}(string(componentRoute.Hostname)),
				})
				rules[c.destSecret] = componentRoute.ServingCertKeyPairSecret.Name
			}
			return componentRoutes, rules, nil
		}
	}
	return nil, nil, nil
}
