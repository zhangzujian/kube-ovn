package cnp

import (
	"context"
	"fmt"
	"reflect"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

// ValidateSchemaObjects uses the API server's OpenAPI, structural pruning,
// defaulting and CEL validators before a schema change can affect storage.
func ValidateSchemaObjects(ctx context.Context, crd *unstructured.Unstructured, objects []unstructured.Unstructured) error {
	var external apiextensionsv1.CustomResourceDefinition
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(crd.Object, &external); err != nil {
		return err
	}
	var schema apiextensions.JSONSchemaProps
	if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(external.Spec.Versions[0].Schema.OpenAPIV3Schema, &schema, nil); err != nil {
		return err
	}
	structural, err := structuralschema.NewStructural(&schema)
	if err != nil {
		return err
	}
	validator, _, err := validation.NewSchemaValidator(&schema)
	if err != nil {
		return err
	}
	celValidator := cel.NewValidator(structural, true, celconfig.PerCallLimit)
	for _, obj := range objects {
		pruned := obj.DeepCopy()
		pruning.Prune(pruned.Object, structural, true)
		if !reflect.DeepEqual(pruned.Object, obj.Object) {
			return fmt.Errorf("target schema would prune fields from CNP %s", obj.GetName())
		}
		defaulting.Default(pruned.Object, structural)
		if errs := validation.ValidateCustomResource(field.NewPath(""), pruned.Object, validator); len(errs) != 0 {
			return fmt.Errorf("CNP %s fails target schema: %w", obj.GetName(), errs.ToAggregate())
		}
		if celValidator != nil {
			errs, _ := celValidator.Validate(ctx, field.NewPath(""), structural, pruned.Object, nil, celconfig.RuntimeCELCostBudget)
			if len(errs) != 0 {
				return fmt.Errorf("CNP %s fails target CEL: %w", obj.GetName(), errs.ToAggregate())
			}
		}
	}
	return nil
}
