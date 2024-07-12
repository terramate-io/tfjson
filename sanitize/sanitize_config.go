package sanitize

import "github.com/terramate-io/tfjson"

// SanitizeProviderConfigs sanitises the constant_value from expressions of the provider_configs to the value set in replaceWith parameter.
func SanitizeProviderConfigs(configs map[string]*tfjson.ProviderConfig, replaceWith interface{}) (map[string]*tfjson.ProviderConfig, error) {
	result := make(map[string]*tfjson.ProviderConfig, len(configs))
	for k, v := range configs {
		cfg, err := SanitizeProviderConfig(v, replaceWith)
		if err != nil {
			return nil, err
		}
		result[k] = cfg
	}
	return result, nil
}

// SanitizeProviderConfig sanitises the constant_value from expressions of the provider_config to the value set in replaceWith parameter.
func SanitizeProviderConfig(old *tfjson.ProviderConfig, replaceWith interface{}) (*tfjson.ProviderConfig, error) {
	result, err := copyProviderConfig(old)
	if err != nil {
		return nil, err
	}
	for _, expression := range result.Expressions {
		sanitizeExpression(expression, replaceWith)
	}
	return result, nil
}

// SanitizeConfigOutputs sanitises the constant_value from the expression of the outputs.
func SanitizeConfigOutputs(old map[string]*tfjson.ConfigOutput, replaceWith interface{}) (map[string]*tfjson.ConfigOutput, error) {
	outputs := make(map[string]*tfjson.ConfigOutput, len(old))
	for name, output := range old {
		output, err := copyConfigOutput(output)
		if err != nil {
			return nil, err
		}
		if output.Sensitive {
			sanitizeExpression(output.Expression, replaceWith)
		}
		outputs[name] = output
	}
	return outputs, nil
}

// SanitizeConfigVariables sanitizes the variables config.
func SanitizeConfigVariables(old map[string]*tfjson.ConfigVariable, replaceWith interface{}) (map[string]*tfjson.ConfigVariable, error) {
	variables := make(map[string]*tfjson.ConfigVariable, len(old))
	for name, variable := range old {
		v, err := copyConfigVariable(variable)
		if err != nil {
			return nil, err
		}
		if v.Sensitive && v.Default != nil {
			v.Default = replaceWith
		}
		variables[name] = v
	}
	return variables, nil
}

func SanitizeModuleResourceProvisioners(old []*tfjson.ConfigResource, replaceWith interface{}) ([]*tfjson.ConfigResource, error) {
	resources := make([]*tfjson.ConfigResource, len(old))
	for i, res := range old {
		r, err := copyConfigResource(res)
		if err != nil {
			return nil, err
		}
		for _, prov := range r.Provisioners {
			for _, expr := range prov.Expressions {
				sanitizeExpression(expr, replaceWith)
			}
		}
		resources[i] = r
	}
	return resources, nil
}

func sanitizeExpression(expression *tfjson.Expression, replaceWith interface{}) {
	if expression == nil || expression.ExpressionData == nil {
		return
	}
	if expression.ConstantValue != tfjson.UnknownConstantValue {
		expression.ConstantValue = replaceWith
	}
	for _, block := range expression.NestedBlocks {
		for _, expr := range block {
			sanitizeExpression(expr, replaceWith)
		}
	}
}
