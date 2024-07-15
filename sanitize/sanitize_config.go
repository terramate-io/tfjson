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

func sanitizeModuleConfig(module *tfjson.ConfigModule, replaceWith interface{}) error {
	var err error
	module.Variables, err = SanitizeConfigVariables(module.Variables, replaceWith)
	if err != nil {
		return err
	}

	for _, res := range module.Resources {
		sanitizeResourceConfig(res, replaceWith)
	}

	for _, mod := range module.ModuleCalls {
		for name, expr := range mod.Expressions {
			if mod.Module.Variables == nil {
				// NOTE(i4k): this should never happen because a module always define all its input.
				// but in case we are dealing with a pre-processed JSON, this ensures
				// we don't leak variables missing definitions.
				sanitizeExpression(expr, replaceWith)
			}
			if varConfig, ok := mod.Module.Variables[name]; ok && varConfig.Sensitive {
				sanitizeExpression(expr, replaceWith)
			}
		}

		sanitizeModuleConfig(mod.Module, replaceWith)
	}

	return nil
}

func sanitizeResourceConfig(r *tfjson.ConfigResource, replaceWith interface{}) {
	for _, prov := range r.Provisioners {
		for _, expr := range prov.Expressions {
			sanitizeExpression(expr, replaceWith)
		}
	}
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
