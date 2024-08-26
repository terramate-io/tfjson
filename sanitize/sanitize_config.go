package sanitize

import "github.com/terramate-io/tfjson"

// SanitizeProviderConfigs sanitises the constant_value from expressions of the provider_configs to the value set in replaceWith parameter.
func SanitizeProviderConfigs(result map[string]*tfjson.ProviderConfig, replaceWith interface{}) {
	for _, v := range result {
		SanitizeProviderConfig(v, replaceWith)
	}
}

// SanitizeProviderConfig sanitises the constant_value from expressions of the provider_config to the value set in replaceWith parameter.
func SanitizeProviderConfig(result *tfjson.ProviderConfig, replaceWith interface{}) {
	if result == nil {
		return
	}

	for _, expression := range result.Expressions {
		sanitizeExpression(expression, replaceWith)
	}
}

// SanitizeConfigOutputs sanitises the constant_value from the expression of the outputs.
func SanitizeConfigOutputs(outputs map[string]*tfjson.ConfigOutput, replaceWith interface{}) {
	for _, output := range outputs {
		if output != nil && output.Sensitive {
			sanitizeExpression(output.Expression, replaceWith)
		}
	}
}

// SanitizeConfigVariables sanitizes the variables config.
func SanitizeConfigVariables(result map[string]*tfjson.ConfigVariable, replaceWith interface{}) {
	for _, v := range result {
		if v != nil && v.Sensitive && v.Default != nil {
			v.Default = replaceWith
		}
	}
}

func sanitizeModuleConfig(module *tfjson.ConfigModule, replaceWith interface{}) {
	if module == nil {
		return
	}

	SanitizeConfigVariables(module.Variables, replaceWith)

	for _, res := range module.Resources {
		sanitizeResourceConfig(res, replaceWith)
	}

	for _, mod := range module.ModuleCalls {
		if mod == nil || mod.Module == nil {
			continue
		}
		for name, expr := range mod.Expressions {
			if expr == nil {
				continue
			}
			if mod.Module.Variables == nil {
				// NOTE(i4k): this should never happen because a module always define all its input.
				// but in case we are dealing with a pre-processed JSON, this ensures
				// we don't leak variables missing definitions.
				sanitizeExpression(expr, replaceWith)
			} else if varConfig, ok := mod.Module.Variables[name]; ok && varConfig.Sensitive {
				sanitizeExpression(expr, replaceWith)
			}
		}

		sanitizeModuleConfig(mod.Module, replaceWith)
	}

	// Sanitize outputs
	SanitizeConfigOutputs(module.Outputs, replaceWith)
}

func sanitizeResourceConfig(r *tfjson.ConfigResource, replaceWith interface{}) {
	for _, prov := range r.Provisioners {
		if prov == nil {
			continue
		}
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
