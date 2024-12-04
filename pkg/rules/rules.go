package rules

import (
	"github.com/khulnasoft/tunnel/pkg/iac/scan"
)

var rules []scan.Rule

func Register(r scan.Rule, f scan.CheckFunc) scan.Rule {
	r.Check = f
	rules = append(rules, r)

	return r
}

func GetRules() []scan.Rule {
	return rules
}
