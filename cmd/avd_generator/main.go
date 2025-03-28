package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/khulnasoft/tunnel-checks/internal/examples"
	"github.com/khulnasoft/tunnel/pkg/iac/framework"
	"github.com/khulnasoft/tunnel/pkg/iac/rego"
	"github.com/khulnasoft/tunnel/pkg/iac/rules"
	"github.com/khulnasoft/tunnel/pkg/iac/scan"
	types "github.com/khulnasoft/tunnel/pkg/iac/types/rules"
)

func main() {
	generateDocs("avd_docs")
}

func generateDocs(path string) {
	var generateCount int

	// Clean up all Go checks
	rules.Reset()

	// Load Rego checks
	rego.LoadAndRegister()

	for _, metadata := range rules.GetRegistered(framework.ALL) {
		writeDocsFile(metadata, path)
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in %s\n", generateCount, path)
}

// nolint: cyclop
func writeDocsFile(meta types.RegisteredRule, path string) {

	tmpl, err := template.New("defsec").Parse(docsMarkdownTemplate)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}

	rule := meta.GetRule()

	docpath := filepath.Join(path,
		strings.ToLower(rule.Provider.ConstName()),
		strings.ToLower(strings.ReplaceAll(rule.Service, "-", "")),
		rule.AVDID,
	)

	if err := os.MkdirAll(docpath, os.ModePerm); err != nil {
		panic(err)
	}

	file, err := os.Create(filepath.Join(docpath, "docs.md"))
	if err != nil {
		fail("error occurred creating the docs file for %s", docpath)
	}

	if err := tmpl.Execute(file, rule); err != nil {
		fail("error occurred generating the document %s", err.Error())
	}
	fmt.Printf("Generating docs file for policy %s\n", rule.AVDID)

	exmpls, path, err := examples.GetCheckExamples(rule)
	if err != nil {
		fail("failed to get check examples: %s", err.Error())
	}

	if path == "" {
		return
	}

	if err := generateExamplesForEngine(rule, rule.Terraform, exmpls, docpath, terraformMarkdownTemplate, "Terraform"); err != nil {
		fail("error generating examples for terraform: %v\n", err)
	}

	if err := generateExamplesForEngine(rule, rule.CloudFormation, exmpls, docpath, cloudformationMarkdownTemplate, "CloudFormation"); err != nil {
		fail("error generating examples for cloudformation: %v\n", err)
	}
}

func generateExamplesForEngine(rule scan.Rule, engine *scan.EngineMetadata, exmpls examples.CheckExamples, docpath, tpl, provider string) error {

	providerExampls := exmpls[strings.ToLower(provider)]

	if providerExampls.IsEmpty() {
		return nil
	}

	engine.GoodExamples = providerExampls.Good.ToStrings()

	for i := range engine.GoodExamples {
		engine.GoodExamples[i] = "\n" + engine.GoodExamples[i]
	}
	tmpl, err := template.New(strings.ToLower(provider)).Parse(tpl)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}
	file, err := os.Create(filepath.Join(docpath, fmt.Sprintf("%s.md", provider)))
	if err != nil {
		fail("error occurred creating the %s file for %s", provider, docpath)
	}
	defer file.Close()

	if err := tmpl.Execute(file, rule); err != nil {
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating %s file for policy %s\n", provider, rule.AVDID)

	return nil
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

var docsMarkdownTemplate = `
{{ .Explanation }}

### Impact
{{ if .Impact }}{{ .Impact }}{{ else }}<!-- Add Impact here -->{{ end }}

<!-- DO NOT CHANGE -->
{{ ` + "`{{ " + `remediationActions ` + "`}}" + `}}

{{ if .Links }}### Links{{ range .Links }}
- {{ . }}
{{ end}}
{{ end }}
`

var terraformMarkdownTemplate = `
{{ .Resolution }}

{{ if .Terraform.GoodExamples }}{{ range .Terraform.GoodExamples }}` + "```hcl" + `{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .Terraform.Links }}#### Remediation Links{{ range .Terraform.Links }}
 - {{ . }}
{{ end}}{{ end }}
`

var cloudformationMarkdownTemplate = `
{{ .Resolution }}

{{ if .CloudFormation.GoodExamples }}{{ range .CloudFormation.GoodExamples }}` + "```yaml" + `{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .CloudFormation.Links }}#### Remediation Links{{ range .CloudFormation.Links }}
 - {{ . }}
{{ end}}{{ end }}
`
