package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/accessanalyzer"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsAccessAnalyzerTestCases)
}

var awsAccessAnalyzerTestCases = testCases{
	"AVD-AWS-0175": {
		// TODO: Tunnel does not export empty structures into Rego
		// {

		// 	name:     "No analyzers enabled",
		// 	input:    state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{}}},
		// 	expected: true,
		// },
		{
			name: "Analyzer disabled",
			input: state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ARN:      tunnelTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", tunnelTypes.NewTestMetadata()),
						Name:     tunnelTypes.String("test", tunnelTypes.NewTestMetadata()),
						Active:   tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Analyzer enabled",
			input: state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ARN:      tunnelTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", tunnelTypes.NewTestMetadata()),
						Name:     tunnelTypes.String("test", tunnelTypes.NewTestMetadata()),
						Active:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				}}},
			},
			expected: false,
		},
	},
}
