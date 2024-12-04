package test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/khulnasoft/tunnel/pkg/iac/rego"
	"github.com/khulnasoft/tunnel/pkg/iac/scanners/dockerfile"
	"github.com/khulnasoft/tunnel/pkg/iac/scanners/options"
	"github.com/stretchr/testify/require"

	builtinrego "github.com/khulnasoft/tunnel-checks/pkg/rego"
)

func init() {
	builtinrego.RegisterBuiltins()
}

func Test_Dockerfile(t *testing.T) {
	tests := []struct {
		name string
		opts []options.ScannerOption
	}{
		{
			name: "checks from disk",
			opts: []options.ScannerOption{
				rego.WithPolicyFilesystem(os.DirFS("../checks/docker")),
				rego.WithPolicyDirs("."),
			},
		},
		{
			name: "embedded checks",
			opts: []options.ScannerOption{
				rego.WithEmbeddedPolicies(true),
			},
		},
	}

	testdata := "./testdata/dockerfile"

	entries, err := os.ReadDir(testdata)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := []options.ScannerOption{
				rego.WithPerResultTracing(true),
				rego.WithEmbeddedLibraries(true),
			}
			opts = append(opts, tt.opts...)

			scanner := dockerfile.NewScanner(opts...)

			results, err := scanner.ScanFS(context.TODO(), os.DirFS(testdata), ".")
			require.NoError(t, err)

			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}

				dirName := entry.Name()

				t.Run(entry.Name(), func(t *testing.T) {
					assertChecks(t, dirName,
						fmt.Sprintf("%s/Dockerfile.denied", dirName),
						fmt.Sprintf("%s/Dockerfile.allowed", dirName),
						results,
					)
				})
			}
		})
	}
}
