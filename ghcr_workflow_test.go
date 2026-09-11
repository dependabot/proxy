package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type ghcrWorkflow struct {
	On          map[string]map[string][]string `yaml:"on"`
	Env         map[string]string              `yaml:"env"`
	Permissions map[string]string              `yaml:"permissions"`
	Jobs        map[string]ghcrWorkflowJob     `yaml:"jobs"`
}

type ghcrWorkflowJob struct {
	If          string             `yaml:"if"`
	Permissions map[string]string  `yaml:"permissions"`
	Steps       []ghcrWorkflowStep `yaml:"steps"`
}

type ghcrWorkflowStep struct {
	ID              string            `yaml:"id"`
	Uses            string            `yaml:"uses"`
	If              string            `yaml:"if"`
	ContinueOnError bool              `yaml:"continue-on-error"`
	With            map[string]string `yaml:"with"`
	Env             map[string]string `yaml:"env"`
	Run             string            `yaml:"run"`
}

func ghcrStepWithID(t *testing.T, steps []ghcrWorkflowStep, id string) (int, ghcrWorkflowStep) {
	t.Helper()
	for index, step := range steps {
		if step.ID == id {
			return index, step
		}
	}
	t.Fatalf("missing publication step %q", id)
	return -1, ghcrWorkflowStep{}
}

func TestGHCRPublicationWorkflow(t *testing.T) {
	content, err := os.ReadFile(".github/workflows/ghcr.yml")
	require.NoError(t, err)

	var workflow ghcrWorkflow
	require.NoError(t, yaml.Unmarshal(content, &workflow))
	publish, ok := workflow.Jobs["publish"]
	require.True(t, ok)

	t.Run("restricts publication and credentials", func(t *testing.T) {
		assert.Equal(t, map[string]map[string][]string{"push": {"branches": {"main"}}}, workflow.On)
		assert.Equal(t, "github.repository == 'dependabot/proxy'", publish.If)
		assert.Empty(t, workflow.Permissions)
		assert.Equal(t, "ghcr.io/dependabot/proxy", workflow.Env["REMOTE_IMAGE"])
		assert.Equal(t, map[string]string{
			"contents":          "write",
			"packages":          "write",
			"id-token":          "write",
			"attestations":      "write",
			"artifact-metadata": "write",
		}, publish.Permissions)

		for _, step := range publish.Steps {
			if step.Uses != "" {
				assert.Regexp(t, `^[^@]+@[0-9a-f]{40}$`, step.Uses)
			}
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				assert.Equal(t, "false", step.With["persist-credentials"])
			}
		}
	})

	t.Run("pushes the production image without release tags", func(t *testing.T) {
		_, build := ghcrStepWithID(t, publish.Steps, "build")
		assert.True(t, strings.HasPrefix(build.Uses, "docker/build-push-action@"))
		assert.Equal(t, ".", build.With["context"])
		assert.Equal(t, "linux/amd64", build.With["platforms"])
		assert.Empty(t, build.With["target"])
		assert.Empty(t, build.With["tags"])
		assert.Equal(t, "false", build.With["provenance"])
		assert.Equal(t, "false", build.With["sbom"])
		assert.Equal(t, "type=inline", build.With["cache-to"])
		assert.Contains(t, build.With["build-args"], "GIT_COMMIT=${{ github.sha }}")
		assert.ElementsMatch(t, []string{
			"type=image",
			"name=${{ env.REMOTE_IMAGE }}",
			"push-by-digest=true",
			"name-canonical=true",
			"push=true",
			"oci-mediatypes=false",
		}, strings.Split(build.With["outputs"], ","))
	})

	t.Run("requires a digest-bound attestation before release tags", func(t *testing.T) {
		buildIndex, _ := ghcrStepWithID(t, publish.Steps, "build")
		digestIndex, digest := ghcrStepWithID(t, publish.Steps, "digest")
		attestIndex, attest := ghcrStepWithID(t, publish.Steps, "attest")
		versionIndex, version := ghcrStepWithID(t, publish.Steps, "version")
		tagsIndex, tags := ghcrStepWithID(t, publish.Steps, "tags")
		gitTagIndex, gitTag := ghcrStepWithID(t, publish.Steps, "git_tag")

		assert.Less(t, buildIndex, digestIndex)
		assert.Less(t, digestIndex, attestIndex)
		assert.Less(t, attestIndex, versionIndex)
		assert.Less(t, versionIndex, tagsIndex)
		assert.Less(t, tagsIndex, gitTagIndex)

		assert.Equal(t, "${{ steps.build.outputs.digest }}", digest.Env["IMAGE_DIGEST"])
		assert.Contains(t, digest.Run, "^sha256:[0-9a-f]{64}$")
		assert.Contains(t, digest.Run, "exit 1")

		assert.True(t, strings.HasPrefix(attest.Uses, "actions/attest@"))
		assert.Equal(t, "${{ env.REMOTE_IMAGE }}", attest.With["subject-name"])
		assert.Equal(t, "${{ steps.build.outputs.digest }}", attest.With["subject-digest"])
		assert.Equal(t, "true", attest.With["push-to-registry"])
		assert.Equal(t, "true", attest.With["create-storage-record"])
		assert.Empty(t, attest.With["subject-path"])

		assert.Contains(t, version.Run, "v2.0.")
		assert.Contains(t, version.Run, "%Y%m%d%H%M%S")
		assert.Equal(t, "${{ steps.build.outputs.digest }}", tags.Env["IMAGE_DIGEST"])
		assert.Equal(t, "${{ steps.version.outputs.version }}", tags.Env["VERSION"])
		assert.Contains(t, tags.Run, "docker buildx imagetools create")
		assert.Contains(t, tags.Run, "--prefer-index=false")
		assert.Contains(t, tags.Run, `"${REMOTE_IMAGE}:${VERSION}"`)
		assert.Contains(t, tags.Run, `"${REMOTE_IMAGE}:latest"`)
		assert.Contains(t, tags.Run, `"${REMOTE_IMAGE}@${IMAGE_DIGEST}"`)

		assert.Equal(t, "${{ steps.version.outputs.version }}", gitTag.Env["VERSION"])
		assert.Equal(t, "${{ secrets.GITHUB_TOKEN }}", gitTag.Env["GH_TOKEN"])
		assert.Contains(t, gitTag.Run, "gh api --method POST")
		assert.Contains(t, gitTag.Run, "repos/${GITHUB_REPOSITORY}/git/refs")
		assert.Contains(t, gitTag.Run, "ref=refs/tags/${VERSION}")
		assert.Contains(t, gitTag.Run, "sha=${GITHUB_SHA}")

		for _, step := range publish.Steps {
			assert.False(t, step.ContinueOnError, "step %q must propagate failure", step.ID)
			assert.Empty(t, step.If, "step %q must use the default success condition", step.ID)
		}
	})
}
