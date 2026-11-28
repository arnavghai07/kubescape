package diff

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintGitHubActions_Posture(t *testing.T) {
	summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
	t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID:   "apps/v1/default/Deployment/web",
				ControlID:    "C-0017",
				ControlName:  "Immutable container filesystem",
				Severity:     "High",
				BaseStatus:   "passed",
				HeadStatus:   "failed",
				RuleName:     "immutable-container-filesystem",
				EvidenceType: "failedPath",
				Path:         "spec.containers[0].securityContext.privileged",
			},
			{
				ResourceID: "v1/default/Pod/low-pod",
				ControlID:  "C-LOW",
				Severity:   "Low",
				BaseStatus: "passed",
				HeadStatus: "failed",
			},
		},
		Incomparable: []ControlChange{
			{
				ResourceID: "apps/v1/default/Deployment/api",
				ControlID:  "C-CRIT",
				Severity:   "Critical",
				HeadStatus: "failed",
				Reason:     "line1\nline2\x1b[31m",
			},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitHubActions(&out, cs, "High"))

	got := out.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	require.Len(t, lines, 2, "Low finding must be filtered out; expected 1 incomparable + 1 new")

	assert.Contains(t, lines[0], "::error title=Kubescape incomparable regression%3A C-CRIT (Critical)::")
	assert.Contains(t, lines[0], "line1%0Aline2[31m")
	assert.NotContains(t, lines[0], "\x1b")

	// The evidence path is a field inside the resource, not a repository file:
	// it must stay out of file= and appear in the message instead.
	assert.True(t, strings.HasPrefix(lines[1], "::error title=Kubescape new regression%3A C-0017 (High)::"), lines[1])
	assert.NotContains(t, lines[1], "file=")
	assert.Contains(t, lines[1], "resource=apps/v1/default/Deployment/web")
	assert.Contains(t, lines[1], "control=C-0017; severity=High; base=passed; head=failed; name=Immutable container filesystem")
	assert.Contains(t, lines[1], "rule=immutable-container-filesystem; evidence=failedPath; path=spec.containers[0].securityContext.privileged")

	summaryBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.Contains(t, string(summaryBytes), "# Kubescape Diff Regressions")
	assert.Contains(t, string(summaryBytes), "C-0017")
	assert.Contains(t, string(summaryBytes), "C-CRIT")
	assert.NotContains(t, string(summaryBytes), "C-LOW")
}

func TestPrintGitHubActions_AnnotationCapAndTruncationWarning(t *testing.T) {
	t.Setenv(githubActionsStepSummaryEnvVar, "")

	cs := &ChangeSet{}
	for i := 0; i < 12; i++ {
		cs.New = append(cs.New, ControlChange{
			ResourceID: fmt.Sprintf("v1/default/Pod/p-%02d", i),
			ControlID:  "C-0017",
			Severity:   "High",
			BaseStatus: "passed",
			HeadStatus: "failed",
		})
	}

	var out bytes.Buffer
	require.NoError(t, PrintGitHubActions(&out, cs, "High"))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 11)
	for i := 0; i < 10; i++ {
		assert.True(t, strings.HasPrefix(lines[i], "::error "))
	}
	assert.Equal(t, "::warning title=Kubescape Diff::Showing 10 of 12 regressions; see the step summary or rerun with --format markdown for the full list.", lines[10])
}

// TestPrintGitHubActions_FromReports runs real posture reports through
// ComputeWithOptions and PrintGitHubActions, so ControlChange.Path holds what
// the evidence pipeline actually puts there (a field path in the resource).
func TestPrintGitHubActions_FromReports(t *testing.T) {
	t.Setenv(githubActionsStepSummaryEnvVar, "")

	const report = `{
  "results": [{
    "resourceID": "/v1/default/Pod/web",
    "controls": [{
      "controlID": "C-0057",
      "name": "Privileged container",
      "status": {"status": %q},
      "rules": [{"name": "rule-privilege-escalation", "status": %q%s}]
    }]
  }],
  "summaryDetails": {"controls": {"C-0057": {"scoreFactor": 7}}}
}`
	base := writeRawReport(t, fmt.Sprintf(report, "passed", "passed", ""))
	head := writeRawReport(t, fmt.Sprintf(report, "failed", "failed",
		`, "paths": [{"failedPath": "spec.containers[0].securityContext.privileged", "resourceID": "/v1/default/Pod/web"}]`))

	tests := []struct {
		granularity Granularity
		want        string
	}{
		{
			granularity: GranularityEvidence,
			want: "::error title=Kubescape new regression%3A C-0057 (High)::" +
				"resource=/v1/default/Pod/web; control=C-0057; severity=High; base=passed; head=failed; name=Privileged container; " +
				"rule=rule-privilege-escalation; evidence=failedPath; path=spec.containers[0].securityContext.privileged",
		},
		{
			granularity: GranularityControl,
			want: "::error title=Kubescape new regression%3A C-0057 (High)::" +
				"resource=/v1/default/Pod/web; control=C-0057; severity=High; base=passed; head=failed; name=Privileged container",
		},
	}
	for _, tc := range tests {
		t.Run(string(tc.granularity), func(t *testing.T) {
			cs, err := ComputeWithOptions(base, head, Options{Granularity: tc.granularity})
			require.NoError(t, err)

			var out bytes.Buffer
			require.NoError(t, PrintGitHubActions(&out, cs, ""))

			assert.Equal(t, tc.want+"\n", out.String())
			assert.NotContains(t, out.String(), "file=")
		})
	}
}

// TestPrintGitHubActions_EvidenceVariants checks that every evidence type is
// rendered in the message (fixCommand as a command, not a path) and that
// workflow-command metacharacters in evidence cannot break the annotation.
func TestPrintGitHubActions_EvidenceVariants(t *testing.T) {
	t.Setenv(githubActionsStepSummaryEnvVar, "")

	tests := []struct {
		name        string
		change      ControlChange
		wantTitle   string
		wantMessage string
		notInMsg    []string
	}{
		{
			name:        "reviewPath",
			change:      ControlChange{EvidenceType: "reviewPath", Path: "spec.serviceAccountName"},
			wantMessage: "evidence=reviewPath; path=spec.serviceAccountName",
		},
		{
			name:        "deletePath",
			change:      ControlChange{EvidenceType: "deletePath", Path: "spec.containers[0].securityContext.capabilities.add[0]"},
			wantMessage: "evidence=deletePath; path=spec.containers[0].securityContext.capabilities.add[0]",
		},
		{
			name:        "fixPath",
			change:      ControlChange{EvidenceType: "fixPath", Path: "spec.containers[0].securityContext.readOnlyRootFilesystem"},
			wantMessage: "evidence=fixPath; path=spec.containers[0].securityContext.readOnlyRootFilesystem",
		},
		{
			name: "fixCommand with workflow metacharacters",
			change: ControlChange{
				EvidenceType: "fixCommand",
				Path:         "kubectl label ns default a=b,c:d --overwrite 100%\nkubectl get ns\x1b[0m",
			},
			wantMessage: "evidence=fixCommand; command=kubectl label ns default a=b,c:d --overwrite 100%25%0Akubectl get ns[0m",
			notInMsg:    []string{"path="},
		},
		{
			name: "special characters in path and control ID",
			change: ControlChange{
				ControlID:    "C-0001,x:y",
				EvidenceType: "failedPath",
				Path:         "metadata.annotations[\"a,b:c%d\"]\r\nx",
			},
			wantTitle:   "::error title=Kubescape new regression%3A C-0001%2Cx%3Ay (High)::",
			wantMessage: "evidence=failedPath; path=metadata.annotations[\"a,b:c%25d\"]%0D%0Ax",
		},
		{
			name: "evidence on a related resource",
			change: ControlChange{
				EvidenceType:       "failedPath",
				Path:               "rules[0].verbs[0]",
				EvidenceResourceID: "rbac.authorization.k8s.io/v1//ClusterRole/admin",
			},
			wantMessage: "evidence=failedPath; path=rules[0].verbs[0]; evidenceResource=rbac.authorization.k8s.io/v1//ClusterRole/admin",
		},
		{
			name:        "rule evidence without a path",
			change:      ControlChange{RuleName: "rule-a", EvidenceType: "rule"},
			wantMessage: "rule=rule-a; evidence=rule",
			notInMsg:    []string{"path=", "command="},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.change
			c.ResourceID = "v1/default/Pod/web"
			if c.ControlID == "" {
				c.ControlID = "C-0017"
			}
			c.Severity = "High"
			c.BaseStatus = "passed"
			c.HeadStatus = "failed"

			var out bytes.Buffer
			require.NoError(t, PrintGitHubActions(&out, &ChangeSet{New: []ControlChange{c}}, "High"))

			got := out.String()
			require.Equal(t, 1, strings.Count(got, "\n"), "evidence must not split the workflow command: %q", got)
			assert.NotContains(t, got, "\r")
			assert.NotContains(t, got, "\x1b")
			assert.NotContains(t, got, "file=")

			wantTitle := tc.wantTitle
			if wantTitle == "" {
				wantTitle = "::error title=Kubescape new regression%3A C-0017 (High)::"
			}
			require.True(t, strings.HasPrefix(got, wantTitle), got)
			msg := strings.TrimSuffix(strings.TrimPrefix(got, wantTitle), "\n")
			assert.Contains(t, msg, tc.wantMessage)
			for _, s := range tc.notInMsg {
				assert.NotContains(t, msg, s)
			}
		})
	}
}

func TestPrintVulnerabilityGitHubActions(t *testing.T) {
	summaryFile := filepath.Join(t.TempDir(), "vuln-summary.md")
	t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

	cs := &VulnerabilityChangeSet{
		BaseImages: []string{"app:1.0"},
		HeadImages: []string{"app:1.1"},
		New: []VulnerabilityChange{
			{ID: "CVE-LOW", Severity: "Low", Package: "zlib", Version: "1.0"},
			{ID: "CVE-CRIT", Severity: "Critical", Package: "openssl", Version: "3.0.1", FixedIn: []string{"3.0.2"}},
			{ID: "CVE-HIGH", Severity: "High", Package: "curl", Version: "8.0.0"},
		},
	}

	var out bytes.Buffer
	require.NoError(t, PrintVulnerabilityGitHubActions(&out, cs, "High"))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "::error title=Kubescape new vulnerability%3A CVE-CRIT (Critical)::package=openssl version=3.0.1 fix=3.0.2")
	assert.Contains(t, lines[1], "::error title=Kubescape new vulnerability%3A CVE-HIGH (High)::package=curl version=8.0.0 fix=none")

	summaryBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.Contains(t, string(summaryBytes), "CVE-CRIT")
	assert.Contains(t, string(summaryBytes), "CVE-HIGH")
	assert.NotContains(t, string(summaryBytes), "CVE-LOW")
}

func TestAppendStepSummary_ExistingFileSizeBudget(t *testing.T) {
	t.Run("truncates append to remaining capacity", func(t *testing.T) {
		summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
		existing := strings.Repeat("a", 600*1024)
		require.NoError(t, os.WriteFile(summaryFile, []byte(existing), 0o600))
		t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

		payload := strings.Repeat("b", 600*1024)
		require.NoError(t, appendStepSummary(func() (string, error) {
			return payload, nil
		}))

		got, err := os.ReadFile(summaryFile)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(got), githubActionsMaxStepSummaryBytes)
		assert.True(t, strings.HasPrefix(string(got), existing))
		assert.True(t, strings.HasSuffix(string(got), githubActionsSummaryTruncatedNote))
	})

	t.Run("preserves existing content when no capacity remains", func(t *testing.T) {
		summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
		existing := strings.Repeat("x", githubActionsMaxStepSummaryBytes)
		require.NoError(t, os.WriteFile(summaryFile, []byte(existing), 0o600))
		t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

		require.NoError(t, appendStepSummary(func() (string, error) {
			return "extra summary", nil
		}))

		got, err := os.ReadFile(summaryFile)
		require.NoError(t, err)
		assert.Equal(t, existing, string(got))
	})
}

func TestAppendStepSummary_TruncatesAtUTF8RuneBoundary(t *testing.T) {
	summaryFile := filepath.Join(t.TempDir(), "step-summary.md")
	// Leave room for 4 bytes of content plus the truncation note, then supply
	// a payload larger than remaining starting with two 3-byte UTF-8 runes ("€€", 6 bytes)
	// so byte offset 4 splits the second rune.
	existingLen := githubActionsMaxStepSummaryBytes - len(githubActionsSummaryTruncatedNote) - 4
	existing := strings.Repeat("a", existingLen)
	require.NoError(t, os.WriteFile(summaryFile, []byte(existing), 0o600))
	t.Setenv(githubActionsStepSummaryEnvVar, summaryFile)

	payload := "€€" + strings.Repeat("z", len(githubActionsSummaryTruncatedNote)+10)
	require.NoError(t, appendStepSummary(func() (string, error) {
		return payload, nil
	}))

	got, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.True(t, utf8.Valid(got), "truncated summary must remain valid UTF-8")
	assert.LessOrEqual(t, len(got), githubActionsMaxStepSummaryBytes)
	assert.Equal(t, existing+"€"+githubActionsSummaryTruncatedNote, string(got))
}
