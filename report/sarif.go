package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/mkmuniz/nadzor/detect"
)

// SARIF is emitted by hand rather than through a library, and deliberately.
//
// It is the format GitHub Code Scanning consumes, and betterleaks is removing
// it in v2 — which is exactly why nadzor should own it rather than inherit it.
// The schema below is SARIF 2.1.0, restricted to the properties GitHub reads.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifText          `json:"shortDescription"`
	FullDescription  sarifText          `json:"fullDescription,omitempty"`
	Help             sarifText          `json:"help,omitempty"`
	Properties       sarifRuleProps     `json:"properties,omitempty"`
	DefaultConfig    sarifRuleConfig    `json:"defaultConfiguration,omitempty"`
	Relationships    []sarifRuleRelated `json:"relationships,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level,omitempty"`
}

type sarifRuleProps struct {
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
}

type sarifRuleRelated struct{}

type sarifText struct {
	Text string `json:"text,omitempty"`
}

type sarifResult struct {
	RuleID          string              `json:"ruleId"`
	RuleIndex       int                 `json:"ruleIndex"`
	Level           string              `json:"level"`
	Message         sarifText           `json:"message"`
	Locations       []sarifLocation     `json:"locations,omitempty"`
	PartialFingerps map[string]string   `json:"partialFingerprints,omitempty"`
	Properties      map[string]string   `json:"properties,omitempty"`
	Fixes           []map[string]string `json:"fixes,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool         `json:"executionSuccessful"`
	ToolExecutionNotifs []sarifNotif `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotif struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// WriteSARIF emits the run as SARIF 2.1.0.
//
// Two decisions worth knowing about:
//
// The message never contains the value, only its redacted form — SARIF output
// is uploaded to GitHub and rendered in a web UI, which makes it exactly the
// kind of destination ADR-003 is about.
//
// partialFingerprints carries nadzor's own fingerprint, which is derived from
// the type and the normalized value and never from the location. That is what
// lets GitHub track a finding as the same alert after the file moves or lines
// are inserted above it.
func WriteSARIF(w io.Writer, run Run) error {
	findings := bySeverity(run.Findings)
	rules, index := sarifRules(findings)

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResultOf(f, index[f.Type]))
	}

	invocation := sarifInvocation{ExecutionSuccessful: len(run.Errors) == 0}
	for _, e := range run.Errors {
		invocation.ToolExecutionNotifs = append(invocation.ToolExecutionNotifs, sarifNotif{
			Level:   "error",
			Message: sarifText{Text: e},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           run.Tool,
				Version:        run.Version,
				InformationURI: "https://github.com/mkmuniz/nadzor",
				Rules:          rules,
			}},
			Results:     results,
			Invocations: []sarifInvocation{invocation},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("report: writing SARIF: %w", err)
	}
	return nil
}

// sarifRules builds one rule per finding type, in a stable order, and returns
// the index each type sits at. SARIF requires ruleIndex to point into this
// array, so the two are built together rather than hoping they agree.
func sarifRules(findings []detect.Finding) ([]sarifRule, map[string]int) {
	seen := map[string]detect.Finding{}
	for _, f := range findings {
		if _, ok := seen[f.Type]; !ok {
			seen[f.Type] = f
		}
	}

	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)

	rules := make([]sarifRule, 0, len(types))
	index := make(map[string]int, len(types))
	for i, t := range types {
		f := seen[t]
		rules = append(rules, sarifRule{
			ID:               t,
			Name:             t,
			ShortDescription: sarifText{Text: describeType(t)},
			FullDescription:  sarifText{Text: f.Reason},
			Help:             sarifText{Text: helpFor(f)},
			DefaultConfig:    sarifRuleConfig{Level: sarifLevel(f)},
			Properties: sarifRuleProps{
				Tags:      tagsFor(f),
				Precision: precisionOf(f.Confidence),
			},
		})
		index[t] = i
	}
	return rules, index
}

func sarifResultOf(f detect.Finding, ruleIndex int) sarifResult {
	res := sarifResult{
		RuleID:    f.Type,
		RuleIndex: ruleIndex,
		Level:     sarifLevel(f),
		// The redacted form, never the value: this output is uploaded and
		// rendered in a web UI.
		Message: sarifText{Text: fmt.Sprintf("%s found: %s", describeType(f.Type), f.Redacted)},
		PartialFingerps: map[string]string{
			"nadzorFingerprint/v1": f.Fingerprint,
		},
		Properties: map[string]string{
			"engine":     f.Engine,
			"validity":   string(f.Validity),
			"confidence": string(f.Confidence),
		},
	}
	if f.Reason != "" {
		res.Properties["reason"] = f.Reason
	}
	for k, v := range f.Extra {
		res.Properties[k] = v
	}

	for _, loc := range f.Locations {
		if loc.Path == "" {
			continue
		}
		physical := sarifPhysical{ArtifactLocation: sarifArtifact{URI: uriOf(loc.Path)}}
		if loc.Line > 0 {
			physical.Region = &sarifRegion{StartLine: loc.Line, StartColumn: loc.Column}
		}
		res.Locations = append(res.Locations, sarifLocation{PhysicalLocation: physical})
	}
	return res
}

// uriOf normalizes a path for SARIF, which wants a relative URI with forward
// slashes. GitHub matches these against the repository tree, so a leading
// "./" or a backslash from Windows means the alert lands on no file at all.
func uriOf(path string) string {
	p := strings.ReplaceAll(path, `\`, "/")
	p = strings.TrimPrefix(p, "./")
	return p
}

// sarifLevel maps a finding onto SARIF's four levels.
//
// Confidence drives this rather than validity, because the level decides
// whether GitHub shows the alert as a failure, and a structurally valid CPF in
// a fixture file is a true positive that is not a problem.
func sarifLevel(f detect.Finding) string {
	switch {
	case f.Validity == detect.ValidityLive:
		return "error"
	case f.Confidence == detect.ConfidenceHigh:
		return "error"
	case f.Confidence == detect.ConfidenceMedium:
		return "warning"
	default:
		return "note"
	}
}

// precisionOf is GitHub's own vocabulary for how much to trust a rule.
func precisionOf(c detect.Confidence) string {
	switch c {
	case detect.ConfidenceHigh:
		return "high"
	case detect.ConfidenceMedium:
		return "medium"
	default:
		return "low"
	}
}

func tagsFor(f detect.Finding) []string {
	tags := []string{"security"}
	if f.Engine == "br" {
		tags = append(tags, "personal-data", "lgpd")
	}
	if f.Engine == "secrets" {
		tags = append(tags, "credential")
	}
	return tags
}

// describeType gives a name a reader recognizes. Unknown types fall through to
// themselves rather than being dropped, because the secret engine's rule IDs
// are upstream's and there are 417 of them.
func describeType(t string) string {
	if d, ok := typeNames[t]; ok {
		return d
	}
	return t
}

var typeNames = map[string]string{
	"cpf":      "CPF",
	"cnpj":     "CNPJ",
	"cnh":      "CNH",
	"pis":      "PIS/PASEP",
	"titulo":   "Título de eleitor",
	"cns":      "CNS",
	"card-pan": "Card number",
	"pix-key":  "Pix key",
	"e2eid":    "Pix end-to-end ID",
}

// helpFor is what a reader sees in the GitHub alert panel, so it says what to
// do rather than restating what was found.
func helpFor(f detect.Finding) string {
	if f.Engine == "secrets" {
		return "Rotate this credential, then remove it from the file and from " +
			"the git history. A credential that reached a log or a commit should " +
			"be treated as compromised regardless of whether it still works."
	}
	return "This value's check digit is valid, so it is a well-formed document " +
		"number, not a random string. If it belongs in the repository, record " +
		"its fingerprint in .nadzorignore with a reason. If it does not, remove " +
		"it and treat it as a personal-data incident under the LGPD."
}
