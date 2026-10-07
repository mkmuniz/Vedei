package transcript

import "sort"

// Stats is a transcript audit reduced to counts, safe to send off the machine.
//
// It exists for one study: run the audit on volunteers' machines and learn how
// often agent transcripts hold a credential or a Brazilian document — the
// number that says whether the problem vedei addresses is real. That only works
// if a volunteer can hand over the result without handing over the data.
//
// So the type holds no field that could carry a value, a path or a
// fingerprint. Fingerprints are left out on purpose, not just values: a CPF's
// fingerprint is a hash of eleven digits, and eleven digits are few enough to
// enumerate, so the hash would give the CPF back.
type Stats struct {
	Transcripts      int                  `json:"transcripts"`
	WithFinding      int                  `json:"transcripts_with_finding"`
	WithCredential   int                  `json:"transcripts_with_credential"`
	WithPersonalData int                  `json:"transcripts_with_personal_data"`
	ByType           map[string]TypeStats `json:"by_type"`
}

// TypeStats counts one finding type.
type TypeStats struct {
	// Transcripts is how many transcripts hold at least one value of the type.
	Transcripts int `json:"transcripts"`
	// Values is how many distinct values of the type were seen, across all
	// transcripts: one CPF in ten files counts once.
	Values int `json:"values"`
}

// engineSecrets names the credential engine; every other engine reports
// Brazilian personal data.
const engineSecrets = "secrets"

// Summarize reduces sessions to counts. scanned is how many transcripts were
// read, including the ones that held nothing.
func Summarize(sessions []Session, scanned int) Stats {
	st := Stats{Transcripts: scanned, ByType: map[string]TypeStats{}}
	// Distinct values are counted by fingerprint, which never leaves this
	// function.
	seen := map[string]map[string]bool{}

	for _, s := range sessions {
		if len(s.Findings) == 0 {
			continue
		}
		st.WithFinding++

		credential, personal := false, false
		typesHere := map[string]bool{}
		for _, f := range s.Findings {
			if f.Engine == engineSecrets {
				credential = true
			} else {
				personal = true
			}
			typesHere[f.Type] = true
			if seen[f.Type] == nil {
				seen[f.Type] = map[string]bool{}
			}
			seen[f.Type][f.Fingerprint] = true
		}
		if credential {
			st.WithCredential++
		}
		if personal {
			st.WithPersonalData++
		}
		for t := range typesHere {
			ts := st.ByType[t]
			ts.Transcripts++
			st.ByType[t] = ts
		}
	}

	for t, fps := range seen {
		ts := st.ByType[t]
		ts.Values = len(fps)
		st.ByType[t] = ts
	}
	return st
}

// Types returns the finding types in the summary, sorted.
func (s Stats) Types() []string {
	out := make([]string, 0, len(s.ByType))
	for t := range s.ByType {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
