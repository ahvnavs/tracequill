package claims

import (
	"fmt"
)

// SourceGroup defines an ingestion provenance group.
type SourceGroup struct {
	Name        string  `json:"name"`
	Reliability float64 `json:"reliability"`
	Description string  `json:"description"`
}

// SourceGroups catalog with non-negotiable Phase 1 reliabilities:
// agent .90, dns .70, git .60, ci .65, inventory .50, human 1.00.
var SourceGroups = map[string]SourceGroup{
	"agent": {
		Name:        "agent",
		Reliability: 0.90,
		Description: "Local kernel/ptrace/eBPF/system inspection capture agent",
	},
	"dns": {
		Name:        "dns",
		Reliability: 0.70,
		Description: "DNS resolution and network name queries",
	},
	"git": {
		Name:        "git",
		Reliability: 0.60,
		Description: "Source control commit and tree metadata",
	},
	"ci": {
		Name:        "ci",
		Reliability: 0.65,
		Description: "Continuous integration pipeline and build environment",
	},
	"inventory": {
		Name:        "inventory",
		Reliability: 0.50,
		Description: "CMDB or cloud inventory registry",
	},
	"human": {
		Name:        "human",
		Reliability: 1.00,
		Description: "Verified human operator assertion or sign-off",
	},
}

// GetSourceReliability returns the reliability score for a source group.
func GetSourceReliability(group string) (float64, error) {
	sg, ok := SourceGroups[group]
	if !ok {
		return 0.0, fmt.Errorf("unknown source group '%s'", group)
	}
	return sg.Reliability, nil
}
