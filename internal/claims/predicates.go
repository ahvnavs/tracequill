package claims

import (
	"fmt"
)

// ImpactDirection defines whether a predicate implies dependency or causality flow.
type ImpactDirection string

const (
	ImpactDirectionForward       ImpactDirection = "forward"
	ImpactDirectionBackward      ImpactDirection = "backward"
	ImpactDirectionBidirectional ImpactDirection = "bidirectional"
	ImpactDirectionNone          ImpactDirection = "none"
)

// Family groups predicates by concern.
type Family string

const (
	FamilyRuntime  Family = "runtime"
	FamilyIdentity Family = "identity"
	FamilySoftware Family = "software"
	FamilyProject  Family = "project"
	FamilyCoverage Family = "coverage"
)

// PredicateDef describes a normative predicate.
type PredicateDef struct {
	Name            string
	ObjectKind      string
	Family          Family
	ImpactDirection ImpactDirection
	Description     string
}

// Catalog holds all registered predicates.
var Catalog = map[string]PredicateDef{
	"run.command": {
		Name:            "run.command",
		ObjectKind:      "text",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Command line executed by a run",
	},
	"run.exit_status": {
		Name:            "run.exit_status",
		ObjectKind:      "int",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Exit code of a run process",
	},
	"run.ran_on": {
		Name:            "run.ran_on",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionBackward,
		Description:     "Host where the run executed",
	},
	"run.read": {
		Name:            "run.read",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionBackward,
		Description:     "Artifact or dataset read by the run",
	},
	"run.wrote": {
		Name:            "run.wrote",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionForward,
		Description:     "Artifact or dataset created or modified by the run",
	},
	"run.loaded": {
		Name:            "run.loaded",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionBackward,
		Description:     "Shared library or binary loaded into memory during the run",
	},
	"run.connected_to": {
		Name:            "run.connected_to",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionBackward,
		Description:     "Network socket or endpoint communicated with during the run",
	},
	"run.env_name": {
		Name:            "run.env_name",
		ObjectKind:      "text",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Name of an environment variable present during the run (values redacted unless allowlisted)",
	},
	"host.kernel": {
		Name:            "host.kernel",
		ObjectKind:      "text",
		Family:          FamilySoftware,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Operating system kernel release running on host",
	},
	"host.cpu_feature": {
		Name:            "host.cpu_feature",
		ObjectKind:      "text",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Hardware instruction set feature flag supported by host CPU",
	},
	"host.gpu": {
		Name:            "host.gpu",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "GPU device available on the host",
	},
	"host.listens": {
		Name:            "host.listens",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionForward,
		Description:     "Network port or endpoint listened on by a host service",
	},
	"artifact.sha256": {
		Name:            "artifact.sha256",
		ObjectKind:      "text",
		Family:          FamilyIdentity,
		ImpactDirection: ImpactDirectionNone,
		Description:     "SHA-256 cryptographic digest of an artifact or dataset payload",
	},
	"package.version": {
		Name:            "package.version",
		ObjectKind:      "text",
		Family:          FamilySoftware,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Installed version string for a software package",
	},
	"coverage.observed": {
		Name:            "coverage.observed",
		ObjectKind:      "text",
		Family:          FamilyCoverage,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Subsystem or boundary verified as actively monitored",
	},
	"coverage.blocked": {
		Name:            "coverage.blocked",
		ObjectKind:      "text",
		Family:          FamilyCoverage,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Subsystem or boundary unobservable due to permissions, sandbox, or missing tool",
	},
	"same_as": {
		Name:            "same_as",
		ObjectKind:      "ref",
		Family:          FamilyIdentity,
		ImpactDirection: ImpactDirectionBidirectional,
		Description:     "Aliased identity asserting two refs represent the identical entity",
	},
	"cannot_link": {
		Name:            "cannot_link",
		ObjectKind:      "ref",
		Family:          FamilyIdentity,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Disproven identity asserting two refs do not represent the same entity",
	},
	"human.verified_by": {
		Name:            "human.verified_by",
		ObjectKind:      "text",
		Family:          FamilyProject,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Identifier of human operator verifying or certifying a claim",
	},
	"tq.meta.retracts": {
		Name:            "tq.meta.retracts",
		ObjectKind:      "text",
		Family:          FamilyProject,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Claim ID retracted or superseded by the subject claim",
	},
	"observed_absent": {
		Name:            "observed_absent",
		ObjectKind:      "text",
		Family:          FamilyCoverage,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Attribute or dependency affirmatively probed and verified absent",
	},
	"capability.can": {
		Name:            "capability.can",
		ObjectKind:      "text",
		Family:          FamilyCoverage,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Capability affirmatively probed and supported by host/agent environment",
	},
	"capability.cannot": {
		Name:            "capability.cannot",
		ObjectKind:      "text",
		Family:          FamilyCoverage,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Capability probed and blocked or unmodeled, with explicit reason code",
	},
	"host.interface": {
		Name:            "host.interface",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionForward,
		Description:     "Network interface present on host",
	},
	"interface.state": {
		Name:            "interface.state",
		ObjectKind:      "text",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Operational state of network interface (e.g. up, down)",
	},
	"interface.counter": {
		Name:            "interface.counter",
		ObjectKind:      "int",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Packet or byte counters associated with interface",
	},
	"host.route": {
		Name:            "host.route",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionForward,
		Description:     "Network routing table entry on host",
	},
	"run.connection": {
		Name:            "run.connection",
		ObjectKind:      "ref",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionForward,
		Description:     "Network connection endpoint opened or accessed by run",
	},
	"rehearsal.result": {
		Name:            "rehearsal.result",
		ObjectKind:      "json",
		Family:          FamilyRuntime,
		ImpactDirection: ImpactDirectionNone,
		Description:     "Hypothetical change simulation result and impact prediction",
	},
}

// GetPredicate returns the predicate definition or an error if not found.
func GetPredicate(name string) (PredicateDef, error) {
	def, ok := Catalog[name]
	if !ok {
		return PredicateDef{}, fmt.Errorf("unknown predicate '%s'", name)
	}
	return def, nil
}
