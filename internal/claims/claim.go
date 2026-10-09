package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Allowed ref kinds
var validRefKinds = map[string]bool{
	"host":     true,
	"run":      true,
	"process":  true,
	"artifact": true,
	"package":  true,
	"gpu":      true,
	"endpoint":   true,
	"zone":       true,
	"service":    true,
	"dataset":    true,
	"interface":  true,
	"route":      true,
	"capability": true,
}

var refPattern = regexp.MustCompile(`^ref://([a-z]+)/([a-zA-Z0-9_.\-:/\[\]]+)$`)

// ValidateRef checks if a ref string matches ref://<kind>/<id> and kind is in the allowlist.
func ValidateRef(ref string) error {
	matches := refPattern.FindStringSubmatch(ref)
	if len(matches) != 3 {
		return fmt.Errorf("invalid ref format '%s': expected ref://<kind>/<id>", ref)
	}
	kind := matches[1]
	if !validRefKinds[kind] {
		return fmt.Errorf("invalid ref kind '%s' in ref '%s'", kind, ref)
	}
	return nil
}

// Source represents the origin of an observation.
type Source struct {
	Group  string `json:"group"`
	ID     string `json:"id"`
	Method string `json:"method"`
}

// Object represents a typed value of a claim.
type Object struct {
	Kind  string      `json:"kind"`  // ref, text, int, bool, json
	Value interface{} `json:"value"` // string, int64, bool, or json object/array
}

// Claim is the normative claim data structure.
type Claim struct {
	ClaimID      string `json:"claim_id,omitempty"`
	Subject      string `json:"subject"`
	Predicate    string `json:"predicate"`
	Object       Object `json:"object"`
	ObservedAt   string `json:"observed_at"`
	Source       Source `json:"source"`
	Scope        string `json:"scope"`
	EvidenceHash string `json:"evidence_hash"`
	Redaction    string `json:"redaction"`
}

// Validate checks claim semantics according to CLAIM_SPEC.md.
func (c *Claim) Validate() error {
	if err := ValidateRef(c.Subject); err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}
	if c.Predicate == "" {
		return fmt.Errorf("predicate cannot be empty")
	}
	switch c.Object.Kind {
	case "ref":
		valStr, ok := c.Object.Value.(string)
		if !ok {
			return fmt.Errorf("object kind 'ref' requires string value")
		}
		if err := ValidateRef(valStr); err != nil {
			return fmt.Errorf("invalid object ref: %w", err)
		}
	case "text":
		if _, ok := c.Object.Value.(string); !ok {
			return fmt.Errorf("object kind 'text' requires string value")
		}
	case "int":
		switch c.Object.Value.(type) {
		case int, int32, int64, float64:
			// JSON unmarshaling numbers default to float64 if not configured, ensure integer value
		default:
			return fmt.Errorf("object kind 'int' requires integer value")
		}
	case "bool":
		if _, ok := c.Object.Value.(bool); !ok {
			return fmt.Errorf("object kind 'bool' requires boolean value")
		}
	case "json":
		// valid json value
	default:
		return fmt.Errorf("unknown object kind: %s", c.Object.Kind)
	}

	if _, err := time.Parse(time.RFC3339, c.ObservedAt); err != nil {
		return fmt.Errorf("invalid observed_at RFC3339 timestamp: %w", err)
	}

	if c.Source.Group == "" || c.Source.ID == "" || c.Source.Method == "" {
		return fmt.Errorf("source group, id, and method must be non-empty")
	}

	if err := ValidateRef(c.Scope); err != nil {
		return fmt.Errorf("invalid scope ref: %w", err)
	}
	if !strings.HasPrefix(c.Scope, "ref://host/") && !strings.HasPrefix(c.Scope, "ref://zone/") {
		return fmt.Errorf("scope must be host or zone ref, got '%s'", c.Scope)
	}

	if len(c.EvidenceHash) != 64 {
		return fmt.Errorf("evidence_hash must be 64 hex characters, got length %d", len(c.EvidenceHash))
	}

	switch c.Redaction {
	case "none", "redacted", "partial":
	default:
		return fmt.Errorf("invalid redaction status '%s': expected none, redacted, or partial", c.Redaction)
	}

	return nil
}

// CanonicalBytes produces the canonical UTF-8 JSON representation with sorted keys and no whitespace.
func (c *Claim) CanonicalBytes() ([]byte, error) {
	// Canonical key order for top level:
	// evidence_hash, object, observed_at, predicate, redaction, scope, source, subject

	// Canonical object
	var objBytes []byte
	switch c.Object.Kind {
	case "int":
		var intVal int64
		switch v := c.Object.Value.(type) {
		case int:
			intVal = int64(v)
		case int32:
			intVal = int64(v)
		case int64:
			intVal = v
		case float64:
			intVal = int64(v)
		default:
			return nil, fmt.Errorf("invalid int value: %v", c.Object.Value)
		}
		objBytes = []byte(fmt.Sprintf(`{"kind":"int","value":%d}`, intVal))
	case "ref":
		refVal, _ := c.Object.Value.(string)
		escaped, _ := json.Marshal(refVal)
		objBytes = []byte(fmt.Sprintf(`{"kind":"ref","value":%s}`, string(escaped)))
	case "text":
		textVal, _ := c.Object.Value.(string)
		escaped, _ := json.Marshal(textVal)
		objBytes = []byte(fmt.Sprintf(`{"kind":"text","value":%s}`, string(escaped)))
	case "bool":
		boolVal, _ := c.Object.Value.(bool)
		objBytes = []byte(fmt.Sprintf(`{"kind":"bool","value":%t}`, boolVal))
	case "json":
		valBytes, err := json.Marshal(c.Object.Value)
		if err != nil {
			return nil, err
		}
		objBytes = []byte(fmt.Sprintf(`{"kind":"json","value":%s}`, string(valBytes)))
	default:
		return nil, fmt.Errorf("unsupported object kind: %s", c.Object.Kind)
	}

	// Canonical source: group, id, method
	escGrp, _ := json.Marshal(c.Source.Group)
	escSrcID, _ := json.Marshal(c.Source.ID)
	escMeth, _ := json.Marshal(c.Source.Method)
	sourceBytes := fmt.Sprintf(`{"group":%s,"id":%s,"method":%s}`, string(escGrp), string(escSrcID), string(escMeth))

	// Escapes for strings
	escEvHash, _ := json.Marshal(c.EvidenceHash)
	escObsAt, _ := json.Marshal(c.ObservedAt)
	escPred, _ := json.Marshal(c.Predicate)
	escRedact, _ := json.Marshal(c.Redaction)
	escScope, _ := json.Marshal(c.Scope)
	escSubj, _ := json.Marshal(c.Subject)

	canonicalStr := fmt.Sprintf(
		`{"evidence_hash":%s,"object":%s,"observed_at":%s,"predicate":%s,"redaction":%s,"scope":%s,"source":%s,"subject":%s}`,
		string(escEvHash),
		string(objBytes),
		string(escObsAt),
		string(escPred),
		string(escRedact),
		string(escScope),
		sourceBytes,
		string(escSubj),
	)

	return []byte(canonicalStr), nil
}

// ComputeID calculates the SHA-256 hash of the canonical bytes.
func (c *Claim) ComputeID() (string, error) {
	bytes, err := c.CanonicalBytes()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:]), nil
}
