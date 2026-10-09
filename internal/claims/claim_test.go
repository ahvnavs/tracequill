package claims_test

import (
	"encoding/json"
	"testing"

	"github.com/OWNER/bokuei/internal/claims"
)

// TestVectors from CLAIM_SPEC.md
func TestSpecVectors(t *testing.T) {
	tests := []struct {
		name         string
		claimJSON    string
		expectedHash string
	}{
		{
			name: "Vector 1: Run command claim",
			claimJSON: `{
				"subject": "ref://run/run-001",
				"predicate": "run.command",
				"object": {"kind": "text", "value": "python train.py --epochs 10"},
				"observed_at": "2026-10-07T10:00:00Z",
				"source": {"group": "agent", "id": "agent-host-alpha", "method": "procfs"},
				"scope": "ref://host/alpha",
				"evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"redaction": "none"
			}`,
			expectedHash: "22272e35730cd4cd4463052cc27bdb2f3e9643c81b968f8c5d87ba218755ee0c",
		},
		{
			name: "Vector 2: Host GPU ref claim",
			claimJSON: `{
				"subject": "ref://host/alpha",
				"predicate": "host.gpu",
				"object": {"kind": "ref", "value": "ref://gpu/gpu-a100-0"},
				"observed_at": "2026-10-07T10:05:00Z",
				"source": {"group": "agent", "id": "agent-host-alpha", "method": "nvidia-smi"},
				"scope": "ref://host/alpha",
				"evidence_hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				"redaction": "none"
			}`,
			expectedHash: "4266c7f6db618a18934f5bf5d64a0e24a67a0d986d25de67e5418f66a4822c4f",
		},
		{
			name: "Vector 3: Run exit status int claim",
			claimJSON: `{
				"subject": "ref://run/run-001",
				"predicate": "run.exit_status",
				"object": {"kind": "int", "value": 0},
				"observed_at": "2026-10-07T10:15:00Z",
				"source": {"group": "agent", "id": "agent-host-alpha", "method": "ptrace"},
				"scope": "ref://host/alpha",
				"evidence_hash": "ca978112ca1bbdcafac231b39a23dc4da7860819c196610286cd41022237f10f",
				"redaction": "none"
			}`,
			expectedHash: "fd7e48011cba10157e52b7efcd8e154158b205af715f0c1f9217f1c04e563c17",
		},
		{
			name: "Vector 4: Redacted claim",
			claimJSON: `{
				"subject": "ref://run/run-002",
				"predicate": "run.command",
				"object": {"kind": "text", "value": "auth_service [REDACTED]"},
				"observed_at": "2026-10-07T11:00:00Z",
				"source": {"group": "agent", "id": "agent-host-beta", "method": "procfs"},
				"scope": "ref://host/beta",
				"evidence_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
				"redaction": "redacted"
			}`,
			expectedHash: "b1cfbb15a40b20e6fd295193605c8bf2cc924a66aa50321abf2707b75ecdb6b0",
		},
		{
			name: "Vector 5: Coverage blocked claim",
			claimJSON: `{
				"subject": "ref://run/run-blocked-001",
				"predicate": "coverage.blocked",
				"object": {"kind": "text", "value": "ptrace_denied:operation_not_permitted"},
				"observed_at": "2026-10-07T11:30:00Z",
				"source": {"group": "agent", "id": "agent-host-gamma", "method": "ptrace_attach"},
				"scope": "ref://zone/zone-c",
				"evidence_hash": "fcde2b2edba56bf408686e333d3a896621514200707151d67d1602ecd3f120f4",
				"redaction": "none"
			}`,
			expectedHash: "6c63e9bf1f6fd60350af9de627d1c3e250bbfbedec2309a033252606b5a0c249",
		},
		{
			name: "Vector 6: Host capability supported (v1.1)",
			claimJSON: `{
				"subject": "ref://capability/ptrace",
				"predicate": "capability.can",
				"object": {"kind": "text", "value": "supported"},
				"observed_at": "2026-10-09T10:00:00Z",
				"source": {"group": "agent", "id": "agent-host-alpha", "method": "procfs_yama"},
				"scope": "ref://host/alpha",
				"evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"redaction": "none"
			}`,
			expectedHash: "3857d152f1b3d8d70e8e71c35a4d2b86d7449ba46e1b4795d46d7fc38a20f82c",
		},
		{
			name: "Vector 7: Host capability blocked with reason code (v1.1)",
			claimJSON: `{
				"subject": "ref://capability/conntrack",
				"predicate": "capability.cannot",
				"object": {"kind": "text", "value": "permission_denied:eacces"},
				"observed_at": "2026-10-09T10:05:00Z",
				"source": {"group": "agent", "id": "agent-host-alpha", "method": "open_proc_net_nf_conntrack"},
				"scope": "ref://host/alpha",
				"evidence_hash": "ca978112ca1bbdcafac231b39a23dc4da7860819c196610286cd41022237f10f",
				"redaction": "none"
			}`,
			expectedHash: "e553bc477cd490353889830f833f813605d580347de4b17ea0ddb2d77a085202",
		},
		{
			name: "Vector 8: Network interface state claim (v1.1)",
			claimJSON: `{
				"subject": "ref://interface/eth0",
				"predicate": "interface.state",
				"object": {"kind": "text", "value": "up"},
				"observed_at": "2026-10-09T10:10:00Z",
				"source": {"group": "agent", "id": "agent-host-alpha", "method": "sysfs_net"},
				"scope": "ref://host/alpha",
				"evidence_hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				"redaction": "none"
			}`,
			expectedHash: "d714adf7cef0de902ba486ced1d6308c12ec91136377f8432dc6cd086d70bbc9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c claims.Claim
			if err := json.Unmarshal([]byte(tt.claimJSON), &c); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("validation error: %v", err)
			}
			hash, err := c.ComputeID()
			if err != nil {
				t.Fatalf("compute hash error: %v", err)
			}
			if hash != tt.expectedHash {
				t.Errorf("hash mismatch:\ngot:  %s\nwant: %s", hash, tt.expectedHash)
			}
		})
	}
}

func TestSourceReliabilities(t *testing.T) {
	expected := map[string]float64{
		"agent":     0.90,
		"dns":       0.70,
		"git":       0.60,
		"ci":        0.65,
		"inventory": 0.50,
		"human":     1.00,
	}

	for group, want := range expected {
		got, err := claims.GetSourceReliability(group)
		if err != nil {
			t.Fatalf("unexpected error for group %s: %v", group, err)
		}
		if got != want {
			t.Errorf("group %s reliability got %f, want %f", group, got, want)
		}
	}
}
