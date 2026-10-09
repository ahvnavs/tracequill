use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Source {
    pub group: String,
    pub id: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectVal {
    pub kind: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub subject: String,
    pub predicate: String,
    pub object: ObjectVal,
    pub observed_at: String,
    pub source: Source,
    pub scope: String,
    pub evidence_hash: String,
    pub redaction: String,
}

impl Claim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: impl Into<String>,
        predicate: impl Into<String>,
        kind: impl Into<String>,
        val: serde_json::Value,
        observed_at: impl Into<String>,
        source_group: impl Into<String>,
        source_id: impl Into<String>,
        source_method: impl Into<String>,
        scope: impl Into<String>,
        evidence_hash: impl Into<String>,
        redaction: impl Into<String>,
    ) -> Self {
        let mut c = Self {
            claim_id: None,
            subject: subject.into(),
            predicate: predicate.into(),
            object: ObjectVal {
                kind: kind.into(),
                value: val,
            },
            observed_at: observed_at.into(),
            source: Source {
                group: source_group.into(),
                id: source_id.into(),
                method: source_method.into(),
            },
            scope: scope.into(),
            evidence_hash: evidence_hash.into(),
            redaction: redaction.into(),
        };
        c.claim_id = Some(c.compute_id());
        c
    }

    /// Produces canonical UTF-8 JSON bytes with sorted keys and no whitespace, matching CLAIM_SPEC.md.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let obj_json = match &self.object.value {
            serde_json::Value::String(s) => {
                let esc = serde_json::to_string(s).unwrap();
                format!(r#"{{"kind":"{}","value":{}}}"#, self.object.kind, esc)
            }
            serde_json::Value::Number(n) => {
                format!(r#"{{"kind":"{}","value":{}}}"#, self.object.kind, n)
            }
            serde_json::Value::Bool(b) => {
                format!(r#"{{"kind":"{}","value":{}}}"#, self.object.kind, b)
            }
            other => {
                let s = serde_json::to_string(other).unwrap();
                format!(r#"{{"kind":"{}","value":{}}}"#, self.object.kind, s)
            }
        };

        let src_grp = serde_json::to_string(&self.source.group).unwrap();
        let src_id = serde_json::to_string(&self.source.id).unwrap();
        let src_meth = serde_json::to_string(&self.source.method).unwrap();
        let src_json = format!(
            r#"{{"group":{},"id":{},"method":{}}}"#,
            src_grp, src_id, src_meth
        );

        let esc_ev = serde_json::to_string(&self.evidence_hash).unwrap();
        let esc_obs = serde_json::to_string(&self.observed_at).unwrap();
        let esc_pred = serde_json::to_string(&self.predicate).unwrap();
        let esc_red = serde_json::to_string(&self.redaction).unwrap();
        let esc_scope = serde_json::to_string(&self.scope).unwrap();
        let esc_subj = serde_json::to_string(&self.subject).unwrap();

        let s = format!(
            r#"{{"evidence_hash":{},"object":{},"observed_at":{},"predicate":{},"redaction":{},"scope":{},"source":{},"subject":{}}}"#,
            esc_ev, obj_json, esc_obs, esc_pred, esc_red, esc_scope, src_json, esc_subj
        );

        s.into_bytes()
    }

    /// Computes lowercase hex SHA-256 of canonical bytes.
    pub fn compute_id(&self) -> String {
        let bytes = self.canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in result {
            hex.push_str(&format!("{:02x}", b));
        }
        hex
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub hash: String,
    pub payload_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimBatch {
    pub batch_id: String,
    pub run_ref: Option<String>,
    pub claims: Vec<Claim>,
    pub evidence: Vec<EvidenceItem>,
    pub env_salt: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_vectors() {
        let vectors = vec![
            (
                r#"{
                    "subject": "ref://run/run-001",
                    "predicate": "run.command",
                    "object": {"kind": "text", "value": "python train.py --epochs 10"},
                    "observed_at": "2026-10-07T10:00:00Z",
                    "source": {"group": "agent", "id": "agent-host-alpha", "method": "procfs"},
                    "scope": "ref://host/alpha",
                    "evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "redaction": "none"
                }"#,
                "22272e35730cd4cd4463052cc27bdb2f3e9643c81b968f8c5d87ba218755ee0c",
            ),
            (
                r#"{
                    "subject": "ref://host/alpha",
                    "predicate": "host.gpu",
                    "object": {"kind": "ref", "value": "ref://gpu/gpu-a100-0"},
                    "observed_at": "2026-10-07T10:05:00Z",
                    "source": {"group": "agent", "id": "agent-host-alpha", "method": "nvidia-smi"},
                    "scope": "ref://host/alpha",
                    "evidence_hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "redaction": "none"
                }"#,
                "4266c7f6db618a18934f5bf5d64a0e24a67a0d986d25de67e5418f66a4822c4f",
            ),
            (
                r#"{
                    "subject": "ref://run/run-001",
                    "predicate": "run.exit_status",
                    "object": {"kind": "int", "value": 0},
                    "observed_at": "2026-10-07T10:15:00Z",
                    "source": {"group": "agent", "id": "agent-host-alpha", "method": "ptrace"},
                    "scope": "ref://host/alpha",
                    "evidence_hash": "ca978112ca1bbdcafac231b39a23dc4da7860819c196610286cd41022237f10f",
                    "redaction": "none"
                }"#,
                "fd7e48011cba10157e52b7efcd8e154158b205af715f0c1f9217f1c04e563c17",
            ),
            (
                r#"{
                    "subject": "ref://run/run-002",
                    "predicate": "run.command",
                    "object": {"kind": "text", "value": "auth_service [REDACTED]"},
                    "observed_at": "2026-10-07T11:00:00Z",
                    "source": {"group": "agent", "id": "agent-host-beta", "method": "procfs"},
                    "scope": "ref://host/beta",
                    "evidence_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                    "redaction": "redacted"
                }"#,
                "b1cfbb15a40b20e6fd295193605c8bf2cc924a66aa50321abf2707b75ecdb6b0",
            ),
            (
                r#"{
                    "subject": "ref://run/run-blocked-001",
                    "predicate": "coverage.blocked",
                    "object": {"kind": "text", "value": "ptrace_denied:operation_not_permitted"},
                    "observed_at": "2026-10-07T11:30:00Z",
                    "source": {"group": "agent", "id": "agent-host-gamma", "method": "ptrace_attach"},
                    "scope": "ref://zone/zone-c",
                    "evidence_hash": "fcde2b2edba56bf408686e333d3a896621514200707151d67d1602ecd3f120f4",
                    "redaction": "none"
                }"#,
                "6c63e9bf1f6fd60350af9de627d1c3e250bbfbedec2309a033252606b5a0c249",
            ),
            (
                r#"{
                    "subject": "ref://capability/ptrace",
                    "predicate": "capability.can",
                    "object": {"kind": "text", "value": "supported"},
                    "observed_at": "2026-10-09T10:00:00Z",
                    "source": {"group": "agent", "id": "agent-host-alpha", "method": "procfs_yama"},
                    "scope": "ref://host/alpha",
                    "evidence_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "redaction": "none"
                }"#,
                "3857d152f1b3d8d70e8e71c35a4d2b86d7449ba46e1b4795d46d7fc38a20f82c",
            ),
            (
                r#"{
                    "subject": "ref://capability/conntrack",
                    "predicate": "capability.cannot",
                    "object": {"kind": "text", "value": "permission_denied:eacces"},
                    "observed_at": "2026-10-09T10:05:00Z",
                    "source": {"group": "agent", "id": "agent-host-alpha", "method": "open_proc_net_nf_conntrack"},
                    "scope": "ref://host/alpha",
                    "evidence_hash": "ca978112ca1bbdcafac231b39a23dc4da7860819c196610286cd41022237f10f",
                    "redaction": "none"
                }"#,
                "e553bc477cd490353889830f833f813605d580347de4b17ea0ddb2d77a085202",
            ),
            (
                r#"{
                    "subject": "ref://interface/eth0",
                    "predicate": "interface.state",
                    "object": {"kind": "text", "value": "up"},
                    "observed_at": "2026-10-09T10:10:00Z",
                    "source": {"group": "agent", "id": "agent-host-alpha", "method": "sysfs_net"},
                    "scope": "ref://host/alpha",
                    "evidence_hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "redaction": "none"
                }"#,
                "d714adf7cef0de902ba486ced1d6308c12ec91136377f8432dc6cd086d70bbc9",
            ),
        ];

        for (json_str, expected_hash) in vectors {
            let claim: Claim = serde_json::from_str(json_str).expect("deserialize failed");
            let computed = claim.compute_id();
            assert_eq!(
                computed, expected_hash,
                "vector failed for {}",
                claim.predicate
            );
        }
    }
}
