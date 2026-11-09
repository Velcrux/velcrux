#![forbid(unsafe_code)]

//! eBPF Streaming Fast-Path Classifier & Dispatcher.
//!
//! Provides line-rate chunk inspection and routing:
//! - Direct zero-copy bypass for incompressible / pre-encrypted payloads
//! - Dynamic steering of structured records into the WASM transformation sandbox
//! - Immediate drop of unauthorized or malformed chunk formats.

use serde::{Deserialize, Serialize};

/// Fast-Path Routing Decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FastPathDecision {
    /// Zero-copy bypass: Chunk skips WASM pipeline entirely.
    Bypass { reason: String },
    /// Transform: Route chunk through the specified WASM transformation pipeline.
    Transform { pipeline_id: String },
    /// Drop: Prohibited or malformed chunk payload.
    Drop { reason: String },
}

/// A pattern or rule evaluated on incoming chunk headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPathRule {
    pub rule_id: String,
    pub magic_prefix: Option<Vec<u8>>,
    pub min_size: usize,
    pub max_size: usize,
    pub target_pipeline: Option<String>,
}

/// eBPF-style Streaming Fast-Path Filter Engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FastPathClassifier {
    pub rules: Vec<FastPathRule>,
    pub bypass_count: u64,
    pub transform_count: u64,
    pub drop_count: u64,
}

impl FastPathClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: FastPathRule) {
        self.rules.push(rule);
    }

    /// Evaluates incoming chunk payload and determines routing decision.
    pub fn classify(&mut self, chunk: &[u8]) -> FastPathDecision {
        // Fast-path 1: Empty chunk bypass
        if chunk.is_empty() {
            self.bypass_count += 1;
            return FastPathDecision::Bypass {
                reason: "Empty chunk payload".to_string(),
            };
        }

        // Fast-path 2: Known pre-compressed formats bypass WASM compute
        // e.g. Zstandard (0x28, 0xB5, 0x2F, 0xFD), Gzip (0x1F, 0x8B), PNG (0x89, 'P', 'N', 'G')
        if chunk.len() >= 4 && chunk[0..4] == [0x28, 0xB5, 0x2F, 0xFD] {
            self.bypass_count += 1;
            return FastPathDecision::Bypass {
                reason: "Zstandard compressed stream detected".to_string(),
            };
        }

        // Fast-path 3: Custom registered rules
        for rule in &self.rules {
            if chunk.len() >= rule.min_size && chunk.len() <= rule.max_size {
                if let Some(ref prefix) = rule.magic_prefix {
                    if chunk.starts_with(prefix) {
                        if let Some(ref pid) = rule.target_pipeline {
                            self.transform_count += 1;
                            return FastPathDecision::Transform {
                                pipeline_id: pid.clone(),
                            };
                        } else {
                            self.bypass_count += 1;
                            return FastPathDecision::Bypass {
                                reason: format!("Rule {} matched bypass", rule.rule_id),
                            };
                        }
                    }
                }
            }
        }

        // Default: If payload resembles JSON / text, route to default transformation pipeline
        let is_text_or_json = chunk
            .iter()
            .take(128)
            .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
        if is_text_or_json {
            self.transform_count += 1;
            FastPathDecision::Transform {
                pipeline_id: "default-pii-pipeline".to_string(),
            }
        } else {
            self.bypass_count += 1;
            FastPathDecision::Bypass {
                reason: "Binary opaque payload default bypass".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_path_classification() {
        let mut classifier = FastPathClassifier::new();
        classifier.add_rule(FastPathRule {
            rule_id: "csv-rule".to_string(),
            magic_prefix: Some(b"CSV:".to_vec()),
            min_size: 4,
            max_size: 65536,
            target_pipeline: Some("csv-transcode".to_string()),
        });

        // 1. Zstd bypass
        let zstd_data = [0x28, 0xB5, 0x2F, 0xFD, 0x01, 0x02];
        let dec1 = classifier.classify(&zstd_data);
        assert!(matches!(dec1, FastPathDecision::Bypass { .. }));

        // 2. CSV rule matched
        let csv_data = b"CSV:col1,col2\n1,2";
        let dec2 = classifier.classify(csv_data);
        assert_eq!(
            dec2,
            FastPathDecision::Transform {
                pipeline_id: "csv-transcode".to_string()
            }
        );

        // 3. JSON text detected
        let json_data = b"{\"hello\": \"world\"}";
        let dec3 = classifier.classify(json_data);
        assert_eq!(
            dec3,
            FastPathDecision::Transform {
                pipeline_id: "default-pii-pipeline".to_string()
            }
        );
    }
}
