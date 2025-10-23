use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveInfo {
    pub letter: String,
    pub label: String,
    pub total_size: u64,
    pub free_size: u64,
    pub file_system: String,
    pub is_removable: bool,
    pub drive_type: String, // "SSD", "HDD", or "Unknown"
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeRequest {
    pub target: String,
    pub method: String,
    pub include_hidden_areas: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeResult {
    pub success: bool,
    pub target: String,
    pub method: String,
    pub bytes_wiped: u64,
    pub passes_completed: u32,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub device_id: String,
    pub hash: String,
    pub error_message: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeProgress {
    pub current_pass: u32,
    pub total_passes: u32,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub percentage: f32,
    pub current_operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    pub wipe_result: WipeResult,
    pub certificate_id: String,
    pub digital_signature: String,
    pub public_key: String,
    pub verification_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WipeMethod {
    NistSp80088,
    DoD522022M,
    Gutmann,
    Random,
    Zero,
}

impl WipeMethod {
    pub fn passes(&self) -> u32 {
        match self {
            WipeMethod::NistSp80088 => 1,
            WipeMethod::DoD522022M => 3,
            WipeMethod::Gutmann => 35,
            WipeMethod::Random => 3,
            WipeMethod::Zero => 1,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            WipeMethod::NistSp80088 => "NIST SP 800-88",
            WipeMethod::DoD522022M => "DoD 5220.22-M",
            WipeMethod::Gutmann => "Gutmann",
            WipeMethod::Random => "Random",
            WipeMethod::Zero => "Zero",
        }
    }
}
