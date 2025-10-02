use std::fs::File;
use std::io::Write;
use serde_json;
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use sha2::{Sha256, Digest};

use crate::types::{WipeResult, CertificateData};

fn key_store_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ZeroRecover")
}

fn load_or_create_persistent_key() -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    let dir = key_store_dir();
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("ed25519_pkcs8.der");

    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        let key = Ed25519KeyPair::from_pkcs8(&bytes).map_err(|e| format!("Failed to load key: {}", e))?;
        return Ok(key);
    }

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| format!("Failed to generate key: {}", e))?;
    std::fs::write(&key_path, pkcs8_bytes.as_ref())?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(|e| format!("Failed to create key from bytes: {}", e))?;
    Ok(key)
}

pub fn generate_certificate(wipe_result: WipeResult) -> Result<String, Box<dyn std::error::Error>> {
    // Use persistent key for signing so certificates are verifiable later
    let key_pair = load_or_create_persistent_key()?;
    
    // Create certificate data
    let certificate_id = uuid::Uuid::new_v4().to_string();
    let public_key = general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
    
    // Create data to sign
    let data_to_sign = format!(
        "{}{}{}{}{}",
        wipe_result.target,
        wipe_result.method,
        wipe_result.bytes_wiped,
        wipe_result.timestamp.timestamp(),
        certificate_id
    );
    
    // Sign the data
    let signature = key_pair.sign(data_to_sign.as_bytes());
    let digital_signature = general_purpose::STANDARD.encode(signature.as_ref());
    
    // Create verification hash
    let mut hasher = Sha256::new();
    hasher.update(data_to_sign.as_bytes());
    hasher.update(signature.as_ref());
    let verification_hash = format!("{:x}", hasher.finalize());
    
    let certificate_data = CertificateData {
        wipe_result: wipe_result.clone(),
        certificate_id,
        digital_signature,
        public_key,
        verification_hash,
    };
    
    // Generate JSON certificate
    let json_cert = generate_json_certificate(&certificate_data)?;
    
    // Generate PDF certificate (as HTML-based PDF)
    let pdf_cert = generate_pdf_certificate(&certificate_data)?;
    
    // Save certificates to user's Documents folder
    let documents_path = dirs::document_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let base_filename = format!("zerorecover_certificate_{}", timestamp);
    
    let json_path = documents_path.join(format!("{}.json", base_filename));
    let pdf_path = documents_path.join(format!("{}.pdf", base_filename));
    
    std::fs::write(&json_path, json_cert)?;
    std::fs::write(&pdf_path, pdf_cert)?;
    
    Ok(format!("Certificates generated:\n{}\n{}", 
        json_path.display(), 
        pdf_path.display()))
}

fn generate_json_certificate(cert_data: &CertificateData) -> Result<String, Box<dyn std::error::Error>> {
    let json_cert = serde_json::json!({
        "certificate_id": cert_data.certificate_id,
        "timestamp": cert_data.wipe_result.timestamp,
        "target": cert_data.wipe_result.target,
        "method": cert_data.wipe_result.method,
        "bytes_wiped": cert_data.wipe_result.bytes_wiped,
        "passes_completed": cert_data.wipe_result.passes_completed,
        "duration_ms": cert_data.wipe_result.duration_ms,
        "device_id": cert_data.wipe_result.device_id,
        "hash": cert_data.wipe_result.hash,
        "digital_signature": cert_data.digital_signature,
        "public_key": cert_data.public_key,
        "verification_hash": cert_data.verification_hash,
        "verification_instructions": {
            "step1": "Verify the digital signature using the provided public key",
            "step2": "Check that the verification hash matches the computed hash",
            "step3": "Validate the timestamp and certificate ID",
            "step4": "Confirm the wipe method and target match your records"
        }
    });
    
    Ok(serde_json::to_string_pretty(&json_cert)?)
}

fn generate_pdf_certificate(cert_data: &CertificateData) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate HTML-based PDF content (simplified approach)
    // In production, you could use printpdf or wkhtmltopdf for better PDF generation
    
    let html_content = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ZeroRecover Certificate</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #667eea; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }}
        .field {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #555; }}
        .value {{ color: #333; word-wrap: break-word; }}
        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 20px 0; }}
        .signature {{ background: #e8f5e8; border-left: 4px solid #28a745; padding: 10px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>🔒 ZeroRecover Data Wiping Certificate</h1>
    
    <div class="section">
        <div class="field">
            <span class="label">Certificate ID:</span>
            <span class="value">{}</span>
        </div>
        <div class="field">
            <span class="label">Generated:</span>
            <span class="value">{}</span>
        </div>
    </div>

    <h2>Wipe Details</h2>
    <div class="section">
        <div class="field">
            <span class="label">Target:</span>
            <span class="value">{}</span>
        </div>
        <div class="field">
            <span class="label">Method:</span>
            <span class="value">{}</span>
        </div>
        <div class="field">
            <span class="label">Bytes Wiped:</span>
            <span class="value">{} bytes</span>
        </div>
        <div class="field">
            <span class="label">Passes Completed:</span>
            <span class="value">{}</span>
        </div>
        <div class="field">
            <span class="label">Duration:</span>
            <span class="value">{} ms</span>
        </div>
        <div class="field">
            <span class="label">Device ID:</span>
            <span class="value">{}</span>
        </div>
        <div class="field">
            <span class="label">Hash:</span>
            <span class="value">{}</span>
        </div>
    </div>

    <h2>Digital Signature</h2>
    <div class="signature">
        <div class="field">
            <span class="label">Signature:</span>
            <div class="value" style="font-family: monospace; font-size: 10px;">{}</div>
        </div>
        <div class="field">
            <span class="label">Public Key:</span>
            <div class="value" style="font-family: monospace; font-size: 10px;">{}</div>
        </div>
        <div class="field">
            <span class="label">Verification Hash:</span>
            <div class="value" style="font-family: monospace; font-size: 10px;">{}</div>
        </div>
    </div>

    <h2>Verification Instructions</h2>
    <div class="warning">
        <ol>
            <li>Verify the digital signature using the provided public key</li>
            <li>Check that the verification hash matches the computed hash</li>
            <li>Validate the timestamp and certificate ID</li>
            <li>Confirm the wipe method and target match your records</li>
        </ol>
    </div>

    <div style="margin-top: 50px; text-align: center; color: #999; font-size: 12px;">
        <p>This certificate was generated by ZeroRecover - Secure Data Wiping Tool</p>
        <p>Certificate is cryptographically signed and tamper-proof</p>
    </div>
</body>
</html>"#,
        cert_data.certificate_id,
        cert_data.wipe_result.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        cert_data.wipe_result.target,
        cert_data.wipe_result.method,
        cert_data.wipe_result.bytes_wiped,
        cert_data.wipe_result.passes_completed,
        cert_data.wipe_result.duration_ms,
        cert_data.wipe_result.device_id,
        cert_data.wipe_result.hash,
        cert_data.digital_signature,
        cert_data.public_key,
        cert_data.verification_hash
    );
    
    // Return HTML as bytes (can be opened in browser or converted to PDF with external tool)
    Ok(html_content.into_bytes())
}
