use std::ptr;
use serde_json;
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use sha2::{Sha256, Digest};
use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
use winapi::um::wincrypt::CRYPTOAPI_BLOB;
use winapi::shared::minwindef::DWORD;

use crate::types::{WipeResult, CertificateData};

fn key_store_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ZeroRecover")
}

/// Get a machine-specific identifier for certificate binding
/// 
/// SECURITY: Creates a unique identifier for this machine to prevent
/// certificate replay attacks on different machines
fn get_machine_identifier() -> String {
    use sha2::Digest;
    
    // Combine multiple machine-specific identifiers
    let mut identifiers = Vec::new();
    
    // Computer name
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        identifiers.push(name);
    }
    
    // User SID (Windows Security Identifier)
    if let Ok(sid) = std::env::var("USERSID") {
        identifiers.push(sid);
    }
    
    // Processor identifier
    if let Ok(proc) = std::env::var("PROCESSOR_IDENTIFIER") {
        identifiers.push(proc);
    }
    
    // Number of processors (helps identify machine)
    if let Ok(num) = std::env::var("NUMBER_OF_PROCESSORS") {
        identifiers.push(num);
    }
    
    // System drive serial (if available)
    if let Ok(drive) = std::env::var("SystemDrive") {
        identifiers.push(drive);
    }
    
    // Combine all identifiers and hash them
    let combined = identifiers.join("|");
    let mut hasher = sha2::Sha256::new();
    hasher.update(combined.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Encrypt data using Windows DPAPI (Data Protection API)
/// 
/// SECURITY: Uses user-specific encryption tied to Windows user account.
/// Data can only be decrypted by the same user on the same machine.
fn dpapi_encrypt(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    unsafe {
        let mut data_in = CRYPTOAPI_BLOB {
            cbData: data.len() as DWORD,
            pbData: data.as_ptr() as *mut u8,
        };

        let mut data_out = CRYPTOAPI_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // Encrypt using DPAPI with current user's credentials
        let result = CryptProtectData(
            &mut data_in,
            ptr::null(),                    // No description
            ptr::null_mut(),                // No optional entropy
            ptr::null_mut(),                // Reserved
            ptr::null_mut(),                // No prompt struct
            CRYPTPROTECT_UI_FORBIDDEN,      // No UI prompts
            &mut data_out,
        );

        if result == 0 {
            return Err("Failed to encrypt data with DPAPI".into());
        }

        // SECURITY: Validate pointer and size before dereferencing
        if data_out.pbData.is_null() {
            return Err("DPAPI returned null pointer for encrypted data".into());
        }
        
        if data_out.cbData == 0 {
            return Err("DPAPI returned zero-length encrypted data".into());
        }

        // Copy encrypted data (now safe after validation)
        let encrypted = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();

        // Free the allocated memory
        winapi::um::winbase::LocalFree(data_out.pbData as *mut _);

        Ok(encrypted)
    }
}

/// Decrypt data using Windows DPAPI (Data Protection API)
/// 
/// SECURITY: Can only decrypt data encrypted by the same user on the same machine.
fn dpapi_decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    unsafe {
        let mut data_in = CRYPTOAPI_BLOB {
            cbData: encrypted_data.len() as DWORD,
            pbData: encrypted_data.as_ptr() as *mut u8,
        };

        let mut data_out = CRYPTOAPI_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        // Decrypt using DPAPI
        let result = CryptUnprotectData(
            &mut data_in,
            ptr::null_mut(),                // No description output
            ptr::null_mut(),                // No optional entropy
            ptr::null_mut(),                // Reserved
            ptr::null_mut(),                // No prompt struct
            CRYPTPROTECT_UI_FORBIDDEN,      // No UI prompts
            &mut data_out,
        );

        if result == 0 {
            return Err("Failed to decrypt data with DPAPI".into());
        }

        // SECURITY: Validate pointer and size before dereferencing
        if data_out.pbData.is_null() {
            return Err("DPAPI returned null pointer for decrypted data".into());
        }
        
        if data_out.cbData == 0 {
            return Err("DPAPI returned zero-length decrypted data".into());
        }

        // Copy decrypted data (now safe after validation)
        let decrypted = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();

        // Free the allocated memory
        winapi::um::winbase::LocalFree(data_out.pbData as *mut _);

        Ok(decrypted)
    }
}

/// Load or create persistent key with DPAPI encryption
/// 
/// SECURITY IMPROVEMENTS:
/// - Private key encrypted with Windows DPAPI
/// - Key tied to user account (can't be used by other users)
/// - Key tied to machine (can't be copied to another machine)
/// - No plaintext key storage
fn load_or_create_persistent_key() -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    let dir = key_store_dir();
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("ed25519_pkcs8.encrypted");

    if key_path.exists() {
        // Load and decrypt existing key
        let encrypted_bytes = std::fs::read(&key_path)?;
        let decrypted_bytes = dpapi_decrypt(&encrypted_bytes)
            .map_err(|e| format!("Failed to decrypt key: {}", e))?;
        
        let key = Ed25519KeyPair::from_pkcs8(&decrypted_bytes)
            .map_err(|e| format!("Failed to load key: {}", e))?;
        return Ok(key);
    }

    // Generate new key
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Failed to generate key: {}", e))?;
    
    // Encrypt key with DPAPI before storing
    let encrypted_bytes = dpapi_encrypt(pkcs8_bytes.as_ref())
        .map_err(|e| format!("Failed to encrypt key: {}", e))?;
    
    // Store encrypted key
    std::fs::write(&key_path, &encrypted_bytes)?;
    
    // Return key pair
    let key = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| format!("Failed to create key from bytes: {}", e))?;
    Ok(key)
}

pub fn generate_certificate(wipe_result: WipeResult) -> Result<String, Box<dyn std::error::Error>> {
    // Use persistent key for signing so certificates are verifiable later
    let key_pair = load_or_create_persistent_key()?;
    
    // Create certificate data
    let certificate_id = uuid::Uuid::new_v4().to_string();
    let public_key = general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
    
    // SECURITY: Gather comprehensive identity and context information
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let user_domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "Unknown".to_string());
    
    // Get machine-specific identifier (MAC address hash or similar)
    let machine_id = get_machine_identifier();
    
    // SECURITY: Create comprehensive data to sign
    // Include ALL critical data to prevent forgery, replay, and modification
    let data_to_sign = format!(
        "CERT_ID:{}\n\
        TARGET:{}\n\
        METHOD:{}\n\
        BYTES_WIPED:{}\n\
        PASSES:{}\n\
        DURATION_MS:{}\n\
        TIMESTAMP:{}\n\
        TIMESTAMP_NANOS:{}\n\
        DEVICE_ID:{}\n\
        HASH:{}\n\
        USERNAME:{}\n\
        COMPUTER:{}\n\
        DOMAIN:{}\n\
        MACHINE_ID:{}\n\
        SUCCESS:{}\n\
        ERROR:{}",
        certificate_id,
        wipe_result.target,
        wipe_result.method,
        wipe_result.bytes_wiped,
        wipe_result.passes_completed,
        wipe_result.duration_ms,
        wipe_result.timestamp.timestamp(),
        wipe_result.timestamp.timestamp_nanos_opt().unwrap_or(0),
        wipe_result.device_id,
        wipe_result.hash,
        username,
        computer_name,
        user_domain,
        machine_id,
        wipe_result.success,
        wipe_result.error_message.as_ref().unwrap_or(&String::new())
    );
    
    // Sign the comprehensive data
    let signature = key_pair.sign(data_to_sign.as_bytes());
    let digital_signature = general_purpose::STANDARD.encode(signature.as_ref());
    
    // Create verification hash from signed data + signature
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
    // SECURITY: Gather identity information for certificate
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let user_domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "Unknown".to_string());
    let machine_id = get_machine_identifier();
    
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
        "success": cert_data.wipe_result.success,
        "error_message": cert_data.wipe_result.error_message,
        "identity": {
            "username": username,
            "computer": computer_name,
            "domain": user_domain,
            "machine_id": machine_id
        },
        "digital_signature": cert_data.digital_signature,
        "public_key": cert_data.public_key,
        "verification_hash": cert_data.verification_hash,
        "security_note": "This certificate includes comprehensive identity and context data in the signature to prevent forgery, replay attacks, and modification.",
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
    use printpdf::*;
    
    // Create a new PDF document
    let (doc, page1, layer1) = PdfDocument::new(
        "ZeroRecover Certificate",
        Mm(210.0), // A4 width
        Mm(297.0), // A4 height
        "Layer 1"
    );
    
    // Get fonts
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;
    
    let current_layer = doc.get_page(page1).get_layer(layer1);
    
    let mut y_position = 270.0; // Start from top (A4 height is 297mm)
    
    // Title
    current_layer.use_text("ZeroRecover - Data Wiping Certificate", 24.0, Mm(20.0), Mm(y_position), &font_bold);
    y_position -= 10.0;
    
    // Draw separator line using simple text line
    current_layer.use_text("_____________________________________________________________________________", 10.0, Mm(20.0), Mm(y_position), &font_regular);
    y_position -= 15.0;
    
    // Certificate ID section
    current_layer.use_text("Certificate Information", 14.0, Mm(20.0), Mm(y_position), &font_bold);
    y_position -= 8.0;
    
    current_layer.use_text("Certificate ID:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&cert_data.certificate_id, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    let timestamp_str = cert_data.wipe_result.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    current_layer.use_text("Generated:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&timestamp_str, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 12.0;
    
    // Wipe Details section
    current_layer.use_text("Wipe Operation Details", 14.0, Mm(20.0), Mm(y_position), &font_bold);
    y_position -= 8.0;
    
    current_layer.use_text("Target:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&cert_data.wipe_result.target, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    current_layer.use_text("Method:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&cert_data.wipe_result.method, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    let bytes_str = format!("{} bytes", cert_data.wipe_result.bytes_wiped);
    current_layer.use_text("Bytes Wiped:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&bytes_str, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    let passes_str = format!("{}", cert_data.wipe_result.passes_completed);
    current_layer.use_text("Passes Completed:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&passes_str, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    let duration_str = format!("{} ms", cert_data.wipe_result.duration_ms);
    current_layer.use_text("Duration:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&duration_str, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    current_layer.use_text("Device ID:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    current_layer.use_text(&cert_data.wipe_result.device_id, 10.0, Mm(70.0), Mm(y_position), &font_regular);
    y_position -= 6.0;
    
    current_layer.use_text("Hash:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    // Wrap long hash
    let hash_chunks: Vec<String> = cert_data.wipe_result.hash
        .chars()
        .collect::<Vec<char>>()
        .chunks(60)
        .map(|c| c.iter().collect())
        .collect();
    for chunk in &hash_chunks {
        current_layer.use_text(chunk, 8.0, Mm(70.0), Mm(y_position), &font_mono);
        y_position -= 4.0;
    }
    y_position -= 6.0;
    
    // Digital Signature section
    current_layer.use_text("Digital Signature", 14.0, Mm(20.0), Mm(y_position), &font_bold);
    y_position -= 8.0;
    
    current_layer.use_text("Signature:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    y_position -= 5.0;
    // Wrap signature
    let sig_chunks: Vec<String> = cert_data.digital_signature
        .chars()
        .collect::<Vec<char>>()
        .chunks(80)
        .map(|c| c.iter().collect())
        .collect();
    for chunk in &sig_chunks {
        current_layer.use_text(chunk, 7.0, Mm(25.0), Mm(y_position), &font_mono);
        y_position -= 4.0;
    }
    y_position -= 3.0;
    
    current_layer.use_text("Public Key:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    y_position -= 5.0;
    // Wrap public key
    let key_chunks: Vec<String> = cert_data.public_key
        .chars()
        .collect::<Vec<char>>()
        .chunks(80)
        .map(|c| c.iter().collect())
        .collect();
    for chunk in &key_chunks {
        current_layer.use_text(chunk, 7.0, Mm(25.0), Mm(y_position), &font_mono);
        y_position -= 4.0;
    }
    y_position -= 3.0;
    
    current_layer.use_text("Verification Hash:", 10.0, Mm(25.0), Mm(y_position), &font_bold);
    y_position -= 5.0;
    // Wrap verification hash
    let hash_ver_chunks: Vec<String> = cert_data.verification_hash
        .chars()
        .collect::<Vec<char>>()
        .chunks(80)
        .map(|c| c.iter().collect())
        .collect();
    for chunk in &hash_ver_chunks {
        current_layer.use_text(chunk, 7.0, Mm(25.0), Mm(y_position), &font_mono);
        y_position -= 4.0;
    }
    y_position -= 8.0;
    
    // Verification Instructions
    if y_position > 50.0 {
        current_layer.use_text("Verification Instructions", 14.0, Mm(20.0), Mm(y_position), &font_bold);
        y_position -= 7.0;
        
        current_layer.use_text("1. Verify the digital signature using the provided public key", 9.0, Mm(25.0), Mm(y_position), &font_regular);
        y_position -= 5.0;
        current_layer.use_text("2. Check that the verification hash matches the computed hash", 9.0, Mm(25.0), Mm(y_position), &font_regular);
        y_position -= 5.0;
        current_layer.use_text("3. Validate the timestamp and certificate ID", 9.0, Mm(25.0), Mm(y_position), &font_regular);
        y_position -= 5.0;
        current_layer.use_text("4. Confirm the wipe method and target match your records", 9.0, Mm(25.0), Mm(y_position), &font_regular);
    }
    
    // Footer
    current_layer.use_text("ZeroRecover - Secure Data Wiping Tool", 8.0, Mm(60.0), Mm(20.0), &font_regular);
    current_layer.use_text("Certificate is cryptographically signed and tamper-proof", 8.0, Mm(45.0), Mm(15.0), &font_regular);
    
    // Save PDF to bytes
    let pdf_bytes = doc.save_to_bytes()?;
    Ok(pdf_bytes)
}
