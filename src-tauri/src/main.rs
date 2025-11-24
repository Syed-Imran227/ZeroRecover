// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod wipe_engine;
mod certificate;
mod types;
mod hidden_storage;
mod path_validator;
mod privilege_check;
mod audit_log;

use crate::types::{WipeResult, DriveInfo, WipeProgress};
use wipe_engine::{WipeEngine, ProgressReporter};
use hidden_storage::HiddenStorageManager;
use path_validator::PathValidator;
use privilege_check::{require_admin, is_elevated};
use audit_log::AuditLogger;
use tauri::{Window, Emitter};

// Progress reporter that sends updates to the frontend
struct TauriProgressReporter {
    window: Window,
    operation_id: String,
}

impl ProgressReporter for TauriProgressReporter {
    fn report(&self, progress: WipeProgress) {
        // Send progress update to the frontend
        if let Err(e) = self.window.emit("wipe-progress", (&self.operation_id, progress)) {
            eprintln!("Failed to send progress update: {}", e);
        }
    }
}

#[tauri::command]
async fn get_drives() -> Result<Vec<DriveInfo>, String> {
    WipeEngine::get_available_drives()
        .map_err(|e| format!("Failed to get drives: {}", e))
}

#[tauri::command]
#[allow(non_snake_case)]
async fn wipe_file(window: tauri::Window, filePath: String, method: String, operationId: Option<String>) -> Result<WipeResult, String> {
    // SECURITY: Audit log the operation attempt
    let audit_logger = AuditLogger::new();
    
    // Validate and canonicalize input path to prevent traversal
    let validated_path = PathValidator::validate_file_path(&filePath)
        .map_err(|e| {
            // Log security violation
            let _ = audit_logger.log_security_violation("Path Validation", &format!("Invalid file path: {}", e));
            format!("Invalid file path: {}", e)
        })?;
    
    // Additional security: Ensure file operations stay within user directories
    // Allow operations in user folders but restrict system areas
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users".to_string());
    let allowed_parent = std::path::Path::new(&user_profile);
    
    // Only apply parent validation for non-admin users on non-system files
    let is_admin = is_elevated().map_err(|e| format!("Failed to check admin status: {}", e))?;
    if !is_admin && !PathValidator::is_system_file(&validated_path.to_string_lossy()) {
        if let Err(e) = PathValidator::validate_path_within_parent(&validated_path, allowed_parent) {
            let _ = audit_logger.log_security_violation("Directory Traversal", &format!("Attempted access outside user directory: {}", e));
            return Err(format!("Access restricted: {}", e));
        }
    }
        
    // Check admin privileges for system files
    if !is_admin && PathValidator::is_system_file(&validated_path.to_string_lossy()) {
        return Err("Administrator privileges required for system files".to_string());
    }
    
    // Log the wipe attempt
    if let Err(e) = audit_logger.log_wipe_operation(
        "file",
        &filePath, 
        &method,
        0,  // bytes_wiped
        false,  // success
    ) {
        eprintln!("Failed to log wipe operation: {}", e);
    }
    
    // Create progress reporter
    let progress_reporter = TauriProgressReporter {
        window: window.clone(),
        operation_id: operationId.clone().unwrap_or_default(),
    };
    
    // Create wipe engine with progress reporting
    let wipe_engine = WipeEngine::with_progress_reporter(Box::new(progress_reporter));
    
    // Perform the wipe
    let result = wipe_engine
        .wipe_file(&validated_path.to_string_lossy(), &method)
        .await
        .map_err(|e| {
            // Log the error
            let _ = audit_logger.log_wipe_operation(
                "file",
                &filePath,
                &method,
                0,  // bytes_wiped
                false,  // success
            );
            e.to_string()
        })?;
    
    // Log the result
    let _ = audit_logger.log_wipe_operation(
        "file",
        &filePath,
        &method,
        result.bytes_wiped,
        true,  // success
    );
    
    Ok(result)
}

#[tauri::command]
#[allow(non_snake_case)]
async fn wipe_folder(folderPath: String, method: String) -> Result<WipeResult, String> {
    // SECURITY: Audit log the operation attempt
    let audit_logger = AuditLogger::new();
    
    // Validate and canonicalize input path to prevent traversal
    let validated_path = PathValidator::validate_folder_path(&folderPath)
        .map_err(|e| {
            // Log security violation
            let _ = audit_logger.log_security_violation("Path Validation", &format!("Invalid folder path: {}", e));
            format!("Invalid folder path: {}", e)
        })?;
    
    // Additional security: Ensure folder operations stay within user directories
    // Allow operations in user folders but restrict system areas
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users".to_string());
    let allowed_parent = std::path::Path::new(&user_profile);
    
    // Only apply parent validation for non-admin users on non-system folders
    let is_admin = is_elevated().map_err(|e| format!("Failed to check admin status: {}", e))?;
    if !is_admin && !PathValidator::is_system_file(&validated_path.to_string_lossy()) {
        if let Err(e) = PathValidator::validate_path_within_parent(&validated_path, allowed_parent) {
            let _ = audit_logger.log_security_violation("Directory Traversal", &format!("Attempted folder access outside user directory: {}", e));
            return Err(format!("Access restricted: {}", e));
        }
    }

    let wipe_engine = WipeEngine::new();
    let result = wipe_engine.wipe_folder(validated_path.to_str().ok_or("Invalid UTF-8 in path")?, &method)
        .await
        .map_err(|e| format!("Failed to wipe folder: {}", e))?;
    
    // SECURITY: Audit log the operation result
    let _ = audit_logger.log_wipe_operation(
        "folder",
        &folderPath,
        &method,
        result.bytes_wiped,
        true,
    );
    
    Ok(result)
}

#[tauri::command]
#[allow(non_snake_case)]
async fn wipe_drive(driveLetter: String, method: String) -> Result<WipeResult, String> {
    // SECURITY: Audit log the operation attempt
    let audit_logger = AuditLogger::new();
    
    // CRITICAL: Check administrator privileges before drive operations
    require_admin()
        .map_err(|e| {
            let _ = audit_logger.log_security_violation("Admin Required", &format!("Drive wipe without admin: {}", driveLetter));
            format!("ADMINISTRATOR PRIVILEGES REQUIRED: {}", e)
        })?;
    
    // Validate drive letter
    let validated_letter = PathValidator::validate_drive_letter(&driveLetter)
        .map_err(|e| {
            let _ = audit_logger.log_security_violation("Drive Validation", &format!("Invalid drive: {}", e));
            format!("Invalid drive: {}", e)
        })?;

    let wipe_engine = WipeEngine::new();
    let result = wipe_engine.wipe_drive(&validated_letter, &method)
        .await
        .map_err(|e| format!("Failed to wipe drive: {}", e))?;
    
    // SECURITY: Audit log the operation result
    let _ = audit_logger.log_wipe_operation(
        "drive",
        &format!("{}:", driveLetter),
        &method,
        result.bytes_wiped,
        true,
    );
    
    Ok(result)
}

#[tauri::command]
async fn generate_certificate(result: WipeResult) -> Result<String, String> {
    certificate::generate_certificate(result)
        .map_err(|e| format!("Failed to generate certificate: {}", e))
}

#[tauri::command]
#[allow(non_snake_case)]
async fn check_hidden_areas(driveLetter: String) -> Result<String, String> {
    // Check admin privileges for low-level drive operations
    require_admin()
        .map_err(|e| format!("ADMINISTRATOR PRIVILEGES REQUIRED: {}", e))?;
    
    let validated_letter = PathValidator::validate_drive_letter(&driveLetter)
        .map_err(|e| format!("Invalid drive: {}", e))?;
    HiddenStorageManager::get_comprehensive_drive_info(&validated_letter)
        .map_err(|e| format!("Failed to check hidden areas: {}", e))
}

#[tauri::command]
async fn check_admin_status() -> Result<bool, String> {
    let result = is_elevated()
        .map_err(|e| format!("Failed to check admin status: {}", e))?;
    
    // SECURITY: Audit log admin privilege check
    let audit_logger = AuditLogger::new();
    let _ = audit_logger.log_admin_check(result);
    
    Ok(result)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_drives,
            wipe_file,
            wipe_folder,
            wipe_drive,
            generate_certificate,
            check_hidden_areas,
            check_admin_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
