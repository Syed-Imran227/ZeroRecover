// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod wipe_engine;
mod certificate;
mod types;
mod hidden_storage;
mod path_validator;

use tauri::{Manager, State};
use wipe_engine::WipeEngine;
use types::{WipeRequest, WipeResult, DriveInfo, WipeProgress};
use hidden_storage::HiddenStorageManager;
use path_validator::PathValidator;

#[tauri::command]
async fn get_drives() -> Result<Vec<DriveInfo>, String> {
    WipeEngine::get_available_drives()
        .map_err(|e| format!("Failed to get drives: {}", e))
}

#[tauri::command]
async fn wipe_file(file_path: String, method: String) -> Result<WipeResult, String> {
    // Validate and canonicalize input path to prevent traversal
    let validated_path = PathValidator::validate_file_path(&file_path)
        .map_err(|e| format!("Invalid file path: {}", e))?;

    let wipe_engine = WipeEngine::new();
    wipe_engine.wipe_file(validated_path.to_str().ok_or("Invalid UTF-8 in path")?, &method)
        .await
        .map_err(|e| format!("Failed to wipe file: {}", e))
}

#[tauri::command]
async fn wipe_folder(folder_path: String, method: String) -> Result<WipeResult, String> {
    // Validate and canonicalize input path to prevent traversal
    let validated_path = PathValidator::validate_folder_path(&folder_path)
        .map_err(|e| format!("Invalid folder path: {}", e))?;

    let wipe_engine = WipeEngine::new();
    wipe_engine.wipe_folder(validated_path.to_str().ok_or("Invalid UTF-8 in path")?, &method)
        .await
        .map_err(|e| format!("Failed to wipe folder: {}", e))
}

#[tauri::command]
async fn wipe_drive(drive_letter: String, method: String) -> Result<WipeResult, String> {
    // Validate drive letter
    let validated_letter = PathValidator::validate_drive_letter(&drive_letter)
        .map_err(|e| format!("Invalid drive: {}", e))?;

    let wipe_engine = WipeEngine::new();
    wipe_engine.wipe_drive(&validated_letter, &method)
        .await
        .map_err(|e| format!("Failed to wipe drive: {}", e))
}

#[tauri::command]
async fn generate_certificate(result: WipeResult) -> Result<String, String> {
    certificate::generate_certificate(result)
        .map_err(|e| format!("Failed to generate certificate: {}", e))
}

#[tauri::command]
async fn check_hidden_areas(drive_letter: String) -> Result<String, String> {
    let validated_letter = PathValidator::validate_drive_letter(&drive_letter)
        .map_err(|e| format!("Invalid drive: {}", e))?;
    HiddenStorageManager::get_comprehensive_drive_info(&validated_letter)
        .map_err(|e| format!("Failed to check hidden areas: {}", e))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_drives,
            wipe_file,
            wipe_folder,
            wipe_drive,
            generate_certificate,
            check_hidden_areas
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
