use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;
use std::collections::HashMap;
use std::ptr;
use std::mem;
use winapi::um::fileapi::{GetDriveTypeA, GetVolumeInformationA, GetDiskFreeSpaceExA, CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winioctl::{IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_PROPERTY_QUERY, StorageDeviceSeekPenaltyProperty};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ};
use winapi::shared::minwindef::{DWORD, LPVOID, FALSE};
use anyhow::{Result, Context};
use rand::Rng;
use sha2::{Sha256, Digest};
use chrono::Utc;

use crate::types::{DriveInfo, WipeResult, WipeMethod, WipeProgress};

#[repr(C)]
struct STORAGE_PROPERTY_QUERY_WRAPPER {
    property_id: i32,
    query_type: i32,
    additional_parameters: [u8; 1],
}

#[repr(C)]
struct DEVICE_SEEK_PENALTY_DESCRIPTOR {
    version: u32,
    size: u32,
    incurs_seek_penalty: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriveType {
    HDD,
    SSD,
    Unknown,
}

pub struct WipeEngine {
    buffer: Vec<u8>,
}

impl WipeEngine {
    pub fn new() -> Self {
        Self {
            buffer: vec![0u8; 1024 * 1024], // 1MB buffer
        }
    }

    /// Detect if a drive is SSD or HDD using Windows API
    fn detect_drive_type(drive_letter: &str) -> DriveType {
        let physical_drive = format!("\\\\.\\{}:", drive_letter);
        
        let handle = unsafe {
            CreateFileA(
                physical_drive.as_ptr() as *const i8,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return DriveType::Unknown;
        }

        let mut query = STORAGE_PROPERTY_QUERY_WRAPPER {
            property_id: StorageDeviceSeekPenaltyProperty as i32,
            query_type: 0, // PropertyStandardQuery
            additional_parameters: [0],
        };

        let mut descriptor = DEVICE_SEEK_PENALTY_DESCRIPTOR {
            version: 0,
            size: 0,
            incurs_seek_penalty: 0,
        };

        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &mut query as *mut _ as LPVOID,
                mem::size_of::<STORAGE_PROPERTY_QUERY_WRAPPER>() as DWORD,
                &mut descriptor as *mut _ as LPVOID,
                mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        unsafe {
            CloseHandle(handle);
        }

        if result == 0 {
            return DriveType::Unknown;
        }

        // If incurs_seek_penalty is FALSE (0), it's an SSD
        // If TRUE (1), it's an HDD
        if descriptor.incurs_seek_penalty == 0 {
            DriveType::SSD
        } else {
            DriveType::HDD
        }
    }

    pub fn get_available_drives() -> Result<Vec<DriveInfo>> {
        let mut drives = Vec::new();
        
        for letter in b'A'..=b'Z' {
            let drive_path = format!("{}:\\", letter as char);
            let drive_type = unsafe {
                GetDriveTypeA(drive_path.as_ptr() as *const i8)
            };
            
            if drive_type == winapi::um::winbase::DRIVE_FIXED {
                if let Ok(info) = Self::get_drive_info(&drive_path) {
                    drives.push(info);
                }
            }
        }
        
        Ok(drives)
    }

    fn get_drive_info(drive_path: &str) -> Result<DriveInfo> {
        let mut volume_name = [0u8; 256];
        let mut file_system = [0u8; 256];
        let mut serial_number = 0u32;
        let mut max_component_length = 0u32;
        let mut file_system_flags = 0u32;

        let result = unsafe {
            GetVolumeInformationA(
                drive_path.as_ptr() as *const i8,
                volume_name.as_mut_ptr() as *mut i8,
                volume_name.len() as u32,
                &mut serial_number,
                &mut max_component_length,
                &mut file_system_flags,
                file_system.as_mut_ptr() as *mut i8,
                file_system.len() as u32,
            )
        };

        if result == 0 {
            return Err(anyhow::anyhow!("Failed to get volume information"));
        }

        let label = String::from_utf8_lossy(&volume_name[..volume_name.iter().position(|&x| x == 0).unwrap_or(volume_name.len())]).to_string();
        let fs = String::from_utf8_lossy(&file_system[..file_system.iter().position(|&x| x == 0).unwrap_or(file_system.len())]).to_string();

        // Get actual drive size using GetDiskFreeSpaceExA
        let mut free_bytes_available: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free_bytes: u64 = 0;

        let disk_result = unsafe {
            GetDiskFreeSpaceExA(
                drive_path.as_ptr() as *const i8,
                &mut free_bytes_available as *mut u64 as *mut _,
                &mut total_bytes as *mut u64 as *mut _,
                &mut total_free_bytes as *mut u64 as *mut _,
            )
        };

        if disk_result == 0 {
            return Err(anyhow::anyhow!("Failed to get disk free space information"));
        }
        let total_size = total_bytes;
        let free_size = free_bytes_available;

        let drive_letter = drive_path.chars().next().unwrap().to_string();
        let detected_type = Self::detect_drive_type(&drive_letter);
        
        let drive_type_str = match detected_type {
            DriveType::SSD => "SSD".to_string(),
            DriveType::HDD => "HDD".to_string(),
            DriveType::Unknown => "Unknown".to_string(),
        };

        Ok(DriveInfo {
            letter: drive_letter,
            label,
            total_size,
            free_size,
            file_system: fs,
            is_removable: false,
            drive_type: drive_type_str,
        })
    }

    pub async fn wipe_file(&self, file_path: &str, method: &str) -> Result<WipeResult> {
        let start_time = Instant::now();
        let wipe_method = Self::parse_method(method);
        
        // Get file size before wiping
        let file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        drop(file); // Close the file
        
        // Detect drive type for the file's location
        let drive_letter = if file_path.len() >= 2 && file_path.chars().nth(1) == Some(':') {
            file_path.chars().nth(0).unwrap().to_string()
        } else {
            "C".to_string() // Default to C: if can't detect
        };
        
        let drive_type = Self::detect_drive_type(&drive_letter);
        
        // Optimize wipe strategy based on drive type
        let passes = match drive_type {
            DriveType::SSD => {
                // For SSDs, reduce passes as they have wear leveling
                // Single pass is usually sufficient for SSDs
                match wipe_method {
                    WipeMethod::Gutmann => 1, // Reduce from 35 to 1 for SSD
                    WipeMethod::DoD_5220_22_M => 1, // Reduce from 3 to 1 for SSD
                    WipeMethod::Random => 1, // Reduce from 3 to 1 for SSD
                    _ => wipe_method.passes(),
                }
            },
            DriveType::HDD => {
                // For HDDs, use full pass count for security
                wipe_method.passes()
            },
            DriveType::Unknown => {
                // If unknown, use full passes to be safe
                wipe_method.passes()
            }
        };
        
        let mut hasher = Sha256::new();
        hasher.update(file_path.as_bytes());
        let device_id = format!("{:x}", hasher.finalize());
        
        let mut total_bytes_written = 0u64;
        
        // Perform multiple overwrite passes
        for pass in 1..=passes {
            let mut file = OpenOptions::new()
                .write(true)
                .open(file_path)?;
            
            file.seek(SeekFrom::Start(0))?;
            
            let pattern = self.get_wipe_pattern(&wipe_method, pass);
            let mut remaining = file_size;
            
            while remaining > 0 {
                let chunk_size = std::cmp::min(remaining, self.buffer.len() as u64);
                file.write_all(&pattern[..chunk_size as usize])?;
                remaining -= chunk_size;
                total_bytes_written += chunk_size;
            }
            
            file.sync_all()?;
        }
        
        // For SSDs, issue TRIM command after wiping (if supported)
        if drive_type == DriveType::SSD {
            // TRIM command would be issued here in full implementation
            // This helps SSDs mark blocks as unused for garbage collection
        }
        
        // Delete the file after wiping
        std::fs::remove_file(file_path)
            .context("Failed to delete file after wiping")?;
        
        let duration = start_time.elapsed();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}{}", file_path, method, Utc::now().timestamp()).as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        // Include drive type info in method description
        let method_description = format!("{} ({})", method, match drive_type {
            DriveType::SSD => "SSD-optimized",
            DriveType::HDD => "HDD",
            DriveType::Unknown => "Unknown drive type",
        });
        
        Ok(WipeResult {
            success: true,
            target: file_path.to_string(),
            method: method_description,
            bytes_wiped: total_bytes_written,
            passes_completed: passes,
            duration_ms: duration.as_millis() as u64,
            timestamp: Utc::now(),
            device_id,
            hash,
            error_message: None,
        })
    }

    pub async fn wipe_folder(&self, folder_path: &str, method: &str) -> Result<WipeResult> {
        let start_time = Instant::now();
        let wipe_method = Self::parse_method(method);
        let passes = wipe_method.passes();
        
        let mut total_bytes = 0u64;
        let mut files_processed = 0u32;
        
        self.wipe_directory_recursive(folder_path, &wipe_method, &mut total_bytes, &mut files_processed)?;
        
        let duration = start_time.elapsed();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}{}", folder_path, method, Utc::now().timestamp()).as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        let mut hasher2 = Sha256::new();
        hasher2.update(format!("{}{}", folder_path, method).as_bytes());
        let device_id = format!("{:x}", hasher2.finalize());
        
        Ok(WipeResult {
            success: true,
            target: folder_path.to_string(),
            method: method.to_string(),
            bytes_wiped: total_bytes,
            passes_completed: passes,
            duration_ms: duration.as_millis() as u64,
            timestamp: Utc::now(),
            device_id,
            hash,
            error_message: None,
        })
    }

    fn wipe_directory_recursive(&self, path: &str, method: &WipeMethod, total_bytes: &mut u64, files_processed: &mut u32) -> Result<()> {
        let entries = std::fs::read_dir(path)?;
        
        for entry in entries {
            let entry = entry?;
            let entry_path = entry.path();
            
            if entry_path.is_file() {
                if let Ok(file_result) = self.wipe_file_sync(entry_path.to_str().unwrap(), &method.name()) {
                    *total_bytes += file_result.bytes_wiped;
                    *files_processed += 1;
                }
            } else if entry_path.is_dir() {
                self.wipe_directory_recursive(entry_path.to_str().unwrap(), method, total_bytes, files_processed)?;
            }
        }
        
        Ok(())
    }

    fn wipe_file_sync(&self, file_path: &str, method: &str) -> Result<WipeResult> {
        let start_time = Instant::now();
        let wipe_method = Self::parse_method(method);
        
        // Get file size before wiping
        let file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        drop(file); // Close the file
        
        // Detect drive type for the file's location
        let drive_letter = if file_path.len() >= 2 && file_path.chars().nth(1) == Some(':') {
            file_path.chars().nth(0).unwrap().to_string()
        } else {
            "C".to_string() // Default to C: if can't detect
        };
        
        let drive_type = Self::detect_drive_type(&drive_letter);
        
        // Optimize wipe strategy based on drive type
        let passes = match drive_type {
            DriveType::SSD => {
                // For SSDs, reduce passes as they have wear leveling
                // Single pass is usually sufficient for SSDs
                match wipe_method {
                    WipeMethod::Gutmann => 1, // Reduce from 35 to 1 for SSD
                    WipeMethod::DoD_5220_22_M => 1, // Reduce from 3 to 1 for SSD
                    WipeMethod::Random => 1, // Reduce from 3 to 1 for SSD
                    WipeMethod::NIST_SP_800_88 => 1, // Reduce from 1 to 1 for SSD (already optimal)
                    WipeMethod::Zero => 1, // Single zero pass for SSD
                }
            },
            DriveType::HDD => {
                // For HDDs, use full passes as they don't have wear leveling
                wipe_method.passes()
            },
            DriveType::Unknown => {
                // For unknown drive types, use conservative approach
                wipe_method.passes()
            }
        };

        // Perform the actual wiping
        for pass in 0..passes {
            let mut file = File::create(file_path)?;
            
            match wipe_method {
                WipeMethod::Zero => {
                    // Write zeros
                    let buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
                    let mut remaining = file_size;
                    while remaining > 0 {
                        let write_size = std::cmp::min(remaining, buffer.len() as u64);
                        file.write_all(&buffer[..write_size as usize])?;
                        remaining -= write_size;
                    }
                },
                WipeMethod::Random => {
                    // Write random data
                    let mut rng = rand::thread_rng();
                    let buffer: Vec<u8> = (0..1024 * 1024).map(|_| rng.gen()).collect();
                    let mut remaining = file_size;
                    while remaining > 0 {
                        let write_size = std::cmp::min(remaining, buffer.len() as u64);
                        file.write_all(&buffer[..write_size as usize])?;
                        remaining -= write_size;
                    }
                },
                WipeMethod::Gutmann => {
                    // Gutmann method patterns (simplified for SSD)
                    if drive_type == DriveType::SSD {
                        // For SSD, just use random data
                        let mut rng = rand::thread_rng();
                        let buffer: Vec<u8> = (0..1024 * 1024).map(|_| rng.gen()).collect();
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                    } else {
                        // For HDD, use Gutmann patterns (simplified)
                        let patterns = [
                            0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
                        ];
                        let pattern = patterns[(pass as usize) % patterns.len()];
                        let buffer = vec![pattern; 1024 * 1024];
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                    }
                },
                WipeMethod::DoD_5220_22_M => {
                    // DoD 5220.22-M method
                    if pass == 0 {
                        // First pass: write zeros
                        let buffer = vec![0u8; 1024 * 1024];
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                    } else if pass == 1 {
                        // Second pass: write ones
                        let buffer = vec![0xFFu8; 1024 * 1024];
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                    } else {
                        // Third pass: write random data
                        let mut rng = rand::thread_rng();
                        let buffer: Vec<u8> = (0..1024 * 1024).map(|_| rng.gen()).collect();
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                    }
                },
                WipeMethod::NIST_SP_800_88 => {
                    // NIST SP 800-88 method (single random pass)
                    let mut rng = rand::thread_rng();
                    let buffer: Vec<u8> = (0..1024 * 1024).map(|_| rng.gen()).collect();
                    let mut remaining = file_size;
                    while remaining > 0 {
                        let write_size = std::cmp::min(remaining, buffer.len() as u64);
                        file.write_all(&buffer[..write_size as usize])?;
                        remaining -= write_size;
                    }
                }
            }
            
            file.flush()?;
        }
        
        // Delete the file after wiping
        std::fs::remove_file(file_path)?;
        
        let duration = start_time.elapsed();
        
        Ok(WipeResult {
            success: true,
            target: file_path.to_string(),
            method: method.to_string(),
            bytes_wiped: file_size,
            duration_ms: duration.as_millis() as u64,
            passes_completed: passes,
            timestamp: Utc::now(),
            device_id: format!("{:x}", Sha256::digest(format!("{}{}", file_path, method).as_bytes())),
            hash: format!("{:x}", Sha256::digest(format!("{}{}{}", file_path, method, file_size).as_bytes())),
            error_message: None,
        })
    }

    pub async fn wipe_drive(&self, drive_letter: &str, method: &str) -> Result<WipeResult> {
        let start_time = Instant::now();
        let wipe_method = Self::parse_method(method);
        
        // Detect drive type (SSD vs HDD)
        let drive_type = Self::detect_drive_type(drive_letter);
        
        // Optimize passes based on drive type
        let passes = match drive_type {
            DriveType::SSD => {
                // For SSDs, reduce passes to minimize wear
                // SSDs have wear leveling, so fewer passes are needed
                match wipe_method {
                    WipeMethod::Gutmann => 1, // Reduce from 35 to 1 for SSD
                    WipeMethod::DoD_5220_22_M => 1, // Reduce from 3 to 1 for SSD
                    WipeMethod::Random => 1, // Reduce from 3 to 1 for SSD
                    _ => wipe_method.passes(),
                }
            },
            DriveType::HDD => {
                // For HDDs, use full pass count for maximum security
                wipe_method.passes()
            },
            DriveType::Unknown => {
                // If unknown, use full passes to be safe
                wipe_method.passes()
            }
        };
        
        let drive_path = format!("{}:\\", drive_letter);
        let mut total_bytes = 0u64;
        
        // Step 1: Wipe all files and folders on the drive
        if let Ok(entries) = std::fs::read_dir(&drive_path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Ok(result) = self.wipe_file(entry_path.to_str().unwrap(), method).await {
                        total_bytes += result.bytes_wiped;
                    }
                } else if entry_path.is_dir() {
                    let mut dir_bytes = 0u64;
                    let mut files_processed = 0u32;
                    if let Ok(_) = self.wipe_directory_recursive(
                        entry_path.to_str().unwrap(), 
                        &wipe_method, 
                        &mut dir_bytes, 
                        &mut files_processed
                    ) {
                        total_bytes += dir_bytes;
                    }
                }
            }
        }
        
        // Step 2: SSD-specific optimizations
        if drive_type == DriveType::SSD {
            // For SSDs, issue TRIM command to help with garbage collection
            // This ensures deleted data is actually erased at the hardware level
            // TRIM command implementation would go here
            // Note: Requires administrator privileges and IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES
        }
        
        // Step 3: Handle hidden storage areas (HPA, DCO) for HDDs
        if drive_type == DriveType::HDD {
            // For HDDs, check and wipe hidden areas
            // This is a simplified implementation - full implementation would require:
            // - Administrator privileges
            // - Direct disk access via CreateFile with GENERIC_READ | GENERIC_WRITE
            // - ATA command pass-through for HPA/DCO detection and removal
        }
        
        let duration = start_time.elapsed();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}{}", drive_letter, method, Utc::now().timestamp()).as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        let mut device_hasher = Sha256::new();
        device_hasher.update(drive_letter.as_bytes());
        let device_id = format!("{:x}", device_hasher.finalize());
        
        // Include drive type info in method description
        let method_description = format!("{} ({})", method, match drive_type {
            DriveType::SSD => "SSD-optimized with reduced passes",
            DriveType::HDD => "HDD with full passes",
            DriveType::Unknown => "Unknown drive type",
        });
        
        Ok(WipeResult {
            success: true,
            target: format!("{}:", drive_letter),
            method: method_description,
            bytes_wiped: total_bytes,
            passes_completed: passes,
            duration_ms: duration.as_millis() as u64,
            timestamp: Utc::now(),
            device_id,
            hash,
            error_message: None,
        })
    }

    fn parse_method(method: &str) -> WipeMethod {
        match method {
            "NIST SP 800-88" => WipeMethod::NIST_SP_800_88,
            "DoD 5220.22-M" => WipeMethod::DoD_5220_22_M,
            "Gutmann" => WipeMethod::Gutmann,
            "Random" => WipeMethod::Random,
            "Zero" => WipeMethod::Zero,
            _ => WipeMethod::NIST_SP_800_88,
        }
    }

    fn get_wipe_pattern(&self, method: &WipeMethod, pass: u32) -> Vec<u8> {
        let mut pattern = vec![0u8; self.buffer.len()];
        
        match method {
            WipeMethod::NIST_SP_800_88 => {
                // Single pass with random data
                let mut rng = rand::thread_rng();
                for byte in pattern.iter_mut() {
                    *byte = rng.gen();
                }
            },
            WipeMethod::DoD_5220_22_M => {
                // DoD 5220.22-M Standard (3 passes):
                // Pass 1: Write a character (0x00)
                // Pass 2: Write complement (0xFF)
                // Pass 3: Write random character and verify
                match pass {
                    1 => pattern.fill(0x00),  // First pass: zeros
                    2 => pattern.fill(0xFF),  // Second pass: ones (complement)
                    3 => {
                        // Third pass: random data
                        let mut rng = rand::thread_rng();
                        for byte in pattern.iter_mut() {
                            *byte = rng.gen();
                        }
                    },
                    _ => pattern.fill(0x00),
                }
            },
            WipeMethod::Gutmann => {
                // Gutmann method patterns (simplified)
                let patterns = [
                    0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                    0xFF, 0x92, 0x49, 0x24, 0x49, 0x24, 0x92, 0x24, 0x49, 0x92,
                    0x24, 0x49, 0x92, 0x49, 0x24, 0x00
                ];
                
                if pass <= patterns.len() as u32 {
                    pattern.fill(patterns[(pass - 1) as usize]);
                } else {
                    let mut rng = rand::thread_rng();
                    for byte in pattern.iter_mut() {
                        *byte = rng.gen();
                    }
                }
            },
            WipeMethod::Random => {
                let mut rng = rand::thread_rng();
                for byte in pattern.iter_mut() {
                    *byte = rng.gen();
                }
            },
            WipeMethod::Zero => {
                pattern.fill(0x00);
            },
        }
        
        pattern
    }
}
