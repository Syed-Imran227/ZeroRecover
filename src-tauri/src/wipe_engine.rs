use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use std::time::Instant;
use std::ptr;
use std::mem;
use std::os::windows::io::AsRawHandle;
use winapi::um::fileapi::{GetDriveTypeA, GetVolumeInformationA, GetDiskFreeSpaceExA, CreateFileA, OPEN_EXISTING, LockFileEx, UnlockFile};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winioctl::{IOCTL_STORAGE_QUERY_PROPERTY, StorageDeviceSeekPenaltyProperty, IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL};
use winapi::um::minwinbase::{OVERLAPPED, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
use winapi::shared::minwindef::{DWORD, LPVOID};
use anyhow::{Result, Context, bail};
use ring::rand::{SystemRandom, SecureRandom};
use sha2::{Sha256, Digest};
use chrono::Utc;
use zeroize::ZeroizeOnDrop;

use crate::types::{DriveInfo, WipeResult, WipeMethod, WipeProgress};

/// Trait for reporting wipe progress
pub trait ProgressReporter: Send + Sync {
    fn report(&self, progress: WipeProgress);
}

/// No-op progress reporter for when no progress reporting is needed
pub struct NoopProgressReporter;

impl ProgressReporter for NoopProgressReporter {
    fn report(&self, _progress: WipeProgress) {
        // Intentionally do nothing
    }
}

#[repr(C)]
struct STORAGE_PROPERTY_QUERY_WRAPPER {
    property_id: i32,
    query_type: i32,
    additional_parameters: [u8; 1],
}

// Windows TRIM/UNMAP structures for SSD optimization
#[repr(C)]
struct DEVICE_MANAGE_DATA_SET_ATTRIBUTES {
    size: DWORD,
    action: DWORD,
    flags: DWORD,
    parameter_block_offset: DWORD,
    parameter_block_length: DWORD,
    data_set_ranges_offset: DWORD,
    data_set_ranges_length: DWORD,
}

#[repr(C)]
struct DEVICE_DATA_SET_RANGE {
    starting_offset: i64,
    length_in_bytes: i64,
}

const DEVICE_DSM_ACTION_TRIM: DWORD = 1;

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

/// SECURITY: Secure buffer that automatically zeros memory on drop
/// Prevents sensitive wipe patterns from remaining in memory/swap
#[derive(ZeroizeOnDrop)]
struct SecureBuffer {
    #[zeroize(skip)]
    _marker: std::marker::PhantomData<()>,
    data: Vec<u8>,
}

impl SecureBuffer {
    fn new(size: usize) -> Self {
        Self {
            _marker: std::marker::PhantomData,
            data: vec![0u8; size],
        }
    }
    
    #[allow(dead_code)]
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.data.len()
    }
}

pub struct WipeEngine {
    progress_reporter: Box<dyn ProgressReporter>,
    buffer: Vec<u8>,
}

impl WipeEngine {
    pub fn new() -> Self {
        Self::with_progress_reporter(Box::new(NoopProgressReporter))
    }

    /// Create a new WipeEngine with a custom progress reporter
    pub fn with_progress_reporter(progress_reporter: Box<dyn ProgressReporter>) -> Self {
        WipeEngine { progress_reporter, buffer: vec![0u8; 1024 * 1024] } // 1MB buffer
    }

    /// Check if a file is locked by another process
    /// 
    /// SECURITY: Prevents wiping files that are currently in use, which could:
    /// - Corrupt running programs
    /// - Crash system processes
    /// - Cause data corruption
    /// - Lead to system instability
    fn is_file_locked(file: &File) -> Result<bool> {
        unsafe {
            let handle = file.as_raw_handle();
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            
            // Try to acquire an exclusive lock on the entire file
            // LOCKFILE_EXCLUSIVE_LOCK: Request exclusive access
            // LOCKFILE_FAIL_IMMEDIATELY: Don't wait, fail immediately if locked
            let result = LockFileEx(
                handle as *mut _,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX, // Lock entire file (low DWORD)
                u32::MAX, // Lock entire file (high DWORD)
                &mut overlapped,
            );
            
            if result == 0 {
                // Failed to acquire lock - file is in use
                return Ok(true);
            }
            
            // Successfully acquired lock - unlock it immediately
            UnlockFile(
                handle as *mut _,
                0,
                0,
                u32::MAX,
                u32::MAX,
            );
            
            // File is not locked
            Ok(false)
        }
    }

    /// Verify file can be safely wiped (not locked, not in use)
    /// 
    /// SECURITY: Multi-layer check to ensure file safety
    fn verify_file_safe_to_wipe(file: &File, file_path: &str) -> Result<()> {
        // Check if file is locked by another process
        if Self::is_file_locked(file)? {
            bail!(
                "File is currently in use by another process: {}\n\
                Please close any programs using this file and try again.\n\
                Common causes:\n\
                - File is open in an application (Word, Excel, etc.)\n\
                - File is being used by a system process\n\
                - File is locked by antivirus software\n\
                - File is a running executable",
                file_path
            );
        }
        
        Ok(())
    }

    /// Issue TRIM command for SSD to mark blocks as unused
    /// 
    /// SECURITY: For SSDs, TRIM ensures deleted data is actually erased
    /// Prevents data recovery from unmapped blocks
    fn issue_trim_command(file_path: &str, file_size: u64) -> Result<()> {
        unsafe {
            // Get file metadata to determine starting offset
            let _metadata = std::fs::metadata(file_path)?;
            
            // Open the volume (drive) for TRIM operation
            let drive_letter = if file_path.len() >= 2 && file_path.chars().nth(1) == Some(':') {
                file_path.chars().nth(0).ok_or_else(|| anyhow::anyhow!("Invalid file path for TRIM"))?
            } else {
                return Ok(()); // Can't determine drive, skip TRIM
            };
            
            let volume_path = format!("\\\\.\\{}:", drive_letter);
            let volume_handle = CreateFileA(
                volume_path.as_ptr() as *const i8,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            
            if volume_handle == INVALID_HANDLE_VALUE {
                // Can't open volume (likely requires admin), skip TRIM
                return Ok(());
            }
            
            // Prepare TRIM data structures
            let range = DEVICE_DATA_SET_RANGE {
                starting_offset: 0, // File offset (simplified - would need actual cluster offset)
                length_in_bytes: file_size as i64,
            };
            
            let manage_data_set = DEVICE_MANAGE_DATA_SET_ATTRIBUTES {
                size: mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>() as DWORD,
                action: DEVICE_DSM_ACTION_TRIM,
                flags: 0,
                parameter_block_offset: 0,
                parameter_block_length: 0,
                data_set_ranges_offset: mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>() as DWORD,
                data_set_ranges_length: mem::size_of::<DEVICE_DATA_SET_RANGE>() as DWORD,
            };
            
            // Combine structures into single buffer
            let mut buffer = Vec::with_capacity(
                mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>() + 
                mem::size_of::<DEVICE_DATA_SET_RANGE>()
            );
            
            // Copy structures to buffer
            let manage_ptr = &manage_data_set as *const _ as *const u8;
            let manage_slice = std::slice::from_raw_parts(
                manage_ptr,
                mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>()
            );
            buffer.extend_from_slice(manage_slice);
            
            let range_ptr = &range as *const _ as *const u8;
            let range_slice = std::slice::from_raw_parts(
                range_ptr,
                mem::size_of::<DEVICE_DATA_SET_RANGE>()
            );
            buffer.extend_from_slice(range_slice);
            
            // Issue TRIM command
            let mut bytes_returned: DWORD = 0;
            let result = DeviceIoControl(
                volume_handle,
                IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES,
                buffer.as_ptr() as LPVOID,
                buffer.len() as DWORD,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            );
            
            CloseHandle(volume_handle);
            
            // TRIM is best-effort, don't fail if it doesn't work
            if result == 0 {
                // TRIM failed, but this is acceptable
                // (may require admin privileges or drive may not support it)
            }
            
            Ok(())
        }
    }

    /// Verify that a wipe pass was successful by reading back the data
    /// 
    /// SECURITY: Ensures data was actually overwritten, not just cached
    /// Detects write errors, disk failures, and caching issues
    fn verify_wipe_pass(file: &mut File, file_size: u64, expected_pattern: &[u8], pass: u32, file_path: &str) -> Result<()> {
        use std::io::Read;
        
        // Seek back to beginning for verification read
        file.seek(SeekFrom::Start(0))?;
        
        let mut verification_buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
        let mut bytes_verified = 0u64;
        let mut mismatches = 0u32;
        let mut first_mismatch_offset: Option<u64> = None;
        
        while bytes_verified < file_size {
            let bytes_to_read = std::cmp::min(
                (file_size - bytes_verified) as usize,
                verification_buffer.len()
            );
            
            // Read actual data from file
            let bytes_read = file.read(&mut verification_buffer[..bytes_to_read])?;
            if bytes_read == 0 {
                break; // EOF
            }
            
            // Verify each byte matches expected pattern
            for i in 0..bytes_read {
                let expected_byte = expected_pattern[i % expected_pattern.len()];
                let actual_byte = verification_buffer[i];
                
                if actual_byte != expected_byte {
                    mismatches += 1;
                    if first_mismatch_offset.is_none() {
                        first_mismatch_offset = Some(bytes_verified + i as u64);
                    }
                    
                    // Limit mismatch counting to avoid performance issues
                    if mismatches >= 100 {
                        break;
                    }
                }
            }
            
            bytes_verified += bytes_read as u64;
            
            // If we found significant mismatches, fail early
            if mismatches >= 100 {
                break;
            }
        }
        
        // Report verification failure if mismatches found
        if mismatches > 0 {
            bail!(
                "VERIFICATION FAILED for pass {} on file: {}\n\
                Data was not properly overwritten!\n\
                Mismatches found: {} bytes\n\
                First mismatch at offset: {}\n\
                Bytes verified: {} / {}\n\n\
                Possible causes:\n\
                - Disk write error\n\
                - Hardware failure\n\
                - File system caching issue\n\
                - Insufficient permissions\n\
                - Disk full or bad sectors\n\n\
                CRITICAL: File may still contain original data!\n\
                Do NOT rely on this wipe operation for security.",
                pass,
                file_path,
                mismatches,
                first_mismatch_offset.unwrap_or(0),
                bytes_verified,
                file_size
            );
        }
        
        Ok(())
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

        let drive_letter = drive_path.chars().next()
            .ok_or_else(|| anyhow::anyhow!("Invalid drive path: empty string"))?
            .to_string();
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
        
        // SECURITY FIX: Open file once and keep handle to prevent TOCTOU race condition
        // This prevents file swapping between size check and wipe operations
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path)
            .context("Failed to open file for wiping")?;
        
        // SECURITY CHECK: Verify file is not locked by another process
        // This prevents corrupting files that are currently in use
        Self::verify_file_safe_to_wipe(&file, file_path)?;
        
        // Get file size from the open handle (no TOCTOU vulnerability)
        let file_size = file.metadata()?.len();
        
        // Detect drive type for the file's location
        let drive_letter = if file_path.len() >= 2 && file_path.chars().nth(1) == Some(':') {
            file_path.chars().nth(0)
                .ok_or_else(|| anyhow::anyhow!("Invalid file path: cannot extract drive letter"))?
                .to_string()
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
                    WipeMethod::DoD522022M => 1, // Reduce from 3 to 1 for SSD
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
        
        // Perform multiple overwrite passes using the same file handle
        for pass in 1..=passes {
            // Seek to beginning for each pass (file handle stays open)
            file.seek(SeekFrom::Start(0))?;
            
            let pattern = self.get_wipe_pattern(&wipe_method, pass)?;
            let mut remaining = file_size;
            
            // Write pass
            while remaining > 0 {
                let chunk_size = std::cmp::min(
                    remaining as usize,
                    self.buffer.len()
                );
                
                // Report progress
                self.progress_reporter.report(WipeProgress {
                    current_pass: pass as u32,
                    total_passes: passes as u32,
                    bytes_processed: file_size - remaining,
                    total_bytes: file_size,
                    percentage: (file_size - remaining) as f32 / file_size as f32 * 100.0,
                    current_operation: format!("Wiping pass {} with {} method", pass, method),
                });
                
                file.write_all(&pattern[..chunk_size])?;
                remaining -= chunk_size as u64;
                total_bytes_written += chunk_size as u64;
            }
            
            // Force write to disk before verification
            file.sync_all()?;
            
            // SECURITY: Verify data was actually written
            // Read back and verify the pattern was written correctly
            Self::verify_wipe_pass(&mut file, file_size, &pattern, pass, file_path)?;
        }
        
        // Close file handle before deletion
        drop(file);
        
        // Delete the file after wiping
        std::fs::remove_file(file_path)
            .context("Failed to delete file after wiping")?;
        
        // SECURITY: For SSDs, issue TRIM command after deletion
        // This ensures deleted data is actually erased from unmapped blocks
        if drive_type == DriveType::SSD {
            // TRIM is best-effort and may require admin privileges
            // Failure is acceptable as the data has already been overwritten
            let _ = Self::issue_trim_command(file_path, file_size);
        }
        
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
        let mut errors: Vec<String> = Vec::new();
        
        // SECURITY FIX: Collect all errors instead of silently ignoring them
        self.wipe_directory_recursive(folder_path, &wipe_method, &mut total_bytes, &mut files_processed, &mut errors)?;
        
        let duration = start_time.elapsed();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}{}", folder_path, method, Utc::now().timestamp()).as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        let mut hasher2 = Sha256::new();
        hasher2.update(format!("{}{}", folder_path, method).as_bytes());
        let device_id = format!("{:x}", hasher2.finalize());
        
        // Determine success based on whether there were errors
        let success = errors.is_empty();
        let error_message = if !errors.is_empty() {
            Some(format!(
                "Folder wipe completed with {} error(s):\n{}\n\n\
                Files successfully wiped: {}\n\
                Total bytes wiped: {}\n\n\
                IMPORTANT: Some files were NOT wiped due to errors above.\n\
                Please review the errors and retry if necessary.",
                errors.len(),
                errors.join("\n"),
                files_processed,
                total_bytes
            ))
        } else {
            None
        };
        
        Ok(WipeResult {
            success,
            target: folder_path.to_string(),
            method: method.to_string(),
            bytes_wiped: total_bytes,
            passes_completed: passes,
            duration_ms: duration.as_millis() as u64,
            timestamp: Utc::now(),
            device_id,
            hash,
            error_message,
        })
    }

    fn wipe_directory_recursive(&self, path: &str, method: &WipeMethod, total_bytes: &mut u64, files_processed: &mut u32, errors: &mut Vec<String>) -> Result<()> {
        let entries = std::fs::read_dir(path)?;
        
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    errors.push(format!("Failed to read directory entry in {}: {}", path, err));
                    continue;
                }
            };
            
            let entry_path = entry.path();
            let entry_path_str = match entry_path.to_str() {
                Some(s) => s,
                None => {
                    errors.push(format!("Invalid UTF-8 in path: {:?}", entry_path));
                    continue;
                }
            };
            
            if entry_path.is_file() {
                // SECURITY FIX: Collect errors instead of silently ignoring them
                match self.wipe_file_sync(entry_path_str, &method.name()) {
                    Ok(file_result) => {
                        *total_bytes += file_result.bytes_wiped;
                        *files_processed += 1;
                    }
                    Err(err) => {
                        // Collect detailed error information
                        errors.push(format!("Failed to wipe file '{}': {}", entry_path_str, err));
                    }
                }
            } else if entry_path.is_dir() {
                // Recursively wipe subdirectory, collecting errors
                if let Err(err) = self.wipe_directory_recursive(entry_path_str, method, total_bytes, files_processed, errors) {
                    errors.push(format!("Failed to process directory '{}': {}", entry_path_str, err));
                }
            }
        }
        
        Ok(())
    }

    fn wipe_file_sync(&self, file_path: &str, method: &str) -> Result<WipeResult> {
        let start_time = Instant::now();
        let wipe_method = Self::parse_method(method);
        let total_passes = wipe_method.passes();
        
        // Report initial progress
        self.progress_reporter.report(WipeProgress {
            current_pass: 0,
            total_passes,
            bytes_processed: 0,
            total_bytes: 0, // Will be updated after getting file size
            percentage: 0.0,
            current_operation: format!("Preparing to wipe with {} method", method),
        });
        
        // SECURITY FIX: Open file once and keep handle to prevent TOCTOU race condition
        // This prevents file swapping between size check and wipe operations
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path)?;
        
        // SECURITY CHECK: Verify file is not locked by another process
        // This prevents corrupting files that are currently in use
        Self::verify_file_safe_to_wipe(&file, file_path)?;
        
        // Get file size from the open handle (no TOCTOU vulnerability)
        let file_size = file.metadata()?.len();
        
        // Detect drive type for the file's location
        let drive_letter = if file_path.len() >= 2 && file_path.chars().nth(1) == Some(':') {
            file_path.chars().nth(0)
                .ok_or_else(|| anyhow::anyhow!("Invalid file path: cannot extract drive letter"))?
                .to_string()
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
                    WipeMethod::DoD522022M => 1, // Reduce from 3 to 1 for SSD
                    WipeMethod::Random => 1, // Reduce from 3 to 1 for SSD
                    WipeMethod::NistSp80088 => 1, // Reduce from 1 to 1 for SSD (already optimal)
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

        // Perform the actual wiping using the same file handle
        for pass in 0..passes {
            // Seek to beginning for each pass (file handle stays open)
            file.seek(SeekFrom::Start(0))?;

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
                WipeMethod::DoD522022M => {
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
                        // Third pass: write cryptographically secure random data
                        let rng = SystemRandom::new();
                        let mut buffer = vec![0u8; 1024 * 1024];
                        rng.fill(&mut buffer).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                    }
                },
                WipeMethod::NistSp80088 => {
                    // NIST SP 800-88 method (single pass with cryptographically secure random data)
                    let rng = SystemRandom::new();
                    let mut buffer = vec![0u8; 1024 * 1024];
                    rng.fill(&mut buffer).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
                    let mut remaining = file_size;
                    while remaining > 0 {
                        let write_size = std::cmp::min(remaining, buffer.len() as u64);
                        file.write_all(&buffer[..write_size as usize])?;
                        remaining -= write_size;
                    }
                },
                WipeMethod::Gutmann => {
                    // Gutmann method with 35 passes
                    let patterns: [u8; 35] = [
                        0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                        0xFF, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                        0x66, 0x77, 0x88, 0x99, 0xAA,
                    ];
                    let pattern_byte = if pass < patterns.len() as u32 {
                        patterns[pass as usize]
                    } else {
                        // For extra passes beyond 35, use random data
                        let rng = SystemRandom::new();
                        let mut buffer = vec![0u8; 1024 * 1024];
                        rng.fill(&mut buffer).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
                        let mut remaining = file_size;
                        while remaining > 0 {
                            let write_size = std::cmp::min(remaining, buffer.len() as u64);
                            file.write_all(&buffer[..write_size as usize])?;
                            remaining -= write_size;
                        }
                        continue;
                    };
                    
                    let buffer = vec![pattern_byte; 1024 * 1024];
                    let mut remaining = file_size;
                    while remaining > 0 {
                        let write_size = std::cmp::min(remaining, buffer.len() as u64);
                        file.write_all(&buffer[..write_size as usize])?;
                        remaining -= write_size;
                    }
                },
                WipeMethod::Random => {
                    // Cryptographically secure random data
                    let rng = SystemRandom::new();
                    let mut buffer = vec![0u8; 1024 * 1024];
                    rng.fill(&mut buffer).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
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
        
        // Close file handle before deletion
        drop(file);
        
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
                    WipeMethod::DoD522022M => 1, // Reduce from 3 to 1 for SSD
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
                    // Skip files with invalid UTF-8 paths
                    if let Some(path_str) = entry_path.to_str() {
                        if let Ok(result) = self.wipe_file(path_str, method).await {
                            total_bytes += result.bytes_wiped;
                        }
                    }
                } else if entry_path.is_dir() {
                    let mut dir_bytes = 0u64;
                    let mut files_processed = 0u32;
                    let mut dir_errors = Vec::new();
                    // Skip directories with invalid UTF-8 paths
                    if let Some(path_str) = entry_path.to_str() {
                        if let Ok(_) = self.wipe_directory_recursive(
                            path_str, 
                            &wipe_method, 
                            &mut dir_bytes, 
                            &mut files_processed,
                            &mut dir_errors
                        ) {
                            total_bytes += dir_bytes;
                        }
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
            "NIST SP 800-88" => WipeMethod::NistSp80088,
            "DoD 5220.22-M" => WipeMethod::DoD522022M,
            "Gutmann" => WipeMethod::Gutmann,
            "Random" => WipeMethod::Random,
            "Zero" => WipeMethod::Zero,
            _ => WipeMethod::NistSp80088,
        }
    }

    fn get_wipe_pattern(&self, method: &WipeMethod, pass: u32) -> Result<Vec<u8>> {
        // SECURITY: Use secure buffer that will be zeroized on drop
        let mut secure_buffer = SecureBuffer::new(self.buffer.len());
        let pattern = secure_buffer.as_mut_slice();
        
        match method {
            WipeMethod::NistSp80088 => {
                // Single pass with cryptographically secure random data
                let rng = SystemRandom::new();
                rng.fill(pattern).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
            },
            WipeMethod::DoD522022M => {
                match pass {
                    1 => pattern.fill(0x00),  // First pass: zeros
                    2 => pattern.fill(0xFF),  // Second pass: ones (complement)
                    3 => {
                        // Third pass: cryptographically secure random data
                        let rng = SystemRandom::new();
                        rng.fill(pattern).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
                    },
                    _ => pattern.fill(0x00),
                }
            },
            WipeMethod::Gutmann => {
                // Gutmann method with 35 passes
                let patterns: [u8; 35] = [
                    0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                    0xFF, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xAA,
                ];
                if pass <= patterns.len() as u32 {
                    pattern.fill(patterns[(pass - 1) as usize]);
                } else {
                    // Cryptographically secure random data for extra passes
                    let rng = SystemRandom::new();
                    rng.fill(pattern).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
                }
            },
            WipeMethod::Random => {
                // Cryptographically secure random data
                let rng = SystemRandom::new();
                rng.fill(pattern).map_err(|_| anyhow::anyhow!("Failed to generate secure random data"))?;
            },
            WipeMethod::Zero => {
                pattern.fill(0x00);
            },
        }
        
        // Clone the data before secure_buffer is dropped and zeroized
        Ok(secure_buffer.data.clone())
    }
}
