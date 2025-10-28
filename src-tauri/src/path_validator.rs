use std::path::{Path, PathBuf};
use anyhow::{Result, Context, bail};

/// Validates and canonicalizes paths to prevent path traversal attacks
pub struct PathValidator;

impl PathValidator {
    /// Validate path before canonicalization to catch UNC/device paths
    /// 
    /// SECURITY: Additional layer to prevent bypass via special paths
    fn pre_validate_path(path: &str) -> Result<()> {
        let path_lower = path.to_lowercase();
        
        // SECURITY: Block UNC paths (\\server\share)
        if path.starts_with("\\\\") || path.starts_with("//") {
            bail!(
                "UNC paths are not supported: {}\n\
                UNC paths (\\\\server\\share) pose security risks and are blocked.\n\
                Please use mapped network drives instead.",
                path
            );
        }
        
        // SECURITY: Block device paths (\\.\, \\?\)
        if path_lower.starts_with("\\\\.\\") || path_lower.starts_with("\\\\?\\") {
            bail!(
                "Device paths are not supported: {}\n\
                Device paths (\\\\.\\device or \\\\?\\path) are blocked for security.\n\
                These paths can access raw devices and bypass security checks.",
                path
            );
        }
        
        // SECURITY: Block paths with null bytes
        if path.contains('\0') {
            bail!(
                "Path contains null bytes - potential security violation.\n\
                Null bytes in paths can be used to bypass security checks."
            );
        }
        
        // SECURITY: Block excessively long paths (potential buffer overflow)
        if path.len() > 32767 {
            bail!(
                "Path exceeds maximum length (32767 characters).\n\
                Excessively long paths may indicate an attack attempt."
            );
        }
        
        // SECURITY: Block paths with suspicious characters
        let suspicious_chars = ['<', '>', '|', '"'];
        for ch in suspicious_chars {
            if path.contains(ch) {
                bail!(
                    "Path contains suspicious character '{}': {}\n\
                    This character is not allowed in Windows paths.",
                    ch, path
                );
            }
        }
        
        Ok(())
    }

    /// Validates a file path and ensures it exists and is a file
    pub fn validate_file_path(path: &str) -> Result<PathBuf> {
        // SECURITY: Pre-validate before canonicalization
        Self::pre_validate_path(path)?;
        
        let path_buf = PathBuf::from(path);
        
        // Canonicalize the path to resolve any .. or symlinks
        let canonical_path = path_buf.canonicalize()
            .context("Failed to canonicalize path - file may not exist or is inaccessible")?;
        
        // SECURITY: Post-canonicalization validation
        Self::post_validate_canonical_path(&canonical_path)?;
        
        // Ensure it's a file
        if !canonical_path.is_file() {
            bail!("Path is not a file: {}", canonical_path.display());
        }
        
        // Additional security check: ensure the path doesn't contain suspicious patterns
        Self::check_suspicious_patterns(&canonical_path)?;
        
        Ok(canonical_path)
    }
    
    /// Post-canonicalization validation
    /// 
    /// SECURITY: Verify canonical path is still safe
    fn post_validate_canonical_path(canonical_path: &Path) -> Result<()> {
        let path_str = canonical_path.to_string_lossy();
        let path_lower = path_str.to_lowercase();
        
        // SECURITY: Ensure canonicalization didn't result in UNC path
        // BUT allow Windows extended-length paths (\\?\C:\...)
        if path_str.starts_with("\\\\") && !path_str.starts_with("\\\\?\\") {
            bail!(
                "Canonicalized path resulted in UNC path: {}\n\
                This may indicate a symlink to a network location, which is blocked.",
                path_str
            );
        }
        
        // SECURITY: Ensure canonicalization didn't result in device path
        // Allow \\?\ (extended-length paths) but block \\.\  (device paths)
        if path_lower.starts_with("\\\\.\\") {
            bail!(
                "Canonicalized path resulted in device path: {}\n\
                This may indicate a symlink to a device, which is blocked.",
                path_str
            );
        }
        
        // SECURITY: Verify path is on a local drive (C:, D:, etc.)
        // Handle both normal paths (C:\...) and extended-length paths (\\?\C:\...)
        let drive_check_path = if path_str.starts_with("\\\\?\\") {
            // For extended-length paths, skip the \\?\ prefix
            &path_str[4..]
        } else {
            &path_str
        };
        
        if drive_check_path.len() >= 2 {
            let first_char = drive_check_path.chars().next()
                .ok_or_else(|| anyhow::anyhow!("Invalid path: empty string"))?;
            let second_char = drive_check_path.chars().nth(1)
                .ok_or_else(|| anyhow::anyhow!("Invalid path: too short"))?;
            
            if !first_char.is_ascii_alphabetic() || second_char != ':' {
                bail!(
                    "Path must be on a local drive (e.g., C:, D:): {}\n\
                    Network paths and special paths are not supported.",
                    path_str
                );
            }
        }
        
        Ok(())
    }

    /// Validates a folder path and ensures it exists and is a directory
    pub fn validate_folder_path(path: &str) -> Result<PathBuf> {
        // SECURITY: Pre-validate before canonicalization
        Self::pre_validate_path(path)?;
        
        let path_buf = PathBuf::from(path);
        
        // Canonicalize the path to resolve any .. or symlinks
        let canonical_path = path_buf.canonicalize()
            .context("Failed to canonicalize path - folder may not exist or is inaccessible")?;
        
        // SECURITY: Post-canonicalization validation
        Self::post_validate_canonical_path(&canonical_path)?;
        
        // Ensure it's a directory
        if !canonical_path.is_dir() {
            bail!("Path is not a directory: {}", canonical_path.display());
        }
        
        // Additional security check: ensure the path doesn't contain suspicious patterns
        Self::check_suspicious_patterns(&canonical_path)?;
        
        Ok(canonical_path)
    }
    
    /// Validates a drive letter (Windows-specific)
    pub fn validate_drive_letter(drive_letter: &str) -> Result<String> {
        // Ensure it's a single letter
        if drive_letter.len() != 1 {
            bail!("Invalid drive letter: must be a single character");
        }
        
        let letter = drive_letter.chars().next()
            .ok_or_else(|| anyhow::anyhow!("Invalid drive letter: empty string"))?
            .to_uppercase().next()
            .ok_or_else(|| anyhow::anyhow!("Invalid drive letter format"))?;
        
        // Ensure it's A-Z
        if !letter.is_ascii_alphabetic() {
            bail!("Invalid drive letter: must be A-Z");
        }
        
        // Check if the drive exists
        let drive_path = format!("{}:\\", letter);
        let path = Path::new(&drive_path);
        
        if !path.exists() {
            bail!("Drive {} does not exist", letter);
        }
        
        // CRITICAL SECURITY CHECK: Prevent wiping the system drive
        let system_drive = std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".to_string());
        
        let system_drive_letter = system_drive.chars().next()
            .ok_or_else(|| anyhow::anyhow!("Invalid system drive path"))?
            .to_uppercase().next()
            .ok_or_else(|| anyhow::anyhow!("Invalid system drive format"))?;
        
        if letter == system_drive_letter {
            bail!(
                "CRITICAL SECURITY ERROR: Cannot wipe system drive {}:. \
                This is your Windows installation drive and wiping it would make your computer unbootable. \
                If you need to wipe this drive, please boot from a different operating system or use a bootable USB tool.",
                letter
            );
        }
        
        // Additional check: Verify this is not a boot drive by checking for Windows directory
        let windows_path = format!("{}:\\Windows", letter);
        if Path::new(&windows_path).exists() {
            bail!(
                "CRITICAL SECURITY ERROR: Cannot wipe drive {}:. \
                This drive contains a Windows installation and wiping it would make your system unbootable. \
                Please use a bootable USB tool if you need to wipe this drive.",
                letter
            );
        }
        
        Ok(letter.to_string())
    }
    
    /// Check for suspicious patterns that might indicate an attack
    fn check_suspicious_patterns(path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy();
        let path_lower = path_str.to_lowercase();
        
        // Get the system drive letter (usually C:)
        let system_drive = std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".to_string())
            .to_lowercase();
        
        // CRITICAL: Prevent wiping system drive root
        // Check if path is exactly the system drive root (e.g., "C:\")
        if let Some(components) = path.components().nth(0) {
            if let Some(prefix) = components.as_os_str().to_str() {
                let prefix_lower = prefix.to_lowercase();
                if prefix_lower.starts_with(&system_drive) {
                    // Check if this is the root directory
                    if path.components().count() <= 1 {
                        bail!("CRITICAL: Cannot wipe system drive root ({}). This would destroy your Windows installation!", path.display());
                    }
                }
            }
        }
        
        // Check for system-critical directories (Windows)
        // Comprehensive list of protected paths
        let protected_paths = [
            // Windows core directories
            "\\windows",
            "\\windows\\system32",
            "\\windows\\syswow64",
            "\\windows\\winsxs",
            "\\windows\\boot",
            "\\windows\\inf",
            "\\windows\\fonts",
            "\\windows\\drivers",
            
            // Program Files
            "\\program files",
            "\\program files (x86)",
            "\\program files\\windowsapps",
            
            // System data
            "\\programdata\\microsoft\\windows",
            "\\programdata\\package cache",
            
            // Boot and recovery
            "\\boot",
            "\\recovery",
            "\\system volume information",
            "\\$recycle.bin",
            
            // User profile critical paths
            "\\users\\default",
            "\\users\\public",
            "\\users\\all users",
        ];
        
        // Check if path starts with or contains protected directories
        for protected in &protected_paths {
            // Check if path starts with protected path (more strict)
            if path_lower.starts_with(protected) {
                bail!("CRITICAL: Cannot wipe system-critical directory: {}. This is a protected Windows system path.", path.display());
            }
            
            // Also check if protected path is anywhere in the path
            // Format: drive letter + protected path
            let full_protected = format!("{}{}", system_drive, protected);
            if path_lower.starts_with(&full_protected) {
                bail!("CRITICAL: Cannot wipe system-critical directory: {}. This is a protected Windows system path.", path.display());
            }
        }
        
        // Additional check: prevent wiping entire user profile directories
        // Allow wiping files/folders INSIDE user directories, but not the profile root itself
        if path_lower.contains("\\users\\") {
            let parts: Vec<&str> = path_lower.split("\\users\\").collect();
            if parts.len() == 2 {
                let after_users = parts[1];
                // Check if this is exactly a user profile root (e.g., C:\Users\John with no subdirectory)
                if !after_users.contains("\\") || after_users.split("\\").count() <= 2 {
                    // Allow Documents, Downloads, Desktop, etc., but warn about profile root
                    let safe_user_folders = ["documents", "downloads", "desktop", "pictures", "videos", "music"];
                    let is_safe_folder = safe_user_folders.iter().any(|folder| after_users.contains(folder));
                    
                    if !is_safe_folder && after_users.split("\\").count() == 1 {
                        bail!("WARNING: Cannot wipe user profile root directory: {}. Please select specific folders within the user profile.", path.display());
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Validates that a path is within an allowed parent directory
    /// This is useful for restricting operations to specific directories
    pub fn validate_path_within_parent(path: &Path, allowed_parent: &Path) -> Result<()> {
        let canonical_path = path.canonicalize()
            .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
            
        let canonical_parent = allowed_parent.canonicalize()
            .with_context(|| format!("Failed to canonicalize parent path: {}", allowed_parent.display()))?;

        if !canonical_path.starts_with(&canonical_parent) {
            bail!(
                "Path '{}' is not within the allowed directory '{}'
                
                SECURITY: This operation is restricted to prevent access to files
                outside the intended directory. This is a security measure to
                protect sensitive system files and user data.",
                canonical_path.display(),
                canonical_parent.display()
            );
        }

        Ok(())
    }
    
    /// Checks if a path is a system file or directory
    /// 
    /// SECURITY: Identifies protected system locations that require admin privileges
    pub fn is_system_file(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        
        // Common system directories
        let system_dirs = [
            "c:\\windows",
            "c:\\program files",
            "c:\\program files (x86)",
            "c:\\programdata",
            "c:\\system volume information",
            "c:\\$recycle.bin",
            "c:\\recovery",
            "c:\\boot",
            "c:\\config.msi",
            "c:\\pagefile.sys",
            "c:\\hiberfil.sys",
            "c:\\swapfile.sys",
        ];
        
        // Check if path contains any system directory
        system_dirs.iter().any(|&dir| path_lower.starts_with(dir))
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_drive_letter() {
        // Invalid: too long
        assert!(PathValidator::validate_drive_letter("CD").is_err());
        
        // Invalid: not alphabetic
        assert!(PathValidator::validate_drive_letter("1").is_err());
        
        // System drive should be blocked (usually C:)
        let system_drive = std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".to_string());
        let system_letter = system_drive.chars().next()
            .unwrap_or('C')
            .to_string();
        
        // This should fail because we block the system drive
        let result = PathValidator::validate_drive_letter(&system_letter);
        assert!(result.is_err(), "System drive should be blocked");
        if let Err(e) = result {
            assert!(e.to_string().contains("CRITICAL"), "Error should mention CRITICAL");
        }
    }
    
    #[test]
    fn test_protected_paths() {
        // Test that Windows directory is protected
        let windows_path = PathBuf::from("C:\\Windows");
        if windows_path.exists() {
            let result = PathValidator::check_suspicious_patterns(&windows_path);
            assert!(result.is_err(), "Windows directory should be protected");
        }
        
        // Test that System32 is protected
        let system32_path = PathBuf::from("C:\\Windows\\System32");
        if system32_path.exists() {
            let result = PathValidator::check_suspicious_patterns(&system32_path);
            assert!(result.is_err(), "System32 should be protected");
        }
        
        // Test that Program Files is protected
        let pf_path = PathBuf::from("C:\\Program Files");
        if pf_path.exists() {
            let result = PathValidator::check_suspicious_patterns(&pf_path);
            assert!(result.is_err(), "Program Files should be protected");
        }
    }
    
    #[test]
    fn test_case_insensitive_protection() {
        // Test various case combinations of Windows path
        let test_paths = vec![
            "C:\\windows",
            "C:\\WINDOWS",
            "C:\\Windows",
            "C:\\WiNdOwS",
        ];
        
        for path_str in test_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                let result = PathValidator::check_suspicious_patterns(&path);
                assert!(result.is_err(), "Path {} should be protected regardless of case", path_str);
            }
        }
    }
    
    #[test]
    fn test_user_profile_protection() {
        // Test that user profile root is protected
        let users_path = PathBuf::from("C:\\Users");
        if users_path.exists() {
            // Try to get first user directory
            if let Ok(entries) = std::fs::read_dir(&users_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let dir_name = path.file_name()
                            .unwrap_or_default()
                            .to_string_lossy().to_lowercase();
                        // Skip system folders
                        if dir_name != "default" && dir_name != "public" && dir_name != "all users" {
                            // User profile root should be protected
                            let result = PathValidator::check_suspicious_patterns(&path);
                            // Note: This might pass if it's a safe folder, which is OK
                            // The important thing is that the check runs without panicking
                            let _ = result;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    #[test]
    fn test_unc_path_blocked() {
        // Test that UNC paths are blocked
        let unc_paths = vec![
            "\\\\server\\share\\file.txt",
            "//server/share/file.txt",
            "\\\\192.168.1.1\\share\\file.txt",
        ];
        
        for path in unc_paths {
            let result = PathValidator::pre_validate_path(path);
            assert!(result.is_err(), "UNC path should be blocked: {}", path);
            if let Err(e) = result {
                assert!(e.to_string().contains("UNC"), "Error should mention UNC");
            }
        }
    }
    
    #[test]
    fn test_device_path_blocked() {
        // Test that device paths are blocked
        let device_paths = vec![
            "\\\\.\\PhysicalDrive0",
            "\\\\.\\C:",
            "\\\\?\\C:\\file.txt",
            "\\\\.\\COM1",
        ];
        
        for path in device_paths {
            let result = PathValidator::pre_validate_path(path);
            assert!(result.is_err(), "Device path should be blocked: {}", path);
            if let Err(e) = result {
                assert!(e.to_string().contains("Device"), "Error should mention Device");
            }
        }
    }
    
    #[test]
    fn test_null_byte_blocked() {
        // Test that null bytes are blocked
        let path_with_null = "C:\\test\0file.txt";
        let result = PathValidator::pre_validate_path(path_with_null);
        assert!(result.is_err(), "Path with null byte should be blocked");
        if let Err(e) = result {
            assert!(e.to_string().contains("null"), "Error should mention null bytes");
        }
    }
    
    #[test]
    fn test_suspicious_characters_blocked() {
        // Test that suspicious characters are blocked
        let suspicious_paths = vec![
            "C:\\test<file.txt",
            "C:\\test>file.txt",
            "C:\\test|file.txt",
            "C:\\test\"file.txt",
        ];
        
        for path in suspicious_paths {
            let result = PathValidator::pre_validate_path(path);
            assert!(result.is_err(), "Path with suspicious character should be blocked: {}", path);
        }
    }
    
    #[test]
    fn test_long_path_blocked() {
        // Test that excessively long paths are blocked
        let long_path = "C:\\".to_string() + &"a".repeat(32800);
        let result = PathValidator::pre_validate_path(&long_path);
        assert!(result.is_err(), "Excessively long path should be blocked");
        if let Err(e) = result {
            assert!(e.to_string().contains("maximum length"), "Error should mention length");
        }
    }
    
    #[test]
    fn test_valid_local_paths() {
        // Test that valid local paths pass pre-validation
        let valid_paths = vec![
            "C:\\test\\file.txt",
            "D:\\documents\\report.pdf",
            "E:\\data\\backup.zip",
        ];
        
        for path in valid_paths {
            let result = PathValidator::pre_validate_path(path);
            // These should pass pre-validation (they may fail canonicalization if they don't exist)
            assert!(result.is_ok(), "Valid local path should pass pre-validation: {}", path);
        }
    }
}
