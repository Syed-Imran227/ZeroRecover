use std::path::{Path, PathBuf};
use anyhow::{Result, Context, bail};

/// Validates and canonicalizes paths to prevent path traversal attacks
pub struct PathValidator;

impl PathValidator {
    /// Validates a file path and ensures it exists and is a file
    pub fn validate_file_path(path: &str) -> Result<PathBuf> {
        let path_buf = PathBuf::from(path);
        
        // Canonicalize the path to resolve any .. or symlinks
        let canonical_path = path_buf.canonicalize()
            .context("Failed to canonicalize path - file may not exist or is inaccessible")?;
        
        // Ensure it's a file
        if !canonical_path.is_file() {
            bail!("Path is not a file: {}", canonical_path.display());
        }
        
        // Additional security check: ensure the path doesn't contain suspicious patterns
        Self::check_suspicious_patterns(&canonical_path)?;
        
        Ok(canonical_path)
    }
    
    /// Validates a folder path and ensures it exists and is a directory
    pub fn validate_folder_path(path: &str) -> Result<PathBuf> {
        let path_buf = PathBuf::from(path);
        
        // Canonicalize the path to resolve any .. or symlinks
        let canonical_path = path_buf.canonicalize()
            .context("Failed to canonicalize path - folder may not exist or is inaccessible")?;
        
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
        
        let letter = drive_letter.chars().next().unwrap().to_uppercase().next().unwrap();
        
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
        
        Ok(letter.to_string())
    }
    
    /// Check for suspicious patterns that might indicate an attack
    fn check_suspicious_patterns(path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy();
        
        // Check for system-critical directories (Windows)
        let protected_paths = [
            "\\windows\\system32",
            "\\windows\\syswow64",
            "\\program files\\windowsapps",
            "\\programdata\\microsoft\\windows",
        ];
        
        let path_lower = path_str.to_lowercase();
        for protected in &protected_paths {
            if path_lower.contains(protected) {
                bail!("Cannot wipe system-critical directory: {}", path.display());
            }
        }
        
        Ok(())
    }
    
    /// Validates that a path is within an allowed parent directory
    /// This is useful for restricting operations to specific directories
    pub fn validate_path_within_parent(path: &Path, allowed_parent: &Path) -> Result<()> {
        let canonical_path = path.canonicalize()
            .context("Failed to canonicalize path")?;
        let canonical_parent = allowed_parent.canonicalize()
            .context("Failed to canonicalize parent path")?;
        
        if !canonical_path.starts_with(&canonical_parent) {
            bail!(
                "Path {} is not within allowed parent directory {}",
                canonical_path.display(),
                canonical_parent.display()
            );
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_drive_letter() {
        // Valid drive letter
        assert!(PathValidator::validate_drive_letter("C").is_ok());
        
        // Invalid: too long
        assert!(PathValidator::validate_drive_letter("CD").is_err());
        
        // Invalid: not alphabetic
        assert!(PathValidator::validate_drive_letter("1").is_err());
    }
}
