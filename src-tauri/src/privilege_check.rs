use std::ptr;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY, HANDLE};
use winapi::um::handleapi::CloseHandle;
use anyhow::{Result, bail};

/// Check if the current process is running with administrator privileges
pub fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token_handle: HANDLE = ptr::null_mut();
        
        // Open the process token
        let result = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle
        );
        
        if result == 0 {
            bail!("Failed to open process token");
        }
        
        // Query token elevation status
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;
        
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length
        );
        
        CloseHandle(token_handle);
        
        if result == 0 {
            bail!("Failed to get token information");
        }
        
        Ok(elevation.TokenIsElevated != 0)
    }
}

/// Require administrator privileges or return an error
pub fn require_admin() -> Result<()> {
    if !is_elevated()? {
        bail!(
            "Administrator privileges required. Please run this application as Administrator.\n\
            Right-click the application and select 'Run as administrator'."
        );
    }
    Ok(())
}

/// Check if admin privileges are available (non-failing version)
#[allow(dead_code)]
pub fn check_admin_available() -> bool {
    is_elevated().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_elevated() {
        // This test just ensures the function doesn't panic
        let result = is_elevated();
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_check_admin_available() {
        // This should never panic
        let _ = check_admin_available();
    }
}
