use std::ptr;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winioctl::{IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_DISK_GET_LENGTH_INFO};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE};
use winapi::shared::minwindef::{DWORD, FALSE};
use anyhow::{Result, Context};

// IOCTL codes for HPA and DCO detection
const IOCTL_ATA_PASS_THROUGH: DWORD = 0x0004D02C;
const IOCTL_STORAGE_QUERY_PROPERTY: DWORD = 0x002D1400;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HiddenAreaInfo {
    pub has_hpa: bool,
    pub hpa_size: u64,
    pub has_dco: bool,
    pub dco_size: u64,
    pub native_max_lba: u64,
    pub current_max_lba: u64,
}

impl Default for HiddenAreaInfo {
    fn default() -> Self {
        Self {
            has_hpa: false,
            hpa_size: 0,
            has_dco: false,
            dco_size: 0,
            native_max_lba: 0,
            current_max_lba: 0,
        }
    }
}

pub struct HiddenStorageManager;

impl HiddenStorageManager {
    /// Detect hidden storage areas on a drive
    pub fn detect_hidden_areas(drive_letter: &str) -> Result<HiddenAreaInfo> {
        let mut info = HiddenAreaInfo::default();
        
        // Open physical drive
        let drive_path = format!("\\\\.\\{}:", drive_letter);
        let handle = unsafe {
            CreateFileA(
                drive_path.as_ptr() as *const i8,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("Failed to open drive for hidden area detection"));
        }

        // Detect HPA (Host Protected Area)
        if let Ok(hpa_info) = Self::detect_hpa(handle) {
            info.has_hpa = hpa_info.0;
            info.hpa_size = hpa_info.1;
            info.native_max_lba = hpa_info.2;
            info.current_max_lba = hpa_info.3;
        }

        // Detect DCO (Device Configuration Overlay)
        if let Ok(dco_info) = Self::detect_dco(handle) {
            info.has_dco = dco_info.0;
            info.dco_size = dco_info.1;
        }

        unsafe {
            CloseHandle(handle);
        }

        Ok(info)
    }

    /// Detect Host Protected Area (HPA)
    fn detect_hpa(handle: HANDLE) -> Result<(bool, u64, u64, u64)> {
        // Safety notice: Full HPA detection requires ATA pass-through with admin rights.
        // We attempt to query disk length and geometry as a heuristic to surface discrepancies.
        // If this heuristic cannot confirm, we return "unknown" as false with sizes 0.

        unsafe {
            let mut bytes_returned: DWORD = 0;

            // Query drive length
            #[repr(C)]
            struct GET_LENGTH_INFORMATION { length: u64 }
            let mut length_info = GET_LENGTH_INFORMATION { length: 0 };
            let ok_len = DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                ptr::null_mut(),
                0,
                &mut length_info as *mut _ as *mut _,
                std::mem::size_of::<GET_LENGTH_INFORMATION>() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            // Query geometry (may be deprecated but available on some systems)
            #[repr(C)]
            struct DISK_GEOMETRY { media_type: u32, cylinders: i64, tracks_per_cylinder: u32, sectors_per_track: u32, bytes_per_sector: u32 }
            let mut geom = DISK_GEOMETRY { media_type: 0, cylinders: 0, tracks_per_cylinder: 0, sectors_per_track: 0, bytes_per_sector: 512 };
            let ok_geo = DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                ptr::null_mut(),
                0,
                &mut geom as *mut _ as *mut _,
                std::mem::size_of::<DISK_GEOMETRY>() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            );

            if ok_len != 0 && ok_geo != 0 && geom.bytes_per_sector != 0 {
                let total_sectors_est = (length_info.length / geom.bytes_per_sector as u64) as u64;
                // Heuristic: if current max LBA (<- what we can access) is less than native implied by length, HPA might exist.
                // Without ATA READ MAX, we cannot confirm. So return sizes but flag false unless we can confirm.
                return Ok((false, 0, total_sectors_est, total_sectors_est));
            }
        }

        Ok((false, 0, 0, 0))
    }

    /// Detect Device Configuration Overlay (DCO)
    fn detect_dco(_handle: HANDLE) -> Result<(bool, u64)> {
        // DCO detection requires ATA pass-through and privilege. Not performed here.
        Ok((false, 0))
    }

    /// Wipe hidden storage areas
    pub fn wipe_hidden_areas(drive_letter: &str, passes: u32) -> Result<u64> {
        let info = Self::detect_hidden_areas(drive_letter)?;
        let mut bytes_wiped = 0u64;

        if info.has_hpa {
            // Remove HPA and wipe the hidden area
            bytes_wiped += Self::wipe_hpa(drive_letter, info.hpa_size, passes)?;
        }

        if info.has_dco {
            // Remove DCO and wipe the hidden area
            bytes_wiped += Self::wipe_dco(drive_letter, info.dco_size, passes)?;
        }

        Ok(bytes_wiped)
    }

    fn wipe_hpa(drive_letter: &str, size: u64, passes: u32) -> Result<u64> {
        // This would require:
        // 1. Send SET MAX ADDRESS command to remove HPA
        // 2. Wipe the newly accessible sectors
        // 3. Optionally restore HPA after wiping
        
        // Simplified implementation
        Ok(0)
    }

    fn wipe_dco(drive_letter: &str, size: u64, passes: u32) -> Result<u64> {
        // This would require:
        // 1. Send DEVICE CONFIGURATION RESTORE command to remove DCO
        // 2. Wipe the newly accessible sectors
        // 3. Optionally restore DCO after wiping
        
        // Simplified implementation
        Ok(0)
    }

    /// Detect and handle SSD remapped sectors
    pub fn handle_ssd_remapped_sectors(drive_letter: &str) -> Result<bool> {
        // For SSDs, we should:
        // 1. Issue TRIM/UNMAP commands
        // 2. Use Secure Erase if supported
        // 3. Handle wear leveling and remapped sectors
        
        // Check if drive is SSD
        if Self::is_ssd(drive_letter)? {
            // Issue TRIM command
            Self::issue_trim_command(drive_letter)?;
            return Ok(true);
        }

        Ok(false)
    }

    fn is_ssd(drive_letter: &str) -> Result<bool> {
        // Simplified check - in production, query STORAGE_PROPERTY_QUERY
        // to determine if drive is SSD
        Ok(false)
    }

    fn issue_trim_command(drive_letter: &str) -> Result<()> {
        // Issue TRIM/UNMAP command to SSD
        // This helps ensure deleted data is actually erased on SSD
        Ok(())
    }

    /// Get comprehensive drive information including hidden areas
    pub fn get_comprehensive_drive_info(drive_letter: &str) -> Result<String> {
        let hidden_info = Self::detect_hidden_areas(drive_letter)?;
        
        let mut report = String::new();
        report.push_str(&format!("Drive: {}\n", drive_letter));
        report.push_str(&format!("HPA Detected: {}\n", hidden_info.has_hpa));
        report.push_str("Note: Hidden area detection is limited in this build and does not perform ATA pass-through. Admin privileges and vendor-specific tooling are required for definitive results.\n");
        
        if hidden_info.has_hpa {
            report.push_str(&format!("  HPA Size: {} bytes\n", hidden_info.hpa_size));
            report.push_str(&format!("  Native Max LBA: {}\n", hidden_info.native_max_lba));
            report.push_str(&format!("  Current Max LBA: {}\n", hidden_info.current_max_lba));
        }
        
        report.push_str(&format!("DCO Detected: {}\n", hidden_info.has_dco));
        
        if hidden_info.has_dco {
            report.push_str(&format!("  DCO Size: {} bytes\n", hidden_info.dco_size));
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hidden_area_detection() {
        // This test would require admin privileges and a real drive
        // For now, just ensure the struct can be created
        let info = HiddenAreaInfo::default();
        assert_eq!(info.has_hpa, false);
        assert_eq!(info.has_dco, false);
    }
}
