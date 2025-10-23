use std::ptr;
use winapi::um::winbase::{RegisterEventSourceA, ReportEventA, DeregisterEventSource};
use winapi::um::winnt::{EVENTLOG_SUCCESS, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, EVENTLOG_ERROR_TYPE};
use anyhow::Result;
use chrono::Utc;

/// Audit log levels matching Windows Event Log severity
#[derive(Debug, Clone, Copy)]
pub enum AuditLevel {
    Success,
    Information,
    Warning,
    Error,
}

impl AuditLevel {
    fn to_event_type(&self) -> u16 {
        match self {
            AuditLevel::Success => EVENTLOG_SUCCESS as u16,
            AuditLevel::Information => EVENTLOG_INFORMATION_TYPE,
            AuditLevel::Warning => EVENTLOG_WARNING_TYPE,
            AuditLevel::Error => EVENTLOG_ERROR_TYPE,
        }
    }
}

/// Audit logger for Windows Event Log
/// 
/// SECURITY: Provides audit trail for compliance and forensic investigation
/// All wipe operations are logged to Windows Event Log
pub struct AuditLogger {
    source_name: String,
}

impl AuditLogger {
    /// Create a new audit logger
    /// 
    /// Source name will appear in Windows Event Viewer
    pub fn new() -> Self {
        Self {
            source_name: "ZeroRecover".to_string(),
        }
    }

    /// Log a wipe operation to Windows Event Log
    /// 
    /// SECURITY: Creates permanent audit trail
    /// - Event ID 1000: File wipe
    /// - Event ID 1001: Folder wipe
    /// - Event ID 1002: Drive wipe
    /// - Event ID 1003: Wipe failure
    pub fn log_wipe_operation(
        &self,
        operation_type: &str,
        target: &str,
        method: &str,
        bytes_wiped: u64,
        success: bool,
    ) -> Result<()> {
        let level = if success {
            AuditLevel::Success
        } else {
            AuditLevel::Error
        };

        let event_id = match operation_type {
            "file" => if success { 1000 } else { 1003 },
            "folder" => if success { 1001 } else { 1003 },
            "drive" => if success { 1002 } else { 1003 },
            _ => 1003,
        };

        let timestamp = Utc::now().to_rfc3339();
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());
        let computer = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());

        let message = if success {
            format!(
                "ZeroRecover Wipe Operation - SUCCESS\n\
                Timestamp: {}\n\
                User: {}\n\
                Computer: {}\n\
                Operation: {} wipe\n\
                Target: {}\n\
                Method: {}\n\
                Bytes Wiped: {}\n\
                Status: Completed successfully",
                timestamp, username, computer, operation_type, target, method, bytes_wiped
            )
        } else {
            format!(
                "ZeroRecover Wipe Operation - FAILED\n\
                Timestamp: {}\n\
                User: {}\n\
                Computer: {}\n\
                Operation: {} wipe\n\
                Target: {}\n\
                Method: {}\n\
                Status: Failed",
                timestamp, username, computer, operation_type, target, method
            )
        };

        self.write_event(event_id, level, &message)?;
        Ok(())
    }

    /// Log administrator privilege check
    pub fn log_admin_check(&self, has_admin: bool) -> Result<()> {
        let level = if has_admin {
            AuditLevel::Information
        } else {
            AuditLevel::Warning
        };

        let timestamp = Utc::now().to_rfc3339();
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());

        let message = format!(
            "ZeroRecover Administrator Privilege Check\n\
            Timestamp: {}\n\
            User: {}\n\
            Has Admin: {}\n\
            Status: {}",
            timestamp,
            username,
            has_admin,
            if has_admin { "Elevated" } else { "Standard user" }
        );

        self.write_event(2000, level, &message)?;
        Ok(())
    }

    /// Log security violation attempt
    pub fn log_security_violation(&self, violation_type: &str, details: &str) -> Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string());
        let computer = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());

        let message = format!(
            "ZeroRecover Security Violation - BLOCKED\n\
            Timestamp: {}\n\
            User: {}\n\
            Computer: {}\n\
            Violation Type: {}\n\
            Details: {}\n\
            Status: Operation blocked by security policy",
            timestamp, username, computer, violation_type, details
        );

        self.write_event(3000, AuditLevel::Warning, &message)?;
        Ok(())
    }

    /// Write event to Windows Event Log
    fn write_event(&self, event_id: u32, level: AuditLevel, message: &str) -> Result<()> {
        unsafe {
            // Register event source
            let source_handle = RegisterEventSourceA(
                ptr::null(),
                self.source_name.as_ptr() as *const i8,
            );

            if source_handle.is_null() {
                // If we can't register (likely no admin), fail silently
                // Audit logging is best-effort
                return Ok(());
            }

            // Prepare message string
            // If message contains null bytes, sanitize it by replacing them
            let sanitized_message = message.replace('\0', "");
            let message_cstr = match std::ffi::CString::new(sanitized_message) {
                Ok(cstr) => cstr,
                Err(_) => {
                    // If still fails, use a fallback message
                    std::ffi::CString::new("Invalid audit log message (contained null bytes)").unwrap()
                }
            };
            let mut messages: [*const i8; 1] = [message_cstr.as_ptr()];

            // Write event
            let result = ReportEventA(
                source_handle,
                level.to_event_type(),
                0,                          // Category
                event_id,                   // Event ID
                ptr::null_mut(),           // User SID
                1,                          // Number of strings
                0,                          // Data size
                messages.as_mut_ptr(),     // Message strings (needs mutable pointer)
                ptr::null_mut(),           // Raw data
            );

            // Deregister event source
            DeregisterEventSource(source_handle);

            if result == 0 {
                // Event log write failed, but don't fail the operation
                // Audit logging is best-effort
            }

            Ok(())
        }
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logger_creation() {
        let logger = AuditLogger::new();
        assert_eq!(logger.source_name, "ZeroRecover");
    }

    #[test]
    fn test_log_wipe_operation() {
        let logger = AuditLogger::new();
        // This test just ensures the function doesn't panic
        // Actual event log writing may fail without admin privileges
        let _ = logger.log_wipe_operation("file", "C:\\test.txt", "NIST SP 800-88", 1024, true);
    }

    #[test]
    fn test_log_admin_check() {
        let logger = AuditLogger::new();
        let _ = logger.log_admin_check(false);
    }

    #[test]
    fn test_log_security_violation() {
        let logger = AuditLogger::new();
        let _ = logger.log_security_violation("System Drive", "Attempted to wipe C:");
    }
}
