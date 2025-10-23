# ZeroRecover - Security Quick Reference

## 🛡️ Security Protection Summary

### What's Protected (Cannot Be Wiped):

#### System Drives:
- ❌ C:\ (system drive root)
- ❌ Any drive with Windows installation
- ❌ Boot partitions

#### Windows Directories:
- ❌ C:\Windows (all subdirectories)
- ❌ C:\Windows\System32
- ❌ C:\Windows\SysWOW64
- ❌ C:\Windows\WinSxS
- ❌ C:\Windows\Boot
- ❌ C:\Windows\Inf
- ❌ C:\Windows\Fonts
- ❌ C:\Windows\Drivers

#### Program Files:
- ❌ C:\Program Files
- ❌ C:\Program Files (x86)
- ❌ C:\Program Files\WindowsApps

#### System Data:
- ❌ C:\ProgramData\Microsoft\Windows
- ❌ C:\ProgramData\Package Cache
- ❌ C:\Boot
- ❌ C:\Recovery
- ❌ C:\System Volume Information
- ❌ C:\$Recycle.Bin

#### User Profiles:
- ❌ C:\Users\Default
- ❌ C:\Users\Public
- ❌ C:\Users\All Users
- ❌ C:\Users\YourName (profile root)

---

### What's Allowed (Can Be Wiped):

#### User Folders:
- ✅ C:\Users\YourName\Documents
- ✅ C:\Users\YourName\Downloads
- ✅ C:\Users\YourName\Desktop
- ✅ C:\Users\YourName\Pictures
- ✅ C:\Users\YourName\Videos
- ✅ C:\Users\YourName\Music

#### External Drives:
- ✅ D:\ (if not system drive)
- ✅ E:\ (if not system drive)
- ✅ USB drives (if not system drive)
- ✅ External HDDs/SSDs

#### Custom Folders:
- ✅ C:\Temp
- ✅ C:\Data
- ✅ Any non-system folder

---

## 🔒 Security Features

### 1. System Drive Protection
```
Error: "CRITICAL SECURITY ERROR: Cannot wipe system drive C:."
Reason: Prevents destroying Windows installation
Bypass: None (by design)
```

### 2. Path Validation
```
- Canonicalization (resolves .. and symlinks)
- Case-insensitive matching
- Protected path detection
- User profile root blocking
```

### 3. Drive Validation
```
- Checks %SystemDrive% environment variable
- Verifies Windows directory doesn't exist on target
- Requires explicit confirmation ("ERASE MY DRIVE")
```

### 4. UI Warnings
```
- Red warning box for drive wipe
- Blue security notification
- Clear risk explanation
- Confirmation input required
```

---

## 🧪 Quick Test Commands

### Test System Drive Protection:
```rust
// Should fail with CRITICAL error
PathValidator::validate_drive_letter("C")
```

### Test Protected Path:
```rust
// Should fail with CRITICAL error
PathValidator::validate_file_path("C:\\Windows\\System32\\test.txt")
```

### Test Case Insensitivity:
```rust
// All should fail
PathValidator::validate_folder_path("C:\\WINDOWS")
PathValidator::validate_folder_path("c:\\windows")
PathValidator::validate_folder_path("C:\\WiNdOwS")
```

### Test User Profile:
```rust
// Should fail
PathValidator::validate_folder_path("C:\\Users\\John")

// Should succeed
PathValidator::validate_folder_path("C:\\Users\\John\\Documents")
```

---

## 🚨 Error Messages

### System Drive Error:
```
CRITICAL SECURITY ERROR: Cannot wipe system drive C:. 
This is your Windows installation drive and wiping it would make 
your computer unbootable. If you need to wipe this drive, please 
boot from a different operating system or use a bootable USB tool.
```

### Protected Path Error:
```
CRITICAL: Cannot wipe system-critical directory: C:\Windows. 
This is a protected Windows system path.
```

### User Profile Error:
```
WARNING: Cannot wipe user profile root directory: C:\Users\John. 
Please select specific folders within the user profile.
```

---

## 📋 Developer Checklist

Before committing code that modifies path validation:

- [ ] Does it maintain system drive protection?
- [ ] Does it use case-insensitive matching?
- [ ] Does it check all protected paths?
- [ ] Does it provide clear error messages?
- [ ] Does it have test coverage?
- [ ] Does it prevent bypass attempts?

---

## 🔧 Common Issues & Solutions

### Issue: "Cannot wipe my external drive"
**Solution**: Check if drive has Windows directory. If yes, it's blocked for safety.

### Issue: "Cannot wipe my Documents folder"
**Solution**: This should work. Check error message for specific reason.

### Issue: "Want to wipe C: drive for reinstall"
**Solution**: Use bootable USB tool (e.g., DBAN, Windows Installation Media). Cannot be done from running Windows.

---

## 📊 Security Levels

| Level | Description | Example |
|-------|-------------|---------|
| 🔴 CRITICAL | System destruction | C:\, C:\Windows |
| 🟠 HIGH | Data loss | C:\Program Files |
| 🟡 MEDIUM | User data | C:\Users\Name |
| 🟢 LOW | Safe folders | Documents, Downloads |

---

## 🎯 Quick Decision Tree

```
Is it the system drive (C:)?
├─ YES → ❌ BLOCKED
└─ NO → Does it have Windows directory?
    ├─ YES → ❌ BLOCKED
    └─ NO → Is it a protected path?
        ├─ YES → ❌ BLOCKED
        └─ NO → Is it user profile root?
            ├─ YES → ❌ BLOCKED
            └─ NO → ✅ ALLOWED
```

---

## 🔐 Security Guarantees

ZeroRecover guarantees:
1. ✅ System drive CANNOT be wiped
2. ✅ Windows installation CANNOT be destroyed
3. ✅ Critical system files CANNOT be deleted
4. ✅ No bypass mechanism exists
5. ✅ Clear warnings before any operation

---

## 📞 Need Help?

- **Documentation**: See `SECURITY.md` for detailed analysis
- **Fixes Applied**: See `SECURITY_FIXES_APPLIED.md` for changes
- **User Guide**: See `USER_GUIDE.md` for end-user instructions
- **Developer Guide**: See `DEVELOPER_GUIDE.md` for build instructions

---

**Last Updated**: 2025-10-18  
**Version**: 0.1.0 (Security Hardened)  
**Status**: ✅ Production Ready
