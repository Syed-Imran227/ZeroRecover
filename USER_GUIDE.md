# ZeroRecover - User Guide

## 🔹 What is ZeroRecover?

ZeroRecover is a Windows-based secure data wiping tool that provides verifiable proof of erasure. Built with Tauri (Rust + React), it offers military-grade data destruction with tamper-proof certificates.

## 🚀 Quick Start

### Installation

1. **Download the installer** from the releases page
2. **Run the MSI installer** or use the standalone .exe
3. **Launch ZeroRecover** from Start Menu or Desktop

### First Use

1. **Launch the application**
2. **Choose your wiping mode** (File, Folder, or Drive)
3. **Select your wipe method** (NIST SP 800-88 recommended)
4. **Select target files/folders/drives**
5. **Click "Start Secure Wipe"**
6. **Wait for completion** - certificates are automatically generated

## 📖 Using ZeroRecover

### File Shredder Mode

**Purpose:** Securely wipe individual files

**Steps:**
1. Click the **"File Shredder"** tab
2. Choose wipe method (NIST SP 800-88 recommended)
3. Click the file input to select files
4. Click **"Start Secure Wipe"**
5. Wait for completion
6. Certificate automatically saved to Documents folder

**Best for:** Deleting sensitive documents, temporary files, or specific files

### Folder Wipe Mode

**Purpose:** Recursively wipe entire directories

**Steps:**
1. Click the **"Folder Wipe"** tab
2. Select wipe method
3. Click **"Browse Folder"** to select a folder
4. Click **"Start Secure Wipe"**
5. All files in folder and subfolders will be securely wiped

**Best for:** Clearing project folders, temporary directories, or user data folders

### Full Drive Wipe Mode

**Purpose:** Complete disk erasure including hidden areas

**Steps:**
1. Click the **"Full Drive Wipe"** tab
2. Select wipe method (DoD 5220.22-M recommended for drives)
3. Select target drive from the list
4. **⚠️ WARNING**: This will permanently erase ALL data on the drive
5. Click **"Start Secure Wipe"**
6. Drive will be completely wiped including hidden areas

**Best for:** Preparing drives for sale/donation, complete system cleanup

## 🔒 Wipe Methods Explained

| Method | Passes | Speed | Security | Use Case |
|--------|--------|-------|----------|----------|
| **NIST SP 800-88** | 1 | ⚡⚡⚡ Fast | 🔒🔒🔒 High | Government standard, recommended |
| **DoD 5220.22-M** | 3 | ⚡⚡ Medium | 🔒🔒🔒🔒 Very High | Military grade, sensitive data |
| **Gutmann** | 35 | ⚡ Slow | 🔒🔒🔒🔒🔒 Maximum | Maximum security, paranoid |
| **Random** | 3 | ⚡⚡ Medium | 🔒🔒🔒 High | Balanced security/speed |
| **Zero** | 1 | ⚡⚡⚡ Fast | 🔒🔒 Medium | Quick wipe, basic security |

### Method Details

**NIST SP 800-88 (Recommended)**
- Single pass with cryptographically secure random data
- Fast and efficient
- Meets government standards for data sanitization
- **Best for:** General use, compliance requirements

**DoD 5220.22-M (Military Grade)**
- 3 passes: 0x00, 0xFF, Random
- Used by US Department of Defense
- High security for sensitive data
- **Best for:** Classified data, sensitive business information

**Gutmann (Maximum Security)**
- 35 passes with specific patterns
- Designed to recover data from magnetic media
- Slowest but most thorough method
- **Best for:** Maximum paranoia, high-value targets

**Random (Balanced)**
- 3 passes with random data
- Good balance of security and speed
- Suitable for most use cases
- **Best for:** Balanced approach, moderate sensitivity

**Zero (Fastest)**
- Single pass with zeros
- Fastest method
- Basic security for non-sensitive data
- **Best for:** Quick cleanup, non-sensitive files

## 💾 SSD/HDD Optimization

ZeroRecover automatically detects whether your drive is an SSD or HDD and optimizes the wiping strategy accordingly:

### For SSDs (Solid State Drives)
- **Reduced passes** to minimize wear while maintaining security
- **Single pass** is usually sufficient due to wear leveling
- **Faster execution** with same security level
- **Longer drive lifespan** by reducing unnecessary writes

### For HDDs (Hard Disk Drives)
- **Full passes** for maximum security against magnetic recovery
- **Multiple overwrites** ensure complete erasure
- **Meets military standards** for sensitive data
- **Protects against advanced recovery techniques**

## 📄 Certificate Generation

After each wipe operation, two certificates are generated:

### JSON Certificate
- **Location:** `Documents\zerorecover_certificate_TIMESTAMP.json`
- **Format:** Machine-readable JSON
- **Contains:** All wipe details and digital signature
- **Use:** Automated verification, compliance systems

### HTML Certificate
- **Location:** `Documents\zerorecover_certificate_TIMESTAMP.pdf`
- **Format:** Human-readable HTML (opens in browser)
- **Contains:** Professional certificate with all details
- **Use:** Compliance documentation, audit trails

### Certificate Contents

- ✅ **Unique Certificate ID** - UUID for tracking
- ✅ **Timestamp** - When wipe occurred (UTC)
- ✅ **Target** - What was wiped (file/folder/drive)
- ✅ **Method** - Wipe method used
- ✅ **Bytes Wiped** - Amount of data destroyed
- ✅ **Passes Completed** - Number of overwrite passes
- ✅ **Duration** - Time taken for operation
- ✅ **Device ID** - Hardware identifier
- ✅ **SHA-256 Hash** - Cryptographic hash of operation
- ✅ **Ed25519 Digital Signature** - Tamper-proof signature
- ✅ **Public Key** - For signature verification
- ✅ **Verification Hash** - Integrity check

## ⚠️ Important Safety Notes

### Before Wiping

1. **Backup Important Data** - Wiping is permanent and irreversible
2. **Close All Programs** - Ensure files are not in use
3. **Run as Administrator** - Required for drive wiping
4. **Verify Target** - Double-check you selected the correct files/drive
5. **Test First** - Try with test files before important data

### Drive Wiping Warnings

- ⚠️ **Cannot be undone** - All data will be permanently destroyed
- ⚠️ **Takes time** - Large drives may take hours
- ⚠️ **Requires admin** - Must run as administrator
- ⚠️ **System drive** - Do not wipe your Windows installation drive
- ⚠️ **External drives** - Can wipe USB drives and external HDDs

## 🎯 Common Use Cases

### 1. Selling/Donating Computer
```
1. Backup important files
2. Use "Full Drive Wipe" with DoD 5220.22-M
3. Wipe all drives except system drive
4. Reinstall Windows on system drive
5. Keep certificates for your records
```

### 2. Deleting Sensitive Documents
```
1. Select files using "File Shredder"
2. Use NIST SP 800-88 for speed
3. Verify files are deleted
4. Store certificate in secure location
```

### 3. Clearing USB Drive
```
1. Plug in USB drive
2. Use "Full Drive Wipe"
3. Select USB drive letter
4. Use Random method (3 passes)
5. Drive is ready for reuse
```

### 4. Compliance Requirements
```
1. Use DoD 5220.22-M or Gutmann
2. Save both JSON and HTML certificates
3. Store certificates securely
4. Include in compliance documentation
5. Certificates prove data destruction
```

## 🔧 Troubleshooting

### "Access Denied" Error
**Solution:** Run the application as Administrator
- Right-click `zero-recover.exe`
- Select "Run as administrator"

### "File in use" Error
**Solution:** Close all programs using the file
- Close Word, Excel, PDF readers, etc.
- Check Task Manager for background processes

### Application Won't Start
**Solution:** Install Visual C++ Redistributable
- Download from Microsoft
- Install both x64 and x86 versions

### Certificate Generation Fails
**Solution:** Check permissions and disk space
- Ensure write permissions in Documents folder
- Check available disk space
- Run as administrator if needed

## 📊 Performance Tips

### Faster Wiping
- Use **NIST SP 800-88** (1 pass) for speed
- Close other applications
- Wipe smaller batches of files
- Use SSD instead of HDD

### Maximum Security
- Use **Gutmann** (35 passes) for paranoid security
- Use **DoD 5220.22-M** (3 passes) for balanced security
- Verify certificates after wiping
- Keep certificates in secure location

## 🎓 Best Practices

1. **Always backup** before wiping
2. **Test first** with non-important files
3. **Verify target** before clicking wipe
4. **Save certificates** for compliance
5. **Use appropriate method** for your needs
6. **Run as admin** for full functionality
7. **Close other apps** during wiping
8. **Keep software updated** for security

## 📞 Support

### Getting Help
- Read this user guide thoroughly
- Check the troubleshooting section
- Review error messages carefully
- Search GitHub Issues for similar problems

### Reporting Issues
Include:
- Error message
- Steps to reproduce
- Windows version
- Application version
- Screenshots if applicable

## ✅ Verification Checklist

Before using ZeroRecover in production:

- [ ] Tested with sample files
- [ ] Verified certificates are generated
- [ ] Checked certificate contents
- [ ] Tested all wipe methods
- [ ] Confirmed files are deleted
- [ ] Reviewed security warnings
- [ ] Backed up important data
- [ ] Read all documentation

## ⚠️ Disclaimer

This tool is designed for legitimate data destruction purposes. Users are responsible for ensuring they have proper authorization to wipe data and comply with applicable laws and regulations. The authors are not responsible for any misuse of this software.

---

**ZeroRecover** - Secure, Verifiable, Professional Data Destruction
