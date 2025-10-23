# build.ps1 - Build ZeroRecover frontend + Tauri app

# Step 1: Clean old Tauri build
Write-Host "Cleaning old builds..."
if (Test-Path "src-tauri\target") {
    Remove-Item -Recurse -Force src-tauri\target
}

# Step 2: Build frontend
Write-Host "Building frontend (Vite)..."
npm run build

# Check if dist folder exists
if (!(Test-Path "dist")) {
    Write-Error "Frontend build failed: 'dist' folder not found."
    exit 1
}

# Step 3: Build Tauri app
Write-Host "Building Tauri app..."
cargo tauri build

# Step 4: Open output folder
$outputPath = "src-tauri\target\release\bundle"
if (Test-Path $outputPath) {
    Write-Host "Build completed. Opening output folder..."
    Start-Process $outputPath
} else {
    Write-Warning "Build completed but bundle folder not found."
}
