# ZeroRecover Development Script
# Quick script to run the app in development mode

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ZeroRecover Development Mode" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "✗ Failed to install dependencies" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Starting development server..." -ForegroundColor Yellow
Write-Host "This will:" -ForegroundColor Cyan
Write-Host "  - Start Vite dev server on http://localhost:1420" -ForegroundColor White
Write-Host "  - Compile Rust backend" -ForegroundColor White
Write-Host "  - Launch application window" -ForegroundColor White
Write-Host "  - Enable hot reload for frontend changes" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

npm run tauri dev
