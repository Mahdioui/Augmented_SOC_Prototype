# setup.ps1 — One-click setup script for the Agentic SOC Prototype (Windows PowerShell)
# Usage: Right-click > "Run with PowerShell", or: .\setup.ps1

Write-Host ""
Write-Host "============================================================"
Write-Host "  Agentic SOC Prototype — Setup Script"
Write-Host "============================================================"
Write-Host ""

# 1. Check Python
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.(1[0-9]|[89])") {
            $pythonCmd = $cmd
            Write-Host "[OK] Python found: $ver (command: $cmd)"
            break
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "[ERROR] Python 3.10+ not found."
    Write-Host "        Download from: https://www.python.org/downloads/"
    Write-Host "        Make sure to check 'Add Python to PATH' during installation."
    exit 1
}

# 2. Create virtual environment
Write-Host ""
Write-Host "[1/3] Creating virtual environment (.venv)..."
& $pythonCmd -m venv .venv
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Failed to create venv"; exit 1 }

# 3. Install dependencies
Write-Host "[2/3] Installing dependencies..."
& ".\.venv\Scripts\pip.exe" install -r requirements.txt -q
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Failed to install dependencies"; exit 1 }

# 4. Quick smoke test
Write-Host "[3/3] Running smoke test..."
& ".\.venv\Scripts\python.exe" -c "from schemas.input_schema import RawAlert; from schemas.output_schema import TriageResult; print('  Schema imports OK')"
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Import test failed"; exit 1 }

Write-Host ""
Write-Host "============================================================"
Write-Host "  Setup complete! To run the prototype:"
Write-Host ""
Write-Host "  .\.venv\Scripts\python.exe app.py"
Write-Host "  .\.venv\Scripts\python.exe app.py --list"
Write-Host "  .\.venv\Scripts\python.exe app.py --scenario brute_force_ldap"
Write-Host "  .\.venv\Scripts\python.exe app.py --simulation"
Write-Host "============================================================"
Write-Host ""
